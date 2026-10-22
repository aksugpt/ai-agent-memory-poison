"""Numbers for the context meter: how big the model's context window is, and how much of it a turn used."""
import json
import os
import time
import urllib.request

import config

# ---- settings ---------------------------------------------------------------------------------
DEFAULT_OLLAMA_WINDOW = 4096   # Ollama's default window, used when the server does not say otherwise
DEFAULT_GROQ_WINDOW = 131_072  # window of the Groq model, used if the lookup fails
WARN_AT = 0.60                 # the meter turns amber from this share of the window
FULL_AT = 0.85                 # the meter turns red from this share (the oldest text may be cut off soon)
_CACHE_SECONDS = 30            # how long a looked-up window size is reused

# Cache of looked-up windows: "provider:model" -> (time looked up, (tokens, where the number came from)).
_cache: dict[str, tuple[float, tuple[int, str]]] = {}


def _get_json(url: str, data: dict | None = None, headers: dict | None = None, timeout: float = 2.0) -> dict:
    """GET (or POST when data is given) a URL and return the JSON answer."""
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode() if data else None,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _ollama_window() -> tuple[int, str]:
    """The window Ollama really uses for the local model (not the model's theoretical maximum)."""
    base = config.OLLAMA_BASE_URL
    try:
        # Best source: the list of loaded models says what window each one was started with.
        for m in _get_json(f"{base}/api/ps").get("models", []):
            if m.get("name") == config.OLLAMA_MODEL and m.get("context_length"):
                return int(m["context_length"]), "reported by Ollama"
        # Not loaded yet: a window fixed in the model file would be listed among its parameters.
        for line in _get_json(f"{base}/api/show", {"model": config.OLLAMA_MODEL}).get("parameters", "").splitlines():
            parts = line.split()
            if parts[:1] == ["num_ctx"] and len(parts) > 1:
                return int(parts[1]), "set in the model file"
    except Exception:
        pass  # Ollama is down or answered oddly: fall back to its default below
    return DEFAULT_OLLAMA_WINDOW, "Ollama default"


def _groq_window() -> tuple[int, str]:
    """The context window Groq lists for the cloud model."""
    key = os.getenv("GROQ_API_KEY")
    if key:
        try:
            data = _get_json("https://api.groq.com/openai/v1/models",
                             headers={"Authorization": "Bearer " + key, "User-Agent": "memory-poisoning-lab/1.0"},
                             timeout=4.0)
            for m in data.get("data", []):
                if m.get("id") == config.GROQ_MODEL and m.get("context_window"):
                    return int(m["context_window"]), "reported by Groq"
        except Exception:
            pass  # offline or rejected: fall back to the known size below
    return DEFAULT_GROQ_WINDOW, "assumed"


def context_window(provider: str) -> tuple[int, str]:
    """(window size in tokens, where that number came from) for the chosen provider, cached for a short time."""
    model = config.GROQ_MODEL if provider == "groq" else config.OLLAMA_MODEL
    key = f"{provider}:{model}"
    now = time.time()
    hit = _cache.get(key)
    if hit and now - hit[0] < _CACHE_SECONDS:
        return hit[1]
    value = _groq_window() if provider == "groq" else _ollama_window()
    _cache[key] = (now, value)
    return value


def usage_from_message(msg) -> dict | None:
    """Token counts the model reported for one reply: {'input': prompt tokens, 'output': answer tokens}, or None."""
    meta = getattr(msg, "usage_metadata", None)
    if not meta:
        return None
    return {"input": int(meta.get("input_tokens", 0)), "output": int(meta.get("output_tokens", 0))}


def level(used: int, window: int) -> str:
    """'ok', 'warn' or 'full', depending on how much of the window is used."""
    share = used / window if window else 0
    return "full" if share >= FULL_AT else "warn" if share >= WARN_AT else "ok"
