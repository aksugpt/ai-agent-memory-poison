"""Vetting of MCP tool *definitions* (descriptions + schemas) before the LLM ever sees them.

Defends against tool poisoning: hidden instructions in a tool's description or parameter docs,
tools that shadow trusted ones, and "rug pulls" (a definition that changes after it was approved).
"""
import hashlib
import json
import re
from dataclasses import dataclass, field

import config
from guard.classifier import Guard
from mcp_client import ToolDef

# File that remembers the approved fingerprint of every tool.
PIN_PATH = config.ROOT / "models" / "tool_pins.json"
# The parts of a JSON schema that hold human-readable text (what the model reads as parameter docs).
_SCHEMA_TEXT_KEYS = {"description", "title", "default", "examples", "const", "enum"}
# Plain-English names for the attack types, used in the "why was it removed" sentence.
_LABELS = {
    "prompt_injection": "hidden instructions aimed at the AI",
    "malicious_intent": "a hidden request to steal or send data",
    "dangerous_command": "a dangerous command or file access",
}


@dataclass
class Finding:
    """One problem the vetting found with one tool."""
    tool: str
    server: str
    kind: str  # description | schema | shadowing | changed
    action: str  # flag | block
    label: str
    score: float
    reasons: list[str] = field(default_factory=list)
    text: str = ""  # the description / parameter text that was judged (shown to the user, never to the model)


# ---- reading and fingerprinting tool definitions ----------------------------------------------
def schema_strings(node) -> list[str]:
    """All human-readable strings in a JSON schema (what the LLM sees as parameter docs)."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _SCHEMA_TEXT_KEYS:
                out += [str(x) for x in (v if isinstance(v, list) else [v]) if isinstance(x, (str, int, float))]
            elif isinstance(v, (dict, list)):
                out += schema_strings(v)  # look inside nested parameter definitions
    elif isinstance(node, list):
        for v in node:
            out += schema_strings(v)
    return out


def fingerprint(d: ToolDef) -> str:
    """A hash of everything the model reads about a tool; it changes if any of it changes."""
    blob = json.dumps({"name": d.name, "description": d.description, "schema": d.input_schema}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class PinStore:
    """Trust-on-first-use pins: server+tool -> hash of the approved definition."""

    def __init__(self, path=PIN_PATH):
        # Load the saved pins, or start empty if the file is missing or unreadable.
        self.path = path
        try:
            self.pins = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except Exception:
            self.pins = {}

    @staticmethod
    def _key(d: ToolDef) -> str:
        """The pin's name: which server offers the tool, and the tool's name."""
        return f"{d.server}::{d.name}"

    def status(self, d: ToolDef) -> str:
        """'new' (never seen), 'ok' (same as approved) or 'changed' (differs from the approved version)."""
        old = self.pins.get(self._key(d))
        return "new" if old is None else ("ok" if old == fingerprint(d) else "changed")

    def approve(self, d: ToolDef) -> None:
        """Remember this tool's current definition as the approved one and save it to disk."""
        self.pins[self._key(d)] = fingerprint(d)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.pins, indent=2), encoding="utf-8")


# ---- messages about removed tools -------------------------------------------------------------
def explain_block(f: Finding) -> str:
    """One plain-language sentence on why a tool was removed."""
    if f.kind == "shadowing":
        return "it tried to replace a trusted tool that has the same name"
    if f.kind == "changed":
        return "its definition changed after it was approved (a possible 'rug pull')"
    where = "its description" if f.kind == "description" else "its parameter descriptions"
    return f"{where} contained {_LABELS.get(f.label, 'suspicious content')} (risk score {f.score:.2f})"


def blocked_tool_for_prompt(prompt: str, findings: list[Finding]) -> Finding | None:
    """The removed tool that the user's message names (e.g. 'use the add_numbers tool'), if any."""
    for f in findings:
        if f.action != "block":
            continue
        for name in {f.tool, f.tool.replace("_", " ")}:  # match "add_numbers" and "add numbers"
            if re.search(rf"\b{re.escape(name)}\b", prompt, re.I):
                return f
    return None


def friendly_block_message(f: Finding) -> str:
    """The reply shown when the user asks for a tool the guard removed."""
    return (f"**I can't use `{f.tool}`.** The security guard removed it before I could see it, because "
            f"{explain_block(f)}. It came from the untrusted server `{f.server}`. "
            "Turn the guard off in the sidebar if you want to see what happens without protection.")


def fake_tool_call_name(text: str) -> str | None:
    """If the model's whole answer is just a tool call written out as JSON text (nothing was actually
    called), return the tool name. Small models do this when asked for a tool they do not have."""
    t = text.strip()
    if not (t.startswith("{") and t.endswith("}")):
        return None
    try:
        obj = json.loads(t)
    except ValueError:
        return None
    if isinstance(obj, dict) and isinstance(obj.get("name"), str) and ("parameters" in obj or "arguments" in obj):
        return obj["name"]
    return None


def reply_for_fake_tool_call(text: str, findings: list[Finding], available: set[str]) -> str | None:
    """A plain-language replacement when the answer is a written-out call to a tool that is not available."""
    name = fake_tool_call_name(text)
    if name is None or name in available:
        return None  # not a fake call, or it names a tool that really exists
    for f in findings:
        if f.action == "block" and f.tool == name:
            return friendly_block_message(f)  # the tool was removed by the guard
    return (f"I tried to use a tool called `{name}`, but I don't have a tool with that name. "
            "Ask me directly (for example, just the calculation) and I will answer without it.")


# ---- the vetting itself -----------------------------------------------------------------------
def vet_tool_defs(defs: list[ToolDef], guard: Guard, pins: PinStore | None = None) -> tuple[list[ToolDef], list[Finding]]:
    """Return (allowed_defs, findings). Earlier servers in `defs` are trusted more than later ones."""
    allowed: list[ToolDef] = []
    findings: list[Finding] = []
    taken = set()  # names already provided by an allowed (more trusted) tool

    for d in defs:
        local: list[Finding] = []

        # Check 1: a later server must not reuse the name of an earlier, trusted tool (shadowing).
        if d.name in taken:
            local.append(Finding(d.name, d.server, "shadowing", "block", "prompt_injection", 1.0,
                                 [f"tool name '{d.name}' is already provided by a trusted server"]))

        # Check 2: classify the description and the parameter docs for hidden instructions.
        for kind, text in (("description", d.description), ("schema", "\n".join(schema_strings(d.input_schema)))):
            if text.strip():
                dec = guard.check(text, source="tool_description")
                if dec.action != "allow":
                    local.append(Finding(d.name, d.server, kind, dec.action, dec.label, dec.score, dec.reasons, text))

        # Check 3: a definition that differs from the approved one is a possible rug pull.
        if pins is not None and pins.status(d) == "changed":
            local.append(Finding(d.name, d.server, "changed", "block", "prompt_injection", 1.0,
                                 ["definition changed since it was approved (possible rug pull); "
                                  "if the change is legitimate, delete models/tool_pins.json to re-approve"]))

        findings += local
        if any(f.action == "block" for f in local):
            continue  # any block removes the tool
        allowed.append(d)
        taken.add(d.name)
        if pins is not None and pins.status(d) == "new":
            pins.approve(d)  # first time seen and clean: remember it as approved

    return allowed, findings
