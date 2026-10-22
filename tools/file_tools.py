"""Sandboxed file tools (plain functions; the agent reaches them through mcp_server.py)."""
from pathlib import Path

import config


def _resolve_in_sandbox(rel: str) -> Path:
    """Turn a relative path into a real path inside the sandbox, or refuse if it would escape it."""
    # Resolving removes "..", symlinks and absolute-path tricks before the check.
    base = config.SANDBOX_DIR.resolve()
    target = (base / rel).resolve()
    # The target must be the sandbox itself or live somewhere underneath it.
    if target != base and base not in target.parents:
        raise PermissionError(f"Path escapes sandbox: {rel}")
    return target


def list_directory(path: str = ".") -> str:
    """List files and folders in a directory (path is relative to the sandbox root)."""
    try:
        target = _resolve_in_sandbox(path)
        if not target.is_dir():
            return f"Error: not a directory: {path}"
        # Folders first, then files, each sorted by name.
        entries = sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name))
        if not entries:
            return "(empty)"
        return "\n".join(f"{'[DIR] ' if p.is_dir() else '[FILE]'} {p.name}" for p in entries)
    except Exception as e:  # errors are returned as text so the model can react to them
        return f"Error: {e}"


def read_file(path: str) -> str:
    """Read a text file (path is relative to the sandbox root)."""
    try:
        target = _resolve_in_sandbox(path)
        if not target.is_file():
            return f"Error: not a file: {path}"
        text = target.read_text(encoding="utf-8", errors="replace")
        # Very long files are cut so one read cannot flood the model's context.
        if len(text) > config.MAX_READ_CHARS:
            text = text[: config.MAX_READ_CHARS] + "\n...[truncated]"
        return text
    except Exception as e:  # errors are returned as text so the model can react to them
        return f"Error: {e}"
