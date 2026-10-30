"""Bridge from FastMCP servers to LangChain tools.

One persistent MCP session per server runs on a background event-loop thread, so tool calls are
fast (no process spawn per call) and the resulting LangChain tools stay synchronous.
Several servers can be connected; their order is their trust order (see guard/toolscan.py).
"""
import asyncio
import atexit
import json
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport
from fastmcp.exceptions import ToolError
from langchain_core.tools import StructuredTool

import config

# The trusted tool server, the read-only Gmail server, and the deliberately malicious one used for tool-poisoning tests.
SERVER_SCRIPT = config.ROOT / "mcp_server.py"
EMAIL_SCRIPT = config.ROOT / "mcp_server_email.py"
WRITE_SCRIPT = config.ROOT / "mcp_server_docs.py"
POISONED_SCRIPT = config.ROOT / "mcp_server_poisoned.py"
# Seconds to wait for a server to start / for one tool call to finish.
CONNECT_TIMEOUT = 90
CALL_TIMEOUT = 120


@dataclass
class ToolDef:
    """What an MCP server advertises about one tool (this is what the LLM reads)."""
    name: str
    description: str
    input_schema: dict
    server: str = "local-tools"  # which server offers it
    script: str = ""             # the server's script path (used to reconnect)
    env: dict = field(default_factory=dict)  # environment the server was started with


class MCPBridge:
    """A live connection to one MCP server, run on its own background thread."""

    def __init__(self, script, env: dict | None = None):
        self.script = Path(script)
        self.env = env or {}
        # State shared with the background thread.
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._stop: asyncio.Event | None = None
        self._client = None
        self.tools = []  # the server's tool definitions, filled in once connected
        # Start the thread and wait until the server is connected (or failed to start).
        self._thread = threading.Thread(target=self._run, name=f"mcp-{self.script.stem}", daemon=True)
        self._thread.start()
        if not self._ready.wait(CONNECT_TIMEOUT):
            raise RuntimeError(f"Timed out starting MCP server {self.script.name}")
        if self._error:
            raise RuntimeError(f"Could not start MCP server {self.script.name}: {self._error!r}")

    def _run(self) -> None:
        """Thread entry point: run the connection until it is told to stop."""
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main())

    async def _main(self) -> None:
        """Start the server, list its tools, then keep the session open until close() is called."""
        self._stop = asyncio.Event()
        try:
            transport = PythonStdioTransport(
                str(self.script), python_cmd=sys.executable, cwd=str(config.ROOT),
                env=self.env or None, keep_alive=False,
            )
            async with Client(transport) as client:
                self._client = client
                self.tools = await client.list_tools()
                self._ready.set()  # tell the constructor we are connected
                await self._stop.wait()
        except BaseException as e:  # surface start-up failures to the constructor
            self._error = e
        finally:
            self._ready.set()

    def call(self, name: str, args: dict) -> str:
        """Run one tool on the server and return its text output (errors come back as text)."""
        fut = asyncio.run_coroutine_threadsafe(self._client.call_tool(name, args), self._loop)
        try:
            result = fut.result(CALL_TIMEOUT)
        except ToolError as e:
            return f"Error: {e}"
        return "\n".join(c.text for c in result.content if getattr(c, "text", None) is not None)

    @property
    def server_name(self) -> str:
        """A short name for the server (its script name)."""
        return self.script.stem

    def close(self) -> None:
        """Disconnect and stop the background thread."""
        if self._stop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._stop.set)
            self._thread.join(timeout=10)


# One shared bridge per (server script, environment); the lock keeps two threads from starting the same one.
_bridges: dict[str, MCPBridge] = {}
_lock = threading.Lock()


def get_bridge(script=SERVER_SCRIPT, env: dict | None = None) -> MCPBridge:
    """Return the shared connection to a server, starting it on first use (or if its thread died)."""
    key = f"{Path(script)}|{json.dumps(env or {}, sort_keys=True)}"
    with _lock:
        b = _bridges.get(key)
        if b is None or not b._thread.is_alive():
            b = _bridges[key] = MCPBridge(script, env)
            atexit.register(b.close)  # make sure the server process is stopped when Python exits
        return b


def fetch_tool_defs(servers=None) -> list[ToolDef]:
    """Connect to each server (script path or (path, env)) and list the tools it advertises."""
    defs = []
    for s in servers or [SERVER_SCRIPT]:
        script, env = (s if isinstance(s, tuple) else (s, None))
        bridge = get_bridge(script, env)
        for t in bridge.tools:
            defs.append(ToolDef(t.name, t.description or "", t.input_schema, bridge.server_name, str(script), env or {}))
    return defs


def to_langchain_tools(defs: list[ToolDef]) -> list[StructuredTool]:
    """Wrap tool definitions as LangChain tools whose calls go to the right MCP server."""
    def make(d: ToolDef):
        # Each tool gets its own function bound to its server and name.
        def run(**kwargs) -> str:
            return get_bridge(d.script, d.env).call(d.name, kwargs)

        return run

    return [
        StructuredTool(name=d.name, description=d.description, args_schema=d.input_schema, func=make(d),
                       metadata={"server": d.server})
        for d in defs
    ]


def load_mcp_tools(servers=None, vet=None) -> list[StructuredTool]:
    """Return MCP tools as LangChain tools. `vet(defs) -> allowed_defs` can filter them first."""
    defs = fetch_tool_defs(servers)
    if vet is not None:
        defs = vet(defs)  # the guard removes tools it does not trust here
    return to_langchain_tools(defs)
