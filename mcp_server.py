"""MCP server exposing the local tools (file access + RAG) via FastMCP.

The agent connects to this as an MCP client (see mcp_client.py); you can also point any
other MCP client (Claude Desktop, MCP Inspector, ...) at it:  python mcp_server.py
"""
from fastmcp import FastMCP

from tools import file_tools, rag_tool

# The server object; "local-tools" is the name clients see.
mcp = FastMCP("local-tools")


# Tool 1: list a folder inside the sandbox. (The docstring is the tool description the model reads.)
@mcp.tool
def list_directory(path: str = ".") -> str:
    """List files and folders in a directory (path is relative to the sandbox root)."""
    return file_tools.list_directory(path)


# Tool 2: read one text file inside the sandbox.
@mcp.tool
def read_file(path: str) -> str:
    """Read a text file (path is relative to the sandbox root)."""
    return file_tools.read_file(path)


# Tool 3: search the company docs and the user's uploaded files with one call.
@mcp.tool
def search_documents(query: str) -> str:
    """Search the documents and return the most relevant passages. Covers the built-in company
    knowledge base (HR, leave, security policy, product FAQ) AND any PDF/TXT files the user has
    uploaded in this chat. Use it for any question about a document, a file, a policy or a product."""
    return rag_tool.search_documents(query)


# Run the server over stdio (stdout carries the protocol, so the startup banner is switched off).
if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="WARNING")
