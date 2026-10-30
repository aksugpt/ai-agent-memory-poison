"""MCP server with WRITE tools for the user's uploaded documents (FastMCP).

These can change or remove what is indexed, unlike every other tool in this lab, which only reads.
They are opt-in in the UI (off by default), kept on a separate server from the read-only ones, and the
guard adds an extra check just for these two: the user's own message must name the file being changed
(see guard/wrap.py, WRITE_TOOLS). With the guard off, that check does not run.
"""
from fastmcp import FastMCP

from tools import rag_tool

# The server object; "doc-write-tools" is the name clients see.
mcp = FastMCP("doc-write-tools")


# Tool 1: replace an uploaded file's text.
@mcp.tool
def update_document(filename: str, new_text: str) -> str:
    """Store new text for an uploaded document and refresh its index entry."""
    return rag_tool.update_document(filename, new_text)


# Tool 2: remove an uploaded file.
@mcp.tool
def delete_document(filename: str) -> str:
    """Remove an uploaded document from the search index."""
    return rag_tool.delete_document(filename)


# Run the server over stdio (stdout carries the protocol, so the startup banner is switched off).
if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="WARNING")
