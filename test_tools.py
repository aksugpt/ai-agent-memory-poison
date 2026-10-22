"""Offline checks for the tools (no language model or API key needed): plain functions first, then through MCP."""
from mcp_client import get_bridge, load_mcp_tools
from tools.file_tools import list_directory, read_file
from tools.rag_tool import ingest_documents, search_documents


def check(name, cond):
    """Print PASS/FAIL for one check and return whether it passed."""
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    return cond


ok = True

# ---- the tools called directly as Python functions ----
print("-- plain functions")
ok &= check("list root", "todo.txt" in list_directory("."))
ok &= check("list subdir", "meeting.txt" in list_directory("notes"))
ok &= check("read file", "Prototype demo" in read_file("notes/meeting.txt"))
# Attempts to leave the sandbox must be refused.
ok &= check("block ../ traversal", "escapes sandbox" in read_file("../../.env.example"))
ok &= check("block absolute path", "escapes sandbox" in read_file("C:/Windows/win.ini"))
ok &= check("block dir traversal", "escapes sandbox" in list_directory(".."))

# Rebuild the company-docs index, then search it.
n = ingest_documents()
ok &= check(f"ingest ({n} chunks)", n > 0)
ok &= check("rag retrieval", "12 USD" in search_documents("How much is the Pro plan?"))

# ---- the same tools reached through the FastMCP server, as the agent uses them ----
print("-- through the FastMCP server")
tools = {t.name: t for t in load_mcp_tools()}
ok &= check("server exposes 3 tools", set(tools) == {"list_directory", "read_file", "search_documents"})
ok &= check("MCP read_file", "Write report draft" in tools["read_file"].invoke({"path": "todo.txt"}))
ok &= check("MCP list_directory default arg", "todo.txt" in tools["list_directory"].invoke({}))
ok &= check("MCP blocks traversal", "escapes sandbox" in tools["read_file"].invoke({"path": "../../.env"}))
ok &= check("MCP rag retrieval", "12 USD" in tools["search_documents"].invoke({"query": "Pro plan price"}))

# Stop the background MCP server and print the overall result.
get_bridge().close()
print("\nALL PASSED" if ok else "\nSOME FAILED")
