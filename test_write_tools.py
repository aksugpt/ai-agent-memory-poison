"""Offline tests for the document-edit tools (update_document / delete_document) and the guard's consent
check on them: a write tool may act only on a file the user's OWN message names (no language model needed).
"""
from langchain_core.tools import StructuredTool

from guard import Guard
from guard.toolscan import vet_tool_defs
from guard.wrap import guard_tool
import config
from mcp_client import fetch_tool_defs
from tools.rag_tool import (_upload_collection, add_uploaded_document, clear_uploaded_documents,
                            delete_document, list_uploaded_documents, update_document)

failed = 0


def check(name: str, ok: bool) -> None:
    """Print PASS/FAIL for one check."""
    global failed
    failed += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")


def tool_for(func, name: str, guard: Guard):
    """A guarded copy of a write tool whose function is `func` (what the agent would call)."""
    return guard_tool(StructuredTool.from_function(func=func, name=name, description="test tool"), guard)


def stored_text(filename: str) -> str:
    """All indexed text for one uploaded file, joined, so a test can check it changed."""
    col = _upload_collection().get(where={"source": filename}, include=["documents"])
    return "\n".join(col["documents"])


# ---- the plain functions (no guard): this is what app.py's own upload/remove buttons also use ------------
clear_uploaded_documents()
add_uploaded_document("vendors.csv", [(0, 1, "Row 1: vendor: Orion Supplies; status: active")])
check("setup: file is indexed", list_uploaded_documents().get("vendors.csv") == 1)

check("update: replaces the text and re-indexes", "passage(s) now indexed" in update_document(
    "vendors.csv", "Row 1: vendor: Orion Supplies\nRow 2: vendor: Kestrel Print"))
check("update: the new text is really there", "Kestrel Print" in stored_text("vendors.csv"))
check("update: a file that was never uploaded gives a clear error", update_document("nope.csv", "x").startswith("Error"))

check("delete: removes a real file", delete_document("vendors.csv").startswith("Deleted"))
check("delete: it is really gone", "vendors.csv" not in list_uploaded_documents())
check("delete: a file that is not indexed gives a clear error", delete_document("vendors.csv").startswith("Error"))

# ---- the guard's consent check: the user's OWN message must name the file ------------------------------
add_uploaded_document("vendors.csv", [(0, 1, "Row 1: vendor: Orion Supplies")])
g = Guard(log=False)
update = tool_for(lambda filename, new_text: update_document(filename, new_text), "update_document", g)
delete = tool_for(lambda filename: delete_document(filename), "delete_document", g)

g.current_question = "Please update vendors.csv: add a new row for Kestrel Print."
out = update.func(filename="vendors.csv", new_text="Row 1: vendor: Orion Supplies\nRow 2: vendor: Kestrel Print")
check("update allowed: the user's message names the exact file", "passage(s) now indexed" in out)
check("update allowed: the text really changed", "Kestrel Print" in stored_text("vendors.csv"))

g.current_question = "Summarize my vendor list."  # does not name vendors.csv
g.removals.clear()
out = delete.func(filename="vendors.csv")
check("delete blocked: the user's message never named the file", out.startswith("[BLOCKED tool call: unauthorized_write]"))
check("delete blocked: the file is untouched", "vendors.csv" in list_uploaded_documents())
check("delete blocked: recorded for the UI", any(r["label"] == "unauthorized_write" and r["origin"] == "vendors.csv" for r in g.removals))

# The realistic attack: a hidden instruction READ from some other file makes the model call update_document
# with ordinary-looking text. The call itself has nothing injection-flavored in it, so only the consent
# check (not the rule/ML layer) can catch this -- which is exactly what it is for.
g.current_question = "Summarize my vendor list."  # the user only asked to summarize, never to change anything
g.removals.clear()
out = update.func(filename="vendors.csv", new_text="The vendor list is temporarily unavailable.")
check("update blocked: ordinary-looking call still refused without the user asking for it",
      out.startswith("[BLOCKED tool call: unauthorized_write]"))
check("the file was not changed by the unrequested call", "temporarily unavailable" not in stored_text("vendors.csv"))

# The stem (file name without extension) is also accepted, so "update vendors" is enough.
g.current_question = "Please update vendors with a new version."
out = update.func(filename="vendors.csv", new_text="Row 1: vendor: Orion Supplies (updated)")
check("update allowed: the file's name without its extension is enough", "passage(s) now indexed" in out)

# A short/common stem should not match by accident (e.g. a 2-letter name).
g.current_question = "What is in my todo list?"
g.removals.clear()
out = delete.func(filename="a.csv")
check("a very short file-name stem does not get a false match", out.startswith("[BLOCKED"))

clear_uploaded_documents()

# ---- without the guard, nothing stops a write tool: this is the attack the toggle demonstrates ---------
add_uploaded_document("vendors.csv", [(0, 1, "Row 1: vendor: Orion Supplies")])
unguarded = StructuredTool.from_function(func=lambda filename: delete_document(filename), name="delete_document",
                                          description="test tool")
check("unwrapped tool (guard off): the call goes straight through", unguarded.func(filename="vendors.csv").startswith("Deleted"))
check("unwrapped tool (guard off): the file really is gone", "vendors.csv" not in list_uploaded_documents())

# ---- the tool definitions themselves are clean (not flagged or blocked by the guard) --------------------
defs = fetch_tool_defs([config.ROOT / "mcp_server_docs.py"])
allowed, findings = vet_tool_defs(defs, Guard(log=False), None)
check("doc-write server offers update_document and delete_document", {d.name for d in defs} == {"update_document", "delete_document"})
check("guard finds nothing wrong with the write-tool definitions", not findings and len(allowed) == 2)

clear_uploaded_documents()
print("ALL PASSED" if not failed else f"{failed} FAILED")
