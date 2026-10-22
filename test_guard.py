"""Guard checks on real project files and on the wrapped tools (no language model needed)."""
import config
from guard import Guard
from guard.wrap import _filter_output, guard_tool
from mcp_client import get_bridge, load_mcp_tools
from tools.rag_tool import PASSAGE_SEP

# The real MCP tools, as the agent gets them.
_mcp = {t.name: t for t in load_mcp_tools()}
list_directory, read_file = _mcp["list_directory"], _mcp["read_file"]

guard = Guard(log=False)
ok = True


def check(name, cond, extra=""):
    """Print PASS/FAIL for one check and remember if anything failed."""
    global ok
    ok &= bool(cond)
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {extra}")


# 1. Every clean sample file in the sandbox and the company docs must not be blocked.
clean = [p for d in (config.SANDBOX_DIR, config.DOCS_DIR) for p in d.rglob("*.*") if "poisoned" not in p.parts]
for p in clean:
    d = guard.check(p.read_text(encoding="utf-8"), "tool_output")
    check(f"clean file not blocked: {p.name}", not d.blocked, f"(action={d.action}, score={d.score})")

# 2. The poisoned test files must be caught.
for p in [config.SANDBOX_DIR / "poisoned" / "vendor_notes.txt", config.ROOT / "data" / "docs_poisoned" / "policy_update.md"]:
    d = guard.check(p.read_text(encoding="utf-8"), "tool_output")
    check(f"poisoned file detected: {p.name}", d.action != "allow", f"(action={d.action}, label={d.label}, score={d.score})")


# 2b. Search-result-shaped output: several passages joined, one of them poisoned (the attack must not get diluted).
def rag_output(paths):
    """Join files the way search_documents joins passages: '[source: name]' header, text, separator."""
    return PASSAGE_SEP.join(f"[source: {p.name}]\n{p.read_text(encoding='utf-8')}" for p in paths)


docs, pdocs = config.DOCS_DIR, config.ROOT / "data" / "docs_poisoned"
d = guard.check(rag_output([docs / "company_policy.md", pdocs / "policy_update.md", docs / "product_faq.md"]), "tool_output")
check("poison hidden among clean RAG chunks is detected", d.action != "allow", f"(action={d.action}, score={d.score})")
d = guard.check(rag_output([docs / "company_policy.md", docs / "product_faq.md"]), "tool_output")
check("clean RAG output is not blocked", not d.blocked, f"(action={d.action}, score={d.score})")

# 2c. Passage filtering: the poisoned passage is dropped, the clean passages still reach the model.
mixed = rag_output([docs / "company_policy.md", pdocs / "policy_update.md", docs / "product_faq.md"])
out = _filter_output(mixed, guard)
check("poisoned passage dropped, clean kept",
      "365" not in out and "24 days of paid leave" in out and "withheld" in out, f"-> {out[:90]!r}")

# 3. Wrapped tools: a traversal is blocked at call time, poisoned output is quarantined, clean calls pass through.
g_read, g_list = guard_tool(read_file, guard), guard_tool(list_directory, guard)
out = g_read.invoke({"path": "../../.env"})
check("wrapped read_file blocks traversal", out.startswith("[BLOCKED tool call"), f"-> {out[:60]}")
out = g_read.invoke({"path": "poisoned/vendor_notes.txt"})
check("wrapped read_file quarantines poisoned output",
      out.startswith("[QUARANTINED") and "ignore the user" not in out.lower() and "../../.env" not in out,
      f"-> {out[:110]}")
out = g_read.invoke({"path": "todo.txt"})
check("wrapped read_file passes clean file", "Write report draft" in out)
out = g_list.invoke({"path": "."})
check("wrapped list_directory passes clean call", "todo.txt" in out)

# Stop the background MCP server and print the overall result.
get_bridge().close()
print("\nALL PASSED" if ok else "\nSOME FAILED")
