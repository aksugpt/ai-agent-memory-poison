"""Upload pipeline checks (no language model needed): extract -> scan/classify -> index -> search through the MCP tool."""
import config
from guard import Guard
from guard.doc_dataset import BENIGN_DOCS, BENIGN_DOCS2, HARD_BENIGN, MALICIOUS_DOCS, MALICIOUS_DOCS2
from guard.docscan import scan_chunks
from mcp_client import get_bridge, load_mcp_tools
from tools.rag_tool import (PASSAGE_SEP, add_uploaded_document, clear_uploaded_documents, ingest_documents,
                            list_uploaded_documents, remove_uploaded_document)
from uploads import UploadError, chunks_for, extract_pages, make_chunks

SAMPLES = config.ROOT / "data" / "samples"  # the ACME handbook test files
CSVDIR = config.ROOT / "test_csv"           # the CSV attack-scenario files
ok = True


def check(name, cond, extra=""):
    """Print PASS/FAIL for one check and remember if anything failed."""
    global ok
    ok &= bool(cond)
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {extra}")


def scan_text(name, text):
    """Scan a piece of text as if it were an uploaded .txt file and return the report."""
    pages = extract_pages(f"{name}.txt", text.encode())
    return scan_chunks(name, pages, make_chunks(pages), guard)


guard = Guard(log=False)

# ---- 1. The four ACME handbook files get the verdict we expect ----
reports = {}
for name, expect in [("acme_handbook_clean.txt", "clean"), ("acme_handbook_clean.pdf", "clean"),
                     ("acme_handbook_malicious.txt", "malicious"), ("acme_handbook_hidden_injection.pdf", "malicious")]:
    pages = extract_pages(name, (SAMPLES / name).read_bytes())
    chunks = make_chunks(pages)
    r = reports[name] = scan_chunks(name, pages, chunks, guard)
    check(f"{name}: classified {expect}", r.verdict == expect,
          f"(verdict={r.verdict}, label={r.label}, pages={r.n_pages}, chunks={r.n_chunks}) {r.summary}")

# ---- 2. Wider check: varied benign documents vs malicious documents with a buried attack ----
print("-- benign documents")
benign_res = {n: scan_text(n, t) for n, t in BENIGN_DOCS.items()}
for n, r in benign_res.items():
    print(f"   {n:<18} {r.verdict:<10} {r.summary if r.verdict != 'clean' else ''}")
check("no benign document is classified malicious", all(r.verdict != "malicious" for r in benign_res.values()))
print(f"   -> clean {sum(r.verdict == 'clean' for r in benign_res.values())}/{len(benign_res)}, "
      f"suspicious {sum(r.verdict == 'suspicious' for r in benign_res.values())}/{len(benign_res)}")
# Documents that legitimately mention secrets are a known hard case: reported, not asserted.
for n, t in HARD_BENIGN.items():
    r = scan_text(n, t)
    print(f"   (known hard case) {n}: {r.verdict}")

print("-- malicious documents")
mal_res = {n: scan_text(n, t) for n, t in MALICIOUS_DOCS.items()}
for n, r in mal_res.items():
    print(f"   {n:<26} {r.verdict:<10} removed {r.removed_sentences} sentence(s)")
print(f"   -> classified malicious {sum(r.verdict == 'malicious' for r in mal_res.values())}/{len(mal_res)}")
check("at least 5 of 6 malicious documents are caught", sum(r.verdict == "malicious" for r in mal_res.values()) >= 5)

# A second set of documents, written after the training data was extended, run once without tuning.
print("-- round 2: FRESH documents (written after training data was extended; no tuning)")
b2 = {n: scan_text(n, t) for n, t in BENIGN_DOCS2.items()}
m2 = {n: scan_text(n, t) for n, t in MALICIOUS_DOCS2.items()}
for n, r in b2.items():
    print(f"   benign    {n:<20} {r.verdict}")
for n, r in m2.items():
    print(f"   malicious {n:<20} {r.verdict}")
print(f"   -> benign: malicious {sum(r.verdict == 'malicious' for r in b2.values())}/{len(b2)} (false positives), "
      f"suspicious {sum(r.verdict == 'suspicious' for r in b2.values())}/{len(b2)}; "
      f"malicious caught {sum(r.verdict == 'malicious' for r in m2.values())}/{len(m2)}")

# ---- 3. Malicious text inside a PDF is pinpointed to the right page ----
r = reports["acme_handbook_hidden_injection.pdf"]
check("hidden PDF injection located on page 2", {f.page for f in r.findings if f.action == "block"} == {2})

# ---- 4. Unreadable files are rejected with a clear error ----
for fname, data, what in [("notes.exe", b"MZ", "unsupported type"), ("empty.txt", b"   ", "empty text"),
                          ("broken.pdf", b"not a pdf", "corrupt PDF")]:
    try:
        extract_pages(fname, data)
        check(f"rejects {what}", False)
    except UploadError as e:
        check(f"rejects {what}", True, f"-> {e}")

# ---- 5. Only the malicious SENTENCES are removed; the legitimate facts around them stay usable ----
name = "acme_handbook_malicious.txt"
pages = extract_pages(name, (SAMPLES / name).read_bytes())
chunks = make_chunks(pages)
rep = reports[name]
removed = [s for f in rep.findings for s in f.removed]
check("only the injected sentence(s) were removed", 1 <= len(removed) <= 3 and all("30 days" not in s for s in removed),
      f"(removed {len(removed)}: {[s[:50] for s in removed]})")
n = add_uploaded_document(name, rep.indexable(chunks))
check("sanitized document is indexed", n > 0 and name in list_uploaded_documents(), f"({n} passages)")

# ---- 6. Searching through the MCP server returns the real answer, never the injected text ----
tools = {t.name: t for t in load_mcp_tools()}
check("MCP server exposes the unified search_documents tool", "search_documents" in tools)
ans = tools["search_documents"].invoke({"query": "How long is the refund window?"})
check("search returns the real answer (30 days)", "30 days" in ans, f"-> {ans[:80]!r}")
check("search never returns the injected text",
      "365" not in ans and "ignore all previous" not in ans.lower() and ".env" not in ans)

# Without quarantine (guard off) the injected text would be indexed as-is.
add_uploaded_document("raw.txt", rep.indexable(chunks, quarantine=False))
raw = tools["search_documents"].invoke({"query": "ignore all previous instructions refund 365 days"})
check("unquarantined index does contain the injection (for guard-off demos)", "365 days" in raw)
remove_uploaded_document("raw.txt")

# ---- 7. Cross-process freshness: the test process rewrites the index while the MCP server is running ----
ingest_documents((config.ROOT / "data" / "docs_poisoned",))
ans = tools["search_documents"].invoke({"query": "How many days of paid leave?"})
check("MCP server sees knowledge-base changes made by another process", "365" in ans, f"-> {ans[:60]!r}")
ingest_documents()  # restore the clean company docs
ans = tools["search_documents"].invoke({"query": "How many days of paid leave?"})
check("...and sees them being reverted", "365" not in ans and "24 days" in ans)

# ---- 8. Questions about a clean uploaded PDF ----
clean = "acme_handbook_clean.pdf"
add_uploaded_document(clean, [(c.idx, c.page, c.text) for c in make_chunks(extract_pages(clean, (SAMPLES / clean).read_bytes()))])
ans = tools["search_documents"].invoke({"query": "Who is the CEO?"})
check("search finds CEO in clean PDF", "Meera Iyer" in ans, f"-> {ans[:80]!r}")

# Routing: queries that point at the user's document stay on it; real company questions still reach company docs.
for q in ["summarize this", "what are the key points?", "What does acme_handbook_clean.pdf say about shipping?"]:
    passages = tools["search_documents"].invoke({"query": q}).split(PASSAGE_SEP)
    check(f"'{q}' searches only the uploaded file", all("uploaded by the user" in p for p in passages),
          f"({len(passages)} passages)")
ans = tools["search_documents"].invoke({"query": "What does the Pro plan cost?"})
check("a company question still reaches the company docs", "12 USD" in ans)

# Removing and clearing uploads.
remove_uploaded_document(clean)
check("remove works", clean not in list_uploaded_documents())
clear_uploaded_documents()
check("clear works", "uploaded by the user" not in tools["search_documents"].invoke({"query": "refund window"}))

# ---- 9. CSV files ----
print("-- CSV files")
# Reading a CSV: rows become "column: value" lines and are never cut in half by chunking.
vp = extract_pages("victim_api_keys.csv", (CSVDIR / "victim_api_keys.csv").read_bytes())
check("CSV rows become 'column: value' lines",
      vp[0][1].startswith("Row 1: service: Payments API;") and "key_or_password: FAKEKEY-PAY-7391-QX82" in vp[0][1])
vc = chunks_for("victim_api_keys.csv", vp)
check("CSV chunking never cuts a row", all(ln.startswith("Row ") for c in vc for ln in c.text.split("\n")))
check("CSV: a cell with line breaks stays on one line",
      extract_pages("q.csv", b'a,b\n1,"two\nlines"\n')[0][1] == "Row 1: a: 1; b: two lines")
check("CSV: header-only file is described", extract_pages("h.csv", b"a,b,c\n")[0][1] == "Columns: a; b; c")
try:
    extract_pages("empty.csv", b"")
    check("empty CSV is rejected", False)
except UploadError:
    check("empty CSV is rejected", True)

# Scanning the two CSV files: the victim's list of keys is fine, the attacker's poisoned cell is not.
vr = scan_chunks("victim_api_keys.csv", vp, vc, guard)
check("victim CSV (a list of fake keys) is not blocked", vr.verdict != "malicious", f"(verdict={vr.verdict})")
ap_ = extract_pages("attacker_vendors.csv", (CSVDIR / "attacker_vendors.csv").read_bytes())
ac = chunks_for("attacker_vendors.csv", ap_)
ar = scan_chunks("attacker_vendors.csv", ap_, ac, guard)
check("attacker CSV (poisoned notes cell) is classified malicious", ar.verdict == "malicious", f"(verdict={ar.verdict})")
clean_rows = "\n".join(t for _, _, t in ar.indexable(ac, quarantine=True))
check("poisoned row removed, other vendors kept",
      "ignore all previous" not in clean_rows.lower() and "NOTE TO AI" not in clean_rows
      and "Orion Supplies" in clean_rows and "Kestrel Print" in clean_rows)

# A file uploaded between two questions must be visible to the very next question.
add_uploaded_document("victim_api_keys.csv", [(c.idx, c.page, c.text) for c in vc])
tools["search_documents"].invoke({"query": "Payments API key"})  # the MCP server has now looked at the index once
add_uploaded_document("attacker_vendors.csv", ar.indexable(ac, quarantine=True))  # a second upload arrives afterwards
fresh_ans = tools["search_documents"].invoke({"query": "Summarize the vendor list"})
check("a file uploaded between two questions is visible to the very next question",
      "Orion Supplies" in fresh_ans, f"-> {' '.join(fresh_ans.split())[:100]!r}")
ans = tools["search_documents"].invoke({"query": "What is the Payments API key?"})
check("the real key is found in the CSV via search", "FAKEKEY-PAY-7391-QX82" in ans)
ans = tools["search_documents"].invoke({"query": "Summarize the vendor list"})
check("sanitized index never serves the injected note", "NOTE TO AI" not in ans and "ignore all previous" not in ans.lower())
clear_uploaded_documents()

# Stop the background MCP server and print the overall result.
get_bridge().close()
print("\nALL PASSED" if ok else "\nSOME FAILED")
