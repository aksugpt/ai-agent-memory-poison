"""Vector-database (Chroma) layer for retrieval: the built-in company docs and the user's uploaded files.

These are plain functions. The agent reaches `search_documents` through the MCP server (mcp_server.py).
"""
import re

import config

# ---- settings ---------------------------------------------------------------------------------
COLLECTION = "knowledge_base"        # Chroma collection with the built-in company docs
UPLOAD_COLLECTION = "uploaded_docs"  # Chroma collection with the files the user uploaded
CHUNK_SIZE = 800                     # characters per passage
CHUNK_OVERLAP = 100                  # characters shared by neighbouring passages
TOP_K = 4                            # passages returned for a normal question
SUMMARY_TOP_K = 6                    # a summary needs more of the document than a factual lookup
UPLOAD_BONUS = 0.3                   # uploaded text ranks slightly ahead of equally relevant company text
PASSAGE_SEP = "\n\n---\n\n"          # separates passages in a search result (the guard splits on it too)

# The query points at the user's own document ("this file", "summarize", ...), not at the company docs.
_DOC_REFERENCE = re.compile(
    r"\b(this|the|that|my|uploaded|attached)\s+(document|doc|file|pdf|upload|attachment|paper)\b"
    r"|\bsummar(?:y|ize|ise)\b|\bkey\s+points\b|\bmain\s+points\b|\buploaded\b",
    re.I,
)
# The query asks for a summary or overview, so more passages are returned.
_SUMMARY = re.compile(
    r"\bsummar(?:y|ize|ise)\b|\bkey\s+points\b|\bmain\s+points\b|\boverview\b|\bwhat\s+is\s+(this|it)\s+about\b",
    re.I,
)


# ---- database access --------------------------------------------------------------------------
def _client(fresh: bool = False):
    """Open the persistent Chroma database. fresh=True first drops this process's cached view of it."""
    import chromadb  # imported here to keep MCP server start-up fast for the file tools

    if fresh:
        # The MCP server is a separate process from the UI that writes the data, and Chroma caches its view
        # of the database per process. Dropping the cache lets us see what other processes wrote.
        from chromadb.api.shared_system_client import SharedSystemClient

        SharedSystemClient.clear_system_cache()
    return chromadb.PersistentClient(path=str(config.CHROMA_DIR))


def _collection():
    """The company-docs collection (embedded with Chroma's small default ONNX model, no torch needed)."""
    return _client().get_or_create_collection(COLLECTION)


def _upload_collection():
    """The collection holding the user's uploaded files."""
    return _client().get_or_create_collection(UPLOAD_COLLECTION)


# ---- company docs -----------------------------------------------------------------------------
def _chunk(text: str) -> list[str]:
    """Cut a text into overlapping passages of CHUNK_SIZE characters."""
    step = CHUNK_SIZE - CHUNK_OVERLAP
    return [text[i : i + CHUNK_SIZE] for i in range(0, max(len(text), 1), step)]


def ingest_documents(extra_dirs=()) -> int:
    """(Re)build the company-docs collection from every .txt/.md file in DOCS_DIR (plus extra_dirs)."""
    # Start from an empty collection so removed or changed files do not linger.
    client = _client()
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass  # nothing to delete the first time
    col = client.get_or_create_collection(COLLECTION)

    # Read every supported file and cut it into passages with an id, text and source label.
    ids, docs, metas = [], [], []
    files = [f for d in (config.DOCS_DIR, *extra_dirs) for f in sorted(d.rglob("*"))]
    for f in files:
        if f.suffix.lower() not in {".txt", ".md"}:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for i, chunk in enumerate(_chunk(text)):
            ids.append(f"{f.name}:{i}")
            docs.append(chunk)
            metas.append({"source": f.name, "chunk": i})
    if docs:
        col.add(ids=ids, documents=docs, metadatas=metas)
    return len(docs)


# ---- uploaded files ---------------------------------------------------------------------------
def add_uploaded_document(filename: str, chunks) -> int:
    """Index a user-uploaded file, replacing any earlier upload with the same name.

    `chunks` is an iterable of (chunk_index, page_number, text). Returns the number indexed.
    """
    col = _upload_collection()
    col.delete(where={"source": filename})  # drop the old version of this file, if any
    items = [(i, p, t) for i, p, t in chunks if t.strip()]  # skip empty passages
    if items:
        col.add(
            ids=[f"{filename}:{i}" for i, _, _ in items],
            documents=[t for _, _, t in items],
            metadatas=[{"source": filename, "chunk": i, "page": p} for i, p, _ in items],
        )
    return len(items)


def remove_uploaded_document(filename: str) -> None:
    """Delete one uploaded file from the index."""
    _upload_collection().delete(where={"source": filename})


def clear_uploaded_documents() -> None:
    """Delete every uploaded file from the index."""
    client = _client()
    try:
        client.delete_collection(UPLOAD_COLLECTION)
    except Exception:
        pass  # nothing to delete when no file was ever uploaded


def list_uploaded_documents() -> dict[str, int]:
    """Return {filename: number of indexed passages} for the uploaded files."""
    counts: dict[str, int] = {}
    for meta in _upload_collection().get(include=["metadatas"])["metadatas"]:
        counts[meta["source"]] = counts.get(meta["source"], 0) + 1
    return counts


# ---- search -----------------------------------------------------------------------------------
def _mentions_upload(query: str, filenames) -> bool:
    """True if the query names one of the uploaded files (by file name or by its name without extension)."""
    q = re.sub(r"[_\-\s]+", " ", query.lower())
    for name in filenames:
        stem = re.sub(r"[_\-\s]+", " ", name.rsplit(".", 1)[0].lower())
        if name.lower() in query.lower() or stem in q:
            return True
    return False


def search_documents(query: str) -> str:
    """One search over BOTH the company docs and the user's uploaded files.

    - If the query points at the user's document (it says "this file", asks for a summary, or names the
      file), only the uploaded files are searched.
    - Otherwise passages from both sources are ranked together (same embedding model, comparable
      distances), with a small bonus for uploaded text.
    Every passage is labelled with its source, so the model never has to choose between tools.
    """
    try:
        # Refresh FIRST. This code runs in the MCP server process while uploads are written by the UI
        # process; refreshing after opening the uploads left every search one step behind, so a file
        # uploaded between two questions was invisible to the next question.
        _client(fresh=True)
        up = _upload_collection()
        has_upload = up.count() > 0

        # Decide whether the question is about the user's own file, and how many passages to return.
        upload_only = has_upload and (
            bool(_DOC_REFERENCE.search(query)) or _mentions_upload(query, list_uploaded_documents())
        )
        k = SUMMARY_TOP_K if _SUMMARY.search(query) else TOP_K

        candidates = []  # (adjusted distance, formatted passage); a smaller distance means more relevant
        # Passages from the uploaded files (their distance is reduced by UPLOAD_BONUS).
        if has_upload:
            r = up.query(query_texts=[query], n_results=min(k, up.count()))
            for doc, m, dist in zip(r["documents"][0], r["metadatas"][0], r["distances"][0]):
                label = f"[source: {m['source']} (uploaded by the user), page {m['page']}]"
                candidates.append((dist - UPLOAD_BONUS, f"{label}\n{doc}"))
        # Passages from the company docs (skipped when the question is clearly about the upload).
        if not upload_only:
            kb = _collection()
            if kb.count():
                r = kb.query(query_texts=[query], n_results=min(TOP_K, kb.count()))
                for doc, m, dist in zip(r["documents"][0], r["metadatas"][0], r["distances"][0]):
                    candidates.append((dist, f"[source: {m['source']}]\n{doc}"))

        if not candidates:
            return "No documents are indexed."
        # Keep the k most relevant passages overall.
        candidates.sort(key=lambda c: c[0])
        return PASSAGE_SEP.join(text for _, text in candidates[:k])
    except Exception as e:  # errors are returned as text so the model can react to them
        return f"Error: {e}"
