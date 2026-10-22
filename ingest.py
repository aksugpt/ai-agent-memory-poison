"""Rebuild the company-docs search index from data/docs.

Run `python ingest.py`. Add `--poisoned` to also load the fake poisoned test document (for guard demos);
run it again without the flag to restore the clean index.
"""
import sys

import config
from tools.rag_tool import ingest_documents

if __name__ == "__main__":
    # With --poisoned, the fake poisoned documents are indexed together with the clean ones.
    extra = (config.ROOT / "data" / "docs_poisoned",) if "--poisoned" in sys.argv else ()
    print(f"Ingested {ingest_documents(extra)} chunks{' (including poisoned test docs)' if extra else ''}.")
