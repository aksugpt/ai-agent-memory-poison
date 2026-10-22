"""Central settings: folder locations and which language model to use."""
import os
from pathlib import Path

from dotenv import load_dotenv

# Project root folder (the folder this file lives in).
ROOT = Path(__file__).parent.resolve()

# Read settings (e.g. GROQ_API_KEY) from the .env file, if it exists.
load_dotenv(ROOT / ".env")

# ---- folders ----------------------------------------------------------------------------------
# Everything the agent's file tools may touch lives under this folder.
SANDBOX_DIR = ROOT / "data" / "sandbox"
# Built-in company documents that are indexed into the vector database.
DOCS_DIR = ROOT / "data" / "docs"
# The vector database itself (kept inside the project).
CHROMA_DIR = ROOT / "data" / "chroma"

# ---- language model ---------------------------------------------------------------------------
# Which provider answers: "ollama" (local) or "groq" (cloud). The UI can switch it per session.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
# Cloud model on Groq (llama-3.3-70b-versatile is no longer offered on this account).
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
# Local model served by Ollama, and the address of the Ollama server.
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# ---- email ------------------------------------------------------------------------------------
# A Gmail search that every email tool call is limited to, so the agent only ever sees the planted lab emails
# (their subjects start with "[LAB]"), never the rest of the account. Set EMAIL_SCOPE= (empty) in .env to lift it.
EMAIL_SCOPE = os.getenv("EMAIL_SCOPE", "subject:LAB")

# ---- limits -----------------------------------------------------------------------------------
# read_file returns at most this many characters of a file.
MAX_READ_CHARS = 8000
