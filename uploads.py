"""Text extraction and chunking for user-uploaded documents (PDF / TXT / MD / CSV)."""
import csv
import io
from dataclasses import dataclass
from pathlib import Path

from tools.rag_tool import CHUNK_OVERLAP, CHUNK_SIZE

# ---- limits and supported types ---------------------------------------------------------------
MAX_BYTES = 15 * 1024 * 1024  # largest file accepted
MAX_PAGES = 300               # only the first 300 PDF pages are read
MAX_CSV_ROWS = 50_000         # only the first 50,000 CSV rows are read
SUPPORTED = {".pdf", ".txt", ".md", ".csv"}


class UploadError(ValueError):
    """The file cannot be read (unsupported type, too big, encrypted, no text...)."""


@dataclass
class Chunk:
    """One passage of a document: its number, the page it came from, and its text."""
    idx: int
    page: int
    text: str


# ---- CSV --------------------------------------------------------------------------------------
def _column_name(header: list[str], i: int) -> str:
    """The name of column i, or 'col<N>' when the header has none."""
    return header[i] if i < len(header) and header[i] else "col" + str(i + 1)


def csv_to_text(text: str) -> str:
    """Turn a CSV into one readable line per row: 'Row 1: service: Payments; key: ...'.

    Every cell is kept, so text hidden in any cell (a 'notes' column, for example) is extracted and scanned.
    """
    # Work out the delimiter (comma, semicolon, tab or pipe); fall back to a normal comma CSV.
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    # Read the rows, skipping blank ones and stopping at the row limit.
    rows = []
    for row in csv.reader(io.StringIO(text), dialect):
        if any(c.strip() for c in row):
            rows.append([" ".join(c.split()) for c in row])  # a cell with line breaks must stay on one line
        if len(rows) > MAX_CSV_ROWS:
            break
    if not rows:
        return ""
    header = [h.strip() for h in rows[0]]
    if len(rows) == 1:
        return "Columns: " + "; ".join(h for h in header if h)  # a header with no data rows
    # One "column: value" line per data row.
    lines = []
    for n, row in enumerate(rows[1:], start=1):
        pairs = [_column_name(header, i) + ": " + c for i, c in enumerate(row) if c]
        lines.append(f"Row {n}: " + "; ".join(pairs))
    return "\n".join(lines)


# ---- reading a file ---------------------------------------------------------------------------
def extract_pages(filename: str, data: bytes) -> list[tuple[int, str]]:
    """Return [(page_number, text)]. Includes ALL text in a PDF, even invisible/hidden text."""
    # Refuse unsupported types and oversized files up front.
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED:
        raise UploadError(f"Unsupported file type '{ext}'. Upload a PDF, TXT, MD or CSV file.")
    if len(data) > MAX_BYTES:
        raise UploadError(f"File is too large ({len(data) / 1e6:.1f} MB; limit {MAX_BYTES // 1_000_000} MB).")

    if ext == ".csv":
        # CSV: each row becomes a readable line (everything is on "page 1").
        pages = [(1, csv_to_text(data.decode("utf-8-sig", errors="replace")))]
    elif ext != ".pdf":
        # Plain text / Markdown: decode as UTF-8 (everything is on "page 1").
        text = data.decode("utf-8", errors="replace")
        pages = [(1, text)]
    else:
        # PDF: extract the text of every page. The extractor returns text whether or not it would be visible.
        from pypdf import PdfReader  # imported here so pypdf is only loaded when a PDF is opened

        try:
            reader = PdfReader(io.BytesIO(data))
            if reader.is_encrypted and not reader.decrypt(""):
                raise UploadError("This PDF is password-protected.")
            pages = []
            for n, page in enumerate(reader.pages[:MAX_PAGES], start=1):
                try:
                    pages.append((n, page.extract_text() or ""))
                except Exception:
                    pages.append((n, ""))  # one unreadable page must not stop the others
        except UploadError:
            raise
        except Exception as e:
            raise UploadError(f"Could not read the PDF ({type(e).__name__}).") from e

    # A file with no text at all (for example a scanned image PDF) cannot be used.
    if not any(t.strip() for _, t in pages):
        raise UploadError("No readable text found (a scanned/image-only PDF would need OCR).")
    return pages


# ---- chunking ---------------------------------------------------------------------------------
def make_chunks(pages: list[tuple[int, str]]) -> list[Chunk]:
    """Split each page into overlapping chunks, keeping the page number."""
    step = CHUNK_SIZE - CHUNK_OVERLAP  # each chunk starts a little before the previous one ended
    chunks: list[Chunk] = []
    for page, text in pages:
        text = text.strip()
        for start in range(0, len(text), step):
            piece = text[start : start + CHUNK_SIZE].strip()
            if piece:
                chunks.append(Chunk(len(chunks), page, piece))
            if start + CHUNK_SIZE >= len(text):
                break  # the rest of the page is already covered
    return chunks


def make_row_chunks(pages: list[tuple[int, str]]) -> list[Chunk]:
    """Chunk by whole lines (CSV rows), so a row is never cut in half. A line longer than a chunk is windowed."""
    chunks: list[Chunk] = []
    for page, text in pages:
        buf: list[str] = []  # lines collected for the chunk being built
        size = 0

        def flush():
            """Turn the collected lines into a chunk and start a new one."""
            nonlocal buf, size
            if buf:
                chunks.append(Chunk(len(chunks), page, "\n".join(buf)))
            buf, size = [], 0

        for line in (ln.strip() for ln in text.split("\n")):
            if not line:
                continue
            if len(line) > CHUNK_SIZE:  # one huge row: fall back to windows
                flush()
                for c in make_chunks([(page, line)]):
                    chunks.append(Chunk(len(chunks), page, c.text))
                continue
            if size + len(line) + 1 > CHUNK_SIZE:  # the next line would not fit: close this chunk first
                flush()
            buf.append(line)
            size += len(line) + 1
        flush()
    return chunks


def chunks_for(filename: str, pages: list[tuple[int, str]]) -> list[Chunk]:
    """The right chunking for the file type: whole rows for CSV, overlapping windows otherwise."""
    return make_row_chunks(pages) if Path(filename).suffix.lower() == ".csv" else make_chunks(pages)
