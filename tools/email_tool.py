"""Email tools: read the lab Gmail inbox (read-only) and hand the text to the agent.

Everything is returned as labelled passages, in the same shape as search results, so the guard can check each
one: `[source: email "Subject" from Name <a@b.c>, body]` / `..., headers]` / `..., attachment name.csv, page 1]`.
The reading functions work on raw email bytes (RFC 822), so they can be tested without Gmail.
"""
import base64
import re
from email import message_from_bytes, policy
from email.message import EmailMessage
from html.parser import HTMLParser

import config
from tools.rag_tool import PASSAGE_SEP
from uploads import SUPPORTED, UploadError, chunks_for, extract_pages, make_chunks

# ---- settings ---------------------------------------------------------------------------------
MAX_LIST = 15           # most emails one list call returns
MAX_PASSAGES = 12       # most passages one read call returns (the rest is cut off with a note)
MAX_BODY_CHARS = 8000   # longest email body that is read
DEFAULT_QUERY = "in:inbox"


# ---- turning HTML into text -------------------------------------------------------------------
class _TextOfHtml(HTMLParser):
    """Collects ALL the text of an HTML email, including text a person cannot see: display:none, white-on-white,
    tiny fonts and comments. This is how a simple email-to-text step behaves, and it is what makes hidden
    instructions reach the model."""

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0  # inside <script> / <style>: not text

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "table"):
            self.parts.append("\n")  # keep block structure as line breaks

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag in ("p", "div", "tr", "li", "td"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)

    def handle_comment(self, data):
        self.parts.append("\n" + data + "\n")  # an HTML comment is invisible to a person but not to this reader


def html_to_text(html: str) -> str:
    """All the text in an HTML document, one tidy line per block."""
    parser = _TextOfHtml()
    parser.feed(html)
    parser.close()
    text = "".join(parser.parts)
    return "\n".join(" ".join(line.split()) for line in text.split("\n") if line.strip())


# ---- reading one email ------------------------------------------------------------------------
def parse(raw: bytes) -> EmailMessage:
    """Parse raw email bytes."""
    return message_from_bytes(raw, policy=policy.default)


def _one_line(value: str, limit: int = 90) -> str:
    """A header value made safe for the passage label: one line, no quotes or brackets, not too long."""
    value = " ".join(str(value or "").split()).replace('"', "'").replace("[", "(").replace("]", ")")
    return value[:limit]


def body_text(msg: EmailMessage) -> str:
    """The text of the email body. The HTML version is used when there is one (like most email readers' text step)."""
    part = msg.get_body(preferencelist=("html", "plain"))
    if part is None:
        return ""
    content = part.get_content()
    text = html_to_text(content) if part.get_content_type() == "text/html" else content
    return text.strip()[:MAX_BODY_CHARS]


def attachments(msg: EmailMessage) -> list[tuple[str, bytes]]:
    """[(file name, content)] for every attachment."""
    out = []
    for part in msg.iter_attachments():
        name = part.get_filename()
        if name:
            out.append((name, part.get_payload(decode=True) or b""))
    return out


def _label(msg: EmailMessage, what: str) -> str:
    """The label that starts every passage: which email it is from and which part of it."""
    return f'[source: email "{_one_line(msg["subject"])}" from {_one_line(msg["from"])}, {what}]'


def headers_passage(msg: EmailMessage, msg_id: str) -> str:
    """Who sent it, when, and which attachments it has."""
    names = ", ".join(f"{n} ({len(d) // 1024 + 1} KB)" for n, d in attachments(msg)) or "none"
    return f"{_label(msg, 'headers')}\nid: {msg_id}; date: {_one_line(msg['date'])}; attachments: {names}"


def read_email_text(raw: bytes, msg_id: str) -> str:
    """The passages for read_email: the headers, then the body."""
    msg = parse(raw)
    body = body_text(msg)
    passages = [headers_passage(msg, msg_id)]
    for c in make_chunks([(1, body)]) if body else []:
        passages.append(f"{_label(msg, 'body')}\n{c.text}")
    if not body:
        passages.append(f"{_label(msg, 'body')}\n(this email has no text)")
    if len(passages) > MAX_PASSAGES:
        passages = passages[:MAX_PASSAGES] + [f"{_label(msg, 'body')}\n(the rest of the email was cut off)"]
    return PASSAGE_SEP.join(passages)


def pick_attachment(files: list[tuple[str, bytes]], filename: str) -> tuple[str, bytes] | None:
    """The attachment the caller means: an exact name, a name that contains the given words, or (when the email
    has only one attachment) that one. None when it cannot be told."""
    want = (filename or "").strip().strip("\"'`").lower()
    for name, data in files:
        if name.lower() == want:
            return name, data
    partial = [(n, d) for n, d in files if want and (want in n.lower() or n.lower() in want)]
    if len(partial) == 1:
        return partial[0]
    return files[0] if len(files) == 1 else None


def read_attachment_text(raw: bytes, filename: str = "") -> str:
    """The passages for read_attachment: the text of one attached PDF / TXT / MD / CSV file."""
    msg = parse(raw)
    files = attachments(msg)
    picked = pick_attachment(files, filename)
    if picked is None:
        have = ", ".join(n for n, _ in files) or "none"
        return f"Error: could not tell which attachment is meant by '{filename}'. This email's attachments: {have}."
    name, data = picked
    try:
        pages = extract_pages(name, data)
    except UploadError as e:
        return f"Error: cannot read attachment '{name}': {e} (supported: {', '.join(sorted(SUPPORTED))})."
    passages = [f'{_label(msg, f"attachment {_one_line(name)}, page {c.page}")}\n{c.text}' for c in chunks_for(name, pages)]
    if len(passages) > MAX_PASSAGES:
        passages = passages[:MAX_PASSAGES] + [f'{_label(msg, f"attachment {_one_line(name)}, page 1")}\n(the rest of the file was cut off)']
    return PASSAGE_SEP.join(passages)


def list_text(items: list[tuple[str, bytes]]) -> str:
    """The passages for list_emails: one short passage per email."""
    if not items:
        return "No emails found."
    return PASSAGE_SEP.join(headers_passage(parse(raw), msg_id) for msg_id, raw in items)


# ---- talking to Gmail -------------------------------------------------------------------------
def _service():
    """The read-only Gmail client (imported here so the parsing functions above need no Google libraries)."""
    from gmail_login import gmail_service

    return gmail_service("read")


def fetch_raw(service, msg_id: str) -> bytes:
    """The raw bytes of one email."""
    data = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()["raw"]
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _scoped(query: str) -> str:
    """The user's search, limited to the configured scope (config.EMAIL_SCOPE)."""
    return f"({query or DEFAULT_QUERY}) {config.EMAIL_SCOPE}".strip()


def _ids(service, query: str, n: int) -> list[str]:
    """Ids of the newest emails matching the (scoped) search."""
    found = service.users().messages().list(userId="me", q=_scoped(query), maxResults=n).execute()
    return [m["id"] for m in found.get("messages", [])]


def resolve(ref: str, find) -> tuple[str | None, str]:
    """Turn what the caller wrote (an email id, or words from its subject or text) into one email id.
    `find(query, n)` returns the ids of the newest emails matching a search. Returns (id, error message)."""
    ref = (ref or "").strip().strip("\"'`")
    if not ref:
        return None, "Error: say which email: its subject (or a few words from it), or an id from list_emails."
    # An id is used as it is, but only if it is inside the allowed scope.
    if re.fullmatch(r"[0-9a-f]{12,20}", ref) and ref in find(DEFAULT_QUERY, 500):
        return ref, ""
    # Otherwise search by subject first, then by any text (sender, body), and take the newest match.
    words = ref.replace("(", " ").replace(")", " ").replace('"', " ")
    for query in (f"subject:({words})", words):
        ids = find(query, 1)
        if ids:
            return ids[0], ""
    return None, f"Error: no email matches '{ref}'. Call list_emails to see which emails exist."


def list_emails(query: str = DEFAULT_QUERY, max_results: int = 10) -> str:
    """List recent emails matching a Gmail search (newest first)."""
    service = _service()
    ids = _ids(service, query, max(1, min(int(max_results), MAX_LIST)))
    return list_text([(i, fetch_raw(service, i)) for i in ids])


def read_email(email: str) -> str:
    """Read one email (found by subject words or id): its headers and its body text."""
    service = _service()
    msg_id, error = resolve(email, lambda q, n: _ids(service, q, n))
    return error or read_email_text(fetch_raw(service, msg_id), msg_id)


def read_attachment(email: str, filename: str = "") -> str:
    """Read the text of one attachment of an email (found by subject words or id)."""
    service = _service()
    msg_id, error = resolve(email, lambda q, n: _ids(service, q, n))
    return error or read_attachment_text(fetch_raw(service, msg_id), filename)
