"""MCP server with read-only email tools for the lab Gmail account (FastMCP).

Run on its own with:  python mcp_server_email.py   (log in first with: python gmail_login.py read)
"""
import warnings

from fastmcp import FastMCP

from tools import email_tool

warnings.filterwarnings("ignore")  # Google's libraries warn about the Python version on every start

# The server object; "email-tools" is the name clients see.
mcp = FastMCP("email-tools")


# Tool 1: find emails.
@mcp.tool
def list_emails(query: str = "in:inbox", max_results: int = 10) -> str:
    """List recent emails from the user's Gmail inbox (newest first). `query` is a Gmail search such as
    'in:inbox', 'from:alice' or 'has:attachment'. Each result shows the email id, date, sender, subject and attachment names."""
    return email_tool.list_emails(query, max_results)


# Tool 2: read one email.
@mcp.tool
def read_email(email: str) -> str:
    """Read one email and return its sender, date, attachment names and text. `email` is the email's subject
    (or a few words from it), for example 'Invoice reminder'. An id from list_emails also works."""
    return email_tool.read_email(email)


# Tool 3: read one attachment.
@mcp.tool
def read_attachment(email: str, filename: str = "") -> str:
    """Show the text of a PDF, TXT, MD or CSV attachment of an email. `email` is the email's subject or a few
    words from it. `filename` is optional when the email has one attachment."""
    return email_tool.read_attachment(email, filename)


# Run the server over stdio (stdout carries the protocol, so the startup banner is switched off).
if __name__ == "__main__":
    mcp.run(show_banner=False, log_level="WARNING")
