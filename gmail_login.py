"""One-time Gmail login for the lab account. Opens your browser, you sign in and approve, and a token is saved.

Run:  .\.venv\Scripts\python.exe gmail_login.py read      (read-only access: what the agent's email tools use)
      .\.venv\Scripts\python.exe gmail_login.py insert    (only for the script that plants the test emails)
Only the lab account listed as a test user in Google Cloud can log in.
"""
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

import config

# Folder that holds credentials.json (from Google Cloud) and the saved tokens; it is outside the agent's file sandbox.
AUTH_DIR = config.ROOT / "gmail_auth"
CREDENTIALS = AUTH_DIR / "credentials.json"
# What each kind of login is allowed to do: "read" can only read mail, "insert" can only add mail to the inbox.
SCOPES = {
    "read": ["https://www.googleapis.com/auth/gmail.readonly"],
    "insert": ["https://www.googleapis.com/auth/gmail.insert"],
}


def token_path(kind: str):
    """Where the saved login for this kind ('read' or 'insert') lives."""
    return AUTH_DIR / f"token_{kind}.json"


def get_credentials(kind: str, interactive: bool = False) -> Credentials:
    """Load the saved login (refreshing it if needed). With interactive=True, open the browser to log in when none exists."""
    path = token_path(kind)
    creds = Credentials.from_authorized_user_file(str(path), SCOPES[kind]) if path.exists() else None
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())  # quietly get a new short-lived key
        path.write_text(creds.to_json(), encoding="utf-8")
    if not creds or not creds.valid:
        if not interactive:
            raise RuntimeError(f"Not logged in to Gmail. Run: python gmail_login.py {kind}")
        creds = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS), SCOPES[kind]).run_local_server(port=0)
        path.write_text(creds.to_json(), encoding="utf-8")
    return creds


def gmail_service(kind: str = "read"):
    """A ready-to-use Gmail API client for the saved login."""
    return build("gmail", "v1", credentials=get_credentials(kind), cache_discovery=False)


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "read"
    if kind not in SCOPES:
        sys.exit("Use: gmail_login.py read   or   gmail_login.py insert")
    get_credentials(kind, interactive=True)
    print(f"Logged in ({kind}). Token saved to {token_path(kind)}")
    if kind == "read":  # prove it works: show which account and how many messages it can see
        profile = gmail_service("read").users().getProfile(userId="me").execute()
        print(f"Account: {profile['emailAddress']} · messages in mailbox: {profile['messagesTotal']}")
