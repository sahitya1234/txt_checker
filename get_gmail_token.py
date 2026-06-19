"""
One-time helper to obtain a Gmail *send* refresh token (Option B — no Workspace
admin needed).

Prerequisites
-------------
1. In GCP Console (project jt-internal-484008) → APIs & Services → OAuth consent
   screen: configure it (User type: Internal), and add the scope
   https://www.googleapis.com/auth/gmail.send
2. APIs & Services → Credentials → Create credentials → OAuth client ID →
   Application type: "Desktop app". Download the JSON and save it here as
   client_secret.json
3. pip install google-auth-oauthlib

Run
---
    python get_gmail_token.py

A browser window opens. **Log in as the mailbox you want to send FROM**
(e.g. the dedicated mailer mailbox) and grant access. The refresh token and
client credentials print at the end — set them as env vars on the app:

    GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN, GMAIL_SENDER

Notes
-----
- GMAIL_SENDER may be the account you log in as OR one of its aliases (Workspace
  account aliases are valid "send as" addresses). Sending as an address that is
  neither makes Gmail rewrite the From header.
- If no refresh token prints, revoke the app's prior access at
  https://myaccount.google.com/permissions and re-run.
"""
import json
import os
import sys

CLIENT_SECRET_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.send']


def main():
    if not os.path.exists(CLIENT_SECRET_FILE):
        print(f"Missing {CLIENT_SECRET_FILE} — download your Desktop-app OAuth "
              f"client JSON (see prerequisites in this file's docstring).")
        sys.exit(1)

    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
    # access_type=offline + prompt=consent guarantees a refresh_token is issued.
    creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')

    with open(CLIENT_SECRET_FILE) as f:
        info = json.load(f)
    client = info.get('installed') or info.get('web') or {}

    print("\n=== Gmail send credentials (set these as env vars) ===")
    print(f"GMAIL_CLIENT_ID={client.get('client_id', '')}")
    print(f"GMAIL_CLIENT_SECRET={client.get('client_secret', '')}")
    print(f"GMAIL_REFRESH_TOKEN={creds.refresh_token or ''}")
    if not creds.refresh_token:
        print("\nWARNING: no refresh_token returned. Revoke prior access at "
              "https://myaccount.google.com/permissions and re-run.")


if __name__ == '__main__':
    main()
