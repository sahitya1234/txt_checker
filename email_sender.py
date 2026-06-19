"""
Result delivery via the Gmail API.

Two auth methods are supported (see _build_credentials):
  * Option B (active, no Workspace admin): an OAuth refresh token for the sender
    mailbox. The token can send ONLY as that single mailbox (and its aliases) —
    least privilege, no domain-wide power. Generate it with get_gmail_token.py.
  * Option A (fallback, needs Workspace admin): keyless domain-wide delegation —
    the runtime SA signs assertions for MAILER_SA and impersonates GMAIL_SENDER.

The result CSV is attached directly. It is gzipped when it exceeds
GZIP_THRESHOLD_BYTES so it stays under Gmail's 25 MB message cap (attachments
are base64-encoded, ~1.33x inflation). The pure helpers (choose_attachment,
build_message) have no GCP dependency so they can be unit-tested offline.
"""
import os
import gzip
import base64
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Load .env before reading the GMAIL_* config below (no-op if python-dotenv or
# the file is absent; never overrides real environment variables, e.g. on Cloud Run).
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

logger = logging.getLogger(__name__)

# --- Config (env-overridable) ---
GMAIL_SENDER = os.environ.get('GMAIL_SENDER', 'noreply@thejungletechnology.com')
GMAIL_REPLY_TO = os.environ.get('GMAIL_REPLY_TO', '')   # optional monitored reply box

# Option B (active): OAuth refresh token for the sender mailbox (no admin needed).
GMAIL_CLIENT_ID = os.environ.get('GMAIL_CLIENT_ID', '')
GMAIL_CLIENT_SECRET = os.environ.get('GMAIL_CLIENT_SECRET', '')
GMAIL_REFRESH_TOKEN = os.environ.get('GMAIL_REFRESH_TOKEN', '')

# Option A (fallback): keyless domain-wide delegation (needs Workspace admin).
MAILER_SA = os.environ.get('MAILER_SA', '')             # DWD-enabled service account email

GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.send'
TOKEN_URI = 'https://oauth2.googleapis.com/token'

# Plain .csv up to this size; gzip above it. ~17 MB leaves headroom under the
# 25 MB message limit after base64 inflation.
GZIP_THRESHOLD_BYTES = int(os.environ.get('GZIP_THRESHOLD_BYTES', 17 * 1024 * 1024))
# Hard cap on raw attachment bytes (~25 MB / 1.33). Above this, don't attach.
MAX_ATTACHMENT_BYTES = int(os.environ.get('MAX_ATTACHMENT_BYTES', 18 * 1024 * 1024))


# --- Pure helpers (no GCP dependency; offline-testable) ---

def choose_attachment(csv_bytes, base_name):
    """Return (data, filename, mimetype). Gzip when the CSV exceeds the threshold."""
    if len(csv_bytes) > GZIP_THRESHOLD_BYTES:
        return gzip.compress(csv_bytes), f'{base_name}.csv.gz', 'application/gzip'
    return csv_bytes, f'{base_name}.csv', 'text/csv'


def build_message(to_addr, subject, body_text, attachment=None):
    """Build a base64url-encoded Gmail 'raw' message.
    attachment = (data_bytes, filename, mimetype) or None."""
    msg = MIMEMultipart()
    msg['To'] = to_addr
    msg['From'] = GMAIL_SENDER
    msg['Subject'] = subject
    if GMAIL_REPLY_TO:
        msg['Reply-To'] = GMAIL_REPLY_TO
    msg.attach(MIMEText(body_text, 'plain'))
    if attachment:
        data, filename, mimetype = attachment
        _, subtype = mimetype.split('/', 1)
        part = MIMEApplication(data, _subtype=subtype)
        part.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(part)
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


# --- Gmail send ---

def _build_credentials():
    """Build Gmail credentials. Prefers the OAuth refresh-token method (Option B,
    no Workspace admin); falls back to keyless domain-wide delegation if a
    MAILER_SA is configured instead."""
    # Option B: OAuth refresh token for the sending mailbox.
    if GMAIL_REFRESH_TOKEN:
        from google.oauth2.credentials import Credentials
        if not (GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET):
            raise RuntimeError("GMAIL_REFRESH_TOKEN set but GMAIL_CLIENT_ID/SECRET missing")
        return Credentials(
            token=None,
            refresh_token=GMAIL_REFRESH_TOKEN,
            client_id=GMAIL_CLIENT_ID,
            client_secret=GMAIL_CLIENT_SECRET,
            token_uri=TOKEN_URI,
            scopes=[GMAIL_SCOPE],
        )

    # Option A: keyless domain-wide delegation (needs Workspace admin).
    if MAILER_SA:
        import google.auth
        from google.auth import iam
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account
        request = Request()
        source_creds, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/iam'])
        signer = iam.Signer(request, source_creds, MAILER_SA)
        return service_account.Credentials(
            signer=signer,
            service_account_email=MAILER_SA,
            token_uri=TOKEN_URI,
            scopes=[GMAIL_SCOPE],
            subject=GMAIL_SENDER,  # impersonate the sender mailbox
        )

    raise RuntimeError(
        "No Gmail auth configured. Set GMAIL_REFRESH_TOKEN (+GMAIL_CLIENT_ID/SECRET) "
        "or MAILER_SA."
    )


def _gmail_service():
    """Build a Gmail API client from the configured credentials."""
    from googleapiclient.discovery import build
    return build('gmail', 'v1', credentials=_build_credentials(), cache_discovery=False)


def _send(to_addr, subject, body_text, attachment=None):
    try:
        raw = build_message(to_addr, subject, body_text, attachment)
        service = _gmail_service()
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logger.info(f"Email sent to {to_addr} (subject='{subject}')")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_addr}: {e}", exc_info=True)
        return False


def send_result_email(to_addr, csv_bytes, base_name, counts=None):
    """Email the result CSV (gzipped if large). Returns True on success."""
    data, filename, mimetype = choose_attachment(csv_bytes, base_name)

    if len(data) > MAX_ATTACHMENT_BYTES:
        # Too large even compressed (practically never for this data).
        mb = len(data) // (1024 * 1024)
        body = ("Your app-ads.txt check finished, but the result file is too large "
                f"to email ({mb} MB compressed). Please contact the team to retrieve it.")
        return _send(to_addr, "Your app-ads.txt results (too large to attach)", body)

    summary = ""
    if counts:
        summary = ("\n\nSummary:\n"
                   f"  Apps processed:          {counts.get('total', '?')}\n"
                   f"  app-ads.txt accessible:  {counts.get('accessible', '?')}\n"
                   f"  Matched all search lines:{counts.get('matched_all', '?')}\n")
    body = (f"Your app-ads.txt bulk check is complete.{summary}\n"
            f"Results are attached as {filename}.\n")
    return _send(to_addr, "Your app-ads.txt results are ready", body,
                 attachment=(data, filename, mimetype))


def send_failure_email(to_addr, error_msg):
    """Email the user that their job failed."""
    body = ("Your app-ads.txt bulk check could not be completed.\n\n"
            f"Error: {error_msg}\n\nPlease try again or contact the team.")
    return _send(to_addr, "Your app-ads.txt results failed", body)


if __name__ == '__main__':
    # Live self-send test (Option B). After generating a token with
    # get_gmail_token.py:
    #   GMAIL_SENDER=noreply@thejungletechnology.com \
    #   GMAIL_CLIENT_ID=... GMAIL_CLIENT_SECRET=... GMAIL_REFRESH_TOKEN=... \
    #   python email_sender.py you@thejungletechnology.com
    import sys
    recipient = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('TEST_RECIPIENT')
    if not recipient:
        print("Usage: python email_sender.py <recipient@domain>  (or set TEST_RECIPIENT)")
        sys.exit(1)
    sample = b"bundle_id,platform,verification_status\ncom.example,android,accessible\n"
    ok = send_result_email(recipient, sample, "results_selftest",
                           counts={'total': 1, 'accessible': 1, 'matched_all': 0})
    print("SENT" if ok else "FAILED")
