# Email Delivery Setup (Gmail API)

Results are processed in the background and **emailed** to the user (the address
from their Google login). `/upload` returns `202` immediately; the worker builds
the result CSV (gzipped if > 17 MB) and emails it via the **Gmail API**.

Two auth methods are supported. **Option B is active** — it needs no Workspace
admin and is least-privilege (the token can send only as one mailbox + its
aliases, never domain-wide). Option A (domain-wide delegation) is the fallback.

---

## Option B — OAuth refresh token (ACTIVE, no Workspace admin)

The app sends using a stored OAuth **refresh token** for the sender mailbox.
Env vars: `GMAIL_SENDER`, `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`,
`GMAIL_REFRESH_TOKEN`.

### Recommended mailbox setup (single mailbox + aliases)
Ask a Workspace admin to create **one** licensed mailbox (e.g.
`mailer@thejungletechnology.com`) and add aliases to it (e.g.
`noreply@thejungletechnology.com`). Aliases are free and are valid "send as"
addresses, so you can send `From` any alias while managing just one mailbox and
one token. No domain-wide delegation needed.

### One-time setup
1. **GCP Console → APIs & Services → OAuth consent screen:** User type
   **Internal**; add scope `https://www.googleapis.com/auth/gmail.send`.
   (Internal avoids Google app-verification for this restricted scope, and
   requires the project to be in the same Workspace org.)
2. **Credentials → Create credentials → OAuth client ID → Desktop app.**
   Download the JSON as `client_secret.json` in the repo root (gitignored).
3. Generate the refresh token (log in as the mailer mailbox when the browser opens):
   ```
   pip install -r requirements.txt
   python get_gmail_token.py
   ```
   It prints `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `GMAIL_REFRESH_TOKEN`.
4. Set those + `GMAIL_SENDER` (an alias is fine) as env vars on the app.

### Test
```
GMAIL_SENDER=noreply@thejungletechnology.com \
GMAIL_CLIENT_ID=... GMAIL_CLIENT_SECRET=... GMAIL_REFRESH_TOKEN=... \
python email_sender.py you@thejungletechnology.com
```

### Caveats
- The refresh token can stop working if unused ~6 months, the mailbox password
  changes, or access is revoked — regenerate with `get_gmail_token.py`.
- Store `GMAIL_REFRESH_TOKEN` as a secret (Cloud Run env / Secret Manager).
- `GMAIL_SENDER` must be the consenting mailbox or one of its aliases, else
  Gmail rewrites the From header.

---

## Option A — Keyless domain-wide delegation (FALLBACK, needs Workspace admin)

The Cloud Run **runtime SA** signs an OAuth assertion for the **mailer SA** via
the IAM Credentials API; that delegated credential impersonates `GMAIL_SENDER`.
Uses env var `MAILER_SA` (leave the Option B vars unset).

> ⚠️ DWD is **domain-wide**: an authorized SA can send as *any* user in the
> domain. Many admins reject it for that reason — prefer Option B.

### One-time setup

#### 1. GCP project
- Enable **Gmail API** and **IAM Service Account Credentials API**.
- Create a mailer service account, e.g.
  `appads-mailer@<project>.iam.gserviceaccount.com`.
- Grant the **Cloud Run runtime service account** the role
  `roles/iam.serviceAccountTokenCreator` **on the mailer SA**
  (so it can sign assertions for it).

#### 2. Google Workspace admin — authorize DWD
In **Admin Console → Security → Access and data control → API controls →
Domain-wide delegation**, add the **mailer SA's client ID (numeric)** with
exactly this scope:
```
https://www.googleapis.com/auth/gmail.send
```

#### 3. Sender mailbox
Ensure `GMAIL_SENDER` is a **real** Workspace mailbox (DWD impersonates a real
mailbox; it can't be fictional).

#### 4. Environment variables (Cloud Run)
```
MAILER_SA=appads-mailer@<project>.iam.gserviceaccount.com
GMAIL_SENDER=noreply@thejungletechnology.com
GMAIL_REPLY_TO=            # optional monitored reply box
```

## Cloud Run deploy flags (background-job reliability)
The job runs in a background thread, so the instance must keep CPU after the
request returns and stay warm:
```
gcloud run deploy <service> \
  --min-instances=1 \
  --no-cpu-throttling \        # CPU always allocated
  --timeout=3600 \
  --memory=2Gi \               # raise for very large inputs
  --set-env-vars GMAIL_SENDER=noreply@thejungletechnology.com,GMAIL_CLIENT_ID=...,GMAIL_CLIENT_SECRET=...,GMAIL_REFRESH_TOKEN=...
```
> Caveat: this is **best-effort** background processing. A redeploy or crash
> mid-job will drop that one job (no email). A hard guarantee would require a
> queue (Cloud Tasks) — a planned future step.

## Troubleshooting
- **No Gmail auth configured** → set the Option B vars (or `MAILER_SA` for A).
- **From rewritten to another address** → `GMAIL_SENDER` isn't the consenting
  mailbox or a valid alias of it.
- **No email but job logs success** → check spam; confirm Workspace SPF/DKIM.
- **`invalid_grant` on send** → refresh token revoked/expired; regenerate with
  `get_gmail_token.py`.
- *(Option A only)* **403 / unauthorized_client** → DWD client ID/scope not
  authorized; **permission denied signing** → runtime SA lacks
  `serviceAccountTokenCreator` on the mailer SA.
