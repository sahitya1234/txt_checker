# App-ads.txt Bulk Line Checker

A Flask web application that checks for the presence of specific lines in app-ads.txt files for a list of apps. Upload your CSV file with Bundle IDs and app-ads.txt URLs, along with a text file containing the lines to check, and get a comprehensive CSV report.

## Features
- 🌐 **Web Interface**: Easy-to-use web interface for file uploads
- ⚡ **Async Processing**: Fast concurrent checking with retries and exponential backoff
- 📊 **Bulk Analysis**: Check thousands of app-ads.txt URLs at once (tested with 10k+)
- 📁 **Flexible Input**: Upload custom lines to check via text file
- 📈 **Detailed Reports**: CSV output with match results for each line
- 🎨 **Modern UI**: Clean, responsive interface using Tailwind CSS
- 🔐 **Google OAuth**: Secure company email authentication via Google SSO
- 🛡️ **Robust Error Handling**: Automatic retries, rate-limit backoff, per-host connection limits

## How It Works (End-to-End Flow)

From the user uploading two files to downloading the results CSV:

```
0. AUTH      Google OAuth (company domain only). DEV_MODE bypasses locally.
             /login → /login/google → /authorize → session['user']

1. UPLOAD    POST /upload with two files:
               • apps_file  → CSV: Bundle ID [, AppAdsURL]
               • lines_file → TXT: ad-network lines to search for

2. PARSE     load_apps_df_from_content(): robust read (never 500s on a bad
   & CLEAN     CSV), normalize URLs, drop bad/empty/duplicate rows, require a
               Bundle ID column (else 400). Lines cleaned of comments/blanks.

3. RESOLVE   For each app, find its app-ads.txt URL via a hybrid chain:
   URLs          1) URL prefilled in the upload row,           else
                 2) server-side metadata.csv lookup,           else
                 3) checkpoint.csv (previously discovered URL), else
                    (if checkpoint marks it "dead" → skip discovery),  else
                 4) DISCOVER (Phase 1) — only the leftovers:
                      • Android → scrape Google Play (semaphore-bounded)
                      • iOS     → iTunes batch Lookup API (≤150 ids/request)
                      (run in parallel; outcomes written back to checkpoint)

4. VERIFY    verify_extracted_urls() (Phase 2):
               • group apps by UNIQUE app-ads.txt URL
               • fetch each unique URL ONCE, substring-match each search line
               • fan the per-URL result out to every app sharing it
               • apps with no usable URL → row with all-FALSE

5. DELIVER   Result CSV emailed to the user (gzipped if > 17 MB) via the
             Gmail API. On failure, a failure email is sent instead.
```

> **Async + email delivery:** `/upload` validates the input, kicks off
> processing in a **background thread**, and returns `202` immediately. The
> result is **emailed** to the logged-in user when ready — so closing or
> refreshing the page no longer loses the result. See
> [EMAIL_SETUP.md](EMAIL_SETUP.md) for the Gmail/DWD configuration.

**Why it's fast / high-coverage:** most apps resolve from the upload or
`metadata.csv` (no scraping); iOS discovery is batched (≈100× fewer requests);
verification fetches each unique URL once (no duplicate fetches); and the
checkpoint lets re-runs skip resolved/dead apps and retry only transient
failures (rate limits, timeouts).

### Persistent state
| File | Role | Read/Write |
|------|------|-----------|
| `metadata.csv` | Curated prefetched `Bundle ID → app-ads.txt URL` mapping | Read-only (you maintain it) |
| `checkpoint.csv` | Learned discovery outcomes (`resolved` / `dead` / `retryable`); grows each run | Read-write (auto-managed) |

> On Cloud Run the local disk is ephemeral, so `checkpoint.csv` resets on
> restart/redeploy. A durable GCS-backed checkpoint is a planned follow-up.

## Project Structure
```
txt_checker/
├── check_app_ads.py          # Main Flask app: OAuth, hybrid resolution, async discovery + verify
├── clean_csv.py              # One-off cleaner for a messy apps CSV (repair/normalize/dedup)
├── metadata.csv              # Prefetched Bundle ID → app-ads.txt URL mapping (METADATA_CSV)
├── checkpoint.csv            # Runtime cache of discovery outcomes (auto-created; gitignored)
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
├── example_apps.csv          # Sample apps input file
├── lines_to_check.txt        # Sample "lines to check" file
├── templates/                # HTML templates (index.html, login.html)
└── static/                   # Static files (style.css, JT_logo.png)
```

### Relevant environment variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `METADATA_CSV` | `metadata.csv` | Path to the prefetched bundle→URL mapping |
| `CHECKPOINT_FILE` | `checkpoint.csv` | Path to the learned-outcomes checkpoint |
| `MAX_DISCOVERY_ATTEMPTS` | `5` | Retries before a failing app is marked dead |
| `ALLOWED_EMAIL_DOMAIN` | `thejungletechnology.com` | Allowed OAuth email domain |
| `DEV_MODE` | `False` | Bypass OAuth for local development |

## Requirements
- Python 3.7+
- Flask
- Flask-Session (for session management)
- pandas
- aiohttp
- authlib (for Google OAuth)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Setup

### 1. Configure Google OAuth
Follow the detailed steps in [OAUTH_SETUP.md](OAUTH_SETUP.md) to:
- Create a Google Cloud project
- Enable Google+ API
- Generate OAuth 2.0 credentials
- Create a `.env` file with your credentials

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage

### 1. Start the Web Application
```bash
python check_app_ads.py
```

### 2. Access the Web Interface
Open your browser and go to: `http://localhost:5000`

### 3. Google Login
- You'll be redirected to Google OAuth login
- Login with your company email (`@thejungletechnology.com`)
- If your email domain doesn't match, you'll get an access denied message

### 4. Upload Files
- **Apps CSV**: Upload a CSV file with Bundle IDs and AppAdsURL columns
- **Lines to Check**: Upload a text file containing the lines you want to check for

### 5. Get Results by Email
After submitting, you'll see a confirmation that the job was accepted — you can
close the page. The application processes the files in the background and
**emails the timestamped CSV report** to your login address when it's done
(gzipped automatically if the file is large). If the job fails, you'll get a
failure email instead.

## Input File Formats

### Apps CSV Format
| Bundle ID        | AppAdsURL                        |
|------------------|----------------------------------|
| com.example.app  | https://example.com/app-ads.txt  |
| com.another.app  | https://another.com/app-ads.txt  |

### Lines to Check Text File Format
```
google.com, pub-9911740406682987, RESELLER, f08c47fec0942fa0
rubiconproject.com, 27854, RESELLER, 0bfd66d529a55807
pubmatic.com, 137711, RESELLER, 5d62403b186f2ace
```

## Output CSV Format
One row per input app. Columns:

| Column | Meaning |
|--------|---------|
| `bundle_id` | The app's bundle ID |
| `platform` | `android` or `iOS` |
| `app_ads_txt_url` | The resolved app-ads.txt URL (blank if none found) |
| `verification_status` | `accessible`, `timeout`, `http_error_<code>`, or `extraction_failed_<reason>` |
| *(one column per search line)* | `TRUE` if that line is present in the file, else `FALSE` |
| `total_lines_found` | Count of search lines matched |
| `has_all_lines` | `TRUE` if every search line was found |

Example:

| bundle_id | platform | app_ads_txt_url | verification_status | google.com, pub-99117... | rubiconproject.com, 27854... | total_lines_found | has_all_lines |
|-----------|----------|-----------------|---------------------|--------------------------|------------------------------|-------------------|---------------|
| com.example.app | android | https://example.com/app-ads.txt | accessible | TRUE | FALSE | 1 | FALSE |

## Development

### Running in Development Mode
```bash
python check_app_ads.py
```
The app runs with debug mode enabled by default.

### Project Structure Details
- **`check_app_ads.py`**: Main Flask application with async processing logic
- **`templates/index.html`**: Web interface template with Tailwind CSS
- **`static/style.css`**: Custom CSS styles (currently minimal, uses Tailwind CDN)
- **`requirements.txt`**: Python package dependencies

## Examples
- See `example_apps.csv` for a sample apps input file
- See `lines_to_check.txt` for a sample lines to check file 