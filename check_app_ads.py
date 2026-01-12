import aiohttp
import asyncio
import pandas as pd
import re
import io
from datetime import datetime
from flask import Flask, render_template, request, send_file, session, redirect, url_for, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
import time
import requests
from bs4 import BeautifulSoup
import os
import random
from functools import wraps
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-prod')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
Session(app)

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

ALLOWED_EMAIL_DOMAIN = os.environ.get('ALLOWED_EMAIL_DOMAIN', 'thejungletechnology.com')

# --- Auth Decorators & Helpers ---
def login_required(f):
    """Decorator to check if user is logged in and has valid company email."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_company_email(email):
    """Check if email ends with the allowed company domain."""
    return email.endswith(f"@{ALLOWED_EMAIL_DOMAIN}")

# --- URL Construction Logic ---
def get_store_url(bundle_id):
    """
    Constructs the appropriate store URL based on the bundle ID format.
    Args:
        bundle_id (str): The bundle ID or app store ID
    Returns:
        tuple: (store_type, url) where store_type is either 'play_store' or 'app_store'
        or (None, None) if there's an error
    """
    try:
        if not bundle_id:
            return None, None
            
        # Remove any whitespace and any 'id=' prefix
        bundle_id = str(bundle_id).strip()
        if bundle_id.startswith('id='):
            bundle_id = bundle_id[3:]
        
        if not bundle_id:  # If bundle_id is empty after cleaning
            return None, None
        
        # Check if the bundle ID is numeric (App Store ID)
        if bundle_id.isdigit():
            return 'app_store', f'https://apps.apple.com/app/id{bundle_id}'
        else:
            # If it contains dots, it's likely a Play Store bundle ID
            return 'play_store', f'https://play.google.com/store/apps/details?id={bundle_id}'
    except Exception as e:
        print(f'Error in get_store_url for bundle_id {bundle_id}: {str(e)}')
        return None, None

def get_support_website(store_url, store_type='play_store'):
    """
    Extracts the support website URL from the app store page.
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

        # Simple retry loop for store page fetch (to handle transient errors and 429)
        max_retries = 3
        base_delay = 0.5
        backoff = 2.0
        last_exc = None
        for attempt in range(max_retries):
            try:
                response = requests.get(store_url, headers=headers, timeout=10)
                response.raise_for_status()
                break
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt == max_retries - 1:
                    raise
                sleep_for = base_delay * (backoff ** attempt) + random.uniform(0, 0.25)
                time.sleep(sleep_for)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        if store_type == 'play_store':
            # Look for the "App support" section and find the website link
            support_section = soup.find_all('div', string=re.compile('App support|Developer|Website'))
            
            if support_section:
                for section in support_section:
                    parent = section.find_parent('div')
                    if parent:
                        links = parent.find_all('a', href=True)
                        for link in links:
                            href = link.get('href', '')
                            if (href.startswith('http') and 
                                not href.startswith('https://play.google.com') and
                                not href.startswith('https://support.google.com') and
                                not 'policy' in href.lower() and
                                not 'privacy' in href.lower()):
                                return href
        else:  # App Store
            # Look for the developer's website by specifically finding the "Developer Website" text
            try:
                # First try to find the text "Developer Website"
                developer_website_element = soup.find(string=re.compile("Developer Website", re.IGNORECASE))
                if developer_website_element:
                    # Find the closest 'a' tag near this text
                    parent_element = developer_website_element.find_parent()
                    if parent_element:
                        link = parent_element.find_next('a')
                        if link:
                            href = link.get('href', '')
                            if (href and 
                                href.startswith('http') and 
                                not href.startswith('https://apps.apple.com') and
                                not 'developer/id' in href):
                                # Clean the URL to keep only up to the domain
                                domain_endings = ['.com', '.org', '.net', '.io', '.app', '.games', '.dev', '.co']
                                for ending in domain_endings:
                                    if ending in href:
                                        # Find the position of the domain ending
                                        pos = href.find(ending) + len(ending)
                                        # Keep only up to the domain ending
                                        href = href[:pos]
                                        break
                                return href

                # Backup: Look in the information section for any external link
                info_section = soup.find('section', {'class': 'l-content-width section section--bordered section--information'})
                if info_section:
                    external_links = info_section.find_all('a', {'class': 'link'})
                    for link in external_links:
                        href = link.get('href', '')
                        if (href and 
                            href.startswith('http') and 
                            not href.startswith('https://apps.apple.com') and
                            not 'developer/id' in href and
                            not 'privacy' in href.lower() and
                            not 'support.apple.com' in href.lower()):
                            return href
                            
            except Exception as e:
                print(f"Error finding developer website in App Store page: {str(e)}")
                return None
                            
        return None
        
    except Exception as e:
        print(f"Error fetching support website: {str(e)}")
        return None

def construct_app_ads_url(website_url):
    """
    Constructs the app-ads.txt URL from the website URL.
    """
    try:
        if not website_url:
            return None
            
        # Validate URL format
        if not website_url.startswith(('http://', 'https://')):
            print(f'Invalid website URL format: {website_url}')
            return None
            
        # Remove trailing slash if present
        website_url = website_url.rstrip('/')
        
        # Check if app-ads.txt is already in the URL
        if website_url.endswith('app-ads.txt'):
            return website_url
        
        # Append app-ads.txt
        return f"{website_url}/app-ads.txt"
    except Exception as e:
        print(f'Error in construct_app_ads_url: {str(e)}')
        return None

def get_app_ads_url(bundle_id):
    """
    Gets the app-ads.txt URL for a bundle ID by checking the store page.
    """
    try:
        store_type, url = get_store_url(bundle_id)
        if not store_type or not url:
            return None
            
        support_website = get_support_website(url, store_type)
        if not support_website:
            return None
            
        return construct_app_ads_url(support_website)
    except Exception as e:
        print(f'Error getting app-ads URL for {bundle_id}: {str(e)}')
        return None

# --- Core Logic ---

RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 0.5
DEFAULT_BACKOFF = 2.0

async def fetch_text_with_retries(session, url, timeout=10,
                                  max_retries=DEFAULT_MAX_RETRIES,
                                  base_delay=DEFAULT_BASE_DELAY,
                                  backoff=DEFAULT_BACKOFF):
    """Fetch URL text with retries and exponential backoff.
    Returns (text, error_message). text=None on failure.
    """
    last_error = None
    for attempt in range(max_retries):
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    return await resp.text(), None
                elif resp.status in RETRYABLE_STATUSES:
                    last_error = f"HTTP {resp.status}"
                    # backoff and retry
                else:
                    return None, f"HTTP {resp.status}"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_error = str(e)
            # backoff and retry

        # sleep before next attempt (except after last)
        if attempt < max_retries - 1:
            sleep_for = base_delay * (backoff ** attempt) + random.uniform(0, 0.25)
            await asyncio.sleep(sleep_for)

    # exhausted
    return None, (last_error or "Unknown error")

def clean_line(line):
    """
    Removes comments, surrounding quotes, and trailing/leading whitespace.
    """
    line = line.split('#')[0]
    line = line.strip()
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1]
    line = line.replace('，', ',')
    return line.strip()

def load_lines_from_memory(file_content):
    """Loads and cleans lines from a file's content in memory."""
    lines = {clean_line(line) for line in file_content.splitlines() if line.strip()}
    return lines

async def fetch_and_check(session, bundle_id, url, lines_to_check, ordered_lines_to_check, semaphore, url_cache):
    """Fetches a URL and checks for matching lines using a set for speed."""
    async with semaphore:
        result = {"Bundle ID": bundle_id, "AppAdsURL": url}
        try:
            # If no URL is provided, try to get it from the store
            if (not url or pd.isna(url) or not isinstance(url, str)):
                # try cache first
                if url_cache is not None and bundle_id in url_cache:
                    url = url_cache[bundle_id]
                else:
                    url = get_app_ads_url(bundle_id)
                    if url_cache is not None:
                        url_cache[bundle_id] = url
                result["AppAdsURL"] = url if url else ""
                
            if url:  # Only proceed if we have a URL
                content, err = await fetch_text_with_retries(session, url, timeout=10)
                if content is not None:
                    downloaded_lines_set = {clean_line(line) for line in content.splitlines()}
                    result["TXT Found"] = "Yes"
                    # Check if any line contains the search term (substring matching)
                    matches = set()
                    for check_line in lines_to_check:
                        for downloaded_line in downloaded_lines_set:
                            if check_line in downloaded_line:
                                matches.add(check_line)
                                break
                    for check_line in ordered_lines_to_check:
                        result[f"{check_line}"] = check_line in matches
                    result["Error"] = "-"
                else:
                    result["TXT Found"] = "No"
                    result["Error"] = err or "Fetch failed"
            else:
                result["TXT Found"] = "No"
                result["Error"] = "No app-ads.txt URL found"
        except Exception as e:
            result["TXT Found"] = "No"
            result["Error"] = str(e)
        
        # Ensure all check lines are present in the result
        if result["TXT Found"] == "No":
            for check_line in ordered_lines_to_check:
                result[f"{check_line}"] = False
        
        return result

async def process_files_async(apps_df, lines_to_check):
    """The main asynchronous processing logic."""
    results = []
    ordered_lines_to_check = sorted(list(lines_to_check))
    column_headers = ["Bundle ID", "AppAdsURL", "TXT Found", "Error"] + \
                     [f"{line}" for line in ordered_lines_to_check]

    # Configurable concurrency via env var, default 100
    try:
        concurrency = int(os.environ.get("APP_CONCURRENCY", "100"))
        concurrency = max(10, min(concurrency, 200))
    except Exception:
        concurrency = 100

    # Create per-run semaphore bound to this event loop
    semaphore = asyncio.Semaphore(concurrency)

    # Per-run URL cache to avoid re-scraping duplicated bundle IDs
    url_cache = {}

    timeout = aiohttp.ClientTimeout(total=20, sock_connect=10, sock_read=10)
    connector = aiohttp.TCPConnector(limit=0, limit_per_host=10, ttl_dns_cache=300)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
    }

    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
        tasks = []
        for _, row in apps_df.iterrows():
            bundle_id = row.get("Bundle ID")
            url = row.get("AppAdsURL")
            tasks.append(fetch_and_check(session, bundle_id, url, lines_to_check, ordered_lines_to_check, semaphore, url_cache))

        for future in asyncio.as_completed(tasks):
            res = await future
            results.append(res)
    
    # Create the final DataFrame and return it
    return pd.DataFrame(results, columns=column_headers)

# --- Flask Routes ---
# This section defines the web page and the file handling logic.

@app.route('/login')
def login():
    """Renders the login page with a button to start Google OAuth."""
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    """Redirects to Google OAuth consent screen."""
    redirect_uri = url_for('authorize', _external=True, _scheme='https')
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    """OAuth callback route. Validates token and checks company email."""
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    
    if not user_info:
        return "Failed to retrieve user info.", 403
    
    email = user_info.get('email', '').lower()
    
    # Check if email is from company domain
    if not is_company_email(email):
        return f"Access denied. You must use a company email (@{ALLOWED_EMAIL_DOMAIN}). Your email: {email}", 403
    
    # Store user info in session
    session['user'] = {
        'email': email,
        'name': user_info.get('name', ''),
        'picture': user_info.get('picture', '')
    }
    session.permanent = True
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Clears user session and redirects to login."""
    session.clear()
    return redirect(url_for('login'))

@app.route('/healthz')
def healthz():
    """Simple health check endpoint for Cloud Run load balancer."""
    return "ok", 200

@app.route('/favicon.ico')
def favicon():
    """Serve favicon to avoid 503s from default /favicon.ico requests."""
    try:
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'JT_logo.png',
            mimetype='image/png'
        )
    except Exception:
        # Return empty 204 if asset missing, so LB doesn't treat as error
        return ('', 204)

@app.route('/', methods=['GET'])
def index():
    """Renders the main upload page."""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    """Handles file uploads, processes them, and returns the result CSV."""
    if 'apps_file' not in request.files or 'lines_file' not in request.files:
        return "Missing file(s) in the form submission.", 400

    apps_file = request.files['apps_file']
    lines_file = request.files['lines_file']

    if apps_file.filename == '' or lines_file.filename == '':
        return "No selected file.", 400

    try:
        # Read file contents into memory
        apps_csv_content = apps_file.stream.read().decode("utf-8")
        lines_txt_content = lines_file.stream.read().decode("utf-8")

        # Load data using pandas and our custom function
        apps_df = pd.read_csv(io.StringIO(apps_csv_content))
        lines_to_check = load_lines_from_memory(lines_txt_content)

        # Run the async processing and get the results DataFrame
        results_df = asyncio.run(process_files_async(apps_df, lines_to_check))
        
        # Save the results DataFrame to an in-memory buffer
        output_buffer = io.StringIO()
        results_df.to_csv(output_buffer, index=False)
        output_buffer.seek(0)
        
        # Create an in-memory bytes buffer to send the file
        mem_file = io.BytesIO()
        mem_file.write(output_buffer.getvalue().encode('utf-8'))
        mem_file.seek(0)
        
        # Create a dynamic filename with the current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        dynamic_filename = f"results_{timestamp}.csv"

        return send_file(
            mem_file,
            as_attachment=True,
            download_name=dynamic_filename,
            mimetype='text/csv'
        )

    except Exception as e:
        return f"An error occurred: {e}", 500

if __name__ == '__main__':
    # Runs the Flask application on a port that avoids macOS AirPlay conflicts (use 8000 by default)
    port = int(os.environ.get('PORT', os.environ.get('FLASK_RUN_PORT', 8000)))
    app.run(host='127.0.0.1', port=port, debug=False)

