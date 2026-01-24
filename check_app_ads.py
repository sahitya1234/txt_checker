import aiohttp
import asyncio
import pandas as pd
import re
import io
from datetime import datetime
from flask import Flask, render_template, request, send_file, session, redirect, url_for, send_from_directory, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import time
import requests
from bs4 import BeautifulSoup
import os
import random
from functools import wraps
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import logging
import sys
import psutil
import os as os_module
import csv

# Load environment variables from .env file
load_dotenv()

# Configure logging for Cloud Run
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- Complete App Ads.txt Analyzer Class ---
class CompleteAdsTxtAnalyzer:
    def __init__(self, android_workers=50, ios_workers=50, ios_delay=0.5, verification_workers=50):
        # Scraping settings
        self.android_workers = android_workers
        self.ios_workers = ios_workers
        self.ios_delay = ios_delay
        self.verification_workers = verification_workers
        
        # Statistics
        self.scraping_stats = {
            'total_apps': 0,
            'android_apps': 0,
            'ios_apps': 0,
            'android_success': 0,
            'ios_success': 0,
            'android_retries': 0,
            'ios_rate_limited': 0,
            'failed': 0
        }
        
        self.verification_stats = {
            'total_urls': 0,
            'accessible': 0,
            'inaccessible': 0,
            'contains_all_lines': 0,
            'missing_some_lines': 0,
            'errors': 0
        }
        
        # Android User Agents
        self.android_user_agents = [
            'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36'
        ]
        
        self.android_regions = ['us', 'gb', 'ca', 'au', 'in']
    
    def load_bundle_ids_from_df(self, apps_df):
        """Load and separate bundle IDs by platform from a DataFrame"""
        try:
            android_bundles = []
            ios_bundles = []
            
            # Normalize column names
            for col in apps_df.columns:
                lower_col = col.lower().strip()
                if 'bundle' in lower_col and 'id' in lower_col:
                    bundle_column = col
                    break
            else:
                logger.error("No bundle ID column found in DataFrame")
                return [], []
            
            logger.info(f"Using column: '{bundle_column}'")
            
            for _, row in apps_df.iterrows():
                bundle_id = str(row.get(bundle_column, '')).strip()
                if bundle_id and bundle_id.lower() not in ['', 'nan', 'none']:
                    if bundle_id.isdigit():
                        ios_bundles.append(bundle_id)
                    else:
                        android_bundles.append(bundle_id)
            
            logger.info(f"Loaded bundle IDs from DataFrame")
            logger.info(f"Distribution: Android: {len(android_bundles):,} | iOS: {len(ios_bundles):,}")
            
            return android_bundles, ios_bundles
            
        except Exception as e:
            logger.error(f"Error loading bundle IDs: {e}")
            return [], []
    
    async def scrape_android_app(self, session, bundle_id, max_retries=3):
        """Scrape Android app for developer website URL"""
        for retry_count in range(max_retries + 1):
            try:
                region = random.choice(self.android_regions)
                user_agent = random.choice(self.android_user_agents)
                
                url = f"https://play.google.com/store/apps/details?id={bundle_id}&gl={region}&hl=en"
                
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                }
                
                timeout = aiohttp.ClientTimeout(total=3)
                
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Look for developer website
                        developer_url = None
                        element = soup.select_one('a.Si6A0c.RrSxVb')
                        if element and element.get('href'):
                            developer_url = element.get('href')
                        
                        # Fallback selector
                        if not developer_url:
                            elements = soup.select('a[href*="http"]')
                            for elem in elements:
                                href = elem.get('href', '')
                                if (href.startswith('http') and 
                                    not 'play.google.com' in href and
                                    not 'support.google.com' in href):
                                    developer_url = href
                                    break
                        
                        if developer_url:
                            # Add /app-ads.txt to the URL
                            if not developer_url.endswith('/'):
                                developer_url += '/'
                            developer_url += 'app-ads.txt'
                            
                            self.scraping_stats['android_success'] += 1
                            return {'bundle_id': bundle_id, 'platform': 'android', 'app_ads_txt_url': developer_url, 'status': 'success'}
                        else:
                            return {'bundle_id': bundle_id, 'platform': 'android', 'app_ads_txt_url': '', 'status': 'no_website_found'}
                    
                    elif response.status == 404:
                        return {'bundle_id': bundle_id, 'platform': 'android', 'app_ads_txt_url': '', 'status': 'not_found'}
                    
                    else:
                        if retry_count < max_retries:
                            await asyncio.sleep(1 * (retry_count + 1))
                            self.scraping_stats['android_retries'] += 1
                            continue
                        return {'bundle_id': bundle_id, 'platform': 'android', 'app_ads_txt_url': '', 'status': f'http_error_{response.status}'}
                        
            except asyncio.TimeoutError:
                if retry_count < max_retries:
                    await asyncio.sleep(1 * (retry_count + 1))
                    self.scraping_stats['android_retries'] += 1
                    continue
                return {'bundle_id': bundle_id, 'platform': 'android', 'app_ads_txt_url': '', 'status': 'timeout'}
                
            except Exception as e:
                if retry_count < max_retries:
                    await asyncio.sleep(1 * (retry_count + 1))
                    self.scraping_stats['android_retries'] += 1
                    continue
                return {'bundle_id': bundle_id, 'platform': 'android', 'app_ads_txt_url': '', 'status': f'error: {str(e)[:30]}'}
    
    async def scrape_ios_app_async(self, session, bundle_id, max_retries=2):
        """Scrape iOS app asynchronously for developer website URL with retry logic"""
        for retry in range(max_retries + 1):
            try:
                url = f"https://apps.apple.com/in/app/id{bundle_id}"
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive'
                }
                
                timeout = aiohttp.ClientTimeout(total=12)
                
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    if response.status == 429:
                        # Rate limited - exponential backoff
                        if retry < max_retries:
                            await asyncio.sleep(2 ** retry)
                            self.scraping_stats['ios_rate_limited'] += 1
                            continue
                        else:
                            return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'rate_limited'}
                    
                    elif response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        developer_url = None
                        
                        # Priority 1: Look for "Developer Website" text first
                        try:
                            all_links = soup.find_all('a', href=True)
                            for link in all_links:
                                href = link.get('href', '')
                                text = link.get_text(strip=True).lower()
                                if 'developer website' in text and href.startswith('http'):
                                    if not any(keyword in href.lower() for keyword in ['apps.apple.com', 'privacy', 'policy']):
                                        developer_url = href
                                        break
                        except Exception as e:
                            logger.debug(f"Error in Priority 1 search: {str(e)}")
                        
                        # Backup: Look in the information section for any external link
                        if not developer_url:
                            try:
                                all_links = soup.find_all('a', href=True)
                                valid_urls = []
                                for link in all_links:
                                    href = link.get('href', '')
                                    if (href.startswith('http') and 
                                        not 'apps.apple.com' in href and
                                        not 'support.apple.com' in href and
                                        not 'itunes.apple.com' in href and
                                        not any(keyword in href.lower() for keyword in 
                                               ['privacy', 'policy', 'terms', 'support', 'about', 
                                                'bug', 'feedback', 'legal', 'cookie', 'contact', 'help'])):
                                        valid_urls.append(href)
                                if valid_urls:
                                    developer_url = valid_urls[0]
                            except Exception as e:
                                logger.debug(f"Error in Priority 2 search: {str(e)}")
                        
                        if developer_url:
                            developer_url = developer_url.rstrip('/')
                            app_ads_url = f"{developer_url}/app-ads.txt"
                            self.scraping_stats['ios_success'] += 1
                            return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': app_ads_url, 'status': 'success'}
                        else:
                            return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'no_website_found'}
                    
                    elif response.status == 404:
                        return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'not_found'}
                    
                    else:
                        # Other HTTP errors - retry once
                        if retry < max_retries:
                            await asyncio.sleep(1 * (retry + 1))
                            continue
                        else:
                            return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': f'http_error_{response.status}'}
                        
            except asyncio.TimeoutError:
                if retry < max_retries:
                    await asyncio.sleep(1 * (retry + 1))
                    continue
                return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'timeout'}
                
            except Exception as e:
                if retry < max_retries:
                    await asyncio.sleep(1 * (retry + 1))
                    continue
                else:
                    return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': f'error: {str(e)[:30]}'}
        
        # Shouldn't reach here, but just in case
        return {'bundle_id': bundle_id, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'unknown_error'}
    
    async def extract_android_urls(self, android_bundles):
        """Extract URLs from Android apps"""
        if not android_bundles:
            return []
        
        logger.info(f"Processing {len(android_bundles)} Android apps...")
        
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=self.android_workers)
        results = []
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Process in batches
            batch_size = 50
            for i in range(0, len(android_bundles), batch_size):
                batch = android_bundles[i:i + batch_size]
                
                tasks = [self.scrape_android_app(session, bundle_id) for bundle_id in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, dict):
                        results.append(result)
                
                batch_num = i//batch_size + 1
                logger.info(f"Android batch {batch_num}: {len(batch)} apps processed ({len(results)} total)")
        
        return results
    
    async def extract_ios_urls(self, ios_bundles):
        """Extract URLs from iOS apps asynchronously"""
        if not ios_bundles:
            return []
        
        logger.info(f"Processing {len(ios_bundles)} iOS apps...")
        
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=self.ios_workers)
        results = []
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Process in batches
            batch_size = 50
            for i in range(0, len(ios_bundles), batch_size):
                batch = ios_bundles[i:i + batch_size]
                
                tasks = [self.scrape_ios_app_async(session, bundle_id) for bundle_id in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, dict):
                        results.append(result)
                
                batch_num = i//batch_size + 1
                logger.info(f"iOS batch {batch_num}: {len(batch)} apps processed ({len(results)} total)")
        
        return results
    
    async def verify_ads_txt_detailed(self, session, url, search_lines, bundle_id, platform, max_retries=2):
        """Verify if app-ads.txt contains each search line individually"""
        for attempt in range(max_retries + 1):
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/plain,text/html,*/*',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive'
                }
                
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        content_lower = content.lower()
                        
                        # Create result dictionary
                        result = {
                            'bundle_id': bundle_id,
                            'platform': platform,
                            'app_ads_txt_url': url,
                            'verification_status': 'accessible'
                        }
                        
                        # Check each line individually
                        lines_found = 0
                        for line in search_lines:
                            result[line] = 'TRUE' if line.lower() in content_lower else 'FALSE'
                            if result[line] == 'TRUE':
                                lines_found += 1
                        
                        result['total_lines_found'] = lines_found
                        result['has_all_lines'] = 'TRUE' if lines_found == len(search_lines) else 'FALSE'
                        
                        return result
                        
                    else:
                        if attempt < max_retries:
                            await asyncio.sleep(1 * (attempt + 1))
                            continue
                        
                        # Create result with all lines as FALSE
                        result = {
                            'bundle_id': bundle_id,
                            'platform': platform,
                            'app_ads_txt_url': url,
                            'verification_status': f'http_error_{response.status}'
                        }
                        
                        for line in search_lines:
                            result[line] = 'FALSE'
                            
                        result['total_lines_found'] = 0
                        result['has_all_lines'] = 'FALSE'
                        return result
                        
            except asyncio.TimeoutError:
                if attempt < max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                    
                result = {
                    'bundle_id': bundle_id,
                    'platform': platform,
                    'app_ads_txt_url': url,
                    'verification_status': 'timeout'
                }
                
                for line in search_lines:
                    result[line] = 'FALSE'
                    
                result['total_lines_found'] = 0
                result['has_all_lines'] = 'FALSE'
                return result
                
            except Exception as e:
                if attempt < max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                    
                result = {
                    'bundle_id': bundle_id,
                    'platform': platform,
                    'app_ads_txt_url': url,
                    'verification_status': f'error: {str(e)[:30]}'
                }
                
                for line in search_lines:
                    result[line] = 'FALSE'
                    
                result['total_lines_found'] = 0
                result['has_all_lines'] = 'FALSE'
                return result
    
    async def verify_extracted_urls(self, extracted_results, search_lines):
        """Verify all extracted URLs for ads.txt content"""
        # Filter only successful extractions
        urls_to_verify = [
            result for result in extracted_results 
            if result.get('status') == 'success' and result.get('app_ads_txt_url')
        ]
        
        if not urls_to_verify:
            logger.info("No URLs to verify")
            return []
        
        logger.info(f"Verifying {len(urls_to_verify)} ads.txt URLs...")
        
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=self.verification_workers,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        verified_results = []
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Process in batches
            batch_size = 50
            for i in range(0, len(urls_to_verify), batch_size):
                batch = urls_to_verify[i:i + batch_size]
                
                tasks = []
                for item in batch:
                    task = self.verify_ads_txt_detailed(
                        session, 
                        item['app_ads_txt_url'], 
                        search_lines, 
                        item['bundle_id'], 
                        item['platform']
                    )
                    tasks.append(task)
                
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, dict):
                        verified_results.append(result)
                        
                        # Update stats
                        if result['verification_status'] == 'accessible':
                            self.verification_stats['accessible'] += 1
                            if result['has_all_lines'] == 'TRUE':
                                self.verification_stats['contains_all_lines'] += 1
                            else:
                                self.verification_stats['missing_some_lines'] += 1
                        else:
                            self.verification_stats['inaccessible'] += 1
                
                logger.info(f"Verification batch {i//batch_size + 1}: {len(batch)} URLs processed")
        
        # Add failed extractions as well (with all FALSE values)
        failed_extractions = [
            result for result in extracted_results 
            if result.get('status') != 'success' or not result.get('app_ads_txt_url')
        ]
        
        for failed in failed_extractions:
            result = {
                'bundle_id': failed['bundle_id'],
                'platform': failed['platform'],
                'app_ads_txt_url': failed.get('app_ads_txt_url', ''),
                'verification_status': f'extraction_failed_{failed.get("status", "unknown")}'
            }
            
            # Add all lines as FALSE
            for line in search_lines:
                result[line] = 'FALSE'
                
            result['total_lines_found'] = 0
            result['has_all_lines'] = 'FALSE'
            verified_results.append(result)
        
        return verified_results
    
    async def run_complete_analysis(self, apps_df, search_lines, user_email="unknown"):
        """Run the complete analysis pipeline"""
        start_time = time.time()
        
        logger.info(f"[{user_email}] Starting Complete App Ads.txt Analysis")
        logger.info(f"[{user_email}] ========================================")
        
        # Step 1: Load and separate bundle IDs
        android_bundles, ios_bundles = self.load_bundle_ids_from_df(apps_df)
        
        self.scraping_stats['total_apps'] = len(android_bundles) + len(ios_bundles)
        self.scraping_stats['android_apps'] = len(android_bundles)
        self.scraping_stats['ios_apps'] = len(ios_bundles)
        
        logger.info(f"[{user_email}] Total apps: {self.scraping_stats['total_apps']:,}")
        logger.info(f"[{user_email}] Android apps: {len(android_bundles):,}")
        logger.info(f"[{user_email}] iOS apps: {len(ios_bundles):,}")
        
        # Step 2: Extract URLs (parallel processing)
        logger.info(f"[{user_email}] Phase 1: Extracting Developer Website URLs")
        logger.info(f"[{user_email}] ----------------------------------------")
        
        # Run Android and iOS extraction in parallel
        android_task = asyncio.create_task(self.extract_android_urls(android_bundles))
        ios_task = asyncio.create_task(self.extract_ios_urls(ios_bundles))

        android_results, ios_results = await asyncio.gather(android_task, ios_task)
        all_extraction_results = android_results + ios_results
        
        # Step 3: Verify ads.txt files
        logger.info(f"[{user_email}] Phase 2: Verifying App-Ads.txt Files")
        logger.info(f"[{user_email}] ----------------------------------------")
        self.verification_stats['total_urls'] = len([r for r in all_extraction_results if r.get('status') == 'success'])
        verified_results = await self.verify_extracted_urls(all_extraction_results, search_lines)
        
        # Step 4: Log final statistics
        elapsed_time = time.time() - start_time
        logger.info(f"[{user_email}] Processing complete!")
        logger.info(f"[{user_email}] Total time: {elapsed_time:.2f}s")
        logger.info(f"[{user_email}] Android success: {self.scraping_stats['android_success']}/{self.scraping_stats['android_apps']}")
        logger.info(f"[{user_email}] iOS success: {self.scraping_stats['ios_success']}/{self.scraping_stats['ios_apps']}")
        logger.info(f"[{user_email}] URLs verified: {self.verification_stats['accessible']}/{self.verification_stats['total_urls']}")
        
        return verified_results

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-prod')
# Remove filesystem sessions - use Flask's built-in secure cookies instead
app.config['SESSION_TYPE'] = 'null'  # or just remove this line
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SESSION_COOKIE_SECURE'] = True  # Only HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # XSS protection
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
# Remove: Session(app)  # Not needed for cookie sessions

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
DEV_MODE = os.environ.get('DEV_MODE', 'False').lower() == 'true'

# --- Auth Decorators & Helpers ---
def login_required(f):
    """Decorator to check if user is logged in and has valid company email."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In DEV_MODE, bypass authentication
        if DEV_MODE and 'user' not in session:
            session['user'] = {
                'email': 'dev@localhost',
                'name': 'Dev User',
                'picture': ''
            }
            logger.info("DEV_MODE: Bypassing authentication")
        
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_company_email(email):
    """Check if email ends with the allowed company domain."""
    return email.endswith(f"@{ALLOWED_EMAIL_DOMAIN}")

# --- Core Logic ---

def load_lines_from_memory(file_content):
    """Loads and cleans lines from a file's content in memory."""
    lines = []
    for line in file_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('//'):
            lines.append(line)
    return lines

async def process_files_async(apps_df, lines_to_check, user_email="unknown"):
    """
    Process files using the complete analyzer.
    
    Args:
        apps_df: DataFrame with bundle IDs
        lines_to_check: List of lines to search for in ads.txt files
        user_email: Email of user for logging
    
    Returns:
        DataFrame with complete analysis results
    """
    analyzer = CompleteAdsTxtAnalyzer(android_workers=50, ios_workers=50, verification_workers=30)
    
    # Run the complete analysis
    verified_results = await analyzer.run_complete_analysis(apps_df, lines_to_check, user_email)
    
    # Create the final DataFrame with proper column order
    if verified_results:
        df_results = pd.DataFrame(verified_results)
        return df_results
    else:
        return pd.DataFrame(verified_results)

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
        logger.warning("OAuth: Failed to retrieve user info")
        return "Failed to retrieve user info.", 403
    
    email = user_info.get('email', '').lower()
    
    # Check if email is from company domain
    if not is_company_email(email):
        logger.warning(f"OAuth: Access denied for {email} - not company domain")
        return f"Access denied. You must use a company email (@{ALLOWED_EMAIL_DOMAIN}). Your email: {email}", 403
    
    # Store user info in session
    session['user'] = {
        'email': email,
        'name': user_info.get('name', ''),
        'picture': user_info.get('picture', '')
    }
    session.permanent = True
    
    logger.info(f"OAuth: User logged in successfully - {email}")
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
    # In DEV_MODE, auto-login without OAuth
    if DEV_MODE and 'user' not in session:
        session['user'] = {
            'email': 'dev@localhost',
            'name': 'Dev User',
            'picture': ''
        }
        logger.info("DEV_MODE: Auto-login bypassing OAuth")
    
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    """Handles file uploads, processes them, and returns the result CSV."""
    user_email = session.get('user', {}).get('email', 'unknown')
    
    if 'apps_file' not in request.files or 'lines_file' not in request.files:
        logger.warning(f"[{user_email}] Upload failed: Missing files in request")
        return "Missing file(s) in the form submission.", 400

    apps_file = request.files['apps_file']
    lines_file = request.files['lines_file']

    if apps_file.filename == '' or lines_file.filename == '':
        logger.warning(f"[{user_email}] Upload failed: Empty filename")
        return "No selected file.", 400

    try:
        # Start timing the entire upload-to-download process
        upload_start_time = time.time()
        
        process = psutil.Process(os_module.getpid())
        upload_start_memory = process.memory_info().rss / 1024 / 1024  # MB
        logger.info(f"[{user_email}] Files uploaded: apps={apps_file.filename}, lines={lines_file.filename} | Memory: {upload_start_memory:.2f} MB")
        
        # Read file contents into memory
        apps_csv_content = apps_file.stream.read().decode("utf-8")
        lines_txt_content = lines_file.stream.read().decode("utf-8")
        print(f"DEBUG: CSV content length: {len(apps_csv_content)}", flush=True)

        # Load data using pandas and our custom function
        apps_df = pd.read_csv(io.StringIO(apps_csv_content))
        print(f"DEBUG: Loaded CSV, columns: {list(apps_df.columns)}, shape: {apps_df.shape}", flush=True)
        logger.info(f"[{user_email}] Files parsed: {len(apps_df)} apps, columns={list(apps_df.columns)}")
        lines_to_check = load_lines_from_memory(lines_txt_content)
        
        # Check if AppAdsURL column exists
        has_url_column = 'AppAdsURL' in apps_df.columns or any('app' in col.lower() and 'ads' in col.lower() for col in apps_df.columns)
        if not has_url_column:
            logger.info(f"[{user_email}] No AppAdsURL column found - will auto-discover URLs from app stores (slower)")
        else:
            urls_provided = apps_df['AppAdsURL'].notna().sum()
            logger.info(f"[{user_email}] AppAdsURL column found: {urls_provided}/{len(apps_df)} apps have URLs pre-filled")
        
        logger.info(f"[{user_email}] Files parsed: {len(apps_df)} apps, {len(lines_to_check)} search terms")

        # Run the async processing and get the results DataFrame
        start_time = time.time()
        process = psutil.Process(os_module.getpid())
        start_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        results_df = asyncio.run(process_files_async(apps_df, lines_to_check, user_email))
        
        elapsed_time = time.time() - start_time
        end_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        logger.info(f"[{user_email}] Processing completed in {elapsed_time:.2f}s")
        logger.info(f"[{user_email}] Upload endpoint memory: Start {start_memory:.2f} MB, End {end_memory:.2f} MB")
        
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
        
        # Count matches for logging (new structure uses 'verification_status' and 'has_all_lines')
        accessible_count = (results_df['verification_status'] == 'accessible').sum() if 'verification_status' in results_df.columns else 0
        all_lines_count = (results_df['has_all_lines'] == 'TRUE').sum() if 'has_all_lines' in results_df.columns else 0
        upload_end_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Calculate total time from upload to final response
        total_elapsed_time = time.time() - upload_start_time
        
        logger.info(f"[{user_email}] Results: {accessible_count}/{len(results_df)} apps had accessible app-ads.txt files")
        logger.info(f"[{user_email}] Results: {all_lines_count}/{len(results_df)} apps matched all search lines")
        logger.info(f"[{user_email}] Total processing time (upload to final): {total_elapsed_time:.2f}s")
        logger.info(f"[{user_email}] Sending file: {dynamic_filename} | Final memory: {upload_end_memory:.2f} MB")

        # Create response with download cookie
        response = make_response(send_file(
            mem_file,
            as_attachment=True,
            download_name=dynamic_filename,
            mimetype='text/csv'
        ))
        
        # Set cookie to signal download has started
        response.set_cookie('download_started', 'true', max_age=10)
        
        return response

    except Exception as e:
        logger.error(f"[{user_email}] Upload processing failed: {str(e)}", exc_info=True)
        return f"An error occurred: {e}", 500

if __name__ == '__main__':
    # Runs the Flask application on a port that avoids macOS AirPlay conflicts (use 8000 by default)
    port = int(os.environ.get('PORT', os.environ.get('FLASK_RUN_PORT', 8000)))
    app.run(host='127.0.0.1', port=port, debug=False)

