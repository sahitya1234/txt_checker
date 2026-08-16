import aiohttp
import asyncio
import pandas as pd
import re
import io
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
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
import csv
import json
import threading
import email_sender

# Load environment variables from .env file
load_dotenv()

# Configure logging for Cloud Run
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- URL normalization & metadata lookup helpers ---

# Path to the server-side prefetched bundle_id -> app-ads.txt URL metadata.
METADATA_CSV = os.environ.get('METADATA_CSV', 'metadata.csv')

# Local-file checkpoint of discovery outcomes (resolved URLs + failure tracking).
# Lets re-runs skip already-resolved / known-dead apps and retry only transient
# failures. NOTE: on Cloud Run the local disk is ephemeral; swap for GCS later.
CHECKPOINT_FILE = os.environ.get('CHECKPOINT_FILE', 'checkpoint.csv')
# After this many failed discovery attempts, stop retrying an app (mark dead).
MAX_DISCOVERY_ATTEMPTS = int(os.environ.get('MAX_DISCOVERY_ATTEMPTS', '5'))

# Collapse repeated '/app-ads.txt/app-ads.txt...' suffixes into a single one.
_DOUBLED_SUFFIX = re.compile(r'(/app-ads\.txt)(?:/app-ads\.txt)+', re.IGNORECASE)


def normalize_app_ads_url(url):
    """Trim whitespace and collapse doubled '/app-ads.txt' suffixes.
    Returns '' for blank/NaN values."""
    if url is None:
        return ''
    url = str(url).strip()
    if not url or url.lower() in ('nan', 'none'):
        return ''
    return _DOUBLED_SUFFIX.sub(r'\1', url)


def _find_column(columns, *, must_contain):
    """Return the first column whose lowercased name contains all the given
    substrings, else None."""
    for col in columns:
        lower = str(col).lower().strip()
        if all(tok in lower for tok in must_contain):
            return col
    return None


_METADATA_CACHE = None


def load_metadata_lookup():
    """Load (once, cached) the prefetched bundle_id -> app-ads.txt URL mapping
    from METADATA_CSV. Missing/unreadable file -> empty dict (lookup disabled)."""
    global _METADATA_CACHE
    if _METADATA_CACHE is not None:
        return _METADATA_CACHE

    lookup = {}
    try:
        if os.path.exists(METADATA_CSV):
            df = pd.read_csv(METADATA_CSV, dtype=str, on_bad_lines='skip')
            bundle_col = _find_column(df.columns, must_contain=('bundle', 'id'))
            url_col = _find_column(df.columns, must_contain=('app', 'ads'))
            if bundle_col and url_col:
                for _, row in df.iterrows():
                    bundle = str(row.get(bundle_col, '')).strip()
                    url = normalize_app_ads_url(row.get(url_col, ''))
                    if bundle and url and bundle not in lookup:
                        lookup[bundle] = url
            logger.info(f"Metadata lookup loaded: {len(lookup):,} bundle->URL entries from {METADATA_CSV}")
        else:
            logger.info(f"Metadata file '{METADATA_CSV}' not found; metadata lookup disabled")
    except Exception as e:
        logger.warning(f"Failed to load metadata lookup from {METADATA_CSV}: {e}")

    _METADATA_CACHE = lookup
    return lookup


# Discovery outcome classification
_RESOLVED = 'resolved'
_DEAD = 'dead'
_RETRYABLE = 'retryable'
# Failures that are permanent (app genuinely has no resolvable site) -> never retry.
_TERMINAL_REASONS = {'not_found', 'no_website_found'}


class CheckpointStore:
    """Local-file persistence of per-app discovery outcomes.

    Keyed by bundle_id, stored as CSV columns:
        bundle_id, status, app_ads_txt_url, attempts, reason, updated_at

    status is one of:
        'resolved'  -> we have a URL; future runs skip discovery
        'dead'      -> terminal failure (no site / attempts exhausted); skip forever
        'retryable' -> transient failure (rate limit / timeout); retry next run

    Writes are atomic (temp file + os.replace). Single-writer assumption holds
    for the current one-upload-at-a-time flow; the GCS version will add locking.
    """

    def __init__(self, path=CHECKPOINT_FILE):
        self.path = path
        self.entries = {}
        self._dirty = False

    def load(self):
        self.entries = {}
        try:
            if os.path.exists(self.path):
                with open(self.path, newline='', encoding='utf-8') as f:
                    for row in csv.DictReader(f):
                        bid = (row.get('bundle_id') or '').strip()
                        if not bid:
                            continue
                        self.entries[bid] = {
                            'status': row.get('status', ''),
                            'app_ads_txt_url': row.get('app_ads_txt_url', '') or '',
                            'attempts': int(row.get('attempts', '0') or 0),
                            'reason': row.get('reason', '') or '',
                        }
                logger.info(f"Checkpoint loaded: {len(self.entries):,} entries from {self.path}")
            else:
                logger.info(f"No checkpoint at {self.path}; starting fresh")
        except Exception as e:
            logger.warning(f"Failed to load checkpoint {self.path}: {e}")
            self.entries = {}
        return self

    def get(self, bundle_id):
        return self.entries.get(bundle_id)

    def _attempts(self, bundle_id):
        e = self.entries.get(bundle_id)
        return e['attempts'] if e else 0

    def record_success(self, bundle_id, url):
        self.entries[bundle_id] = {
            'status': _RESOLVED,
            'app_ads_txt_url': url,
            'attempts': self._attempts(bundle_id),
            'reason': 'success',
        }
        self._dirty = True

    def record_failure(self, bundle_id, reason):
        attempts = self._attempts(bundle_id) + 1
        # Terminal reason, or too many tries -> give up (dead); else keep retrying.
        if reason in _TERMINAL_REASONS or attempts >= MAX_DISCOVERY_ATTEMPTS:
            status = _DEAD
        else:
            status = _RETRYABLE
        self.entries[bundle_id] = {
            'status': status,
            'app_ads_txt_url': '',
            'attempts': attempts,
            'reason': reason,
        }
        self._dirty = True

    def save(self):
        if not self._dirty:
            return
        try:
            tmp = f"{self.path}.tmp"
            with open(tmp, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['bundle_id', 'status', 'app_ads_txt_url', 'attempts', 'reason', 'updated_at'])
                now = datetime.now().isoformat()
                for bid, e in self.entries.items():
                    writer.writerow([bid, e['status'], e['app_ads_txt_url'], e['attempts'], e.get('reason', ''), now])
            os.replace(tmp, self.path)
            self._dirty = False
            logger.info(f"Checkpoint saved: {len(self.entries):,} entries -> {self.path}")
        except Exception as e:
            logger.warning(f"Failed to save checkpoint {self.path}: {e}")


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
    
    def prepare_app_records(self, apps_df):
        """Build per-app records from the uploaded DataFrame, reading both the
        bundle ID and any prefilled app-ads.txt URL.

        Returns a list of dicts: {'bundle_id', 'platform', 'app_ads_txt_url'}
        where 'app_ads_txt_url' is the (normalized) URL from the upload, or ''
        if the upload didn't provide one. Platform is inferred from the bundle
        id (all-digits -> iOS, otherwise Android)."""
        try:
            bundle_column = _find_column(apps_df.columns, must_contain=('bundle', 'id'))
            if not bundle_column:
                logger.error("No bundle ID column found in DataFrame")
                return []
            url_column = _find_column(apps_df.columns, must_contain=('app', 'ads'))

            logger.info(f"Using bundle column: '{bundle_column}', URL column: '{url_column}'")

            records = []
            for _, row in apps_df.iterrows():
                bundle_id = str(row.get(bundle_column, '')).strip()
                if not bundle_id or bundle_id.lower() in ('', 'nan', 'none'):
                    continue
                upload_url = normalize_app_ads_url(row.get(url_column, '')) if url_column else ''
                platform = 'iOS' if bundle_id.isdigit() else 'android'
                records.append({
                    'bundle_id': bundle_id,
                    'platform': platform,
                    'app_ads_txt_url': upload_url,
                })

            n_ios = sum(1 for r in records if r['platform'] == 'iOS')
            logger.info(f"Prepared {len(records):,} app records | Android: {len(records) - n_ios:,} | iOS: {n_ios:,}")
            return records

        except Exception as e:
            logger.error(f"Error preparing app records: {e}")
            return []

    @staticmethod
    def normalize_domain_url(raw_value, default_filename='ads.txt'):
        """Turn a raw Domain or URL cell into a clean, fetchable URL.

        Preserves an explicitly-typed scheme (e.g. http://) instead of
        forcing https. If the value already has a path beyond the bare
        host (e.g. a full URL to a specific ads.txt/app-ads.txt location),
        it's used as-is; only a bare host gets the default filename appended.
        """
        if not raw_value or not isinstance(raw_value, str):
            return ''
        v = raw_value.strip()
        if not v or v.lower() in ('nan', 'none'):
            return ''
        if not re.match(r'^https?://', v, re.IGNORECASE):
            v = f'https://{v}'
        v = v.rstrip('/')
        without_scheme = re.sub(r'^https?://', '', v, flags=re.IGNORECASE)
        if '/' in without_scheme:
            return v
        return f'{v}/{default_filename}'

    def load_domains_from_df(self, domains_df):
        """Build ready-to-verify result dicts directly from a domain-checker DataFrame.

        No store scraping - rows already carry (or can trivially derive) their
        ads.txt URL, so they go straight to verification. The identifier column
        may be named either "Domain" or "Bundle ID" - the team isn't required
        to rename their existing sheets to use this tool.
        """
        try:
            results = []
            skipped = 0

            domain_column = _find_column(domains_df.columns, must_contain=('domain',)) \
                or _find_column(domains_df.columns, must_contain=('bundle', 'id'))
            if domain_column is None:
                logger.error("No Domain or Bundle ID column found in DataFrame")
                return []

            url_column = _find_column(domains_df.columns, must_contain=('app', 'ads'))
            if url_column is None:
                for col in domains_df.columns:
                    lower_col = col.lower().strip()
                    if 'url' in lower_col and 'domain' not in lower_col:
                        url_column = col
                        break

            logger.info(f"Using identifier column: '{domain_column}'" + (f", URL column: '{url_column}'" if url_column else ""))

            for _, row in domains_df.iterrows():
                domain = str(row.get(domain_column, '')).strip()
                if domain.lower() in ('nan', 'none'):
                    domain = ''

                raw_url = ''
                if url_column is not None:
                    raw_url = row.get(url_column, '')
                    raw_url = str(raw_url).strip() if pd.notna(raw_url) else ''
                    if raw_url.lower() == 'nan':
                        raw_url = ''

                if not domain and not raw_url:
                    skipped += 1
                    continue

                identifier = domain if domain else raw_url
                final_url = self.normalize_domain_url(raw_url) if raw_url else self.normalize_domain_url(domain)
                if not final_url:
                    skipped += 1
                    continue

                results.append({
                    'bundle_id': identifier,
                    'platform': 'domain',
                    'app_ads_txt_url': final_url,
                    'status': 'success'
                })

            logger.info(f"Loaded {len(results):,} domain rows for direct verification (skipped {skipped:,} empty rows)")
            return results

        except Exception as e:
            logger.error(f"Error loading domains: {e}")
            return []

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
    
    async def lookup_ios_batch(self, session, bundle_ids, max_retries=4):
        """Resolve a batch of iOS apps (up to ~150) to developer websites via the
        iTunes Lookup API. One HTTP request returns structured JSON for the whole
        batch, which is far more reliable and rate-limit friendly than scraping the
        App Store HTML one app at a time."""
        id_param = ','.join(bundle_ids)
        url = f"https://itunes.apple.com/lookup?id={id_param}&country=us"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json,text/javascript,*/*',
            'Accept-Encoding': 'gzip, deflate',
        }

        def build_results(status):
            """Fallback result list (one per bundle id) for a failed batch."""
            return [
                {'bundle_id': bid, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': status}
                for bid in bundle_ids
            ]

        for attempt in range(max_retries + 1):
            try:
                timeout = aiohttp.ClientTimeout(total=20)

                async with session.get(url, headers=headers, timeout=timeout) as response:
                    # 403/429 = rate limited by Apple. Be patient (the apps exist),
                    # back off exponentially with jitter, and keep retrying.
                    if response.status in (403, 429):
                        if attempt < max_retries:
                            await asyncio.sleep((2 ** attempt) + random.uniform(0, 1))
                            self.scraping_stats['ios_rate_limited'] += 1
                            continue
                        return build_results('rate_limited')

                    elif response.status == 200:
                        # iTunes serves JSON as text/javascript, so parse manually.
                        text = await response.text()
                        data = json.loads(text)

                        # Map App Store track IDs -> developer (seller) website.
                        found_ids = set()
                        seller_urls = {}
                        for item in data.get('results', []):
                            track_id = str(item.get('trackId', ''))
                            found_ids.add(track_id)
                            seller_urls[track_id] = (item.get('sellerUrl') or '').strip()

                        batch_results = []
                        for bid in bundle_ids:
                            if bid not in found_ids:
                                # Not returned by the API for this id.
                                batch_results.append({'bundle_id': bid, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'not_found'})
                            elif seller_urls[bid]:
                                developer_url = seller_urls[bid].rstrip('/')
                                app_ads_url = f"{developer_url}/app-ads.txt"
                                self.scraping_stats['ios_success'] += 1
                                batch_results.append({'bundle_id': bid, 'platform': 'iOS', 'app_ads_txt_url': app_ads_url, 'status': 'success'})
                            else:
                                # App found but no developer website listed.
                                batch_results.append({'bundle_id': bid, 'platform': 'iOS', 'app_ads_txt_url': '', 'status': 'no_website_found'})
                        return batch_results

                    else:
                        if attempt < max_retries:
                            await asyncio.sleep(1 * (attempt + 1))
                            continue
                        return build_results(f'http_error_{response.status}')

            except asyncio.TimeoutError:
                if attempt < max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                return build_results('timeout')

            except Exception as e:
                if attempt < max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
                    continue
                return build_results(f'error: {str(e)[:30]}')

        return build_results('unknown_error')

    async def extract_android_urls(self, android_bundles):
        """Extract developer URLs for Android apps.

        Uses a Semaphore to bound concurrency instead of fixed-size batches, so a
        slow/stalling app no longer blocks the others (no head-of-line blocking).
        The TCP connector still caps per-host connections."""
        if not android_bundles:
            return []

        total = len(android_bundles)
        logger.info(f"Processing {total} Android apps...")

        connector = aiohttp.TCPConnector(limit=100, limit_per_host=self.android_workers)
        semaphore = asyncio.Semaphore(self.android_workers)
        results = []

        async with aiohttp.ClientSession(connector=connector) as session:
            async def scrape_one(bundle_id):
                async with semaphore:
                    return await self.scrape_android_app(session, bundle_id)

            tasks = [asyncio.create_task(scrape_one(b)) for b in android_bundles]

            # Collect as each completes so fast apps aren't gated by slow ones.
            done = 0
            log_every = max(50, total // 20)  # ~20 progress lines max
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                    if isinstance(result, dict):
                        results.append(result)
                except Exception as e:
                    logger.error(f"Android scrape task failed: {e}")
                done += 1
                if done % log_every == 0 or done == total:
                    logger.info(f"Android progress: {done}/{total} processed")

        return results
    
    async def extract_ios_urls(self, ios_bundles):
        """Extract developer URLs for iOS apps via the batched iTunes Lookup API.

        Each request resolves up to 150 apps, so a handful of requests covers
        thousands of apps. Concurrency is kept low to stay under Apple's per-IP
        rate limit while still running batches in parallel."""
        if not ios_bundles:
            return []

        logger.info(f"Processing {len(ios_bundles)} iOS apps via iTunes Lookup API...")

        batch_size = 150
        batches = [ios_bundles[i:i + batch_size] for i in range(0, len(ios_bundles), batch_size)]
        logger.info(f"iOS: {len(batches)} lookup request(s) for {len(ios_bundles)} apps")

        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        semaphore = asyncio.Semaphore(5)
        results = []

        async with aiohttp.ClientSession(connector=connector) as session:
            async def run_batch(batch, batch_num):
                async with semaphore:
                    batch_results = await self.lookup_ios_batch(session, batch)
                    logger.info(f"iOS batch {batch_num}/{len(batches)}: {len(batch)} apps resolved")
                    return batch_results

            tasks = [run_batch(batch, i + 1) for i, batch in enumerate(batches)]
            completed = await asyncio.gather(*tasks, return_exceptions=True)

            for result in completed:
                if isinstance(result, list):
                    results.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"iOS batch failed: {result}")

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
        """Verify extracted URLs for ads.txt content.

        Many apps share the same publisher app-ads.txt URL, so we fetch+check
        each UNIQUE URL only once and fan the per-URL result back out to every
        app that uses it. This cuts network calls dramatically on large inputs."""
        # Only successful extractions with a URL get fetched
        urls_to_verify = [
            result for result in extracted_results
            if result.get('status') == 'success' and result.get('app_ads_txt_url')
        ]

        # Group apps by their (unique) URL
        url_to_apps = {}
        for item in urls_to_verify:
            url_to_apps.setdefault(item['app_ads_txt_url'], []).append(item)

        unique_urls = list(url_to_apps.keys())
        logger.info(f"Verifying {len(unique_urls):,} unique URLs "
                    f"covering {len(urls_to_verify):,} apps "
                    f"({len(urls_to_verify) - len(unique_urls):,} duplicate fetches avoided)")

        verified_results = []

        if unique_urls:
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=self.verification_workers,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            semaphore = asyncio.Semaphore(self.verification_workers)

            async with aiohttp.ClientSession(connector=connector) as session:
                async def check_url(url):
                    # bundle_id/platform are placeholders here; the line-match
                    # result depends only on the URL content, so we fan out after.
                    async with semaphore:
                        return url, await self.verify_ads_txt_detailed(
                            session, url, search_lines, bundle_id='', platform=''
                        )

                tasks = [check_url(url) for url in unique_urls]
                completed = await asyncio.gather(*tasks, return_exceptions=True)

                for outcome in completed:
                    if isinstance(outcome, Exception):
                        logger.error(f"Verification task failed: {outcome}")
                        continue
                    url, url_result = outcome

                    # Fan the per-URL result out to each app sharing this URL
                    for app in url_to_apps[url]:
                        result = dict(url_result)
                        result['bundle_id'] = app['bundle_id']
                        result['platform'] = app['platform']
                        result['app_ads_txt_url'] = url
                        verified_results.append(result)

                        # Update stats per app (preserves prior reporting semantics)
                        if result['verification_status'] == 'accessible':
                            self.verification_stats['accessible'] += 1
                            if result['has_all_lines'] == 'TRUE':
                                self.verification_stats['contains_all_lines'] += 1
                            else:
                                self.verification_stats['missing_some_lines'] += 1
                        else:
                            self.verification_stats['inaccessible'] += 1

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
        
        # Step 1: Build per-app records (bundle id + any prefilled URL)
        records = self.prepare_app_records(apps_df)

        self.scraping_stats['total_apps'] = len(records)
        self.scraping_stats['android_apps'] = sum(1 for r in records if r['platform'] == 'android')
        self.scraping_stats['ios_apps'] = sum(1 for r in records if r['platform'] == 'iOS')

        logger.info(f"[{user_email}] Total apps: {self.scraping_stats['total_apps']:,}")

        # Step 2: Resolve each app's URL via the hybrid strategy:
        #   1) URL prefilled in the upload, else
        #   2) server-side prefetched metadata lookup, else
        #   3) checkpoint of previously discovered URLs, else
        #      (known-dead in checkpoint -> skip discovery entirely), else
        #   4) discover by scraping the app store (Phase 1).
        metadata = load_metadata_lookup()
        checkpoint = CheckpointStore().load()

        resolved_results = []          # already have a URL -> skip discovery
        terminal_failures = []         # known-dead in checkpoint -> skip discovery
        bundles_to_discover = []       # records needing store scraping
        from_upload = from_metadata = from_checkpoint = skipped_dead = 0

        for rec in records:
            bid = rec['bundle_id']
            url = rec['app_ads_txt_url']
            if url:
                from_upload += 1
            elif bid in metadata:
                url = metadata[bid]
                from_metadata += 1
            else:
                cp = checkpoint.get(bid)
                if cp and cp['status'] == _RESOLVED and cp['app_ads_txt_url']:
                    url = cp['app_ads_txt_url']
                    from_checkpoint += 1
                elif cp and cp['status'] == _DEAD:
                    # Previously exhausted/terminal -> don't waste a request.
                    skipped_dead += 1
                    terminal_failures.append({
                        'bundle_id': bid,
                        'platform': rec['platform'],
                        'app_ads_txt_url': '',
                        'status': cp.get('reason') or 'dead',
                    })
                    continue
                # else: retryable failure or never seen -> fall through to discovery

            if url:
                resolved_results.append({
                    'bundle_id': bid,
                    'platform': rec['platform'],
                    'app_ads_txt_url': url,
                    'status': 'success',
                })
            else:
                bundles_to_discover.append(rec)

        logger.info(f"[{user_email}] URL resolution: {from_upload:,} upload, "
                    f"{from_metadata:,} metadata, {from_checkpoint:,} checkpoint, "
                    f"{skipped_dead:,} skipped (known-dead), {len(bundles_to_discover):,} need discovery")

        # Step 3: Discover URLs only for the leftover apps (Phase 1)
        logger.info(f"[{user_email}] Phase 1: Discovering Developer Website URLs (for {len(bundles_to_discover):,} apps)")
        logger.info(f"[{user_email}] ----------------------------------------")

        android_bundles = [r['bundle_id'] for r in bundles_to_discover if r['platform'] == 'android']
        ios_bundles = [r['bundle_id'] for r in bundles_to_discover if r['platform'] == 'iOS']
        n_android_discover = len(android_bundles)
        n_ios_discover = len(ios_bundles)

        android_task = asyncio.create_task(self.extract_android_urls(android_bundles))
        ios_task = asyncio.create_task(self.extract_ios_urls(ios_bundles))

        android_results, ios_results = await asyncio.gather(android_task, ios_task)
        discovery_results = android_results + ios_results

        # Record discovery outcomes to the checkpoint so future runs skip
        # resolved/dead apps and retry only transient failures.
        for r in discovery_results:
            if r['status'] == 'success' and r.get('app_ads_txt_url'):
                checkpoint.record_success(r['bundle_id'], r['app_ads_txt_url'])
            else:
                checkpoint.record_failure(r['bundle_id'], r['status'])
        checkpoint.save()

        all_extraction_results = resolved_results + terminal_failures + discovery_results

        # Step 3: Verify ads.txt files
        logger.info(f"[{user_email}] Phase 2: Verifying App-Ads.txt Files")
        logger.info(f"[{user_email}] ----------------------------------------")
        self.verification_stats['total_urls'] = len([r for r in all_extraction_results if r.get('status') == 'success'])
        verified_results = await self.verify_extracted_urls(all_extraction_results, search_lines)
        
        # Step 4: Log final statistics
        elapsed_time = time.time() - start_time
        resolved_without_discovery = from_upload + from_metadata
        logger.info(f"[{user_email}] Processing complete!")
        logger.info(f"[{user_email}] Total time: {elapsed_time:.2f}s")
        logger.info(f"[{user_email}] URLs resolved without discovery: {resolved_without_discovery:,}/{len(records):,} "
                    f"({from_upload:,} upload, {from_metadata:,} metadata)")
        logger.info(f"[{user_email}] Discovery (scraped): Android {self.scraping_stats['android_success']}/{n_android_discover}, "
                    f"iOS {self.scraping_stats['ios_success']}/{n_ios_discover}")
        logger.info(f"[{user_email}] URLs verified accessible: {self.verification_stats['accessible']}/{self.verification_stats['total_urls']}")
        
        return verified_results

    async def run_domain_analysis(self, domains_df, search_lines, user_email="unknown"):
        """Run analysis directly against a Domain/Bundle ID column - no store discovery/scraping."""
        start_time = time.time()

        logger.info(f"[{user_email}] Starting Domain Ads.txt Analysis")
        logger.info(f"[{user_email}] ========================================")

        prefilled_results = self.load_domains_from_df(domains_df)
        self.verification_stats['total_urls'] = len(prefilled_results)

        verified_results = await self.verify_extracted_urls(prefilled_results, search_lines)

        elapsed_time = time.time() - start_time
        logger.info(f"[{user_email}] Domain analysis complete in {elapsed_time:.2f}s")
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


class AppsCsvError(ValueError):
    """Raised when an uploaded apps CSV can't be used (e.g. no bundle column)."""


def load_apps_df_from_content(csv_content):
    """Parse an uploaded apps CSV robustly so a malformed file never crashes the
    request. Skips unparseable rows, validates the bundle column exists, and
    normalizes the app-ads.txt URL column (whitespace + doubled suffix).

    Raises AppsCsvError with a user-friendly message on unrecoverable input."""
    try:
        df = pd.read_csv(io.StringIO(csv_content), dtype=str, on_bad_lines='skip')
    except Exception as e:
        raise AppsCsvError(f"Could not parse the apps CSV: {e}")

    if df.empty:
        raise AppsCsvError("The apps CSV is empty.")

    bundle_col = _find_column(df.columns, must_contain=('bundle', 'id'))
    if not bundle_col:
        raise AppsCsvError(
            f"No 'Bundle ID' column found. Columns seen: {list(df.columns)}"
        )

    # Drop rows with no bundle id
    df[bundle_col] = df[bundle_col].astype(str).str.strip()
    df = df[~df[bundle_col].str.lower().isin(['', 'nan', 'none'])]

    # Normalize the URL column if present
    url_col = _find_column(df.columns, must_contain=('app', 'ads'))
    if url_col:
        df[url_col] = df[url_col].map(normalize_app_ads_url)

    # Drop exact duplicate rows
    df = df.drop_duplicates().reset_index(drop=True)

    return df

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


class DomainsCsvError(ValueError):
    """Raised when an uploaded domains CSV can't be used (e.g. no identifier column)."""


def load_domains_df_from_content(csv_content):
    """Parse an uploaded domains CSV robustly so a malformed file never crashes
    the request. Validates that an identifier column (Domain or Bundle ID)
    exists. Row-level blank handling is left to load_domains_from_df, since a
    row with a blank identifier but a filled-in URL is still valid there.

    Raises DomainsCsvError with a user-friendly message on unrecoverable input."""
    try:
        df = pd.read_csv(io.StringIO(csv_content), dtype=str, on_bad_lines='skip')
    except Exception as e:
        raise DomainsCsvError(f"Could not parse the domains CSV: {e}")

    if df.empty:
        raise DomainsCsvError("The domains CSV is empty.")

    identifier_col = _find_column(df.columns, must_contain=('domain',)) \
        or _find_column(df.columns, must_contain=('bundle', 'id'))
    if not identifier_col:
        raise DomainsCsvError(
            f"No 'Domain' or 'Bundle ID' column found. Columns seen: {list(df.columns)}"
        )

    # Drop exact duplicate rows
    df = df.drop_duplicates().reset_index(drop=True)

    return df


async def process_domain_files_async(domains_df, lines_to_check, user_email="unknown"):
    """
    Process a Domain-column file directly, with no store discovery/scraping.

    Args:
        domains_df: DataFrame with a Domain or Bundle ID column (and optional URL column)
        lines_to_check: List of lines to search for in ads.txt files
        user_email: Email of user for logging

    Returns:
        DataFrame with verification results
    """
    analyzer = CompleteAdsTxtAnalyzer(verification_workers=30)

    verified_results = await analyzer.run_domain_analysis(domains_df, lines_to_check, user_email)

    if verified_results:
        return pd.DataFrame(verified_results)
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

def _run_job_and_email(apps_df, lines_to_check, user_email):
    """Background worker: process the upload, build the result CSV, and email it.

    Runs off the request thread so the user is never blocked and a disconnect /
    refresh / request timeout doesn't lose the result. On any failure, emails the
    user so a job is never a silent black hole."""
    job_start = time.time()
    try:
        logger.info(f"[{user_email}] Background job started: {len(apps_df)} apps, {len(lines_to_check)} search terms")

        results_df = asyncio.run(process_files_async(apps_df, lines_to_check, user_email))

        # Serialize results to CSV bytes in memory
        buf = io.StringIO()
        results_df.to_csv(buf, index=False)
        csv_bytes = buf.getvalue().encode('utf-8')

        # Summary counts for the email body
        total = len(results_df)
        accessible = int((results_df['verification_status'] == 'accessible').sum()) if 'verification_status' in results_df.columns else 0
        matched_all = int((results_df['has_all_lines'] == 'TRUE').sum()) if 'has_all_lines' in results_df.columns else 0
        counts = {'total': total, 'accessible': accessible, 'matched_all': matched_all}

        base_name = f"results_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"
        elapsed = time.time() - job_start
        logger.info(f"[{user_email}] Background job done in {elapsed:.2f}s: "
                    f"{total} apps, {accessible} accessible, {matched_all} matched all. "
                    f"Emailing result ({len(csv_bytes):,} bytes)...")

        if email_sender.send_result_email(user_email, csv_bytes, base_name, counts=counts):
            logger.info(f"[{user_email}] Result email sent.")
        else:
            logger.error(f"[{user_email}] Result email FAILED to send.")

    except Exception as e:
        logger.error(f"[{user_email}] Background job failed: {e}", exc_info=True)
        try:
            email_sender.send_failure_email(user_email, str(e))
        except Exception as ee:
            logger.error(f"[{user_email}] Failure email also failed: {ee}")


@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    """Accepts the two uploaded files, validates + parses them, then processes
    in a background thread and emails the result. Returns 202 immediately so the
    user isn't blocked and a closed/refreshed tab doesn't lose the result."""
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
        logger.info(f"[{user_email}] Files uploaded: apps={apps_file.filename}, lines={lines_file.filename}")

        # Read file contents into memory
        apps_csv_content = apps_file.stream.read().decode("utf-8")
        lines_txt_content = lines_file.stream.read().decode("utf-8")

        # Robustly parse the apps CSV (skips bad rows, normalizes URLs).
        # Raises AppsCsvError -> 400 for unrecoverable input.
        try:
            apps_df = load_apps_df_from_content(apps_csv_content)
        except AppsCsvError as ce:
            logger.warning(f"[{user_email}] Invalid apps CSV: {ce}")
            return f"Invalid apps CSV: {ce}", 400

        lines_to_check = load_lines_from_memory(lines_txt_content)
        if not lines_to_check:
            return "The 'lines to check' file is empty.", 400

        url_col = _find_column(apps_df.columns, must_contain=('app', 'ads'))
        if url_col:
            urls_provided = (apps_df[url_col].astype(str).str.strip() != '').sum()
            logger.info(f"[{user_email}] AppAdsURL column: {urls_provided}/{len(apps_df)} pre-filled")
        logger.info(f"[{user_email}] Accepted upload: {len(apps_df)} apps, {len(lines_to_check)} search terms")

        # Hand off to a background thread and respond immediately.
        threading.Thread(
            target=_run_job_and_email,
            args=(apps_df, lines_to_check, user_email),
            daemon=True,
        ).start()

        msg = (f"Your file was accepted and is being processed. "
               f"Results will be emailed to {user_email} when ready — you can close this page.")
        return msg, 202

    except Exception as e:
        logger.error(f"[{user_email}] Upload acceptance failed: {str(e)}", exc_info=True)
        return f"An error occurred: {e}", 500


def _run_domain_job_and_email(domains_df, lines_to_check, user_email):
    """Background worker: process a domain-check upload, build the result CSV, and email it.

    No store discovery/scraping involved, so this typically finishes much
    faster than the Bundle ID flow's _run_job_and_email."""
    job_start = time.time()
    try:
        logger.info(f"[{user_email}] Background domain job started: {len(domains_df)} rows, {len(lines_to_check)} search terms")

        results_df = asyncio.run(process_domain_files_async(domains_df, lines_to_check, user_email))

        buf = io.StringIO()
        results_df.to_csv(buf, index=False)
        csv_bytes = buf.getvalue().encode('utf-8')

        total = len(results_df)
        accessible = int((results_df['verification_status'] == 'accessible').sum()) if 'verification_status' in results_df.columns else 0
        matched_all = int((results_df['has_all_lines'] == 'TRUE').sum()) if 'has_all_lines' in results_df.columns else 0
        counts = {'total': total, 'accessible': accessible, 'matched_all': matched_all}

        base_name = f"domain_results_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"
        elapsed = time.time() - job_start
        logger.info(f"[{user_email}] Background domain job done in {elapsed:.2f}s: "
                    f"{total} rows, {accessible} accessible, {matched_all} matched all. "
                    f"Emailing result ({len(csv_bytes):,} bytes)...")

        if email_sender.send_result_email(user_email, csv_bytes, base_name, counts=counts):
            logger.info(f"[{user_email}] Result email sent.")
        else:
            logger.error(f"[{user_email}] Result email FAILED to send.")

    except Exception as e:
        logger.error(f"[{user_email}] Background domain job failed: {e}", exc_info=True)
        try:
            email_sender.send_failure_email(user_email, str(e))
        except Exception as ee:
            logger.error(f"[{user_email}] Failure email also failed: {ee}")


@app.route('/upload_domains', methods=['POST'])
@login_required
def upload_domains():
    """Accepts a Domain/Bundle ID CSV, checks ads.txt directly (no store
    discovery), then processes in a background thread and emails the result."""
    user_email = session.get('user', {}).get('email', 'unknown')

    if 'domains_file' not in request.files or 'lines_file' not in request.files:
        logger.warning(f"[{user_email}] Domain upload failed: Missing files in request")
        return "Missing file(s) in the form submission.", 400

    domains_file = request.files['domains_file']
    lines_file = request.files['lines_file']

    if domains_file.filename == '' or lines_file.filename == '':
        logger.warning(f"[{user_email}] Domain upload failed: Empty filename")
        return "No selected file.", 400

    try:
        logger.info(f"[{user_email}] Files uploaded: domains={domains_file.filename}, lines={lines_file.filename}")

        domains_csv_content = domains_file.stream.read().decode("utf-8")
        lines_txt_content = lines_file.stream.read().decode("utf-8")

        try:
            domains_df = load_domains_df_from_content(domains_csv_content)
        except DomainsCsvError as ce:
            logger.warning(f"[{user_email}] Invalid domains CSV: {ce}")
            return f"Invalid domains CSV: {ce}", 400

        lines_to_check = load_lines_from_memory(lines_txt_content)
        if not lines_to_check:
            return "The 'lines to check' file is empty.", 400

        logger.info(f"[{user_email}] Accepted domain upload: {len(domains_df)} rows, {len(lines_to_check)} search terms")

        threading.Thread(
            target=_run_domain_job_and_email,
            args=(domains_df, lines_to_check, user_email),
            daemon=True,
        ).start()

        msg = (f"Your file was accepted and is being processed. "
               f"Results will be emailed to {user_email} when ready — you can close this page.")
        return msg, 202

    except Exception as e:
        logger.error(f"[{user_email}] Domain upload acceptance failed: {str(e)}", exc_info=True)
        return f"An error occurred: {e}", 500

if __name__ == '__main__':
    # Runs the Flask application on a port that avoids macOS AirPlay conflicts (use 8000 by default)
    port = int(os.environ.get('PORT', os.environ.get('FLASK_RUN_PORT', 8000)))
    app.run(host='127.0.0.1', port=port, debug=False)

