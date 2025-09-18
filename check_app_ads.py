import aiohttp
import asyncio
import pandas as pd
import re
import io
from datetime import datetime
from flask import Flask, render_template, request, send_file
import time
import requests
from bs4 import BeautifulSoup

# Initialize the Flask application
app = Flask(__name__)

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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(store_url, headers=headers)
        response.raise_for_status()
        
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
SEMAPHORE = asyncio.Semaphore(100)

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

async def fetch_and_check(session, bundle_id, url, lines_to_check, ordered_lines_to_check):
    """Fetches a URL and checks for matching lines using a set for speed."""
    async with SEMAPHORE:
        result = {"Bundle ID": bundle_id, "AppAdsURL": url}
        try:
            # If no URL is provided, try to get it from the store
            if not url or pd.isna(url) or not isinstance(url, str):
                url = get_app_ads_url(bundle_id)
                result["AppAdsURL"] = url if url else ""
                
            if url:  # Only proceed if we have a URL
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        downloaded_lines_set = {clean_line(line) for line in content.splitlines()}
                        result["TXT Found"] = "Yes"
                        matches = lines_to_check.intersection(downloaded_lines_set)
                        for check_line in ordered_lines_to_check:
                            result[f"{check_line}"] = check_line in matches
                        result["Error"] = "-"
                    else:
                        result["TXT Found"] = "No"
                        result["Error"] = f"HTTP {resp.status}"
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

    async with aiohttp.ClientSession() as session:
        tasks = []
        for _, row in apps_df.iterrows():
            bundle_id = row.get("Bundle ID")
            url = row.get("AppAdsURL")
            tasks.append(fetch_and_check(session, bundle_id, url, lines_to_check, ordered_lines_to_check))

        for future in asyncio.as_completed(tasks):
            res = await future
            results.append(res)
    
    # Create the final DataFrame and return it
    return pd.DataFrame(results, columns=column_headers)

# --- Flask Routes ---
# This section defines the web page and the file handling logic.

@app.route('/', methods=['GET'])
def index():
    """Renders the main upload page."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
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
    # Runs the Flask application
    app.run(debug=True)

