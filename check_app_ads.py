from flask import Flask, render_template, request, send_file
import pandas as pd
import aiohttp
import asyncio
import re
import io
from datetime import datetime

# Initialize the Flask application
app = Flask(__name__)

# --- Core Logic from your script ---
# This section contains the functions from your original Python script.

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
        except Exception as e:
            result["TXT Found"] = "No"
            result["Error"] = str(e)
        
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
            if pd.notna(row.get("AppAdsURL")) and isinstance(row.get("AppAdsURL"), str):
                tasks.append(fetch_and_check(session, row.get("Bundle ID"), row["AppAdsURL"], lines_to_check, ordered_lines_to_check))

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

