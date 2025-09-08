# App-ads.txt Bulk Line Checker

A Flask web application that checks for the presence of specific lines in app-ads.txt files for a list of apps. Upload your CSV file with Bundle IDs and app-ads.txt URLs, along with a text file containing the lines to check, and get a comprehensive CSV report.

## Features
- 🌐 **Web Interface**: Easy-to-use web interface for file uploads
- ⚡ **Async Processing**: Fast concurrent checking of multiple URLs
- 📊 **Bulk Analysis**: Check any number of app-ads.txt URLs at once
- 📁 **Flexible Input**: Upload custom lines to check via text file
- 📈 **Detailed Reports**: CSV output with match results for each line
- 🎨 **Modern UI**: Clean, responsive interface using Tailwind CSS

## Project Structure
```
text_scrapper_JT/
├── check_app_ads.py          # Main Flask application
├── requirements.txt          # Python dependencies
├── templates/                # HTML templates
│   └── index.html           # Main page template
└── static/                  # Static files (CSS, JS)
    └── style.css            # Custom styles
```

## Requirements
- Python 3.7+
- Flask
- pandas
- aiohttp

Install dependencies:
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

### 3. Upload Files
- **Apps CSV**: Upload a CSV file with Bundle IDs and AppAdsURL columns
- **Lines to Check**: Upload a text file containing the lines you want to check for

### 4. Download Results
The application will process your files and automatically download a timestamped CSV report.

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
| Bundle ID        | AppAdsURL                        | TXT Found | google.com, pub-9911740406682987... | rubiconproject.com, 27854... | Error |
|------------------|----------------------------------|-----------|-------------------------------------|-------------------------------|-------|
| com.example.app  | https://example.com/app-ads.txt  | Yes       | True                               | False                          | -     |

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