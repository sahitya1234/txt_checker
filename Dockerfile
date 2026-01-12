FROM python:3.9-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set environment variables
ENV FLASK_APP=check_app_ads.py
ENV PORT=8080

# Expose port
EXPOSE 8080

# Run with gunicorn
CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 --timeout 600 check_app_ads:app
