# Use official slim Python image (lighter & faster)
FROM python:3.12-slim

# Don't create .pyc files, send logs straight to console
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# 1) Install dependencies first (better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) Copy the entire project code
COPY . .

# 3) Expose port (Gunicorn will listen here)
EXPOSE 8000

# 4) Run with Gunicorn (better for production)
# -b 0.0.0.0:8000   → bind to all interfaces
# --workers 2        → 2 workers (adjust based on CPU)
# run:app            → module:Flask_app_object
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "run:app"]