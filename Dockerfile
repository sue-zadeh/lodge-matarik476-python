# Use official Python 3.12 slim image (lightweight, fast)
FROM python:3.12-slim

# Prevent Python from writing .pyc files & buffer logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install dependencies first (better Docker caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project (including connect.py at root)
COPY . .

# Expose the port Gunicorn will use (8000 is standard for Railway)
EXPOSE 8000

# Run Gunicorn – bind to 0.0.0.0:8000
# run:app → run.py has the 'app' Flask object
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "run:app"]