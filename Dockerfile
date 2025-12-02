# Dockerfile
FROM python:3.12-slim

# Don't create .pyc files, send logs straight to console
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 1) Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) Copy the project code
COPY . .

# 3) Tell Docker which port the app will listen on
EXPOSE 8000

# 4) Start the app (gunicorn is nicer than "flask run" for demos)
CMD ["gunicorn", "-b", "0.0.0.0:8000", "run:app"]
