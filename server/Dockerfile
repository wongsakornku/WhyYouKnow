FROM python:3.12-slim

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# Install system dependencies if required (e.g. gcc for c extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . ./

# Cloud Run injects $PORT (default 8080)
EXPOSE 8080

# Run uvicorn on 0.0.0.0 and port $PORT
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}

