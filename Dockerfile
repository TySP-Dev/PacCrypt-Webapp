# Base image
FROM python:3.11-slim

# Environment vars
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PRODUCTION=true

# Working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency file
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire app
COPY . .

# Ensure uploads folder exists
RUN mkdir -p uploads

# Expose the port Flask uses
EXPOSE 5000

# Start the app
CMD ["python", "app.py"]
