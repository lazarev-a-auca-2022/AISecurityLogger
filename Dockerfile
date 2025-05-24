FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY tools/ ./tools/
COPY docker/entrypoint.sh ./entrypoint.sh

# Create directories for data and reports
RUN mkdir -p /app/data/db /app/data/logs /app/reports && \
    chmod +x /app/entrypoint.sh /app/tools/generate_test_logs.py

# Install netcat for health checks
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port for potential web interface
EXPOSE 8080

# Default entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
