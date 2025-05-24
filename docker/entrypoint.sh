#!/bin/bash
# Docker entrypoint script

set -e

# Check for required environment variables
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "Error: OPENROUTER_API_KEY environment variable is not set."
    echo "Please set the OPENROUTER_API_KEY in the .env file or pass it as an environment variable."
    exit 1
fi

# Create necessary directories
mkdir -p /app/data/db /app/data/logs /app/reports

# Wait for Redis to be ready
echo "Waiting for Redis..."
while ! ping -c 1 redis &>/dev/null; do
    echo "Redis not available yet - sleeping"
    sleep 1
done
echo "Redis is ready!"

# Run the application
echo "Starting AI Security Logger..."
python -u src/main.py
