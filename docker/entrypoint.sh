#!/bin/bash
# Docker entrypoint script

set -e

# Determine which API provider is being used
AI_PROVIDER=${AI_PROVIDER:-openrouter}

# Check for required environment variables based on the provider
if [ "$AI_PROVIDER" = "openrouter" ] && [ -z "$OPENROUTER_API_KEY" ]; then
    echo "Error: OPENROUTER_API_KEY environment variable is not set."
    echo "Please set the OPENROUTER_API_KEY in the .env file or pass it as an environment variable."
    exit 1
elif [ "$AI_PROVIDER" = "openai" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo "Error: OPENAI_API_KEY environment variable is not set."
    echo "Please set the OPENAI_API_KEY in the .env file or pass it as an environment variable."
    exit 1
elif [ "$AI_PROVIDER" = "google" ] && [ -z "$GOOGLE_API_KEY" ]; then
    echo "Error: GOOGLE_API_KEY environment variable is not set."
    echo "Please set the GOOGLE_API_KEY in the .env file or pass it as an environment variable."
    exit 1
elif [ "$AI_PROVIDER" = "azure" ] && [ -z "$AZURE_API_KEY" ]; then
    echo "Error: AZURE_API_KEY environment variable is not set."
    echo "Please set the AZURE_API_KEY in the .env file or pass it as an environment variable."
    exit 1
elif [ "$AI_PROVIDER" = "anthropic" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "Error: ANTHROPIC_API_KEY environment variable is not set."
    echo "Please set the ANTHROPIC_API_KEY in the .env file or pass it as an environment variable."
    exit 1
elif [ "$AI_PROVIDER" = "custom" ] && [ -z "$CUSTOM_API_KEY" ]; then
    echo "Error: CUSTOM_API_KEY environment variable is not set."
    echo "Please set the CUSTOM_API_KEY in the .env file or pass it as an environment variable."
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
