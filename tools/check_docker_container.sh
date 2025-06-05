#!/bin/bash

# Script to check if the AI Security Logger docker service is running and start it if needed
echo "Checking if AI Security Logger container is running..."

# Check if Docker is running
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in your PATH. Please install Docker first."
    exit 1
fi

# Check if the container is running
if [ -z "$(docker ps -q -f name=ai-security-logger)" ]; then
    echo "AI Security Logger container is not running. Starting it now..."
    cd "$(dirname "$0")/.."
    
    # Check if docker-compose is available
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        # Try with docker compose (newer syntax)
        docker compose up -d
    fi
    
    echo "Waiting for services to start up..."
    sleep 5
    
    # Check again if container is now running
    if [ -z "$(docker ps -q -f name=ai-security-logger)" ]; then
        echo "❌ Failed to start AI Security Logger container. Please check docker logs."
        exit 1
    fi
    
    echo "✅ AI Security Logger container started successfully."
else
    echo "✅ AI Security Logger container is already running."
fi

# Show mapped port information
MAPPED_PORT=$(docker port ai-security-logger 5356 | cut -d ':' -f 2)
if [ -n "$MAPPED_PORT" ]; then
    echo "Health check server is accessible at http://localhost:$MAPPED_PORT"
else
    echo "⚠️ Could not determine port mapping for health check server."
    echo "Using default port 5358."
    MAPPED_PORT=5358
fi

# Open browser to the dashboard if possible
if command -v xdg-open &> /dev/null; then
    echo "Opening dashboard in browser..."
    xdg-open "http://localhost:8359/index.html" &> /dev/null
fi

echo "✅ AI Security Logger is ready to use!"
