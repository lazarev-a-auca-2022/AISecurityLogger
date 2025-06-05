#!/bin/bash

# This script starts both the main application and the health check server
echo "Starting AI Security Logger with Health Check Server..."

# Navigate to the project root directory
cd "$(dirname "$0")/.."

# Make sure the logs directory exists
mkdir -p data/logs

# Start the health check server in the background
echo "Starting Health Check Server..."
python3 src/health_check.py &
HEALTH_PID=$!

# Give the health check server a moment to start
sleep 1

# Start the main application
echo "Starting Main Application..."
python3 src/main.py

# When the main application exits, also terminate the health check server
kill $HEALTH_PID

exit 0
