#!/bin/bash

# Script to test the health check server's generate_logs endpoint directly
echo "Testing generate_logs endpoint directly..."

# Get the mapped port from Docker
MAPPED_PORT=$(docker port ai-security-logger 5356 | cut -d ':' -f 2 || echo "5358")
echo "Using port $MAPPED_PORT to connect to health check server"

# Make a direct call to the health check server
curl -X POST \
  http://localhost:$MAPPED_PORT/generate_logs \
  -H "Content-Type: application/json" \
  -d '{
    "num_logs": 5,
    "interval": 0.1,
    "include_security": true,
    "app_type": "generic"
  }'

echo -e "\n\nWaiting for logs to be generated..."
sleep 3

# Check if the log file was created (inside the container)
echo "Checking for log files inside the container:"
docker exec ai-security-logger ls -la /app/data/logs/

echo -e "\nLog file contents (if available):"
docker exec ai-security-logger cat /app/data/logs/generic_sample.log 2>/dev/null || \
  echo "Log file not found in expected location"
