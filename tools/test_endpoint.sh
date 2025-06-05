#!/bin/bash

# Script to test the health check server's generate_logs endpoint directly
echo "Testing generate_logs endpoint directly..."

# Make a direct call to the health check server
curl -X POST \
  http://localhost:5356/generate_logs \
  -H "Content-Type: application/json" \
  -d '{
    "num_logs": 5,
    "interval": 0.1,
    "include_security": true,
    "app_type": "generic"
  }'

echo -e "\n\nWaiting for logs to be generated..."
sleep 2

# Check if the log file was created
echo "Checking for log files in ../data/logs/"
ls -la ../data/logs/
