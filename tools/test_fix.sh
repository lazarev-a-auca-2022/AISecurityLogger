#!/bin/bash

# Test fix for AISecurityLogger reporting with empty logs
echo "Starting test script for AISecurityLogger empty logs fix"

# Define paths
DATA_DIR="/home/main/AISecurityLogger/data"
LOGS_DIR="$DATA_DIR/logs"
REPORTS_DIR="/home/main/AISecurityLogger/reports"

# Stop any running instances of the program
echo "Stopping any running instances..."
pkill -f "python3 .*/src/main.py" || true

# Clean up any old logs
echo "Cleaning up old test logs..."
mkdir -p "$LOGS_DIR"
rm -f "$LOGS_DIR"/*.log
rm -f "$LOGS_DIR"/*.log.old

# Backup existing reports before testing
echo "Backing up existing reports..."
BACKUP_DIR="$REPORTS_DIR/backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp "$REPORTS_DIR"/*.html "$BACKUP_DIR"/ 2>/dev/null || true
cp "$REPORTS_DIR"/reports.json "$BACKUP_DIR"/ 2>/dev/null || true
echo "Reports backed up to $BACKUP_DIR"

# Create some test log files
# Run the test script for empty logs behavior
echo "Running test script for empty logs behavior..."
python3 /home/main/AISecurityLogger/tools/test_empty_logs.py

# Pause to review results
echo "Test script completed. Press Enter to continue and run the main program..."
read

# Create a sample log file to test the fix
echo "Creating a sample log file..."
cat > "$LOGS_DIR/sample.log" << EOF
[2025-05-25 15:30:45] ERROR: Multiple failed login attempts for user admin from IP 203.0.113.42
[2025-05-25 15:31:12] WARNING: High CPU usage detected: 85%
[2025-05-25 15:31:45] CRITICAL: Database dump attempt detected from unauthorized process
[2025-05-25 15:32:13] ERROR: Out of memory error in background worker
[2025-05-25 15:32:47] WARNING: Rate limit approaching for client 192.168.1.100
EOF

echo "Sample log file created at $LOGS_DIR/sample.log"

# Start the main program to observe its behavior
echo "Starting the main program..."
cd /home/main/AISecurityLogger
python3 src/main.py
        config['log_sources'] = config.get('log_sources', []) + [test_logs_dir]
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    print(f'Updated {config_file} with test logs directory: {test_logs_dir}')
else:
    print(f'Config file {config_file} not found')
"

# Run the application
echo "Starting the application..."
python3 src/main.py

echo "Test complete!"
