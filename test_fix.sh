#!/bin/bash

# Test script for AISecurityLogger
echo "Starting test script for AISecurityLogger"

# Create test directory if it doesn't exist
mkdir -p test_logs

# Clean up any old logs
echo "Cleaning up old test logs..."
rm -f test_logs/*.log
rm -f test_logs/*.log.old

# Create some test log files
echo "Creating test log files..."
cat > test_logs/test1.log << EOF
May 25 12:30:45 testserver sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 49812 ssh2
May 25 12:31:12 testserver sshd[12346]: Failed password for invalid user admin from 192.168.1.100 port 49813 ssh2
May 25 12:31:45 testserver sshd[12347]: Failed password for invalid user admin from 192.168.1.100 port 49814 ssh2
May 25 12:32:13 testserver sshd[12348]: Failed password for invalid user admin from 192.168.1.100 port 49815 ssh2
May 25 12:32:47 testserver sshd[12349]: Failed password for invalid user admin from 192.168.1.100 port 49816 ssh2
EOF

cat > test_logs/test2.log << EOF
May 25 13:15:22 testserver kernel: [12345.678901] Firewall: BLOCKED INPUT IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.200 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=45678 DF PROTO=TCP SPT=12345 DPT=22 WINDOW=5840 RES=0x00 SYN URGP=0
May 25 13:16:45 testserver kernel: [12346.789012] Firewall: BLOCKED INPUT IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.200 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=45679 DF PROTO=TCP SPT=12346 DPT=3306 WINDOW=5840 RES=0x00 SYN URGP=0
EOF

# Update the settings to include our test logs directory
echo "Updating settings to include test logs directory..."

# Run the application with the test logs
echo "Running AISecurityLogger with test logs..."
cd "$(dirname "$0")"
export TEST_LOGS_DIR="$(pwd)/test_logs"
echo "Test logs directory: $TEST_LOGS_DIR"

# Add test logs directory to the settings if needed
python -c "
import json
import os

config_file = 'config/settings.json'
if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    test_logs_dir = os.environ.get('TEST_LOGS_DIR')
    if test_logs_dir and test_logs_dir not in config.get('log_sources', []):
        config['log_sources'] = config.get('log_sources', []) + [test_logs_dir]
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    print(f'Updated {config_file} with test logs directory: {test_logs_dir}')
else:
    print(f'Config file {config_file} not found')
"

# Run the application
echo "Starting the application..."
python src/main.py

echo "Test complete!"
