#!/usr/bin/env python3
"""
Test the AI Security Logger by generating some sample logs
"""

import argparse
import logging
import os
import random
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Sample log patterns
SAMPLE_LOGS = [
    # Normal logs
    "[INFO] User logged in: user123",
    "[INFO] Application started successfully",
    "[INFO] Database connection established",
    "[INFO] Cache refreshed at {timestamp}",
    "[INFO] API request completed in 120ms",
    
    # Warning logs
    "[WARNING] High CPU usage detected: 85%",
    "[WARNING] Memory usage approaching threshold: 75%",
    "[WARNING] Slow database query detected (took 3.5s)",
    "[WARNING] Rate limit approaching for client 192.168.1.100",
    "[WARNING] API endpoint /api/v1/data deprecated, will be removed in next version",
    
    # Error logs
    "[ERROR] Database query failed: connection timeout",
    "[ERROR] Failed to process request: invalid parameters",
    "[ERROR] Out of memory error in background worker",
    "[ERROR] API service unavailable after 3 retry attempts",
    "[ERROR] Cache refresh failed: Redis connection error",
    
    # Security relevant logs
    "[WARN] Multiple failed login attempts for user admin from IP 203.0.113.42",
    "[ERROR] Authentication failed: Invalid credentials for admin account from IP 203.0.113.42",
    "[CRITICAL] Possible brute force attack detected from IP 203.0.113.42 (10 failed attempts)",
    "[WARN] Unusual access pattern detected: user123 accessing admin resources",
    "[CRITICAL] File permission change detected on /etc/passwd",
    "[ERROR] Firewall rule violation: outbound connection to known malicious IP 185.143.223.12",
    "[WARN] SSH login from unusual geographic location: admin from Country: Russia",
    "[CRITICAL] Database dump attempt detected from unauthorized process",
    "[ERROR] Unexpected privilege escalation detected for user: guest",
    "[WARN] Unusual file access pattern detected in /var/www/html",
]

def generate_log(log_file, num_logs=10, interval=1.0, include_security=True):
    """Generate sample logs to test the AI Security Logger"""
    logger.info(f"Generating {num_logs} sample logs to {log_file}")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    with open(log_file, 'a') as f:
        for i in range(num_logs):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Select log pattern
            if include_security and random.random() < 0.3:  # 30% chance for security logs
                log_pattern = random.choice(SAMPLE_LOGS[15:])  # Security logs
            else:
                log_pattern = random.choice(SAMPLE_LOGS[:15])  # Normal logs
            
            # Replace timestamp placeholder if present
            log_line = log_pattern.format(timestamp=timestamp)
            
            # Add timestamp prefix if not already present
            if not log_line.startswith('20'):
                log_line = f"{timestamp} {log_line}"
            
            # Write to file
            f.write(f"{log_line}\n")
            f.flush()
            
            logger.info(f"Generated log: {log_line}")
            
            # Sleep between logs
            if i < num_logs - 1:
                time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description='Generate sample logs for AI Security Logger testing')
    parser.add_argument('-f', '--file', default='data/logs/sample.log',
                        help='Log file to write to (default: data/logs/sample.log)')
    parser.add_argument('-n', '--num-logs', type=int, default=10,
                        help='Number of logs to generate (default: 10)')
    parser.add_argument('-i', '--interval', type=float, default=1.0,
                        help='Interval between logs in seconds (default: 1.0)')
    parser.add_argument('--no-security', action='store_true',
                        help='Do not include security-related logs')
    
    args = parser.parse_args()
    
    generate_log(
        log_file=args.file,
        num_logs=args.num_logs,
        interval=args.interval,
        include_security=not args.no_security
    )

if __name__ == "__main__":
    main()
