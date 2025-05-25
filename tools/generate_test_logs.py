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

# Sample log patterns for various applications
APP_LOG_PATTERNS = {
    "generic": {
        "normal": [
            "User logged in: user123",
            "Application started successfully",
            "Database connection established",
            "Cache refreshed at {timestamp}",
            "API request completed in 120ms",
        ],
        "warning": [
            "High CPU usage detected: 85%",
            "Memory usage approaching threshold: 75%",
            "Slow database query detected (took 3.5s)",
            "Rate limit approaching for client 192.168.1.100",
            "API endpoint /api/v1/data deprecated, will be removed in next version",
        ],
        "error": [
            "Database query failed: connection timeout",
            "Failed to process request: invalid parameters",
            "Out of memory error in background worker",
            "API service unavailable after 3 retry attempts",
            "Cache refresh failed: Redis connection error",
        ],
        "security": [
            "Multiple failed login attempts for user admin from IP 203.0.113.42",
            "Authentication failed: Invalid credentials for admin account from IP 203.0.113.42",
            "Possible brute force attack detected from IP 203.0.113.42 (10 failed attempts)",
            "Unusual access pattern detected: user123 accessing admin resources",
            "File permission change detected on /etc/passwd",
            "Firewall rule violation: outbound connection to known malicious IP 185.143.223.12",
            "SSH login from unusual geographic location: admin from Country: Russia",
            "Database dump attempt detected from unauthorized process",
            "Unexpected privilege escalation detected for user: guest",
            "Unusual file access pattern detected in /var/www/html",
        ]
    },
    "apache": {
        "normal": [
            '192.168.1.1 - - [{timestamp}] "GET /index.html HTTP/1.1" 200 1234',
            '10.0.0.5 - - [{timestamp}] "POST /submit-form HTTP/1.1" 200 56',
            '172.16.0.10 - - [{timestamp}] "GET /images/logo.png HTTP/1.1" 200 7890',
        ],
        "warning": [
            '192.168.1.10 - - [{timestamp}] "GET /admin HTTP/1.1" 401 234 - Authorization required',
            '10.0.0.15 - - [{timestamp}] "GET /old-api HTTP/1.1" 301 0 - Deprecated API access',
        ],
        "error": [
            '192.168.1.20 - - [{timestamp}] "GET /nonexistent HTTP/1.1" 404 199 - File not found',
            '10.0.0.25 - - [{timestamp}] "POST /upload HTTP/1.1" 500 0 - Internal Server Error',
            '172.16.0.30 - - [{timestamp}] "GET /bad-request HTTP/1.1" 400 150 - Malformed request',
        ],
        "security": [
            '203.0.113.1 - - [{timestamp}] "GET /etc/passwd HTTP/1.1" 403 200 - Forbidden access attempt',
            '203.0.113.2 - - [{timestamp}] "GET /wp-admin/setup.php HTTP/1.1" 404 199 - WordPress setup attempt',
            '203.0.113.3 - - [{timestamp}] "POST /phpmyadmin/index.php HTTP/1.1" 200 1234 - phpMyAdmin access',
            '203.0.113.4 - - [{timestamp}] "GET /shell.php HTTP/1.1" 404 199 - Web shell attempt',
        ]
    },
    "nginx": {
        "normal": [
            '192.168.1.1 - [{timestamp}] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
            '10.0.0.5 - [{timestamp}] "POST /api/data HTTP/1.1" 201 56 "-" "curl/7.64.1"',
            '172.16.0.10 - [{timestamp}] "GET /assets/style.css HTTP/1.1" 200 7890 "-" "Mozilla/5.0"',
        ],
        "warning": [
            '192.168.1.10 - [{timestamp}] "GET /old-endpoint HTTP/1.1" 301 0 "-" "Mozilla/5.0" - Deprecated',
            '10.0.0.15 - [{timestamp}] "GET /large-file.zip HTTP/1.1" 200 10485760 "-" "Wget/1.20.3" - Large file download',
        ],
        "error": [
            '192.168.1.20 - [{timestamp}] "GET /nonexistent-page HTTP/1.1" 404 199 "-" "Mozilla/5.0" - Not Found',
            '10.0.0.25 - [{timestamp}] "POST /api/v2/process HTTP/1.1" 502 0 "-" "Go-http-client/1.1" - Bad Gateway',
            '172.16.0.30 - [{timestamp}] "GET /malformed-uri% HTTP/1.1" 400 150 "-" "Python-urllib/3.8" - Bad Request',
        ],
        "security": [
            '203.0.113.1 - [{timestamp}] "GET /phpmyadmin/ HTTP/1.1" 403 169 "-" "Mozilla/5.0" - Forbidden',
            '203.0.113.2 - [{timestamp}] "GET /wp-login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0" - WordPress login attempt',
            '203.0.113.3 - [{timestamp}] "GET /admin/config.bak HTTP/1.1" 200 500 "-" "curl/7.64.1" - Sensitive file access',
            '203.0.113.4 - [{timestamp}] "POST /cgi-bin/test.cgi HTTP/1.1" 403 169 "-" "Nikto" - CGI scan attempt',
        ]
    },
    "wordpress": {
        "normal": [
            '[{timestamp}] WordPress: User "editor" updated post "My Latest Article"',
            '[{timestamp}] WordPress: Plugin "Yoast SEO" updated successfully',
            '[{timestamp}] WordPress: Theme "Twenty Twenty-One" activated',
        ],
        "warning": [
            '[{timestamp}] WordPress: Failed login attempt for username "admin" from IP 192.168.1.100',
            '[{timestamp}] WordPress: Disk space low, 10% remaining',
        ],
        "error": [
            '[{timestamp}] WordPress: Database error: Table \'wp_posts\' not found',
            '[{timestamp}] WordPress: PHP Fatal error: Call to undefined function some_function() in /var/www/html/wp-content/plugins/broken-plugin/broken.php on line 123',
            '[{timestamp}] WordPress: Could not connect to external API for plugin "Social Share"',
        ],
        "security": [
            '[{timestamp}] WordPress: Multiple failed login attempts for user "admin" from IP 203.0.113.50',
            '[{timestamp}] WordPress: Unauthorized file upload detected: shell.php in /wp-content/uploads/',
            '[{timestamp}] WordPress: SQL Injection attempt detected in comment submission from IP 203.0.113.51',
            '[{timestamp}] WordPress: Cross-Site Scripting (XSS) attempt detected in URL parameter',
            '[{timestamp}] WordPress: User "admin" changed password from IP 203.0.113.52',
        ]
    }
}

def generate_log(log_file, num_logs=10, interval=1.0, include_security=True, app_type="generic"):
    """Generate sample logs to test the AI Security Logger"""
    logger.info(f"Generating {num_logs} sample logs for {app_type} to {log_file}")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    if app_type not in APP_LOG_PATTERNS:
        logger.warning(f"Unknown app type '{app_type}'. Falling back to 'generic' logs.")
        app_type = "generic"

    app_logs = APP_LOG_PATTERNS[app_type]
    
    with open(log_file, 'a') as f:
        for i in range(num_logs):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Select log pattern based on type
            log_category = random.choices(
                ['normal', 'warning', 'error', 'security'],
                weights=[0.5, 0.2, 0.2, 0.1 if include_security else 0], # Adjust weights for security logs
                k=1
            )[0]
            
            if log_category == 'security' and not include_security:
                log_category = random.choice(['normal', 'warning', 'error']) # Fallback if security logs are disabled

            log_pattern = random.choice(app_logs[log_category])
            
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
    parser.add_argument('-f', '--file', default='../data/logs/sample.log',
                        help='Log file to write to (default: ../data/logs/sample.log)')
    parser.add_argument('-n', '--num-logs', type=int, default=10,
                        help='Number of logs to generate (default: 10)')
    parser.add_argument('-i', '--interval', type=float, default=1.0,
                        help='Interval between logs in seconds (default: 1.0)')
    parser.add_argument('--no-security', action='store_true',
                        help='Do not include security-related logs')
    parser.add_argument('-a', '--app-type', default='generic',
                        choices=list(APP_LOG_PATTERNS.keys()),
                        help=f"Type of application logs to generate (choices: {', '.join(APP_LOG_PATTERNS.keys())}, default: generic)")
    
    args = parser.parse_args()
    
    generate_log(
        log_file=args.file,
        num_logs=args.num_logs,
        interval=args.interval,
        include_security=not args.no_security,
        app_type=args.app_type
    )

if __name__ == "__main__":
    main()
