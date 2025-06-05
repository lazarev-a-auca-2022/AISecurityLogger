"""
Test Fixtures and Factories for AI Security Logger Tests
Provides reusable test data and mock objects
"""

import json
import tempfile
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
import os


class MockSettings:
    """Mock settings for testing"""
    
    def __init__(self, **kwargs):
        # Default test settings
        self.THREAT_ANALYZER_ENABLED = kwargs.get('THREAT_ANALYZER_ENABLED', True)
        self.AI_PROVIDER = kwargs.get('AI_PROVIDER', 'openrouter')
        self.AI_MODEL = kwargs.get('AI_MODEL', 'openai/gpt-4o-mini')
        self.OPENROUTER_API_KEY = kwargs.get('OPENROUTER_API_KEY', 'test_key')
        self.OPENAI_API_KEY = kwargs.get('OPENAI_API_KEY', 'test_key')
        self.GOOGLE_API_KEY = kwargs.get('GOOGLE_API_KEY', 'test_key')
        self.AZURE_API_KEY = kwargs.get('AZURE_API_KEY', 'test_key')
        self.ANTHROPIC_API_KEY = kwargs.get('ANTHROPIC_API_KEY', 'test_key')
        self.CUSTOM_API_ENDPOINT = kwargs.get('CUSTOM_API_ENDPOINT', 'http://localhost:8000')
        self.CUSTOM_API_KEY = kwargs.get('CUSTOM_API_KEY', 'test_key')
        self.MAX_CONCURRENT_REQUESTS = kwargs.get('MAX_CONCURRENT_REQUESTS', 3)
        self.REQUEST_TIMEOUT = kwargs.get('REQUEST_TIMEOUT', 30)
        self.RETRY_ATTEMPTS = kwargs.get('RETRY_ATTEMPTS', 3)
        self.RETRY_DELAY = kwargs.get('RETRY_DELAY', 1)
        self.LOG_DIRECTORY = kwargs.get('LOG_DIRECTORY', '/tmp/test_logs')
        self.DATABASE_PATH = kwargs.get('DATABASE_PATH', ':memory:')
        self.REPORT_DIRECTORY = kwargs.get('REPORT_DIRECTORY', '/tmp/test_reports')
        self.REPORT_SCHEDULE = kwargs.get('REPORT_SCHEDULE', '0 0 * * *')
        self.KEYWORDS = kwargs.get('KEYWORDS', ['error', 'warning', 'failed', 'attack'])
        self.LOG_LEVEL = kwargs.get('LOG_LEVEL', 'INFO')


class LogDataFactory:
    """Factory for creating test log data"""
    
    @staticmethod
    def create_syslog_entries(count: int = 5) -> List[str]:
        """Create sample syslog entries"""
        base_time = datetime.now()
        entries = []
        
        templates = [
            "Dec  5 12:34:56 server1 sshd[12345]: Failed password for user from 192.168.1.100 port 22 ssh2",
            "Dec  5 12:35:00 server1 kernel: [12345.678] iptables: DROP IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2",
            "Dec  5 12:35:15 server1 apache2[5678]: [error] [client 192.168.1.50] File does not exist: /var/www/html/admin",
            "Dec  5 12:35:30 server1 postfix/smtpd[9999]: warning: unknown[suspicious-ip]: SASL authentication failure",
            "Dec  5 12:35:45 server1 mysqld[1111]: [Warning] Access denied for user 'root'@'external-host'"
        ]
        
        for i in range(count):
            timestamp = base_time + timedelta(minutes=i)
            template = templates[i % len(templates)]
            # Update timestamp in log entry
            month_day = timestamp.strftime("%b %d %H:%M:%S")
            entry = template.replace("Dec  5 12:34:56", month_day)
            entries.append(entry)
        
        return entries
    
    @staticmethod
    def create_nginx_entries(count: int = 5) -> List[str]:
        """Create sample nginx access log entries"""
        base_time = datetime.now()
        entries = []
        
        templates = [
            '{ip} - - [{timestamp}] "GET /admin HTTP/1.1" 404 162 "-" "Mozilla/5.0"',
            '{ip} - - [{timestamp}] "POST /login HTTP/1.1" 401 43 "-" "curl/7.68.0"',
            '{ip} - - [{timestamp}] "GET /../../../etc/passwd HTTP/1.1" 403 162 "-" "BadBot/1.0"',
            '{ip} - - [{timestamp}] "DELETE /api/users HTTP/1.1" 403 0 "-" "AttackTool/2.0"',
            '{ip} - - [{timestamp}] "GET /wp-admin HTTP/1.1" 404 162 "-" "Scanner/1.0"'
        ]
        
        ips = ["192.168.1.100", "10.0.0.50", "203.0.113.1", "198.51.100.5", "172.16.0.10"]
        
        for i in range(count):
            timestamp = base_time + timedelta(minutes=i)
            template = templates[i % len(templates)]
            entry = template.format(
                ip=ips[i % len(ips)],
                timestamp=timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
            )
            entries.append(entry)
        
        return entries
    
    @staticmethod
    def create_apache_entries(count: int = 5) -> List[str]:
        """Create sample apache error log entries"""
        base_time = datetime.now()
        entries = []
        
        templates = [
            "[{timestamp}] [error] [client {ip}:port] File does not exist: /var/www/html/admin",
            "[{timestamp}] [warn] [client {ip}:port] mod_fcgid: HTTP request length exceeds MaxRequestLen",
            "[{timestamp}] [error] [client {ip}:port] Directory index forbidden by Options directive",
            "[{timestamp}] [crit] [client {ip}:port] (13)Permission denied: access to /secret denied",
            "[{timestamp}] [alert] [client {ip}:port] attempt to invoke directory as script"
        ]
        
        ips = ["192.168.1.200", "10.0.0.75", "203.0.113.10", "198.51.100.15", "172.16.0.20"]
        
        for i in range(count):
            timestamp = base_time + timedelta(minutes=i)
            template = templates[i % len(templates)]
            entry = template.format(
                ip=ips[i % len(ips)],
                timestamp=timestamp.strftime("%a %b %d %H:%M:%S.%f %Y")
            )
            entries.append(entry)
        
        return entries
    
    @staticmethod
    def create_generic_entries(count: int = 5) -> List[str]:
        """Create sample generic log entries"""
        base_time = datetime.now()
        entries = []
        
        templates = [
            "{timestamp} ERROR: Database connection failed for user admin",
            "{timestamp} WARNING: Multiple failed login attempts detected",
            "{timestamp} CRITICAL: Unauthorized access attempt blocked",
            "{timestamp} INFO: Security scan completed successfully",
            "{timestamp} ERROR: Invalid API key provided for service call"
        ]
        
        for i in range(count):
            timestamp = base_time + timedelta(minutes=i)
            template = templates[i % len(templates)]
            entry = template.format(timestamp=timestamp.isoformat())
            entries.append(entry)
        
        return entries


class ThreatDataFactory:
    """Factory for creating test threat data"""
    
    @staticmethod
    def create_threat_dict(
        source: str = "test.log",
        log_entry: str = "Test log entry with attack pattern",
        severity: str = "HIGH",
        threat_type: str = "brute_force",
        confidence: float = 0.85,
        timestamp: datetime = None
    ) -> Dict[str, Any]:
        """Create a threat dictionary"""
        if timestamp is None:
            timestamp = datetime.now()
            
        return {
            'timestamp': timestamp.isoformat(),
            'source': source,
            'log_entry': log_entry,
            'severity': severity,
            'threat_type': threat_type,
            'confidence': confidence,
            'description': f"Test threat of type {threat_type}",
            'recommendation': f"Investigate {threat_type} activity",
            'affected_systems': ['test-server'],
            'indicators': ['suspicious_ip', 'failed_auth']
        }
    
    @staticmethod
    def create_threat_list(count: int = 10) -> List[Dict[str, Any]]:
        """Create a list of threat dictionaries"""
        threats = []
        base_time = datetime.now()
        
        threat_types = ['brute_force', 'sql_injection', 'xss', 'dos', 'malware']
        severities = ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL']
        sources = ['auth.log', 'access.log', 'error.log', 'security.log']
        
        for i in range(count):
            timestamp = base_time + timedelta(hours=i)
            threat = ThreatDataFactory.create_threat_dict(
                source=sources[i % len(sources)],
                threat_type=threat_types[i % len(threat_types)],
                severity=severities[i % len(severities)],
                confidence=0.7 + (i % 3) * 0.1,
                timestamp=timestamp
            )
            threats.append(threat)
        
        return threats


class ReportDataFactory:
    """Factory for creating test report data"""
    
    @staticmethod
    def create_report_data(threat_count: int = 5) -> Dict[str, Any]:
        """Create sample report data"""
        threats = ThreatDataFactory.create_threat_list(threat_count)
        
        return {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'period_start': (datetime.now() - timedelta(days=1)).isoformat(),
                'period_end': datetime.now().isoformat(),
                'total_threats': len(threats),
                'version': '1.0.0'
            },
            'summary': {
                'total_threats': len(threats),
                'severity_counts': {
                    'CRITICAL': len([t for t in threats if t['severity'] == 'CRITICAL']),
                    'HIGH': len([t for t in threats if t['severity'] == 'HIGH']),
                    'MEDIUM': len([t for t in threats if t['severity'] == 'MEDIUM']),
                    'LOW': len([t for t in threats if t['severity'] == 'LOW'])
                },
                'threat_type_counts': {}
            },
            'threats': threats,
            'recommendations': [
                "Review and strengthen authentication mechanisms",
                "Implement rate limiting for API endpoints",
                "Update security monitoring rules"
            ]
        }


class DatabaseFixture:
    """Fixture for creating test databases"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            self.temp_dir = tempfile.mkdtemp()
            self.db_path = os.path.join(self.temp_dir, 'test.db')
        else:
            self.db_path = db_path
            self.temp_dir = None
        
        self.connection = None
    
    def setup(self):
        """Setup test database with schema"""
        self.connection = sqlite3.connect(self.db_path)
        cursor = self.connection.cursor()
        
        # Create threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                log_entry TEXT NOT NULL,
                severity TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                analysis_data TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.connection.commit()
        return self
    
    def add_sample_threats(self, count: int = 5):
        """Add sample threats to the database"""
        threats = ThreatDataFactory.create_threat_list(count)
        cursor = self.connection.cursor()
        
        for threat in threats:
            cursor.execute('''
                INSERT INTO threats 
                (timestamp, source, log_entry, severity, threat_type, confidence, analysis_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat['timestamp'],
                threat['source'],
                threat['log_entry'],
                threat['severity'],
                threat['threat_type'],
                threat['confidence'],
                json.dumps(threat)
            ))
        
        self.connection.commit()
        return self
    
    def cleanup(self):
        """Clean up test database"""
        if self.connection:
            self.connection.close()
        
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)


class FileFixture:
    """Fixture for creating test files and directories"""
    
    def __init__(self, base_dir: str = None):
        if base_dir is None:
            self.base_dir = tempfile.mkdtemp()
            self.cleanup_needed = True
        else:
            self.base_dir = base_dir
            self.cleanup_needed = False
        
        self.created_files = []
        self.created_dirs = []
    
    def create_log_file(self, filename: str, log_type: str = 'syslog', entry_count: int = 10) -> str:
        """Create a test log file"""
        file_path = os.path.join(self.base_dir, filename)
        
        # Create directory if needed
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        if log_type == 'syslog':
            entries = LogDataFactory.create_syslog_entries(entry_count)
        elif log_type == 'nginx':
            entries = LogDataFactory.create_nginx_entries(entry_count)
        elif log_type == 'apache':
            entries = LogDataFactory.create_apache_entries(entry_count)
        else:
            entries = LogDataFactory.create_generic_entries(entry_count)
        
        with open(file_path, 'w') as f:
            f.write('\n'.join(entries) + '\n')
        
        self.created_files.append(file_path)
        return file_path
    
    def create_config_file(self, filename: str, config_data: Dict[str, Any]) -> str:
        """Create a test configuration file"""
        file_path = os.path.join(self.base_dir, filename)
        
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        if filename.endswith('.json'):
            with open(file_path, 'w') as f:
                json.dump(config_data, f, indent=2)
        elif filename.endswith('.env'):
            with open(file_path, 'w') as f:
                for key, value in config_data.items():
                    f.write(f"{key}={value}\n")
        
        self.created_files.append(file_path)
        return file_path
    
    def create_directory(self, dirname: str) -> str:
        """Create a test directory"""
        dir_path = os.path.join(self.base_dir, dirname)
        os.makedirs(dir_path, exist_ok=True)
        self.created_dirs.append(dir_path)
        return dir_path
    
    def cleanup(self):
        """Clean up created files and directories"""
        if self.cleanup_needed:
            import shutil
            if os.path.exists(self.base_dir):
                shutil.rmtree(self.base_dir)


class MockAIResponse:
    """Mock AI API response"""
    
    def __init__(self, content: str, status_code: int = 200):
        self.content = content
        self.status_code = status_code
        self.headers = {'content-type': 'application/json'}
    
    async def json(self):
        """Mock json() method"""
        if self.status_code == 200:
            return {
                "choices": [{
                    "message": {
                        "content": self.content
                    }
                }]
            }
        else:
            return {"error": "API Error"}
    
    async def text(self):
        """Mock text() method"""
        return self.content


# Helper functions for test setup
def create_temp_database() -> str:
    """Create a temporary database file"""
    temp_dir = tempfile.mkdtemp()
    return os.path.join(temp_dir, 'test.db')


def create_test_settings(**kwargs) -> MockSettings:
    """Create test settings with optional overrides"""
    return MockSettings(**kwargs)


def cleanup_temp_files(*file_paths):
    """Clean up temporary files and directories"""
    import shutil
    for path in file_paths:
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                parent_dir = os.path.dirname(path)
                if os.path.basename(parent_dir).startswith('tmp'):
                    shutil.rmtree(parent_dir)
                else:
                    os.remove(path)
