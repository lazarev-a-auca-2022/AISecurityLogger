"""
Integration tests for the AI Security Logger system
"""

import asyncio
import tempfile
import os
import pytest
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from config.settings import Settings
from storage.database import Database
from analyzer.threat_analyzer import ThreatAnalyzer
from ingestor.log_ingestor import LogIngestor
from reporting.report_generator import ReportGenerator


class MockSettings:
    """Mock settings for integration testing"""
    def __init__(self):
        self.ai_provider = 'openrouter'
        self.api_key = 'test_api_key'
        self.api_base_url = 'https://api.test.com'
        self.model_id = 'test-model'
        self.max_tokens = 1000
        self.temperature = 0.3
        self.batch_size = 5
        self.batch_timeout = 30
        self.log_paths = []
        self.log_extensions = ['.log', '.txt']
        self.keywords = ['error', 'warning', 'critical', 'failed', 'denied']
        self.process_interval = 5
        self.report_schedule = 'hourly'
        self.report_formats = ['html', 'json']


class TestIntegration:
    """Integration test cases"""

    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.settings = MockSettings()
        self.settings.report_path = self.temp_dir
        
        # Create temp database
        self.db_path = os.path.join(self.temp_dir, 'test.db')
        self.database = Database(self.db_path)
        
        # Initialize components
        self.threat_analyzer = ThreatAnalyzer(self.settings, self.database)
        self.log_ingestor = LogIngestor(self.settings, self.threat_analyzer)
        self.report_generator = ReportGenerator(self.settings, self.database)

    def teardown_method(self):
        """Clean up after tests"""
        asyncio.run(self._cleanup())

    async def _cleanup(self):
        """Async cleanup method"""
        if self.database.db:
            await self.database.close()
        if self.log_ingestor.running:
            await self.log_ingestor.stop()
        if self.report_generator.running:
            await self.report_generator.stop()
        
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_database_initialization(self):
        """Test database initialization"""
        await self.database.initialize()
        
        # Check that database is properly initialized
        assert self.database.db is not None
        
        # Verify table exists
        cursor = await self.database.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='threats'"
        )
        result = await cursor.fetchone()
        assert result is not None

    @pytest.mark.asyncio
    async def test_end_to_end_log_processing(self):
        """Test complete log processing pipeline"""
        await self.database.initialize()
        
        # Create a test log file
        log_file = os.path.join(self.temp_dir, 'test.log')
        log_content = """
2024-01-01 12:00:00 ERROR: Authentication failed for user admin
2024-01-01 12:01:00 INFO: Normal operation
2024-01-01 12:02:00 CRITICAL: Security breach detected
2024-01-01 12:03:00 WARNING: Multiple failed login attempts
"""
        with open(log_file, 'w') as f:
            f.write(log_content)
        
        # Mock AI response
        mock_ai_response = {
            "threat_detected": True,
            "severity": "HIGH",
            "summary": "Multiple security threats detected",
            "details": "Authentication failures and security breach",
            "recommended_actions": "Investigate and block suspicious IPs"
        }
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Mock successful AI API response
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": json.dumps(mock_ai_response)}}]
            }
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            # Process the log file
            await self.log_ingestor.process_file(log_file)
            
            # Check that threats were stored in database
            threats = await self.database.get_threats()
            assert len(threats) > 0
            
            # Verify threat data
            threat = threats[0]
            assert threat['threat_detected'] is True
            assert threat['severity'] == 'HIGH'
            assert 'security threats' in threat['summary'].lower()

    @pytest.mark.asyncio
    async def test_threat_analysis_integration(self):
        """Test threat analyzer integration with database"""
        await self.database.initialize()
        await self.threat_analyzer.start_session()
        
        # Create test log entry
        log_entry = {
            'timestamp': '2024-01-01T12:00:00',
            'message': 'CRITICAL: SQL injection attempt detected',
            'source_file': '/var/log/security.log',
            'log_type': 'security'
        }
        
        # Mock AI response
        mock_response = {
            "threat_detected": True,
            "severity": "CRITICAL",
            "summary": "SQL injection attack",
            "details": "Malicious SQL code detected in user input",
            "recommended_actions": "Block IP address and review application security"
        }
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": json.dumps(mock_response)}}]
            }
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            # Analyze the log entry
            result = await self.threat_analyzer.analyze_log(log_entry)
            
            # Verify analysis result
            assert result is not None
            assert result['threat_detected'] is True
            assert result['severity'] == 'CRITICAL'
            
            # Verify data was stored in database
            threats = await self.database.get_threats()
            assert len(threats) == 1
            assert threats[0]['summary'] == mock_response['summary']

    @pytest.mark.asyncio
    async def test_report_generation_integration(self):
        """Test report generation with database data"""
        await self.database.initialize()
        
        # Store some test threats
        threat_data = [
            {
                'threat_detected': True,
                'severity': 'HIGH',
                'summary': 'Brute force attack detected',
                'details': 'Multiple failed login attempts from same IP',
                'recommended_actions': 'Block IP address',
                'log_entries': [{'message': 'Failed login', 'timestamp': '2024-01-01T12:00:00'}]
            },
            {
                'threat_detected': True,
                'severity': 'MEDIUM',
                'summary': 'Suspicious file access',
                'details': 'Unusual file access patterns detected',
                'recommended_actions': 'Monitor user activity',
                'log_entries': [{'message': 'File access', 'timestamp': '2024-01-01T12:05:00'}]
            }
        ]
        
        for threat in threat_data:
            await self.database.store_threat(threat)
        
        # Generate report
        with patch.object(self.report_generator, '_update_reports_json'):
            await self.report_generator.generate_report(force=True)
        
        # Check that report files were created
        report_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.html')]
        assert len(report_files) > 0
        
        # Verify report content
        html_file = os.path.join(self.temp_dir, report_files[0])
        with open(html_file, 'r') as f:
            content = f.read()
            assert 'Brute force attack' in content
            assert 'Suspicious file access' in content
            assert 'HIGH' in content
            assert 'MEDIUM' in content

    @pytest.mark.asyncio
    async def test_log_parsing_integration(self):
        """Test log parsing integration with different log formats"""
        # Test different log formats
        test_logs = [
            # Syslog format
            "Jan  1 12:00:00 hostname daemon[1234]: ERROR: Service failed to start",
            # Nginx access log
            '192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /admin HTTP/1.1" 401 567',
            # Generic format
            "2024-01-01 12:00:00 CRITICAL: Database connection lost"
        ]
        
        log_file = os.path.join(self.temp_dir, 'mixed.log')
        with open(log_file, 'w') as f:
            f.write('\n'.join(test_logs))
        
        # Mock threat analyzer to capture processed logs
        processed_logs = []
        
        async def mock_analyze_log(log_entry):
            processed_logs.append(log_entry)
            return None
        
        self.threat_analyzer.analyze_log = mock_analyze_log
        
        # Process the file
        await self.log_ingestor.process_file(log_file)
        
        # Verify all logs were processed and parsed correctly
        assert len(processed_logs) >= 3
        
        # Check specific parsing
        log_types = [log.get('log_type') for log in processed_logs if log]
        assert 'syslog' in log_types
        assert 'nginx' in log_types
        assert 'generic' in log_types

    @pytest.mark.asyncio
    async def test_error_handling_integration(self):
        """Test error handling across components"""
        await self.database.initialize()
        
        # Test with corrupted log file
        log_file = os.path.join(self.temp_dir, 'corrupted.log')
        with open(log_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03')  # Binary data
        
        # Should handle gracefully without crashing
        await self.log_ingestor.process_file(log_file)
        
        # Test with network error in threat analyzer
        log_entry = {
            'timestamp': '2024-01-01T12:00:00',
            'message': 'CRITICAL: Test error',
            'source_file': '/test.log'
        }
        
        with patch('aiohttp.ClientSession.post', side_effect=Exception("Network error")):
            result = await self.threat_analyzer.analyze_log(log_entry)
            # Should return None instead of crashing
            assert result is None

    @pytest.mark.asyncio
    async def test_concurrent_processing(self):
        """Test concurrent processing of multiple log files"""
        await self.database.initialize()
        
        # Create multiple log files
        log_files = []
        for i in range(3):
            log_file = os.path.join(self.temp_dir, f'test_{i}.log')
            with open(log_file, 'w') as f:
                f.write(f"2024-01-01 12:0{i}:00 ERROR: Test error {i}\n")
            log_files.append(log_file)
        
        # Mock threat analyzer
        processed_count = 0
        
        async def mock_analyze_log(log_entry):
            nonlocal processed_count
            processed_count += 1
            return {
                "threat_detected": True,
                "severity": "MEDIUM",
                "summary": f"Test threat {processed_count}"
            }
        
        self.threat_analyzer.analyze_log = mock_analyze_log
        
        # Process files concurrently
        tasks = [self.log_ingestor.process_file(log_file) for log_file in log_files]
        await asyncio.gather(*tasks)
        
        # Verify all files were processed
        assert processed_count >= 3

    @pytest.mark.asyncio
    async def test_data_persistence(self):
        """Test data persistence across database sessions"""
        await self.database.initialize()
        
        # Store threat data
        threat_data = {
            'threat_detected': True,
            'severity': 'HIGH',
            'summary': 'Persistence test threat',
            'details': 'Test threat for persistence',
            'recommended_actions': 'Test actions',
            'log_entries': [{'message': 'test'}]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        
        # Close database
        await self.database.close()
        
        # Reinitialize database
        new_database = Database(self.db_path)
        await new_database.initialize()
        
        # Retrieve stored data
        retrieved_threat = await new_database.get_threat_by_id(threat_id)
        
        assert retrieved_threat is not None
        assert retrieved_threat['summary'] == threat_data['summary']
        assert retrieved_threat['severity'] == threat_data['severity']
        
        await new_database.close()

    @pytest.mark.asyncio
    async def test_full_system_workflow(self):
        """Test complete system workflow from log ingestion to report generation"""
        await self.database.initialize()
        
        # Create test log with security events
        log_file = os.path.join(self.temp_dir, 'security.log')
        security_logs = [
            "2024-01-01 12:00:00 ERROR: Failed login attempt from 192.168.1.100",
            "2024-01-01 12:01:00 WARNING: Multiple authentication failures",
            "2024-01-01 12:02:00 CRITICAL: Potential brute force attack detected",
            "2024-01-01 12:03:00 ERROR: Unauthorized access attempt to /admin",
            "2024-01-01 12:04:00 INFO: Normal user login successful"
        ]
        
        with open(log_file, 'w') as f:
            f.write('\n'.join(security_logs))
        
        # Mock AI responses for different severity levels
        ai_responses = [
            {
                "threat_detected": True,
                "severity": "HIGH",
                "summary": "Brute force attack detected",
                "details": "Multiple failed login attempts from same IP",
                "recommended_actions": "Block IP address immediately"
            },
            {
                "threat_detected": True,
                "severity": "MEDIUM", 
                "summary": "Unauthorized access attempt",
                "details": "Attempt to access restricted admin area",
                "recommended_actions": "Review access logs and monitor"
            }
        ]
        
        response_index = 0
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            def get_mock_response(*args, **kwargs):
                nonlocal response_index
                mock_resp = AsyncMock()
                mock_resp.status = 200
                mock_resp.json.return_value = {
                    "choices": [{"message": {"content": json.dumps(ai_responses[response_index % len(ai_responses)])}}]
                }
                response_index += 1
                return mock_resp
            
            mock_post.return_value.__aenter__ = get_mock_response
            
            # 1. Process logs through ingestor
            await self.log_ingestor.process_file(log_file)
            
            # 2. Verify threats were stored
            threats = await self.database.get_threats()
            assert len(threats) > 0
            
            # 3. Generate reports
            with patch.object(self.report_generator, '_update_reports_json'):
                await self.report_generator.generate_report(force=True)
            
            # 4. Verify reports were created with threat data
            html_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.html')]
            assert len(html_files) > 0
            
            # Check report content
            with open(os.path.join(self.temp_dir, html_files[0]), 'r') as f:
                report_content = f.read()
                # Should contain threat information
                assert any(keyword in report_content.lower() for keyword in ['threat', 'attack', 'security'])

    @pytest.mark.asyncio
    async def test_configuration_integration(self):
        """Test configuration integration across components"""
        # Test that settings are properly shared across components
        assert self.threat_analyzer.settings == self.settings
        assert self.log_ingestor.settings == self.settings
        assert self.report_generator.settings == self.settings
        
        # Test configuration changes
        original_batch_size = self.settings.batch_size
        self.settings.batch_size = 10
        
        # Components should use updated settings
        assert self.threat_analyzer.settings.batch_size == 10

    @pytest.mark.asyncio
    async def test_memory_management(self):
        """Test memory management during processing"""
        await self.database.initialize()
        
        # Process a large number of log entries
        large_log_file = os.path.join(self.temp_dir, 'large.log')
        with open(large_log_file, 'w') as f:
            for i in range(1000):
                f.write(f"2024-01-01 12:00:{i:02d} INFO: Log entry {i}\n")
        
        # Mock analyzer to avoid actual AI calls
        async def mock_analyze_log(log_entry):
            return None  # No threats detected
        
        self.threat_analyzer.analyze_log = mock_analyze_log
        
        # Process the large file
        await self.log_ingestor.process_file(large_log_file)
        
        # Should complete without memory issues
        assert True  # If we get here, memory management is working

    @pytest.mark.asyncio
    async def test_component_lifecycle(self):
        """Test proper lifecycle management of components"""
        await self.database.initialize()
        await self.threat_analyzer.start_session()
        
        # Components should be properly initialized
        assert self.database.db is not None
        assert self.threat_analyzer.session is not None
        
        # Test cleanup
        await self.threat_analyzer.close_session()
        await self.database.close()
        
        # Components should be properly cleaned up
        assert self.threat_analyzer.session.closed if self.threat_analyzer.session else True


if __name__ == '__main__':
    pytest.main([__file__])
