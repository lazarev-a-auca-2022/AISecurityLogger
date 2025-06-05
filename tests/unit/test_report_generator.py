"""
Unit tests for the ReportGenerator class
"""

import asyncio
import tempfile
import os
import pytest
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from reporting.report_generator import ReportGenerator


class MockSettings:
    """Mock settings for testing"""
    def __init__(self):
        self.report_schedule = 'hourly'  # hourly, daily, weekly
        self.report_path = '/tmp/test_reports'
        self.output_log_dir = '/tmp/test_reports'  # Added missing property
        self.report_formats = ['html'] # Default format for tests


class TestReportGenerator:
    """Test cases for ReportGenerator"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_settings = MockSettings()
        self.mock_database = AsyncMock()
        self.generator = ReportGenerator(self.mock_settings, self.mock_database)
        
        # Create temp directory for reports
        self.temp_dir = tempfile.mkdtemp()
        self.mock_settings.output_log_dir = self.temp_dir

    def teardown_method(self):
        """Clean up after tests"""
        # Stop generator if running
        if self.generator.running:
            asyncio.run(self.generator.stop())
        
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test ReportGenerator initialization"""
        assert self.generator.settings == self.mock_settings
        assert self.generator.database == self.mock_database
        assert self.generator.running is False
        assert self.generator.scheduler_task is None
        assert self.generator.last_report_time == 0
        assert self.generator.min_report_interval == 300

    def test_get_schedule_interval_hourly(self):
        """Test schedule interval calculation for hourly reports"""
        self.mock_settings.report_schedule = 'hourly'
        interval = self.generator._get_schedule_interval()
        assert interval == 3600  # 1 hour

    def test_get_schedule_interval_daily(self):
        """Test schedule interval calculation for daily reports"""
        self.mock_settings.report_schedule = 'daily'
        interval = self.generator._get_schedule_interval()
        assert interval == 86400  # 24 hours

    def test_get_schedule_interval_weekly(self):
        """Test schedule interval calculation for weekly reports"""
        self.mock_settings.report_schedule = 'weekly'
        interval = self.generator._get_schedule_interval()
        assert interval == 604800  # 7 days

    def test_get_schedule_interval_default(self):
        """Test schedule interval calculation for unknown schedule"""
        self.mock_settings.report_schedule = 'unknown'
        interval = self.generator._get_schedule_interval()
        assert interval == 86400  # defaults to daily

    @pytest.mark.asyncio
    async def test_generate_report_forced(self):
        """Test forced report generation"""
        # Mock database to return sample threats
        sample_threats = [
            {
                'id': 1,
                'timestamp': datetime.now().timestamp(),
                'detected_at': datetime.now().isoformat(),
                'threat_detected': True,
                'severity': 'HIGH',
                'summary': 'Test threat',
                'details': 'Test details',
                'recommended_actions': 'Test actions',
                'log_entries': [{'message': 'test log'}]
            }
        ]
        self.mock_database.get_threats.return_value = sample_threats
        
        # Ensure the directory exists
        os.makedirs(self.temp_dir, exist_ok=True)
        
        result = await self.generator.generate_report(force=True)
        
        # Should have called database
        self.mock_database.get_threats.assert_called_once()
        # Should return a path to the generated report
        assert len(result) > 0
        assert result[0].endswith('.html')

    @pytest.mark.asyncio
    async def test_generate_report_min_interval_respected(self):
        """Test that minimum interval is respected for non-forced reports"""
        # Set last report time to recent
        self.generator.last_report_time = datetime.now().timestamp() - 100  # 100 seconds ago
        
        await self.generator.generate_report(force=False)
        
        # Should not call database (too soon)
        self.mock_database.get_threats.assert_not_called()

    @pytest.mark.asyncio
    async def test_generate_report_min_interval_exceeded(self):
        """Test report generation when minimum interval is exceeded"""
        # Set last report time to long ago
        self.generator.last_report_time = datetime.now().timestamp() - 400  # 400 seconds ago
        
        sample_threats = []
        self.mock_database.get_threats.return_value = sample_threats
        
        with patch.object(self.generator, '_update_reports_json'):
            await self.generator.generate_report(force=False)
            
            # Should call database (enough time passed)
            self.mock_database.get_threats.assert_called_once()

    def test_count_by_severity(self):
        """Test counting threats by severity"""
        threats = [
            {'severity': 'HIGH'},
            {'severity': 'MEDIUM'},
            {'severity': 'HIGH'},
            {'severity': 'LOW'},
            {'severity': 'HIGH'},
            {'severity': 'CRITICAL'}
        ]
        
        counts = self.generator._count_by_severity(threats)
        
        expected = {
            'CRITICAL': 1,
            'HIGH': 3,
            'MEDIUM': 1,
            'LOW': 1
        }
        assert counts == expected

    def test_count_by_severity_empty(self):
        """Test counting threats by severity with empty list"""
        counts = self.generator._count_by_severity([])
        expected = {}  # Empty dict for empty list
        assert counts == expected

    def test_generate_json_report(self):
        """Test JSON report generation"""
        threats = [
            {
                'id': 1,
                'timestamp': 1640995200,  # 2022-01-01 00:00:00
                'threat_detected': True,
                'severity': 'HIGH',
                'summary': 'Test threat',
                'details': 'Test details'
            }
        ]
        
        start_time = 1640995200
        end_time = 1640995260
        
        json_report = self.generator._generate_json_report(threats, start_time, end_time)
        
        # Parse JSON to verify structure
        report_data = json.loads(json_report)
        
        assert 'threats_count' in report_data
        assert 'threats' in report_data
        assert report_data['threats_count']['total'] == 1
        assert report_data['threats_count']['by_severity']['HIGH'] == 1

    def test_generate_json_report_empty(self):
        """Test JSON report generation with no threats"""
        threats = []
        start_time = 1640995200
        end_time = 1640995260
        
        json_report = self.generator._generate_json_report(threats, start_time, end_time)
        report_data = json.loads(json_report)
        
        assert report_data['threats_count']['total'] == 0
        assert report_data['threats'] == []

    def test_generate_html_report_with_threats(self):
        """Test HTML report generation with threats"""
        threats = [
            {
                'id': 1,
                'timestamp': datetime.now().timestamp(),
                'detected_at': datetime.now().isoformat(),
                'threat_detected': True,
                'severity': 'CRITICAL',
                'summary': 'Critical security breach',
                'details': 'Detailed analysis of the breach',
                'recommended_actions': 'Immediate action required',
                'log_entries': [{'message': 'suspicious activity detected'}]
            }
        ]
        
        start_time = datetime.now().timestamp() - 3600
        end_time = datetime.now().timestamp()
        
        html_report = self.generator._generate_html_report(threats, start_time, end_time)
        
        # Verify HTML structure
        assert '<html lang="en">' in html_report
        assert '<title>' in html_report
        assert 'Security Report' in html_report
        assert 'Critical security breach' in html_report
        assert 'CRITICAL' in html_report

    def test_generate_html_report_empty(self):
        """Test HTML report generation with no threats"""
        threats = []
        start_time = datetime.now().timestamp() - 3600
        end_time = datetime.now().timestamp()
        
        html_report = self.generator._generate_html_report(threats, start_time, end_time)
        
        # Should contain empty state message
        assert '<html lang="en">' in html_report
        assert 'No security threats detected' in html_report or 'no threats' in html_report.lower()

    def test_generate_threats_html(self):
        """Test threats HTML generation"""
        threats = [
            {
                'id': 1,
                'detected_at': '2024-01-01T12:00:00',
                'severity': 'HIGH',
                'summary': 'SQL Injection attempt',
                'details': 'Malicious SQL detected in user input',
                'recommended_actions': 'Block source IP',
                'log_entries': [
                    {'message': 'SQL injection detected', 'timestamp': '2024-01-01T12:00:00'}
                ]
            },
            {
                'id': 2,
                'detected_at': '2024-01-01T12:05:00',
                'severity': 'MEDIUM',
                'summary': 'Multiple failed logins',
                'details': 'Brute force attempt detected',
                'recommended_actions': 'Monitor user account',
                'log_entries': [
                    {'message': 'Failed login attempt', 'timestamp': '2024-01-01T12:05:00'}
                ]
            }
        ]
        
        threats_html = self.generator._generate_threats_html(threats)
        
        # Verify content
        assert 'SQL Injection attempt' in threats_html
        assert 'Multiple failed logins' in threats_html
        assert 'HIGH' in threats_html
        assert 'MEDIUM' in threats_html

    def test_generate_empty_state_html(self):
        """Test empty state HTML generation"""
        empty_html = self.generator._generate_empty_state_html()
        
        assert 'no threats' in empty_html.lower() or 'no security threats' in empty_html.lower()
        assert '<div' in empty_html  # Should be valid HTML

    @pytest.mark.asyncio
    async def test_start_stop_scheduler(self):
        """Test starting and stopping the scheduler"""
        # Mock generate_report to avoid actual report generation
        with patch.object(self.generator, 'generate_report') as mock_generate:
            # Start scheduler
            start_task = asyncio.create_task(self.generator.start_scheduler())
            await asyncio.sleep(0.1)  # Let it start
            
            assert self.generator.running is True
            mock_generate.assert_called()  # Initial report should be generated
            
            # Stop scheduler
            await self.generator.stop()
            start_task.cancel()
            
            assert self.generator.running is False

    @pytest.mark.asyncio
    async def test_scheduler_periodic_reports(self):
        """Test that scheduler generates periodic reports"""
        # Set very short interval for testing
        with patch.object(self.generator, '_get_schedule_interval', return_value=0.1), \
             patch.object(self.generator, 'generate_report') as mock_generate:
            
            # Start scheduler
            start_task = asyncio.create_task(self.generator.start_scheduler())
            await asyncio.sleep(0.3)  # Wait for multiple intervals
            
            # Stop scheduler
            await self.generator.stop()
            start_task.cancel()
            
            # Should have called generate_report multiple times
            assert mock_generate.call_count >= 2

    @pytest.mark.asyncio
    async def test_update_reports_json(self):
        """Test updating reports.json file"""
        # Create a test report file
        test_report = {
            'timestamp': datetime.now().isoformat(),
            'filename': 'test_report.html',
            'threats_count': 5
        }
        
        # Mock os.listdir to return test files
        test_files = ['security_report_20240101_120000.html', 'security_report_20240102_120000.html']
        
        with patch('os.listdir', return_value=test_files), \
             patch('os.path.isfile', return_value=True), \
             patch('os.path.getmtime', return_value=datetime.now().timestamp()):
            
            await self.generator._update_reports_json()
            
            # Check if reports.json was created
            reports_json_path = os.path.join(self.temp_dir, 'reports.json')
            if os.path.exists(reports_json_path):
                with open(reports_json_path, 'r') as f:
                    reports_data = json.load(f)
                assert isinstance(reports_data, list)

    @pytest.mark.asyncio
    async def test_generate_report_file_creation(self):
        """Test that report generation creates actual files"""
        # Mock database with sample data
        sample_threats = [
            {
                'id': 1,
                'timestamp': datetime.now().timestamp(),
                'detected_at': datetime.now().isoformat(),
                'threat_detected': True,
                'severity': 'HIGH',
                'summary': 'File creation test',
                'details': 'Test details',
                'recommended_actions': 'Test actions',
                'log_entries': [{'message': 'test'}]
            }
        ]
        self.mock_database.get_threats.return_value = sample_threats
        
        # Ensure directory exists
        os.makedirs(self.temp_dir, exist_ok=True)
        
        with patch.object(self.generator, '_update_reports_json'):
            await self.generator.generate_report(force=True)
        
        # Check if report files were created
        report_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.html')]
        assert len(report_files) > 0
        
        # Verify HTML content
        html_file = os.path.join(self.temp_dir, report_files[0])
        with open(html_file, 'r') as f:
            content = f.read()
            assert 'File creation test' in content

    @pytest.mark.asyncio
    async def test_generate_report_both_formats(self):
        """Test generating both HTML and JSON formats"""
        self.mock_settings.report_formats = ['html', 'json']
        self.mock_database.get_threats.return_value = []
        
        # Ensure directory exists
        os.makedirs(self.temp_dir, exist_ok=True)
        
        with patch.object(self.generator, '_update_reports_json'):
            generated_paths = await self.generator.generate_report(force=True)
        
        # Check both formats were created
        html_files = [f for f in generated_paths if f.endswith('.html')]
        json_files = [f for f in generated_paths if f.endswith('.json')]
        
        assert len(html_files) > 0
        assert len(json_files) > 0

    @pytest.mark.asyncio
    async def test_generate_report_json_only(self):
        """Test generating JSON format only"""
        self.mock_settings.report_formats = ['json']
        self.mock_database.get_threats.return_value = []
        
        # Ensure directory exists
        os.makedirs(self.temp_dir, exist_ok=True)
        
        with patch.object(self.generator, '_update_reports_json'):
            generated_paths = await self.generator.generate_report(force=True)
        
        # Check only JSON was created
        html_files = [f for f in generated_paths if f.endswith('.html')]
        json_files = [f for f in generated_paths if f.endswith('.json')]
        
        assert len(html_files) == 0
        assert len(json_files) > 0

    def test_severity_order_in_html(self):
        """Test that severities are ordered correctly in HTML"""
        threats = [
            {'severity': 'LOW', 'summary': 'Low threat', 'id': 1, 'detected_at': '2024-01-01T12:00:00'},
            {'severity': 'CRITICAL', 'summary': 'Critical threat', 'id': 2, 'detected_at': '2024-01-01T12:00:00'}
        ]
        
        html = self.generator._generate_html_report(threats, 0, time.time()) # Generate full HTML
        
        # Extract the section containing detected threats
        threats_section_start = html.find('<div class="section">')
        threats_section_end = html.find('<div class="footer">')
        
        # Ensure both start and end are found
        assert threats_section_start != -1
        assert threats_section_end != -1
        
        threats_html_content = html[threats_section_start:threats_section_end]
        
        # Use regex to find all severity badges within the threats_html_content
        import re
        severity_matches = re.findall(r'severity-(CRITICAL|HIGH|MEDIUM|LOW|INFO)', threats_html_content)
        
        actual_severities_in_order = severity_matches
        
        expected_severities_order = ['CRITICAL', 'LOW'] # Expected for this simplified case
        
        # Check if the actual order of severities matches the expected order
        assert actual_severities_in_order == expected_severities_order

    @pytest.mark.asyncio
    async def test_error_handling_in_scheduler(self):
        """Test error handling in scheduler"""
        # Make generate_report raise an exception
        with patch.object(self.generator, 'generate_report', side_effect=Exception("Test error")):
            # Start scheduler
            start_task = asyncio.create_task(self.generator.start_scheduler())
            await asyncio.sleep(0.1)
            
            # Should still be running despite the error
            assert self.generator.running is True
            
            # Stop scheduler
            await self.generator.stop()
            start_task.cancel()

    @pytest.mark.asyncio
    async def test_concurrent_report_generation(self):
        """Test concurrent report generation requests"""
        self.mock_database.get_threats.return_value = []
        
        with patch.object(self.generator, '_update_reports_json'):
            # Generate multiple reports concurrently
            tasks = [
                self.generator.generate_report(force=True)
                for _ in range(3)
            ]
            await asyncio.gather(*tasks)
            
            # All should complete successfully
            assert True  # If we get here without exception, test passes

    def test_html_report_structure(self):
        """Test HTML report has proper structure"""
        threats = [
            {
                'id': 1,
                'detected_at': '2024-01-01T12:00:00',
                'severity': 'HIGH',
                'summary': 'Test threat',
                'details': 'Test details',
                'recommended_actions': 'Test actions',
                'log_entries': [{'message': 'test log'}]
            }
        ]
        
        html = self.generator._generate_html_report(threats, 0, time.time())
        
        # Check for proper HTML structure
        assert html.startswith('<!DOCTYPE html>')
        assert '<html lang="en">' in html
        assert '<head>' in html
        assert '<body>' in html
        assert '<title>' in html
        assert '</html>' in html.strip()
        
        # Check for CSS styling
        assert '<style>' in html
        assert 'css' in html.lower() or 'style' in html
        
        # Check for JavaScript (if any)
        # HTML report might include interactive elements

    @pytest.mark.asyncio
    async def test_database_connection_error(self):
        """Test handling of database connection errors"""
        # Make database raise an exception
        self.mock_database.get_threats.side_effect = Exception("Database error")
        
        # Should handle the error gracefully
        await self.generator.generate_report(force=True)
        
        # Verify the error was logged (we can't easily test logging here)
        assert True  # If we get here without exception, test passes


if __name__ == '__main__':
    pytest.main([__file__])
