"""
Tests for Report Generator Module
"""

import os
import time
import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# Add src to Python path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.reporting.report_generator import ReportGenerator
from src.config.settings import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = MagicMock(spec=Settings)
    settings.report_schedule = 'hourly'
    settings.output_log_dir = '/app/reports'
    settings.report_email_enabled = False
    return settings


@pytest.fixture
def mock_database():
    """Create mock database for testing"""
    db = AsyncMock()
    
    # Configure get_threats to return sample threats
    sample_threats = [
        {
            'id': 1,
            'timestamp': time.time() - 3600,  # 1 hour ago
            'detected_at': datetime.now().isoformat(),
            'threat_detected': True,
            'severity': 'WARNING',
            'summary': 'Warning threat',
            'details': 'Test details',
            'recommended_actions': 'Test actions',
            'log_entries': [{'source_file': 'test.log', 'raw_line': 'Warning log entry'}]
        },
        {
            'id': 2,
            'timestamp': time.time() - 1800,  # 30 minutes ago
            'detected_at': datetime.now().isoformat(),
            'threat_detected': True,
            'severity': 'ERROR',
            'summary': 'Error threat',
            'details': 'Test details',
            'recommended_actions': 'Test actions',
            'log_entries': [{'source_file': 'test.log', 'raw_line': 'Error log entry'}]
        }
    ]
    db.get_threats = AsyncMock(return_value=sample_threats)
    db.get_threats_count = AsyncMock(return_value=len(sample_threats))
    
    return db


@pytest.mark.asyncio
async def test_report_generator_init(mock_settings, mock_database):
    """Test ReportGenerator initialization"""
    generator = ReportGenerator(mock_settings, mock_database)
    assert generator.settings == mock_settings
    assert generator.database == mock_database
    assert generator.running == False
    assert generator.scheduler_task is None
    assert generator.last_report_time == 0


@pytest.mark.asyncio
async def test_get_schedule_interval(mock_settings, mock_database):
    """Test schedule interval calculation"""
    generator = ReportGenerator(mock_settings, mock_database)
    
    # Test hourly
    mock_settings.report_schedule = 'hourly'
    assert generator._get_schedule_interval() == 3600
    
    # Test daily
    mock_settings.report_schedule = 'daily'
    assert generator._get_schedule_interval() == 86400
    
    # Test weekly
    mock_settings.report_schedule = 'weekly'
    assert generator._get_schedule_interval() == 604800
    
    # Test invalid/custom
    mock_settings.report_schedule = 'custom'
    assert generator._get_schedule_interval() == 3600  # Default to hourly


@pytest.mark.asyncio
async def test_generate_json_report(mock_settings, mock_database):
    """Test JSON report generation"""
    generator = ReportGenerator(mock_settings, mock_database)
    
    # Get sample threats
    threats = await mock_database.get_threats()
    
    # Generate JSON report
    start_time = time.time() - 3600
    end_time = time.time()
    report = generator._generate_json_report(threats, start_time, end_time)
    
    # Parse the report
    report_data = json.loads(report)
    
    # Check report structure
    assert 'report_time' in report_data
    assert 'time_range' in report_data
    assert 'threat_count' in report_data
    assert 'threats' in report_data
    assert report_data['threat_count'] == 2
    assert len(report_data['threats']) == 2


@pytest.mark.asyncio
async def test_generate_html_report(mock_settings, mock_database):
    """Test HTML report generation"""
    generator = ReportGenerator(mock_settings, mock_database)
    
    # Get sample threats
    threats = await mock_database.get_threats()
    
    # Generate HTML report
    start_time = time.time() - 3600
    end_time = time.time()
    report = generator._generate_html_report(threats, start_time, end_time)
    
    # Check that report contains expected elements
    assert '<!DOCTYPE html>' in report
    assert '<title>Security Threat Report</title>' in report
    assert 'Warning threat' in report
    assert 'Error threat' in report
    assert 'Test details' in report


@pytest.mark.asyncio
async def test_count_by_severity(mock_settings, mock_database):
    """Test severity count aggregation"""
    generator = ReportGenerator(mock_settings, mock_database)
    
    # Get sample threats
    threats = await mock_database.get_threats()
    
    # Count by severity
    counts = generator._count_by_severity(threats)
    
    # Check counts
    assert counts['WARNING'] == 1
    assert counts['ERROR'] == 1
    assert counts.get('CRITICAL', 0) == 0


@pytest.mark.asyncio
async def test_generate_report(mock_settings, mock_database):
    """Test full report generation process"""
    generator = ReportGenerator(mock_settings, mock_database)
    
    # Mock path operations
    with patch('pathlib.Path.mkdir') as mock_mkdir, \
         patch('builtins.open', MagicMock()), \
         patch('os.path.join', return_value='/app/reports/security_report.html'):
        
        # Generate report
        report_path = await generator.generate_report(time_range=3600, output_format='html')
        
        # Check that database was queried
        mock_database.get_threats.assert_called_once()
        
        # Check that directory was created
        mock_mkdir.assert_called_once()
        
        # Check that a path was returned
        assert report_path is not None
        assert 'security_report' in report_path


@pytest.mark.asyncio
async def test_start_stop_scheduler(mock_settings, mock_database):
    """Test starting and stopping the report scheduler"""
    generator = ReportGenerator(mock_settings, mock_database)
    
    # Patch generate_report to prevent actual report generation
    with patch.object(generator, 'generate_report', AsyncMock()) as mock_generate_report:
        
        # Start scheduler in background
        task = asyncio.create_task(generator.start_scheduler())
        
        # Give it a moment to start
        await asyncio.sleep(0.1)
        
        # Check that generate_report was called
        mock_generate_report.assert_called_once()
        
        # Stop the scheduler
        await generator.stop()
        
        # Check that running flag was set to False
        assert generator.running is False
        
        # Cancel the task
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
