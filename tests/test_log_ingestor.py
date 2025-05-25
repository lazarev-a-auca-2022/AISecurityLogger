"""
Tests for Log Ingestor Module
"""

import os
import re
import sys
import queue
import asyncio
import logging
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingestor.log_ingestor import LogIngestor, LogFileHandler
from src.config.settings import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = MagicMock(spec=Settings)
    settings.log_sources = ['/var/log/syslog', '/var/log/auth.log']
    settings.sensitivity_keywords = ['error', 'failed', 'warning', 'critical']
    settings.processing_interval = 60
    return settings


@pytest.fixture
def mock_analyzer():
    """Create mock threat analyzer for testing"""
    analyzer = AsyncMock()
    analyzer.analyze_log = AsyncMock(return_value={
        'threat_detected': True,
        'severity': 'WARNING',
        'summary': 'Test threat'
    })
    return analyzer


@pytest.mark.asyncio
async def test_log_ingestor_init(mock_settings, mock_analyzer):
    """Test LogIngestor initialization"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    assert ingestor.settings == mock_settings
    assert ingestor.threat_analyzer == mock_analyzer
    assert ingestor.running == False
    assert isinstance(ingestor.file_positions, dict)
    assert isinstance(ingestor.file_handler, LogFileHandler)


@pytest.mark.asyncio
async def test_contains_sensitive_keywords(mock_settings, mock_analyzer):
    """Test sensitive keyword detection"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    
    # Line with sensitive keyword
    sensitive_line = "Error: Connection failed due to timeout"
    assert ingestor._contains_sensitive_keywords(sensitive_line) is True
    
    # Line without sensitive keyword
    normal_line = "User logged in successfully"
    assert ingestor._contains_sensitive_keywords(normal_line) is False


@pytest.mark.asyncio
async def test_determine_log_type(mock_settings, mock_analyzer):
    """Test log type determination based on file path"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    
    # Test syslog type
    assert ingestor._determine_log_type('/var/log/syslog') == 'syslog'
    assert ingestor._determine_log_type('/var/log/auth.log') == 'syslog'
    
    # Test nginx types
    assert ingestor._determine_log_type('/var/log/nginx/access.log') == 'nginx_access'
    assert ingestor._determine_log_type('/var/log/nginx/error.log') == 'nginx_error'
    
    # Default type
    assert ingestor._determine_log_type('/var/log/custom.log') == 'unknown'


@pytest.mark.asyncio
async def test_parse_log_line(mock_settings, mock_analyzer):
    """Test parsing of different log formats"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    
    # Test syslog format
    syslog_line = "May 25 12:34:56 hostname sshd[1234]: Failed password for root from 192.168.1.100 port 22"
    parsed = ingestor._parse_log_line(syslog_line, '/var/log/auth.log')
    assert parsed is not None
    assert parsed['log_type'] == 'syslog'
    assert parsed['hostname'] == 'hostname'
    assert parsed['program'] == 'sshd[1234]'
    assert parsed['message'] == 'Failed password for root from 192.168.1.100 port 22'
    
    # Test nginx access log format
    nginx_access_line = '192.168.1.100 - user [25/May/2025:12:34:56 +0000] "GET /admin HTTP/1.1" 403 287 "-" "Mozilla/5.0"'
    parsed = ingestor._parse_log_line(nginx_access_line, '/var/log/nginx/access.log')
    assert parsed is not None
    assert parsed['log_type'] == 'nginx_access'
    assert parsed['ip'] == '192.168.1.100'
    assert parsed['status'] == '403'
    
    # Test unparseable line
    unparseable_line = "This is not a valid log line"
    parsed = ingestor._parse_log_line(unparseable_line, '/var/log/custom.log')
    assert parsed is not None
    assert parsed['log_type'] == 'unknown'
    assert parsed['raw_line'] == unparseable_line


@pytest.mark.asyncio
async def test_process_log_line(mock_settings, mock_analyzer):
    """Test processing of log lines"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    
    # Create a sensitive log line
    log_line = "May 25 12:34:56 hostname sshd[1234]: Failed password for root from 192.168.1.100 port 22"
    
    # Process the log line
    await ingestor._process_log_line(log_line, '/var/log/auth.log')
    
    # Check that analyze_log was called
    mock_analyzer.analyze_log.assert_called_once()
    
    # Get the call arguments
    call_args = mock_analyzer.analyze_log.call_args[0][0]
    assert call_args['log_type'] == 'syslog'
    assert call_args['source_file'] == '/var/log/auth.log'
    assert call_args['raw_line'] == log_line


@pytest.mark.asyncio
async def test_log_file_handler(mock_settings, mock_analyzer):
    """Test LogFileHandler event handling"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    handler = LogFileHandler(ingestor)
    
    # Create a mock event
    mock_event = MagicMock()
    mock_event.is_directory = False
    mock_event.src_path = '/var/log/auth.log'
    
    # Handle the event
    handler.on_modified(mock_event)
    
    # Check that the file was added to the queue
    assert not handler.file_queue.empty()
    assert handler.file_queue.get() == '/var/log/auth.log'


@pytest.mark.asyncio
async def test_schedule_file_for_rename(mock_settings, mock_analyzer):
    """Test scheduling a file for renaming"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    
    # Schedule a file for renaming
    file_path = '/var/log/auth.log'
    ingestor._schedule_file_for_rename(file_path)
    
    # Check that the file was added to the set
    assert file_path in ingestor.files_to_rename


@pytest.mark.asyncio
async def test_start_stop(mock_settings, mock_analyzer):
    """Test starting and stopping the log ingestor"""
    ingestor = LogIngestor(mock_settings, mock_analyzer)
    
    # Patch setup_file_watchers to prevent actual file system operations
    with patch.object(ingestor, '_setup_file_watchers', AsyncMock()), \
         patch.object(ingestor, '_process_existing_logs', AsyncMock()), \
         patch.object(ingestor.observer, 'start'), \
         patch.object(ingestor.observer, 'stop'), \
         patch.object(ingestor.observer, 'join'):
        
        # Start the ingestor
        await ingestor.start()
        assert ingestor.running is True
        ingestor.observer.start.assert_called_once()
        
        # Stop the ingestor
        await ingestor.stop()
        assert ingestor.running is False
        ingestor.observer.stop.assert_called_once()
        ingestor.observer.join.assert_called_once()
