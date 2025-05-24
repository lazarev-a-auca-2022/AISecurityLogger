"""
Tests for Threat Analyzer Module
"""

import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# Add src to Python path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer.threat_analyzer import ThreatAnalyzer
from src.config.settings import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = MagicMock(spec=Settings)
    settings.openrouter_api_key = 'test_api_key'
    settings.openrouter_model_id = 'test_model'
    settings.openrouter_base_url = 'https://api.test.com'
    settings.max_log_batch_size = 5
    settings.ai_request_timeout = 10
    settings.max_retries = 2
    return settings


@pytest.mark.asyncio
async def test_contains_urgent_keywords(mock_settings):
    """Test detection of urgent keywords in log entries"""
    analyzer = ThreatAnalyzer(mock_settings)
    
    # Log with urgent keyword
    urgent_log = {
        'raw_line': 'Unauthorized access detected from IP 192.168.1.100'
    }
    assert analyzer._contains_urgent_keywords(urgent_log) is True
    
    # Log without urgent keyword
    normal_log = {
        'raw_line': 'User logged in successfully'
    }
    assert analyzer._contains_urgent_keywords(normal_log) is False


@pytest.mark.asyncio
async def test_format_log_entries(mock_settings):
    """Test formatting of log entries for API request"""
    analyzer = ThreatAnalyzer(mock_settings)
    
    log_entries = [
        {
            'source_file': '/var/log/auth.log',
            'log_type': 'syslog',
            'raw_line': 'Failed password for root from 192.168.1.100'
        },
        {
            'source_file': '/var/log/nginx/access.log',
            'log_type': 'nginx_access',
            'raw_line': '192.168.1.100 - - [25/May/2025:10:00:00 +0000] "GET /admin HTTP/1.1" 403 287'
        }
    ]
    
    formatted = analyzer._format_log_entries(log_entries)
    
    # Check that both entries are included
    assert 'Failed password for root' in formatted
    assert 'GET /admin HTTP/1.1" 403' in formatted
    assert '[Source: /var/log/auth.log' in formatted
    assert '[Source: /var/log/nginx/access.log' in formatted


@pytest.mark.asyncio
async def test_process_ai_response(mock_settings):
    """Test processing of AI response"""
    analyzer = ThreatAnalyzer(mock_settings)
    
    # Sample log entries
    log_entries = [
        {
            'source_file': '/var/log/auth.log',
            'raw_line': 'Failed password for root from 192.168.1.100'
        }
    ]
    
    # Sample AI response
    ai_response = json.dumps({
        "threat_detected": True,
        "severity": "WARNING",
        "summary": "Failed root login attempt",
        "details": "There was a failed login attempt for the root user",
        "recommended_actions": "Monitor for additional attempts"
    })
    
    result = analyzer._process_ai_response(ai_response, log_entries)
    
    # Check that the result includes expected fields
    assert result['threat_detected'] is True
    assert result['severity'] == 'WARNING'
    assert result['summary'] == 'Failed root login attempt'
    assert result['log_entries'] == log_entries


@pytest.mark.asyncio
async def test_call_openrouter_api(mock_settings):
    """Test calling OpenRouter API"""
    analyzer = ThreatAnalyzer(mock_settings)
    
    # Mock aiohttp ClientSession
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        'choices': [
            {
                'message': {
                    'content': json.dumps({
                        "threat_detected": True,
                        "severity": "WARNING",
                        "summary": "Failed root login attempt",
                        "details": "There was a failed login attempt for the root user",
                        "recommended_actions": "Monitor for additional attempts"
                    })
                }
            }
        ]
    })
    
    mock_session = MagicMock()
    mock_session.post = AsyncMock(return_value=mock_response)
    mock_session.closed = False
    
    # Patch session creation
    with patch.object(analyzer, 'session', mock_session):
        result = await analyzer._call_openrouter_api('Test log entry')
        
        # Check that API was called correctly
        mock_session.post.assert_called_once()
        assert mock_settings.openrouter_api_key in str(mock_session.post.call_args)
        assert mock_settings.openrouter_model_id in str(mock_session.post.call_args)
        
        # Check that result is as expected
        assert 'Failed root login attempt' in result
