"""
Tests for Health Check Module
"""

import json
import socket
import pytest
from datetime import datetime
from http.server import HTTPServer
from unittest.mock import patch, MagicMock, AsyncMock
from io import BytesIO

# Add src to Python path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.health_check import HealthCheckHandler, HealthCheckServer


class MockHTTPRequest:
    """Mock HTTP request for testing handler"""
    
    def __init__(self, path='/health'):
        self.path = path


class MockResponse:
    """Mock response to capture handler output"""
    
    def __init__(self):
        self.status = None
        self.headers = {}
        self.wfile = BytesIO()
    
    def send_response(self, status):
        self.status = status
    
    def send_header(self, name, value):
        self.headers[name] = value
    
    def end_headers(self):
        pass


@pytest.fixture
def mock_handler():
    """Create a mock handler with test app status"""
    app_status = {
        'uptime': '0:10:00',
        'logs_processed': 1234,
        'threats_detected': 5,
        'api_calls': 20,
        'api_errors': 1,
        'last_report_time': datetime.now().isoformat()
    }
    
    # Create handler with mock request and response
    handler = HealthCheckHandler.__new__(HealthCheckHandler)
    handler.app_status = app_status
    handler.path = '/health'
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = BytesIO()
    
    return handler


def test_health_check_handler_init():
    """Test HealthCheckHandler initialization with app_status"""
    app_status = {'test': 'status'}
    handler = HealthCheckHandler.__new__(HealthCheckHandler)
    handler.__init__(app_status=app_status)
    assert handler.app_status == app_status


def test_handle_health_check(mock_handler):
    """Test health check endpoint"""
    mock_handler._handle_health_check()
    
    # Check response headers
    mock_handler.send_response.assert_called_with(200)
    mock_handler.send_header.assert_called_with('Content-Type', 'application/json')
    mock_handler.end_headers.assert_called_once()
    
    # Check response body
    response = mock_handler.wfile.getvalue().decode('utf-8')
    response_data = json.loads(response)
    
    assert response_data['status'] == 'ok'
    assert 'timestamp' in response_data
    assert response_data['uptime'] == '0:10:00'
    assert response_data['version'] == '1.0.0'


def test_handle_metrics(mock_handler):
    """Test metrics endpoint"""
    mock_handler.path = '/metrics'
    mock_handler._handle_metrics()
    
    # Check response headers
    mock_handler.send_response.assert_called_with(200)
    mock_handler.send_header.assert_called_with('Content-Type', 'application/json')
    mock_handler.end_headers.assert_called_once()
    
    # Check response body
    response = mock_handler.wfile.getvalue().decode('utf-8')
    response_data = json.loads(response)
    
    assert response_data['logs_processed'] == 1234
    assert response_data['threats_detected'] == 5
    assert response_data['api_calls'] == 20
    assert response_data['api_errors'] == 1
    assert 'system' in response_data
    assert 'hostname' in response_data['system']


def test_get_memory_usage():
    """Test memory usage retrieval"""
    handler = HealthCheckHandler.__new__(HealthCheckHandler)
    
    # Test with psutil available
    with patch.dict('sys.modules', {'psutil': MagicMock()}):
        mock_process = MagicMock()
        mock_process.memory_info.return_value.rss = 1024 * 1024 * 100  # 100 MB
        
        with patch('psutil.Process', return_value=mock_process):
            memory = handler._get_memory_usage()
            assert memory == '100.0 MB'
    
    # Test with psutil import error
    with patch.dict('sys.modules', {'psutil': None}):
        with patch('importlib.import_module', side_effect=ImportError()):
            memory = handler._get_memory_usage()
            assert memory == 'N/A (psutil not installed)'


def test_do_get(mock_handler):
    """Test GET request handling"""
    # Test health endpoint
    mock_handler.path = '/health'
    with patch.object(mock_handler, '_handle_health_check') as mock_health:
        mock_handler.do_GET()
        mock_health.assert_called_once()
    
    # Test metrics endpoint
    mock_handler.path = '/metrics'
    with patch.object(mock_handler, '_handle_metrics') as mock_metrics:
        mock_handler.do_GET()
        mock_metrics.assert_called_once()
    
    # Test unknown endpoint
    mock_handler.path = '/unknown'
    mock_handler.send_response = MagicMock()
    mock_handler.do_GET()
    mock_handler.send_response.assert_called_with(404)


def test_health_check_server_init():
    """Test HealthCheckServer initialization"""
    app_status = {'test': 'status'}
    server = HealthCheckServer(host='127.0.0.1', port=8080, app_status=app_status)
    
    assert server.host == '127.0.0.1'
    assert server.port == 8080
    assert server.app_status == app_status


def test_health_check_server_start_stop():
    """Test starting and stopping the health check server"""
    app_status = {'test': 'status'}
    server = HealthCheckServer(app_status=app_status)
    
    # Mock HTTPServer to prevent actual server creation
    with patch('http.server.HTTPServer') as mock_http_server, \
         patch('threading.Thread') as mock_thread:
        
        # Start server
        server.start()
        
        # Check that server was created with correct parameters
        mock_http_server.assert_called_once()
        mock_thread.assert_called_once()
        
        # Check that thread was started
        assert mock_thread.return_value.daemon is True
        mock_thread.return_value.start.assert_called_once()
        
        # Stop server
        server.stop()
        
        # Check that server was shut down
        mock_http_server.return_value.shutdown.assert_called_once()
        mock_thread.return_value.join.assert_called_once()
