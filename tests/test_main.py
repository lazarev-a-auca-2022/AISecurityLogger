"""
Tests for Main Application Module
"""

import os
import time
import asyncio
import pytest
import signal
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock, call

# Add src to Python path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import AISecurityLogger


@pytest.fixture
def mock_components():
    """Create mock components for testing"""
    # Mock settings
    settings = MagicMock()
    settings.log_file = '/app/data/logs/application.log'
    settings.log_level = 'INFO'
    
    # Mock database
    database = MagicMock()
    database.initialize = AsyncMock()
    
    # Mock threat analyzer
    threat_analyzer = MagicMock()
    threat_analyzer.start_session = AsyncMock()
    
    # Mock log ingestor
    log_ingestor = MagicMock()
    log_ingestor.start = AsyncMock()
    log_ingestor.stop = AsyncMock()
    
    # Mock report generator
    report_generator = MagicMock()
    report_generator.start_scheduler = AsyncMock()
    report_generator.stop = AsyncMock()
    
    # Mock health server
    health_server = MagicMock()
    health_server.start = MagicMock()
    health_server.stop = MagicMock()
    
    return {
        'settings': settings,
        'database': database,
        'threat_analyzer': threat_analyzer,
        'log_ingestor': log_ingestor,
        'report_generator': report_generator,
        'health_server': health_server
    }


@pytest.fixture
def app_with_mocks(mock_components):
    """Create app instance with mocked components"""
    with patch('src.main.Settings', return_value=mock_components['settings']), \
         patch('src.main.Database', return_value=mock_components['database']), \
         patch('src.main.ThreatAnalyzer', return_value=mock_components['threat_analyzer']), \
         patch('src.main.LogIngestor', return_value=mock_components['log_ingestor']), \
         patch('src.main.ReportGenerator', return_value=mock_components['report_generator']), \
         patch('src.main.HealthCheckServer', return_value=mock_components['health_server']), \
         patch('pathlib.Path.mkdir'):
        
        app = AISecurityLogger()
        app._update_status = AsyncMock()  # Mock the update status method
        
        return app


def test_ai_security_logger_init(app_with_mocks, mock_components):
    """Test AISecurityLogger initialization"""
    app = app_with_mocks
    
    # Check component initialization
    assert app.settings == mock_components['settings']
    assert app.database == mock_components['database']
    assert app.threat_analyzer == mock_components['threat_analyzer']
    assert app.log_ingestor == mock_components['log_ingestor']
    assert app.report_generator == mock_components['report_generator']
    assert app.health_server == mock_components['health_server']
    
    # Check app status
    assert app.running == False
    assert 'uptime' in app.app_status
    assert 'logs_processed' in app.app_status
    assert 'threats_detected' in app.app_status


def test_setup_logging(app_with_mocks):
    """Test logging setup"""
    app = app_with_mocks
    
    with patch('logging.basicConfig') as mock_logging_config, \
         patch('pathlib.Path.mkdir') as mock_mkdir:
        
        app._setup_logging()
        
        # Check that log directory was created
        mock_mkdir.assert_called_once()
        
        # Check logging configuration
        mock_logging_config.assert_called_once()
        args, kwargs = mock_logging_config.call_args
        assert kwargs['level'] == getattr(logging, app.settings.log_level)
        assert len(kwargs['handlers']) == 2  # File handler and stream handler


@pytest.mark.asyncio
async def test_start(app_with_mocks, mock_components):
    """Test starting the application"""
    app = app_with_mocks
    
    # Start the app
    await app.start()
    
    # Check that components were started
    mock_components['database'].initialize.assert_called_once()
    mock_components['threat_analyzer'].start_session.assert_called_once()
    mock_components['log_ingestor'].start.assert_called_once()
    mock_components['report_generator'].start_scheduler.assert_called_once()
    mock_components['health_server'].start.assert_called_once()
    
    # Check that running flag was set
    assert app.running == True
    
    # Check that update status was started
    app._update_status.assert_called_once()


@pytest.mark.asyncio
async def test_stop(app_with_mocks, mock_components):
    """Test stopping the application"""
    app = app_with_mocks
    app.running = True
    
    # Stop the app
    await app.stop()
    
    # Check that components were stopped
    mock_components['log_ingestor'].stop.assert_called_once()
    mock_components['report_generator'].stop.assert_called_once()
    mock_components['health_server'].stop.assert_called_once()
    
    # Check that running flag was cleared
    assert app.running == False


@pytest.mark.asyncio
async def test_update_status(app_with_mocks):
    """Test status update method"""
    app = app_with_mocks
    
    # Replace _update_status with the real implementation
    app._update_status = AISecurityLogger._update_status.__get__(app, AISecurityLogger)
    
    # Set the start time
    app.start_time = time.time() - 60  # 1 minute ago
    app.running = True
    
    # Create a task to run update_status for a short time
    task = asyncio.create_task(app._update_status())
    
    # Let it run briefly
    await asyncio.sleep(0.1)
    
    # Stop the task
    app.running = False
    await asyncio.sleep(0.1)
    task.cancel()
    
    try:
        await task
    except asyncio.CancelledError:
        pass
    
    # Check that uptime was updated
    assert '0:01:' in app.app_status['uptime']  # Should be around 1 minute


def test_signal_handler(app_with_mocks):
    """Test signal handler"""
    app = app_with_mocks
    
    # Replace the async stop method with a sync version for testing
    app.stop = MagicMock()
    
    with patch('asyncio.get_event_loop') as mock_get_loop:
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        
        # Call signal handler
        app._signal_handler(signal.SIGINT, None)
        
        # Check that stop was scheduled on the event loop
        mock_loop.create_task.assert_called_once_with(app.stop())


@pytest.mark.asyncio
async def test_main_function():
    """Test main function"""
    # Mock AISecurityLogger
    mock_app = MagicMock()
    mock_app.start = AsyncMock()
    mock_app.stop = AsyncMock()
    
    with patch('src.main.AISecurityLogger', return_value=mock_app):
        # Run main function
        with patch('asyncio.run') as mock_run:
            from src.main import main
            await main()
            
            # Check that app was started and stopped
            mock_app.start.assert_called_once()
            
            # Run should not be called since we're calling main directly
            mock_run.assert_not_called()
