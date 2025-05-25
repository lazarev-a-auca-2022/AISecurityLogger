"""
Tests for Database Initialization Tool
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.init_db import init_db


@pytest.mark.asyncio
async def test_init_db_success():
    """Test successful database initialization"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, 'test.db')
        
        # Mock Database class
        mock_db = AsyncMock()
        mock_db.initialize = AsyncMock()
        mock_db.close = AsyncMock()
        
        # Mock environment and Database constructor
        with patch.dict('os.environ', {'DB_PATH': db_path}), \
             patch('tools.init_db.Database', return_value=mock_db):
            
            # Call init_db
            exit_code = await init_db()
            
            # Check that database was initialized
            mock_db.initialize.assert_called_once()
            mock_db.close.assert_called_once()
            
            # Check exit code
            assert exit_code == 0


@pytest.mark.asyncio
async def test_init_db_creates_directory():
    """Test that init_db creates the database directory"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, 'subdir', 'test.db')
        
        # Check that directory doesn't exist yet
        assert not os.path.exists(os.path.dirname(db_path))
        
        # Mock Database class
        mock_db = AsyncMock()
        
        # Mock environment and Database constructor
        with patch.dict('os.environ', {'DB_PATH': db_path}), \
             patch('tools.init_db.Database', return_value=mock_db):
            
            # Call init_db
            await init_db()
            
            # Check that directory was created
            assert os.path.exists(os.path.dirname(db_path))


@pytest.mark.asyncio
async def test_init_db_error_handling():
    """Test error handling in init_db"""
    # Mock Database class to raise an exception
    mock_db = AsyncMock()
    mock_db.initialize = AsyncMock(side_effect=Exception("Test error"))
    
    # Mock environment and Database constructor
    with patch('tools.init_db.Database', return_value=mock_db), \
         patch('logging.getLogger') as mock_logger:
        
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance
        
        # Call init_db
        exit_code = await init_db()
        
        # Check that error was logged
        mock_logger_instance.error.assert_called_once()
        assert "Test error" in str(mock_logger_instance.error.call_args)
        
        # Check exit code
        assert exit_code == 1


def test_main_function():
    """Test main function execution"""
    # Mock asyncio.run and sys.exit
    with patch('asyncio.run', return_value=0) as mock_run, \
         patch('sys.exit') as mock_exit:
        
        # Import and run __main__ code
        from tools.init_db import __name__ as module_name
        if module_name == "__main__":
            # This would run the main code, but we're mocking it
            pass
        
        # Since we mocked the entire module, we can only verify
        # that our patches worked as expected
        assert mock_run.called
        mock_exit.assert_called_with(0)
