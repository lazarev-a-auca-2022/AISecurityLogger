"""
Tests for Settings Module
"""

import os
import pytest
from unittest.mock import patch, MagicMock

# Add src to Python path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.settings import Settings


@patch.object(Path, 'mkdir')
def test_settings_default_values(mock_mkdir):
    """Test that default values are set correctly"""
    # Clear environment variables that might interfere with the test
    with patch.dict(os.environ, {'OPENROUTER_API_KEY': 'dummy_key'}, clear=True):
        settings = Settings()
        
        # Check default values
        assert settings.openrouter_model_id == 'openai/gpt-3.5-turbo'
        assert settings.processing_interval == 60
        assert 'error' in settings.sensitivity_keywords
        assert 'warning' in settings.sensitivity_keywords
    
    # Verify mkdir was called
    mock_mkdir.assert_called()


@patch.object(Path, 'mkdir')
def test_settings_from_env(mock_mkdir):
    """Test that environment variables are loaded correctly"""
    test_env = {
        'OPENROUTER_API_KEY': 'test_api_key',
        'OPENROUTER_MODEL_ID': 'test_model',
        'PROCESSING_INTERVAL': '30',
        'SENSITIVITY_KEYWORDS': 'test1,test2,test3',
        'LOG_LEVEL': 'DEBUG'
    }
    
    with patch.dict(os.environ, test_env):
        settings = Settings()
        
        # Check values from environment
        assert settings.openrouter_api_key == 'test_api_key'
        assert settings.openrouter_model_id == 'test_model'
        assert settings.processing_interval == 30
        assert settings.sensitivity_keywords == ['test1', 'test2', 'test3']
        assert settings.log_level == 'DEBUG'
    
    # Verify mkdir was called
    mock_mkdir.assert_called()


@patch.object(Path, 'mkdir')
def test_validate_missing_api_key(mock_mkdir):
    """Test validation of required settings"""
    with patch.dict(os.environ, {}, clear=True):
        # API key is required, should raise an error
        with pytest.raises(ValueError):
            Settings()
    
    # With API key set, it should initialize correctly
    with patch.dict(os.environ, {'OPENROUTER_API_KEY': 'test_key'}):
        settings = Settings()
        assert settings.openrouter_api_key == 'test_key'
    
    # Verify mkdir was called
    mock_mkdir.assert_called()
