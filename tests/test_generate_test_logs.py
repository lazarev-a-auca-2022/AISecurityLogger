"""
Tests for Generate Test Logs Tool
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

# Add src to Python path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.generate_test_logs import generate_log, main, SAMPLE_LOGS


def test_generate_log_creates_file():
    """Test that generate_log creates the log file"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, 'test_logs', 'test.log')
        
        # Generate logs
        generate_log(log_file, num_logs=5, interval=0.01)
        
        # Check that file exists
        assert os.path.exists(log_file)
        
        # Check that file contains 5 lines
        with open(log_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 5


def test_generate_log_appends_to_existing_file():
    """Test that generate_log appends to an existing file"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, 'test.log')
        
        # Create initial file with some content
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, 'w') as f:
            f.write("Initial log line\n")
        
        # Generate logs
        generate_log(log_file, num_logs=3, interval=0.01)
        
        # Check that file contains 4 lines (1 initial + 3 generated)
        with open(log_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 4
            assert lines[0] == "Initial log line\n"


def test_generate_log_includes_security_logs():
    """Test that security logs are included when requested"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, 'test.log')
        
        # Force selection of security logs
        with patch('random.random', return_value=0.1), \
             patch('random.choice', return_value=SAMPLE_LOGS[15]):  # First security log
            
            # Generate logs
            generate_log(log_file, num_logs=10, interval=0.01, include_security=True)
            
            # Check that file contains security-related content
            with open(log_file, 'r') as f:
                content = f.read()
                assert "Multiple failed login attempts" in content


def test_generate_log_excludes_security_logs():
    """Test that security logs are excluded when requested"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, 'test.log')
        
        # Force selection of normal logs
        with patch('random.choice', return_value=SAMPLE_LOGS[0]):  # First normal log
            
            # Generate logs
            generate_log(log_file, num_logs=10, interval=0.01, include_security=False)
            
            # Check that file contains only normal logs
            with open(log_file, 'r') as f:
                content = f.read()
                assert "User logged in: user123" in content
                assert "Multiple failed login attempts" not in content


def test_main_function():
    """Test the main function with command line arguments"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, 'test.log')
        
        # Mock command line arguments
        test_args = [
            'generate_test_logs.py',
            '--file', log_file,
            '--num-logs', '2',
            '--interval', '0.01'
        ]
        
        # Mock generate_log to check arguments
        with patch('sys.argv', test_args), \
             patch('tools.generate_test_logs.generate_log') as mock_generate_log:
            
            # Call main function
            main()
            
            # Check that generate_log was called with correct arguments
            mock_generate_log.assert_called_once_with(
                log_file=log_file,
                num_logs=2,
                interval=0.01,
                include_security=True
            )


def test_main_function_no_security():
    """Test the main function with no-security flag"""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = os.path.join(temp_dir, 'test.log')
        
        # Mock command line arguments
        test_args = [
            'generate_test_logs.py',
            '--file', log_file,
            '--no-security'
        ]
        
        # Mock generate_log to check arguments
        with patch('sys.argv', test_args), \
             patch('tools.generate_test_logs.generate_log') as mock_generate_log:
            
            # Call main function
            main()
            
            # Check that generate_log was called with include_security=False
            mock_generate_log.assert_called_once_with(
                log_file=log_file,
                num_logs=10,  # Default
                interval=1.0,  # Default
                include_security=False
            )
