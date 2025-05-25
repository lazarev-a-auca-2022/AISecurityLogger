#!/usr/bin/env python3
"""
Test Runner Script for AI Security Logger
Runs all unit tests and generates a coverage report
"""

import os
import sys
import pytest
import subprocess
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))


def run_tests():
    """Run all tests with coverage reporting"""
    try:
        # Ensure pytest and pytest-cov are installed
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pytest', 'pytest-asyncio', 'pytest-cov'])
        
        print("Running tests with coverage reporting...")
        
        # Build coverage command
        cmd = [
            'pytest',
            'tests/',
            '-v',
            '--cov=src',
            '--cov=tools',
            '--cov-report=term',
            '--cov-report=html:reports/coverage'
        ]
        
        # Create coverage report directory
        os.makedirs('reports/coverage', exist_ok=True)
        
        # Run tests with coverage
        result = subprocess.run(cmd)
        
        if result.returncode == 0:
            print("\n✅ All tests passed!")
            print(f"Coverage report available at: {os.path.abspath('reports/coverage/index.html')}")
        else:
            print("\n❌ Some tests failed.")
            
        return result.returncode
    
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
