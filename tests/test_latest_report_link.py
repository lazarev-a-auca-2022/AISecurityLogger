"""
Test that the latest_report.html symlink is created correctly
"""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import time
import datetime
from pathlib import Path

# Add parent directory to path to allow importing from src
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.reporting.report_generator import ReportGenerator
from src.config.settings import Settings


class TestLatestReportLink(unittest.TestCase):
    """Test the creation of the latest_report.html symlink"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for test reports
        self.test_dir = tempfile.TemporaryDirectory()
        self.report_dir = Path(self.test_dir.name)
        
        # Mock settings and database
        self.mock_settings = MagicMock(spec=Settings)
        self.mock_settings.output_log_dir = str(self.report_dir)
        self.mock_settings.report_schedule = "daily"
        
        self.mock_db = MagicMock()
        self.mock_db.get_threats = MagicMock(return_value=[])
        
        # Create ReportGenerator with mocked dependencies
        self.report_generator = ReportGenerator(self.mock_settings, self.mock_db)
    
    def tearDown(self):
        """Clean up test environment"""
        self.test_dir.cleanup()
    
    @patch('time.time')
    async def test_latest_report_symlink_creation(self, mock_time):
        """Test that the latest_report.html symlink is created correctly"""
        # Set the current time
        current_time = datetime.datetime(2025, 5, 25, 10, 0, 0).timestamp()
        mock_time.return_value = current_time
        
        # Generate a report
        report_path = await self.report_generator.generate_report(force=True)
        
        # Check that the report was created
        self.assertTrue(os.path.exists(report_path))
        
        # Check that the latest_report.html symlink was created
        latest_report_path = os.path.join(self.mock_settings.output_log_dir, "latest_report.html")
        self.assertTrue(os.path.exists(latest_report_path))
        
        # Check that the symlink points to the correct file
        if os.path.islink(latest_report_path):
            target = os.readlink(latest_report_path)
            self.assertEqual(os.path.basename(report_path), target)
        else:
            # If it's not a symlink (on Windows), check that it has the same content
            with open(report_path, 'r') as f_orig, open(latest_report_path, 'r') as f_latest:
                self.assertEqual(f_orig.read(), f_latest.read())
    
    @patch('time.time')
    async def test_latest_report_symlink_update(self, mock_time):
        """Test that the latest_report.html symlink is updated when a new report is generated"""
        # Set the first time
        first_time = datetime.datetime(2025, 5, 25, 10, 0, 0).timestamp()
        mock_time.return_value = first_time
        
        # Generate first report
        first_report_path = await self.report_generator.generate_report(force=True)
        
        # Wait to ensure timestamp differs
        second_time = datetime.datetime(2025, 5, 25, 11, 0, 0).timestamp()
        mock_time.return_value = second_time
        
        # Generate second report
        second_report_path = await self.report_generator.generate_report(force=True)
        
        # Check that both reports exist
        self.assertTrue(os.path.exists(first_report_path))
        self.assertTrue(os.path.exists(second_report_path))
        
        # Check that the latest_report.html symlink points to the second report
        latest_report_path = os.path.join(self.mock_settings.output_log_dir, "latest_report.html")
        if os.path.islink(latest_report_path):
            target = os.readlink(latest_report_path)
            self.assertEqual(os.path.basename(second_report_path), target)
        else:
            # If it's not a symlink, check that it has the same content as the second report
            with open(second_report_path, 'r') as f_second, open(latest_report_path, 'r') as f_latest:
                self.assertEqual(f_second.read(), f_latest.read())


if __name__ == '__main__':
    unittest.main()
