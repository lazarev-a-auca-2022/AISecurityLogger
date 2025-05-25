#!/usr/bin/env python3
"""
Test the report generation behavior when log directory is empty
"""

import asyncio
import os
import sys
from pathlib import Path
import shutil
import time
import logging

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config.settings import Settings
from storage.database import Database
from reporting.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    """Test the report generation with and without logs"""
    settings = Settings()
    
    # Set up paths
    data_dir = Path(__file__).parent.parent / "data"
    logs_dir = data_dir / "logs"
    test_log_file = logs_dir / "test.log"
    reports_dir = Path(__file__).parent.parent / "reports"
    
    # Initialize database
    database = Database(settings.db_path)
    await database.initialize()
    
    # Initialize report generator
    report_generator = ReportGenerator(settings, database)
    
    # Test 1: Empty logs directory
    logger.info("TEST 1: Testing report generation with empty logs directory")
    
    # Make sure logs directory exists but is empty
    logs_dir.mkdir(parents=True, exist_ok=True)
    for file in logs_dir.glob("*"):
        if file.is_file():
            file.unlink()
    
    # Generate report with force=False (should not generate a report)
    logger.info("Generating report with empty logs directory (force=False)")
    report_path = await report_generator.generate_report(force=False)
    
    if report_path:
        logger.error(f"ERROR: Report was generated despite empty logs directory: {report_path}")
    else:
        logger.info("SUCCESS: No report was generated with empty logs directory")
    
    # Generate report with force=True (should generate a report with warning)
    logger.info("Generating report with empty logs directory (force=True)")
    report_path = await report_generator.generate_report(force=True)
    
    if report_path:
        logger.info(f"SUCCESS: Report was generated with force=True: {report_path}")
    else:
        logger.error("ERROR: No report was generated even with force=True")
    
    # Test 2: With logs present
    logger.info("TEST 2: Testing report generation with logs present")
    
    # Create a test log file with some security-related content
    with open(test_log_file, "w") as f:
        f.write("[2025-05-25 10:15:30] ERROR: Multiple failed login attempts for user admin from IP 203.0.113.42\n")
        f.write("[2025-05-25 10:15:35] WARNING: High CPU usage detected: 85%\n")
        f.write("[2025-05-25 10:15:40] CRITICAL: Database dump attempt detected from unauthorized process\n")
    
    # Give the log ingestor time to process the file (in a real scenario)
    logger.info(f"Created test log file: {test_log_file}")
    logger.info("In a real scenario, the log ingestor would need time to process this file")
    
    # Clean up
    await database.close()
    logger.info("Tests completed")

if __name__ == "__main__":
    asyncio.run(main())
