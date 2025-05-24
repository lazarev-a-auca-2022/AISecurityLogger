#!/bin/bash

# Force a new report generation
echo "Forcing a new report generation..."

# Create test directory if it doesn't exist
mkdir -p test_logs

# Create a test log file with security-relevant content
echo "Creating test log file..."
cat > test_logs/test5.log << EOF
May 25 14:30:45 testserver sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 49812 ssh2
May 25 14:31:12 testserver sshd[12346]: Failed password for invalid user admin from 192.168.1.100 port 49813 ssh2
May 25 14:31:45 testserver sshd[12347]: Failed password for invalid user admin from 192.168.1.100 port 49814 ssh2
May 25 14:32:13 testserver sshd[12348]: Failed password for invalid user admin from 192.168.1.100 port 49815 ssh2
May 25 14:32:47 testserver sshd[12349]: Failed password for invalid user admin from 192.168.1.100 port 49816 ssh2
EOF

# Run the application with test logs and force report generation
echo "Running AISecurityLogger with test logs and forcing report generation..."

# Run the Python script to generate a report
python -c "
import asyncio
import sys
import os
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path('src')))

from config.settings import Settings
from storage.database import Database
from reporting.report_generator import ReportGenerator

async def main():
    print('Forcing report generation...')
    settings = Settings()
    database = Database(settings.db_path)
    await database.initialize()
    
    report_generator = ReportGenerator(settings, database)
    report_path = await report_generator.generate_report(time_range=86400*7)  # 7 days
    
    print(f'Report generated at: {report_path}')
    await database.close()

asyncio.run(main())
"

echo "Report generation complete!"

# Check if the report was generated
ls -la reports/
