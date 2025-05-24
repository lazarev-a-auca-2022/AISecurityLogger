"""
Tests for Database Module
"""

import os
import pytest
import aiosqlite
import tempfile
from unittest.mock import patch, MagicMock

# Add src to Python path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.database import Database


@pytest.fixture
async def temp_db():
    """Create a temporary database for testing"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, 'test.db')
    
    db = Database(db_path)
    await db.initialize()
    
    yield db
    
    # Clean up
    await db.close()
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.mark.asyncio
async def test_database_initialization():
    """Test database initialization"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, 'test.db')
    
    # Initialize database
    db = Database(db_path)
    await db.initialize()
    
    # Check that the database file was created
    assert os.path.exists(db_path)
    
    # Clean up
    await db.close()
    os.remove(db_path)


@pytest.mark.asyncio
async def test_store_and_get_threat(temp_db):
    """Test storing and retrieving a threat"""
    # Sample threat data
    threat_data = {
        'timestamp': 1621234567.89,
        'threat_detected': True,
        'severity': 'WARNING',
        'summary': 'Test threat',
        'details': 'Test details',
        'recommended_actions': 'Test actions',
        'log_entries': [
            {'source_file': 'test.log', 'raw_line': 'Test log entry'}
        ]
    }
    
    # Store threat
    threat_id = await temp_db.store_threat(threat_data)
    assert threat_id > 0
    
    # Get threat by ID
    retrieved_threat = await temp_db.get_threat_by_id(threat_id)
    
    # Check that the retrieved threat matches the original
    assert retrieved_threat is not None
    assert retrieved_threat['severity'] == 'WARNING'
    assert retrieved_threat['summary'] == 'Test threat'
    assert len(retrieved_threat['log_entries']) == 1
    assert retrieved_threat['log_entries'][0]['raw_line'] == 'Test log entry'


@pytest.mark.asyncio
async def test_get_threats_with_filtering(temp_db):
    """Test getting threats with filtering"""
    # Sample threat data
    threats = [
        {
            'timestamp': 1621234567.89,
            'threat_detected': True,
            'severity': 'WARNING',
            'summary': 'Warning threat',
            'details': 'Test details',
            'recommended_actions': 'Test actions',
            'log_entries': [{'source_file': 'test.log', 'raw_line': 'Warning log entry'}]
        },
        {
            'timestamp': 1621234568.89,
            'threat_detected': True,
            'severity': 'ERROR',
            'summary': 'Error threat',
            'details': 'Test details',
            'recommended_actions': 'Test actions',
            'log_entries': [{'source_file': 'test.log', 'raw_line': 'Error log entry'}]
        },
        {
            'timestamp': 1621234569.89,
            'threat_detected': True,
            'severity': 'CRITICAL',
            'summary': 'Critical threat',
            'details': 'Test details',
            'recommended_actions': 'Test actions',
            'log_entries': [{'source_file': 'test.log', 'raw_line': 'Critical log entry'}]
        }
    ]
    
    # Store threats
    for threat in threats:
        await temp_db.store_threat(threat)
    
    # Get all threats
    all_threats = await temp_db.get_threats()
    assert len(all_threats) == 3
    
    # Filter by severity
    warning_threats = await temp_db.get_threats(severity='WARNING')
    assert len(warning_threats) == 1
    assert warning_threats[0]['summary'] == 'Warning threat'
    
    # Filter by time range
    time_filtered_threats = await temp_db.get_threats(start_time=1621234568.0)
    assert len(time_filtered_threats) == 2
    
    # Check count
    count = await temp_db.get_threats_count()
    assert count == 3
    
    # Check count with filter
    count_critical = await temp_db.get_threats_count(severity='CRITICAL')
    assert count_critical == 1
