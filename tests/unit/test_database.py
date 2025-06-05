"""
Unit tests for the Database class
"""

import asyncio
import tempfile
import os
import pytest
import json
from datetime import datetime, timedelta
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from storage.database import Database


class TestDatabase:
    """Test cases for Database"""

    def setup_method(self):
        """Set up test fixtures"""
        # Create temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.database = Database(self.db_path)

    def teardown_method(self):
        """Clean up after tests"""
        # Close database connection and remove temp file
        asyncio.run(self._cleanup())

    async def _cleanup(self):
        """Async cleanup method"""
        if self.database.db:
            await self.database.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_init(self):
        """Test Database initialization"""
        assert self.database.db_path == self.db_path
        assert self.database.db is None

    def test_init_creates_directory(self):
        """Test that initialization creates parent directory"""
        # Test with nested path
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_path = os.path.join(temp_dir, 'subdir', 'db', 'test.db')
            db = Database(nested_path)
            
            # Parent directory should be created
            assert os.path.exists(os.path.dirname(nested_path))

    @pytest.mark.asyncio
    async def test_initialize_creates_tables(self):
        """Test that initialize creates the threats table"""
        await self.database.initialize()
        
        # Check that threats table exists
        cursor = await self.database.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='threats'"
        )
        result = await cursor.fetchone()
        assert result is not None
        assert result[0] == 'threats'

    @pytest.mark.asyncio
    async def test_initialize_table_structure(self):
        """Test that the threats table has correct structure"""
        await self.database.initialize()
        
        # Check table structure
        cursor = await self.database.db.execute("PRAGMA table_info(threats)")
        columns = await cursor.fetchall()
        
        expected_columns = {
            'id', 'timestamp', 'detected_at', 'threat_detected', 
            'severity', 'summary', 'details', 'recommended_actions', 'log_entries'
        }
        actual_columns = {col[1] for col in columns}
        
        assert expected_columns == actual_columns

    @pytest.mark.asyncio
    async def test_close(self):
        """Test database connection closure"""
        await self.database.initialize()
        db_connection = self.database.db
        
        await self.database.close()
        
        # Connection should be closed
        assert db_connection is not None
        # Note: aiosqlite doesn't provide a direct way to check if closed

    @pytest.mark.asyncio
    async def test_close_when_not_initialized(self):
        """Test closing database when not initialized"""
        # Should not raise exception
        await self.database.close()

    @pytest.mark.asyncio
    async def test_store_threat_basic(self):
        """Test storing basic threat data"""
        await self.database.initialize()
        
        threat_data = {
            'threat_detected': True,
            'severity': 'HIGH',
            'summary': 'Test threat',
            'details': 'Detailed description',
            'recommended_actions': 'Take action',
            'log_entries': [{'message': 'test log', 'timestamp': '2024-01-01'}]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        
        assert isinstance(threat_id, int)
        assert threat_id > 0

    @pytest.mark.asyncio
    async def test_store_threat_full_data(self):
        """Test storing threat with all fields"""
        await self.database.initialize()
        
        threat_data = {
            'threat_detected': True,
            'severity': 'CRITICAL',
            'summary': 'Critical security threat detected',
            'details': 'SQL injection attempt from suspicious IP',
            'recommended_actions': 'Block IP, review logs, update firewall rules',
            'log_entries': [
                {'message': 'SQL injection detected', 'timestamp': '2024-01-01T12:00:00'},
                {'message': 'Multiple failed login attempts', 'timestamp': '2024-01-01T12:01:00'}
            ]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        
        # Verify stored data
        stored_threat = await self.database.get_threat_by_id(threat_id)
        assert stored_threat is not None
        assert stored_threat['threat_detected'] == threat_data['threat_detected']
        assert stored_threat['severity'] == threat_data['severity']
        assert stored_threat['summary'] == threat_data['summary']

    @pytest.mark.asyncio
    async def test_store_threat_no_threat_detected(self):
        """Test storing data when no threat is detected"""
        await self.database.initialize()
        
        threat_data = {
            'threat_detected': False,
            'severity': 'INFO',
            'summary': 'No threats found',
            'details': 'Log analysis completed successfully',
            'recommended_actions': 'Continue monitoring',
            'log_entries': [{'message': 'normal log', 'timestamp': '2024-01-01'}]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        assert threat_id > 0

    @pytest.mark.asyncio
    async def test_get_threats_all(self):
        """Test retrieving all threats"""
        await self.database.initialize()
        
        # Store multiple threats
        threats = []
        for i in range(3):
            threat_data = {
                'threat_detected': True,
                'severity': 'HIGH',
                'summary': f'Test threat {i}',
                'details': f'Details {i}',
                'recommended_actions': f'Action {i}',
                'log_entries': [{'message': f'log {i}'}]
            }
            await self.database.store_threat(threat_data)
        
        # Retrieve all threats
        retrieved_threats = await self.database.get_threats()
        
        assert len(retrieved_threats) == 3
        assert all('id' in threat for threat in retrieved_threats)

    @pytest.mark.asyncio
    async def test_get_threats_with_limit(self):
        """Test retrieving threats with limit"""
        await self.database.initialize()
        
        # Store 5 threats
        for i in range(5):
            threat_data = {
                'threat_detected': True,
                'severity': 'MEDIUM',
                'summary': f'Threat {i}',
                'log_entries': [{'message': f'log {i}'}]
            }
            await self.database.store_threat(threat_data)
        
        # Retrieve with limit
        threats = await self.database.get_threats(limit=3)
        assert len(threats) == 3

    @pytest.mark.asyncio
    async def test_get_threats_with_offset(self):
        """Test retrieving threats with offset"""
        await self.database.initialize()
        
        # Store threats with distinguishable data
        summaries = []
        for i in range(5):
            summary = f'Unique threat {i}'
            summaries.append(summary)
            threat_data = {
                'threat_detected': True,
                'severity': 'LOW',
                'summary': summary,
                'log_entries': [{'message': f'log {i}'}]
            }
            await self.database.store_threat(threat_data)
        
        # Get with offset
        threats = await self.database.get_threats(offset=2, limit=2)
        assert len(threats) == 2
        
        # Should skip first 2 (offset=2) and return next 2
        retrieved_summaries = [t['summary'] for t in threats]
        # Note: Order depends on timestamp, so we check that we got 2 different ones
        assert len(set(retrieved_summaries)) == 2

    @pytest.mark.asyncio
    async def test_get_threats_severity_filter(self):
        """Test retrieving threats filtered by severity"""
        await self.database.initialize()
        
        # Store threats with different severities
        severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        for severity in severities:
            threat_data = {
                'threat_detected': True,
                'severity': severity,
                'summary': f'{severity} threat',
                'log_entries': [{'message': f'{severity} log'}]
            }
            await self.database.store_threat(threat_data)
        
        # Filter by HIGH severity (using correct parameter name)
        high_threats = await self.database.get_threats(severity='HIGH')
        assert len(high_threats) == 1
        assert high_threats[0]['severity'] == 'HIGH'

    @pytest.mark.asyncio
    async def test_get_threats_date_range_filter(self):
        """Test retrieving threats filtered by date range"""
        await self.database.initialize()
        
        # Store threats at different times
        base_time = datetime.now()
        for i in range(3):
            threat_data = {
                'threat_detected': True,
                'severity': 'MEDIUM',
                'summary': f'Time-based threat {i}',
                'log_entries': [{'message': f'log {i}'}]
            }
            await self.database.store_threat(threat_data)
        
        # Filter by date range (last hour) - using correct parameter names and timestamp format
        now = datetime.now().timestamp()
        since = now - 3600  # 1 hour ago
        until = now + 3600  # 1 hour from now
        
        filtered_threats = await self.database.get_threats(start_time=since, end_time=until)
        assert len(filtered_threats) == 3

    @pytest.mark.asyncio
    async def test_get_threat_by_id_exists(self):
        """Test retrieving specific threat by ID"""
        await self.database.initialize()
        
        threat_data = {
            'threat_detected': True,
            'severity': 'HIGH',
            'summary': 'Specific threat',
            'details': 'Specific details',
            'recommended_actions': 'Specific actions',
            'log_entries': [{'message': 'specific log'}]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        retrieved_threat = await self.database.get_threat_by_id(threat_id)
        
        assert retrieved_threat is not None
        assert retrieved_threat['id'] == threat_id
        assert retrieved_threat['summary'] == 'Specific threat'

    @pytest.mark.asyncio
    async def test_get_threat_by_id_not_exists(self):
        """Test retrieving non-existent threat by ID"""
        await self.database.initialize()
        
        result = await self.database.get_threat_by_id(999999)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_threats_count_all(self):
        """Test counting all threats"""
        await self.database.initialize()
        
        # Store some threats
        for i in range(4):
            threat_data = {
                'threat_detected': True,
                'severity': 'MEDIUM',
                'summary': f'Count test {i}',
                'log_entries': [{'message': f'log {i}'}]
            }
            await self.database.store_threat(threat_data)
        
        count = await self.database.get_threats_count()
        assert count == 4

    @pytest.mark.asyncio
    async def test_get_threats_count_with_filters(self):
        """Test counting threats with filters"""
        await self.database.initialize()
        
        # Store threats with different severities
        for severity in ['LOW', 'HIGH', 'HIGH']:
            threat_data = {
                'threat_detected': True,
                'severity': severity,
                'summary': f'{severity} threat',
                'log_entries': [{'message': f'{severity} log'}]
            }
            await self.database.store_threat(threat_data)
        
        # Count HIGH severity threats (using correct parameter name)
        high_count = await self.database.get_threats_count(severity='HIGH')
        assert high_count == 2
        
        # Count all threats
        total_count = await self.database.get_threats_count()
        assert total_count == 3

    @pytest.mark.asyncio
    async def test_delete_threat_exists(self):
        """Test deleting existing threat"""
        await self.database.initialize()
        
        threat_data = {
            'threat_detected': True,
            'severity': 'LOW',
            'summary': 'To be deleted',
            'log_entries': [{'message': 'delete me'}]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        
        # Delete the threat
        success = await self.database.delete_threat(threat_id)
        assert success is True
        
        # Verify it's deleted
        deleted_threat = await self.database.get_threat_by_id(threat_id)
        assert deleted_threat is None

    @pytest.mark.asyncio
    async def test_delete_threat_not_exists(self):
        """Test deleting non-existent threat"""
        await self.database.initialize()
        
        success = await self.database.delete_threat(999999)
        assert success is False

    @pytest.mark.asyncio
    async def test_log_entries_json_serialization(self):
        """Test that log entries are properly serialized/deserialized"""
        await self.database.initialize()
        
        complex_log_entries = [
            {
                'timestamp': '2024-01-01T12:00:00Z',
                'message': 'Complex log entry',
                'source': 'nginx',
                'client_ip': '192.168.1.1',
                'method': 'POST',
                'url': '/api/login',
                'status': 401,
                'nested': {'key': 'value', 'list': [1, 2, 3]}
            }
        ]
        
        threat_data = {
            'threat_detected': True,
            'severity': 'MEDIUM',
            'summary': 'JSON test',
            'log_entries': complex_log_entries
        }
        
        threat_id = await self.database.store_threat(threat_data)
        retrieved = await self.database.get_threat_by_id(threat_id)
        
        # Log entries should be properly deserialized
        assert retrieved['log_entries'] == complex_log_entries

    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent database operations"""
        await self.database.initialize()
        
        async def store_threat(i):
            threat_data = {
                'threat_detected': True,
                'severity': 'MEDIUM',
                'summary': f'Concurrent threat {i}',
                'log_entries': [{'message': f'concurrent log {i}'}]
            }
            return await self.database.store_threat(threat_data)
        
        # Store threats concurrently
        tasks = [store_threat(i) for i in range(5)]
        threat_ids = await asyncio.gather(*tasks)
        
        # All should succeed
        assert len(threat_ids) == 5
        assert all(isinstance(tid, int) and tid > 0 for tid in threat_ids)
        
        # Count should be correct
        count = await self.database.get_threats_count()
        assert count == 5

    @pytest.mark.asyncio
    async def test_empty_database_queries(self):
        """Test queries on empty database"""
        await self.database.initialize()
        
        # Get threats from empty DB
        threats = await self.database.get_threats()
        assert threats == []
        
        # Count threats in empty DB
        count = await self.database.get_threats_count()
        assert count == 0
        
        # Get non-existent threat
        threat = await self.database.get_threat_by_id(1)
        assert threat is None

    @pytest.mark.asyncio
    async def test_database_error_handling(self):
        """Test database error handling"""
        await self.database.initialize()
        
        # Close the database to simulate connection error
        await self.database.close()
        
        # Try to store data when database is closed - should return -1 (error)
        result = await self.database.store_threat({
            'threat_detected': True,
            'severity': 'HIGH',
            'summary': 'Test threat'
        })
        assert result == -1

    @pytest.mark.asyncio
    async def test_threat_data_completeness(self):
        """Test that stored threats contain all expected fields"""
        await self.database.initialize()
        
        threat_data = {
            'threat_detected': True,
            'severity': 'HIGH',
            'summary': 'Complete test',
            'details': 'All fields test',
            'recommended_actions': 'Test actions',
            'log_entries': [{'test': 'entry'}]
        }
        
        threat_id = await self.database.store_threat(threat_data)
        retrieved = await self.database.get_threat_by_id(threat_id)
        
        # Check all expected fields are present
        expected_fields = {
            'id', 'timestamp', 'detected_at', 'threat_detected',
            'severity', 'summary', 'details', 'recommended_actions', 'log_entries'
        }
        assert set(retrieved.keys()) == expected_fields
        
        # Check timestamp is reasonable (within last minute)
        stored_time = datetime.fromisoformat(retrieved['detected_at'])
        time_diff = datetime.now() - stored_time
        assert time_diff.total_seconds() < 60

    @pytest.mark.asyncio
    async def test_ordering_by_timestamp(self):
        """Test that threats are returned in timestamp order"""
        await self.database.initialize()
        
        # Store threats with slight delays to ensure different timestamps
        threat_ids = []
        for i in range(3):
            threat_data = {
                'threat_detected': True,
                'severity': 'MEDIUM',
                'summary': f'Order test {i}',
                'log_entries': [{'order': i}]
            }
            threat_id = await self.database.store_threat(threat_data)
            threat_ids.append(threat_id)
            await asyncio.sleep(0.01)  # Small delay
        
        # Retrieve threats (should be ordered by timestamp desc)
        threats = await self.database.get_threats()
        
        # Latest should be first (assuming desc order)
        assert len(threats) == 3
        retrieved_ids = [t['id'] for t in threats]
        # Most recent first
        assert retrieved_ids == list(reversed(threat_ids))


if __name__ == '__main__':
    pytest.main([__file__])
