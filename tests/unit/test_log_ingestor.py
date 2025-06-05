"""
Unit tests for the LogIngestor and LogFileHandler classes
"""

import asyncio
import tempfile
import os
import pytest
import queue
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from ingestor.log_ingestor import LogIngestor, LogFileHandler


class MockSettings:
    """Mock settings for testing"""
    def __init__(self):
        self.log_sources = ['/tmp/test_logs']
        self.log_extensions = ['.log', '.txt']
        self.sensitivity_keywords = ['error', 'warning', 'critical', 'failed', 'denied']
        self.batch_size = 5
        self.batch_timeout = 30
        self.process_interval = 5


class TestLogFileHandler:
    """Test cases for LogFileHandler"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_ingestor = MagicMock()
        self.mock_ingestor.processed_files = set()
        self.mock_ingestor.files_to_rename = set()
        self.handler = LogFileHandler(self.mock_ingestor)

    def test_init(self):
        """Test LogFileHandler initialization"""
        assert self.handler.ingestor == self.mock_ingestor
        assert isinstance(self.handler.file_queue, queue.Queue)

    def test_on_created_valid_file(self):
        """Test file creation event handling for valid files"""
        event = MagicMock()
        event.is_directory = False
        event.src_path = '/tmp/test.log'
        
        self.handler.on_created(event)
        
        # Check that file was added to queue
        assert not self.handler.file_queue.empty()
        assert self.handler.file_queue.get() == '/tmp/test.log'

    def test_on_created_application_log_ignored(self):
        """Test that application.log files are ignored"""
        event = MagicMock()
        event.is_directory = False
        event.src_path = '/tmp/application.log'
        
        self.handler.on_created(event)
        
        # Queue should be empty
        assert self.handler.file_queue.empty()

    def test_on_created_directory_ignored(self):
        """Test that directory events are ignored"""
        event = MagicMock()
        event.is_directory = True
        event.src_path = '/tmp/testdir'
        
        self.handler.on_created(event)
        
        # Queue should be empty
        assert self.handler.file_queue.empty()

    def test_on_created_already_processed_ignored(self):
        """Test that already processed files are ignored"""
        event = MagicMock()
        event.is_directory = False
        event.src_path = '/tmp/test.log'
        
        # Add file to processed files
        self.mock_ingestor.processed_files.add('/tmp/test.log')
        
        self.handler.on_created(event)
        
        # Queue should be empty
        assert self.handler.file_queue.empty()

    def test_on_modified_valid_file(self):
        """Test file modification event handling for valid files"""
        event = MagicMock()
        event.is_directory = False
        event.src_path = '/tmp/test.log'
        
        self.handler.on_modified(event)
        
        # Check that file was added to queue
        assert not self.handler.file_queue.empty()
        assert self.handler.file_queue.get() == '/tmp/test.log'

    def test_on_modified_old_file_ignored(self):
        """Test that .old files are ignored on modification"""
        event = MagicMock()
        event.is_directory = False
        event.src_path = '/tmp/test.log.old'
        
        self.handler.on_modified(event)
        
        # Queue should be empty
        assert self.handler.file_queue.empty()


class TestLogIngestor:
    """Test cases for LogIngestor"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_settings = MockSettings()
        self.mock_threat_analyzer = AsyncMock()
        self.ingestor = LogIngestor(self.mock_settings, self.mock_threat_analyzer)

    @pytest.mark.asyncio
    async def test_init(self):
        """Test LogIngestor initialization"""
        assert self.ingestor.settings == self.mock_settings
        assert self.ingestor.threat_analyzer == self.mock_threat_analyzer
        assert self.ingestor.processed_files == set()
        assert self.ingestor.files_to_rename == set()
        assert self.ingestor.running is False

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test start and stop functionality"""
        with patch('watchdog.observers.Observer') as mock_observer:
            mock_observer_instance = MagicMock()
            mock_observer.return_value = mock_observer_instance
            mock_observer_instance.is_alive.return_value = False
            
            # Mock the file watching methods to prevent actual file system operations
            with patch.object(self.ingestor, '_setup_file_watchers'), \
                 patch.object(self.ingestor, '_process_existing_logs'), \
                 patch.object(self.ingestor, '_check_for_new_logs'), \
                 patch.object(self.ingestor, '_check_threat_analyzer_status'), \
                 patch.object(self.ingestor, '_rename_processed_files'):
                
                # Start the ingestor as a task
                start_task = asyncio.create_task(self.ingestor.start())
                await asyncio.sleep(0.1)  # Let it start
                
                assert self.ingestor.running is True
                
                # Stop the ingestor
                await self.ingestor.stop()
                
                # Cancel the start task to prevent it from hanging
                start_task.cancel()
                try:
                    await start_task
                except asyncio.CancelledError:
                    pass
                
                assert self.ingestor.running is False

    def test_contains_sensitive_keywords_true(self):
        """Test sensitive keyword detection - positive cases"""
        assert self.ingestor._contains_sensitive_keywords("error occurred")
        assert self.ingestor._contains_sensitive_keywords("WARNING: issue detected")
        assert self.ingestor._contains_sensitive_keywords("CRITICAL failure")
        assert self.ingestor._contains_sensitive_keywords("authentication failed")
        assert self.ingestor._contains_sensitive_keywords("access denied")

    def test_contains_sensitive_keywords_false(self):
        """Test sensitive keyword detection - negative cases"""
        assert not self.ingestor._contains_sensitive_keywords("info message")
        assert not self.ingestor._contains_sensitive_keywords("debug trace")
        assert not self.ingestor._contains_sensitive_keywords("normal operation")

    def test_determine_log_type_syslog(self):
        """Test log type determination for syslog"""
        assert self.ingestor._determine_log_type("/var/log/syslog") == "syslog"
        assert self.ingestor._determine_log_type("/var/log/messages") == "syslog"

    def test_determine_log_type_nginx(self):
        """Test log type determination for nginx"""
        assert self.ingestor._determine_log_type("/var/log/nginx/access.log") == "nginx"
        assert self.ingestor._determine_log_type("/var/log/nginx/error.log") == "nginx"

    def test_determine_log_type_apache(self):
        """Test log type determination for apache"""
        assert self.ingestor._determine_log_type("/var/log/apache2/access.log") == "apache"
        assert self.ingestor._determine_log_type("/var/log/httpd/error.log") == "apache"

    def test_determine_log_type_generic(self):
        """Test log type determination for generic logs"""
        assert self.ingestor._determine_log_type("/tmp/application.log") == "generic"
        assert self.ingestor._determine_log_type("/home/user/test.log") == "generic"

    def test_parse_log_line_syslog(self):
        """Test parsing syslog format"""
        line = "Jan  1 12:00:00 hostname daemon[1234]: Test message"
        result = self.ingestor._parse_log_line(line, "/var/log/syslog")
        
        assert result is not None
        assert result['log_type'] == 'syslog'
        assert result['message'] == 'Test message'
        assert result['service'] == 'daemon'
        assert result['source_file'] == '/var/log/syslog'

    def test_parse_log_line_nginx_access(self):
        """Test parsing nginx access log format"""
        line = '192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /test HTTP/1.1" 200 1234'
        result = self.ingestor._parse_log_line(line, "/var/log/nginx/access.log")
        
        assert result is not None
        assert result['log_type'] == 'nginx'
        assert result['client_ip'] == '192.168.1.1'
        assert result['method'] == 'GET'
        assert result['url'] == '/test'
        assert result['status'] == '200'

    def test_parse_log_line_nginx_error(self):
        """Test parsing nginx error log format"""
        line = "2024/01/01 12:00:00 [error] 1234#0: Test error message"
        result = self.ingestor._parse_log_line(line, "/var/log/nginx/error.log")
        
        assert result is not None
        assert result['log_type'] == 'nginx'
        assert result['level'] == 'error'
        assert result['message'] == 'Test error message'

    def test_parse_log_line_apache_access(self):
        """Test parsing apache access log format"""
        line = '192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "POST /api HTTP/1.1" 404 567'
        result = self.ingestor._parse_log_line(line, "/var/log/apache2/access.log")
        
        assert result is not None
        assert result['log_type'] == 'apache'
        assert result['client_ip'] == '192.168.1.1'
        assert result['method'] == 'POST'
        assert result['url'] == '/api'
        assert result['status'] == '404'

    def test_parse_log_line_generic(self):
        """Test parsing generic log format"""
        line = "2024-01-01 12:00:00 ERROR: Test error message"
        result = self.ingestor._parse_log_line(line, "/tmp/application.log")
        
        assert result is not None
        assert result['log_type'] == 'generic'
        assert result['message'] == line

    def test_parse_log_line_empty(self):
        """Test parsing empty log line"""
        result = self.ingestor._parse_log_line("", "/tmp/test.log")
        assert result is None

    def test_parse_log_line_whitespace_only(self):
        """Test parsing whitespace-only log line"""
        result = self.ingestor._parse_log_line("   \t  \n", "/tmp/test.log")
        assert result is None

    @pytest.mark.asyncio
    async def test_process_log_line_with_keywords(self):
        """Test processing log line containing sensitive keywords"""
        line = "2024-01-01 12:00:00 ERROR: Authentication failed"
        
        with patch.object(self.ingestor, '_parse_log_line') as mock_parse:
            mock_parse.return_value = {
                'timestamp': '2024-01-01 12:00:00',
                'message': 'Authentication failed',
                'log_type': 'generic'
            }
            
            await self.ingestor._process_log_line(line, "/tmp/test.log")
            
            # Should call threat analyzer
            self.mock_threat_analyzer.analyze_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_log_line_without_keywords(self):
        """Test processing log line without sensitive keywords"""
        line = "2024-01-01 12:00:00 INFO: Normal operation"
        
        with patch.object(self.ingestor, '_parse_log_line') as mock_parse:
            mock_parse.return_value = {
                'timestamp': '2024-01-01 12:00:00',
                'message': 'Normal operation',
                'log_type': 'generic'
            }
            
            await self.ingestor._process_log_line(line, "/tmp/test.log")
            
            # Should not call threat analyzer
            self.mock_threat_analyzer.analyze_log.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_log_line_unparseable(self):
        """Test processing unparseable log line"""
        line = "invalid log line"
        
        with patch.object(self.ingestor, '_parse_log_line') as mock_parse:
            mock_parse.return_value = None
            
            await self.ingestor._process_log_line(line, "/tmp/test.log")
            
            # Should not call threat analyzer
            self.mock_threat_analyzer.analyze_log.assert_not_called()

    def test_schedule_file_for_rename(self):
        """Test scheduling file for rename"""
        file_path = "/tmp/test.log"
        self.ingestor._schedule_file_for_rename(file_path)
        
        assert file_path in self.ingestor.files_to_rename

    @pytest.mark.asyncio
    async def test_rename_processed_files(self):
        """Test renaming processed files"""
        # Set up mock threat analyzer attributes to simulate idle state
        self.mock_threat_analyzer.processing = False
        self.mock_threat_analyzer.queue = []
        
        # Mock shutil.move to simulate a successful rename without actual file system operations
        with patch('shutil.move') as mock_shutil_move:
            # Create a dummy file path for the test
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                test_file_path = temp_file.name
            
            old_file_path = Path(test_file_path)
            new_file_path = Path(test_file_path + ".old")

            # Configure the mock to simulate the file being moved
            def side_effect_move(src, dst):
                # Simulate the source file no longer existing and the destination existing
                # In a real scenario, you might create dummy files and then delete/create them
                pass # We just need to ensure the mock is called

            mock_shutil_move.side_effect = side_effect_move
            
            try:
                # Add file to rename list
                self.ingestor.files_to_rename.add(test_file_path)
                
                await self.ingestor._rename_processed_files()
                
                # Assert that shutil.move was called with the correct paths
                mock_shutil_move.assert_called_once_with(test_file_path, str(new_file_path))
                
                # Assert that the file is marked as processed and removed from files_to_rename
                assert test_file_path in self.ingestor.processed_files
                assert len(self.ingestor.files_to_rename) == 0
            finally:
                # Clean up the dummy file
                if os.path.exists(test_file_path):
                    os.unlink(test_file_path)
                if os.path.exists(new_file_path):
                    os.unlink(new_file_path)

    @pytest.mark.asyncio
    async def test_rename_processed_files_nonexistent(self):
        """Test renaming non-existent files"""
        # Set up mock threat analyzer attributes to simulate idle state
        self.mock_threat_analyzer.processing = False
        self.mock_threat_analyzer.queue = []
        
        non_existent_file = "/tmp/nonexistent.log"
        self.ingestor.files_to_rename.add(non_existent_file)
        
        # Should not raise exception
        await self.ingestor._rename_processed_files()
        
        # File should be removed from rename list
        assert non_existent_file not in self.ingestor.files_to_rename

    @pytest.mark.asyncio
    async def test_tail_file(self):
        """Test tailing a file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            # Write test content
            lines = [f"Line {i}\n" for i in range(1, 11)]
            temp_file.writelines(lines)
            temp_file.flush()
            
            try:
                # Tail last 5 lines
                result = await self.ingestor._tail_file(temp_file.name, 5)
                
                assert len(result) == 5
                assert result[0].strip() == "Line 6"
                assert result[-1].strip() == "Line 10"
            finally:
                os.unlink(temp_file.name)

    @pytest.mark.asyncio
    async def test_tail_file_nonexistent(self):
        """Test tailing non-existent file"""
        result = await self.ingestor._tail_file("/tmp/nonexistent.log")
        assert result == []

    @pytest.mark.asyncio
    async def test_process_file(self):
        """Test processing a file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as temp_file:
            # Write test content with sensitive keywords
            temp_file.write("2024-01-01 12:00:00 ERROR: Test error\n")
            temp_file.write("2024-01-01 12:01:00 INFO: Normal message\n")
            temp_file.flush()
            
            try:
                await self.ingestor.process_file(temp_file.name)
                
                # File should be scheduled for rename
                assert temp_file.name in self.ingestor.files_to_rename
                
            finally:
                os.unlink(temp_file.name)

    @pytest.mark.asyncio
    async def test_process_file_already_processed(self):
        """Test processing already processed file"""
        file_path = "/tmp/test.log"
        self.ingestor.processed_files.add(file_path)
        
        with patch.object(self.ingestor, '_tail_file') as mock_tail:
            await self.ingestor.process_file(file_path)
            
            # Should not process the file
            mock_tail.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_threat_analyzer_status(self):
        """Test checking threat analyzer status"""
        mock_status = {
            "processing": False,
            "queue_size": 5,
            "last_processed": "2024-01-01T12:00:00"
        }
        self.mock_threat_analyzer.check_processing_status.return_value = mock_status
        
        await self.ingestor._check_threat_analyzer_status()
        
        self.mock_threat_analyzer.check_processing_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_force_complete_analysis(self):
        """Test forcing complete analysis"""
        # Mock the threat analyzer's processing and queue to simulate an active state
        self.mock_threat_analyzer.processing = True
        self.mock_threat_analyzer.queue = [1, 2, 3] # Simulate items in queue
        
        # Mock the _process_queue method of the threat analyzer to clear its queue
        async def mock_process_queue():
            self.mock_threat_analyzer.queue = []
            self.mock_threat_analyzer.processing = False

        self.mock_threat_analyzer._process_queue = mock_process_queue

        # Patch _rename_processed_files to ensure it's called
        with patch.object(self.ingestor, '_rename_processed_files') as mock_rename:
            await self.ingestor.force_complete_analysis()
            mock_rename.assert_called_once()

        # Assert that processing is reset and queue is empty after force completion
        assert self.mock_threat_analyzer.processing is False
        assert len(self.mock_threat_analyzer.queue) == 0

    def test_extract_parsed_data_syslog(self):
        """Test extracting parsed data for syslog"""
        import re
        syslog_pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^[]+)\[(\d+)\]:\s+(.+)$'
        match = re.match(syslog_pattern, "Jan  1 12:00:00 hostname daemon[1234]: Test message")
        
        result = self.ingestor._extract_parsed_data(match, 'syslog')
        
        assert result['timestamp'] == 'Jan  1 12:00:00'
        assert result['hostname'] == 'hostname'
        assert result['service'] == 'daemon'
        assert result['pid'] == '1234'
        assert result['message'] == 'Test message'

    def test_extract_parsed_data_nginx_access(self):
        """Test extracting parsed data for nginx access log"""
        import re
        nginx_access_pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
        match = re.match(nginx_access_pattern, '192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /test HTTP/1.1" 200 1234')
        
        result = self.ingestor._extract_parsed_data(match, 'nginx_access')
        
        assert result['client_ip'] == '192.168.1.1'
        assert result['timestamp'] == '01/Jan/2024:12:00:00 +0000'
        assert result['method'] == 'GET'
        assert result['url'] == '/test'
        assert result['status'] == '200'
        assert result['size'] == '1234'

    @pytest.mark.asyncio
    async def test_process_file_queue_empty_queue(self):
        """Test processing empty file queue"""
        # Mock empty queue
        mock_handler = MagicMock()
        mock_handler.file_queue = queue.Queue()
        self.ingestor.file_handlers = [mock_handler]
        
        with patch.object(self.ingestor, 'process_file') as mock_process:
            await self.ingestor._process_file_queue()
            
            # Should not process any files
            mock_process.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_file_queue_with_files(self):
        """Test processing file queue with files"""
        # Mock the file_queue's get_nowait to return files and then raise Empty
        mock_queue = MagicMock(spec=queue.Queue)
        mock_queue.get_nowait.side_effect = ["/tmp/test1.log", "/tmp/test2.log", queue.Empty]
        
        with patch.object(self.ingestor.file_handler, 'file_queue', new=mock_queue):
            with patch.object(self.ingestor, 'process_file') as mock_process:
                self.ingestor.running = True
                
                # Create task for the infinite loop method
                task = asyncio.create_task(self.ingestor._process_file_queue())
                
                # Give it a moment to process files
                await asyncio.sleep(0.2)
                
                # Stop the ingestor and wait for task to complete
                self.ingestor.running = False
                await asyncio.sleep(0.2)  # Allow time for loop to exit
                task.cancel()
                
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                
                # Should process both files
                assert mock_process.call_count == 2
                mock_queue.get_nowait.assert_called() # Ensure get_nowait was called

    @pytest.mark.asyncio
    async def test_multiple_log_formats_in_single_file(self):
        """Test processing file with multiple log formats"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as temp_file:
            # Write mixed format content
            temp_file.write("Jan  1 12:00:00 hostname daemon[1234]: Syslog error\n")
            temp_file.write("2024-01-01 12:01:00 ERROR: Generic error\n")
            temp_file.write('192.168.1.1 - - [01/Jan/2024:12:02:00 +0000] "GET /test HTTP/1.1" 404 567\n')
            temp_file.flush()
            
            try:
                with patch.object(self.ingestor, '_process_log_line') as mock_process:
                    await self.ingestor.process_file(temp_file.name)
                    
                    # Should process all lines
                    assert mock_process.call_count == 3
                    
            finally:
                os.unlink(temp_file.name)


if __name__ == '__main__':
    pytest.main([__file__])
