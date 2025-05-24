"""
Log Ingestor - Monitors and processes log files
"""

import asyncio
import logging
import re
import queue
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log files"""
    
    def __init__(self, ingestor):
        self.ingestor = ingestor
        self.logger = logging.getLogger(__name__)
        self.file_queue = queue.Queue()
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.logger.debug(f"File modified: {event.src_path}")
            # Add the file to the queue for processing
            self.file_queue.put(event.src_path)


class LogIngestor:
    """Main log ingestion class"""
    
    def __init__(self, settings, threat_analyzer):
        self.settings = settings
        self.threat_analyzer = threat_analyzer
        self.logger = logging.getLogger(__name__)
        self.observer = Observer()
        self.running = False
        self.file_positions = {}  # Track file positions for tailing
        self.file_handler = LogFileHandler(self)
        
        # Compile regex patterns for common log formats
        self.log_patterns = {
            'syslog': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$'),
            'nginx_access': re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'),
            'nginx_error': re.compile(r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$'),
        }
    
    async def start(self):
        """Start the log ingestor"""
        self.logger.info("Starting log ingestor...")
        self.running = True
        
        try:
            # Setup file watchers
            await self._setup_file_watchers()
            
            # Process existing log files
            await self._process_existing_logs()
            
            # Start observer
            self.observer.start()
            
            # Start task to process files from the queue
            asyncio.create_task(self._process_file_queue())
            
            # Keep running
            while self.running:
                await asyncio.sleep(self.settings.processing_interval)
                await self._check_for_new_logs()
                
        except Exception as e:
            self.logger.error(f"Error in log ingestor: {e}")
            raise
    
    async def stop(self):
        """Stop the log ingestor"""
        self.logger.info("Stopping log ingestor...")
        self.running = False
        self.observer.stop()
        self.observer.join()
    
    async def _setup_file_watchers(self):
        """Setup file system watchers for log sources"""
        # Use the already created handler instance
        for log_source in self.settings.log_sources:
            log_path = Path(log_source)
            
            if log_path.is_file():
                # Watch the parent directory for file changes
                self.observer.schedule(self.file_handler, str(log_path.parent), recursive=False)
                self.logger.info(f"Watching log file: {log_source}")
            elif log_path.is_dir():
                # Watch the directory recursively
                self.observer.schedule(self.file_handler, str(log_path), recursive=True)
                self.logger.info(f"Watching log directory: {log_source}")
            else:
                self.logger.warning(f"Log source not found: {log_source}")
    
    async def _process_existing_logs(self):
        """Process existing log files from the end"""
        for log_source in self.settings.log_sources:
            log_path = Path(log_source)
            
            if log_path.is_file():
                await self._tail_file(str(log_path))
            elif log_path.is_dir():
                for log_file in log_path.rglob("*.log"):
                    await self._tail_file(str(log_file))
    
    async def _tail_file(self, file_path: str, lines: int = 100):
        """Tail a file and process recent lines"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Get file size
                f.seek(0, 2)  # Go to end
                file_size = f.tell()
                
                # Store current position
                self.file_positions[file_path] = file_size
                
                # Read last N lines
                lines_found = []
                block_size = 1024
                
                f.seek(max(0, file_size - block_size))
                remaining_data = f.read()
                
                lines_found = remaining_data.split('\n')
                lines_found = [line for line in lines_found if line.strip()][-lines:]
                
                # Process lines
                for line in lines_found:
                    await self._process_log_line(line, file_path)
                    
        except Exception as e:
            self.logger.error(f"Error tailing file {file_path}: {e}")
    
    async def process_file(self, file_path: str):
        """Process new content in a file"""
        try:
            current_pos = self.file_positions.get(file_path, 0)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(current_pos)
                new_lines = f.readlines()
                
                # Update position
                self.file_positions[file_path] = f.tell()
                
                # Process new lines
                for line in new_lines:
                    line = line.strip()
                    if line:
                        await self._process_log_line(line, file_path)
                        
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
    
    async def _process_log_line(self, line: str, source_file: str):
        """Process a single log line"""
        try:
            # Check if line contains sensitive keywords
            if not self._contains_sensitive_keywords(line):
                return
            
            # Parse log line
            parsed_log = self._parse_log_line(line, source_file)
            
            if parsed_log:
                # Send to threat analyzer
                await self.threat_analyzer.analyze_log(parsed_log)
                
        except Exception as e:
            self.logger.error(f"Error processing log line: {e}")
    
    def _contains_sensitive_keywords(self, line: str) -> bool:
        """Check if log line contains sensitive keywords"""
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in self.settings.sensitivity_keywords)
    
    def _parse_log_line(self, line: str, source_file: str) -> Optional[Dict[str, Any]]:
        """Parse a log line and extract structured information"""
        try:
            # Determine log type based on file path
            log_type = self._determine_log_type(source_file)
            
            parsed = {
                'timestamp': datetime.now().isoformat(),
                'source_file': source_file,
                'log_type': log_type,
                'raw_line': line,
                'parsed_data': {}
            }
            
            # Try to parse with appropriate pattern
            if log_type in self.log_patterns:
                match = self.log_patterns[log_type].match(line)
                if match:
                    parsed['parsed_data'] = self._extract_parsed_data(match, log_type)
            
            return parsed
            
        except Exception as e:
            self.logger.error(f"Error parsing log line: {e}")
            return None
    
    def _determine_log_type(self, file_path: str) -> str:
        """Determine log type based on file path"""
        file_path_lower = file_path.lower()
        
        if 'nginx' in file_path_lower:
            if 'access' in file_path_lower:
                return 'nginx_access'
            elif 'error' in file_path_lower:
                return 'nginx_error'
        elif 'syslog' in file_path_lower or 'auth' in file_path_lower:
            return 'syslog'
        
        return 'unknown'
    
    def _extract_parsed_data(self, match, log_type: str) -> Dict[str, str]:
        """Extract parsed data from regex match"""
        if log_type == 'syslog':
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'message': match.group(3)
            }
        elif log_type == 'nginx_access':
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'request': match.group(3),
                'status': match.group(4),
                'size': match.group(5),
                'referer': match.group(6),
                'user_agent': match.group(7)
            }
        elif log_type == 'nginx_error':
            return {
                'timestamp': match.group(1),
                'level': match.group(2),
                'message': match.group(3)
            }
        
        return {}
    
    async def _check_for_new_logs(self):
        """Periodically check for new logs in watched files"""
        for log_source in self.settings.log_sources:
            log_path = Path(log_source)
            
            if log_path.is_file():
                await self.process_file(str(log_path))
    
    async def _process_file_queue(self):
        """Process files from the queue (called from the main event loop)"""
        while self.running:
            try:
                # Non-blocking check for files
                for _ in range(10):  # Process up to 10 files per cycle
                    try:
                        file_path = self.file_handler.file_queue.get_nowait()
                        await self.process_file(file_path)
                        self.file_handler.file_queue.task_done()
                    except queue.Empty:
                        break
            except Exception as e:
                self.logger.error(f"Error processing file queue: {e}")
            
            # Sleep briefly to prevent busy loop
            await asyncio.sleep(0.1)
