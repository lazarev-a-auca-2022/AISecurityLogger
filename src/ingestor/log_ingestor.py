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
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            file_path = event.src_path
            # Skip application.log and files already in the processed list
            if ("application.log" not in file_path and 
                file_path not in self.ingestor.processed_files and
                file_path not in self.ingestor.files_to_rename):
                self.logger.debug(f"File created: {file_path}")
                self.file_queue.put(file_path)

    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            file_path = event.src_path
            # Skip application.log, already processed files, and files already in the processed list
            if ("application.log" not in file_path and 
                not file_path.endswith('.old') and
                file_path not in self.ingestor.processed_files and
                file_path not in self.ingestor.files_to_rename):
                self.logger.debug(f"File modified: {file_path}")
                # Add the file to the queue for processing
                self.file_queue.put(file_path)


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
        self.processed_files = set()  # Track fully processed files
        self.files_to_rename = {}  # Files scheduled for renaming: {file_path: attempt_count}
        self.MAX_RENAME_ATTEMPTS = 3 # Max attempts to rename a file
        
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
                
                # Check if the threat analyzer has completed processing
                await self._check_threat_analyzer_status()
                
                # Try to rename processed files
                await self._rename_processed_files()
                
                # Log current status
                if self.files_to_rename:
                    self.logger.debug(f"Files awaiting rename: {list(self.files_to_rename.keys())}")
                
        except Exception as e:
            self.logger.error(f"Error in log ingestor: {e}")
            raise
    
    async def _check_threat_analyzer_status(self):
        """Check if the threat analyzer has completed all pending tasks"""
        # Check if the threat analyzer is stuck and reset if necessary
        await self.threat_analyzer.check_processing_status()
        
        if not self.threat_analyzer.processing and len(self.threat_analyzer.queue) == 0:
            # Threat analyzer is idle, safe to rename files
            self.logger.debug("Threat analyzer is idle, safe to rename processed files")
        else:
            self.logger.debug(f"Threat analyzer still processing: queue={len(self.threat_analyzer.queue)}, processing={self.threat_analyzer.processing}")
    
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
                # Skip if it's application.log, already processed (.old extension), or in processed list
                file_path_str = str(log_path)
                if ("application.log" not in file_path_str and 
                    not file_path_str.endswith('.old') and
                    file_path_str not in self.processed_files):
                    await self._tail_file(file_path_str)
            elif log_path.is_dir():
                for log_file in log_path.rglob("*.log"):
                    # Skip if it's application.log, already processed (.old extension), or in processed list
                    file_path_str = str(log_file)
                    if ("application.log" not in file_path_str and 
                        not file_path_str.endswith('.old') and
                        file_path_str not in self.processed_files):
                        await self._tail_file(file_path_str)
    
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
                
                # Schedule file for renaming after processing if we found lines to process
                if (lines_found and 
                    not file_path.endswith('.old') and 
                    "application.log" not in file_path and 
                    file_path not in self.files_to_rename):
                    self.logger.info(f"Scheduled file {file_path} for renaming after initial tail processing")
                    self._schedule_file_for_rename(file_path)
                    
        except Exception as e:
            self.logger.error(f"Error tailing file {file_path}: {e}")
    
    async def process_file(self, file_path: str):
        """Process new content in a file"""
        try:
            # Skip application.log and already processed files
            if "application.log" in file_path or file_path.endswith('.old'):
                return
                
            # Check if we already processed this file completely
            if file_path in self.processed_files:
                return
                
            current_pos = self.file_positions.get(file_path, 0)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(current_pos)
                new_lines = f.readlines()
                
                # Update position
                self.file_positions[file_path] = f.tell()
                
                # Process new lines and collect results
                analysis_results = []
                for line in new_lines:
                    line = line.strip()
                    if line:
                        result = await self._process_log_line(line, file_path)
                        if result:
                            analysis_results.append(result)
            
            # Schedule the file for renaming if we've processed it and it's not already scheduled
            # This handles both files with new content and files that were fully processed during initial tailing
            if (not file_path.endswith('.old') and 
                "application.log" not in file_path and 
                file_path not in self.files_to_rename and
                file_path not in self.processed_files):
                self.logger.info(f"Scheduled file {file_path} for renaming after analysis completes")
                # Add to a list of files to be renamed later
                self._schedule_file_for_rename(file_path)
                        
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
            
    def _schedule_file_for_rename(self, file_path: str):
        """Schedule a file to be renamed after analysis is complete"""
        if file_path not in self.files_to_rename:
            self.files_to_rename[file_path] = 0 # Initialize attempt count

    async def _rename_processed_files(self):
        """Rename files that have been processed"""
        if not self.files_to_rename:
            return
            
        # Create a list of files to process to avoid modifying dict during iteration
        files_to_process = list(self.files_to_rename.keys())
        self.logger.debug(f"Checking {len(files_to_process)} files for renaming. Threat analyzer processing: {self.threat_analyzer.processing}, queue length: {len(self.threat_analyzer.queue)}")
        
        for file_path in files_to_process:
            # Only attempt rename if threat analyzer is idle
            if (not self.threat_analyzer.processing and 
                len(self.threat_analyzer.queue) == 0):
                
                old_path = Path(file_path)
                new_path = Path(f"{file_path}.old")
                
                # Check if file still exists and is not already renamed
                if not old_path.exists() or file_path.endswith('.old'):
                    self.logger.debug(f"File {file_path} no longer exists or already renamed. Removing from rename queue.")
                    self.files_to_rename.pop(file_path, None)
                    self.processed_files.add(file_path) # Ensure it's marked as processed
                    continue

                try:
                    # If the new path already exists, try to remove it first
                    if new_path.exists():
                        self.logger.warning(f"Target rename path {new_path} already exists. Attempting to remove.")
                        try:
                            new_path.unlink() # Remove the existing .old file
                        except Exception as unlink_error:
                            self.logger.error(f"Failed to remove existing target file {new_path}: {unlink_error}")
                            # If we can't remove the target, we can't rename. Increment attempts and continue.
                            self.files_to_rename[file_path] += 1
                            if self.files_to_rename[file_path] >= self.MAX_RENAME_ATTEMPTS:
                                self.logger.critical(f"Max rename attempts reached for {file_path}. Failed to remove existing target. Marking as processed.")
                                self.processed_files.add(file_path)
                                self.files_to_rename.pop(file_path, None)
                            continue # Skip rename attempt if unlink failed

                    old_path.rename(new_path)
                    self.logger.info(f"Renamed processed file {file_path} to {new_path}")
                    
                    # Remove from tracked positions
                    if file_path in self.file_positions:
                        del self.file_positions[file_path]
                    
                    # Add to processed files to avoid reprocessing
                    self.processed_files.add(file_path)
                    
                    # Remove from rename queue
                    self.files_to_rename.pop(file_path, None)

                except Exception as rename_error:
                    self.files_to_rename[file_path] += 1
                    if self.files_to_rename[file_path] < self.MAX_RENAME_ATTEMPTS:
                        self.logger.warning(f"Error renaming file {file_path}: {rename_error}. Retrying (attempt {self.files_to_rename[file_path]}/{self.MAX_RENAME_ATTEMPTS}).")
                    else:
                        self.logger.critical(f"Max rename attempts reached for {file_path}: {rename_error}. Marking as processed to prevent re-processing.")
                        # Even if renaming fails after max attempts, mark as processed to prevent re-processing
                        self.processed_files.add(file_path)
                        # Remove from rename queue
                        self.files_to_rename.pop(file_path, None)
            else:
                self.logger.debug(f"Skipping rename for {file_path}: Threat analyzer busy (processing={self.threat_analyzer.processing}, queue={len(self.threat_analyzer.queue)}).")
    
    async def _process_log_line(self, line: str, source_file: str):
        """Process a single log line"""
        try:
            # Check if line contains sensitive keywords
            if not self._contains_sensitive_keywords(line):
                return None
            
            # Parse log line
            parsed_log = self._parse_log_line(line, source_file)
            
            if parsed_log:
                # Send to threat analyzer and return result
                result = await self.threat_analyzer.analyze_log(parsed_log)
                return result
                
        except Exception as e:
            self.logger.error(f"Error processing log line: {e}")
            
        return None
    
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
                # Skip application.log, already processed files, and files scheduled for renaming
                file_path_str = str(log_path)
                if ("application.log" not in file_path_str and 
                    not file_path_str.endswith('.old') and
                    file_path_str not in self.processed_files):
                    await self.process_file(file_path_str)
            elif log_path.is_dir():
                # Find new log files in directory
                for log_file in log_path.rglob("*.log"):
                    # Skip application.log, already processed files, and files scheduled for renaming
                    file_path_str = str(log_file)
                    if ("application.log" not in file_path_str and 
                        not file_path_str.endswith('.old') and
                        file_path_str not in self.processed_files):
                        await self.process_file(file_path_str)
    
    async def _process_file_queue(self):
        """Process files from the queue (called from the main event loop)"""
        while self.running:
            try:
                # Non-blocking check for files
                for _ in range(10):  # Process up to 10 files per cycle
                    try:
                        file_path = self.file_handler.file_queue.get_nowait()
                        
                        # Skip if file is already processed or scheduled for renaming
                        if (file_path not in self.processed_files and 
                            "application.log" not in file_path and 
                            not file_path.endswith('.old')):
                            await self.process_file(file_path)
                            
                        self.file_handler.file_queue.task_done()
                    except queue.Empty:
                        break
            except Exception as e:
                self.logger.error(f"Error processing file queue: {e}")
            
            # Sleep briefly to prevent busy loop
            await asyncio.sleep(0.1)
    
    async def force_complete_analysis(self):
        """Force completion of any pending analysis and renaming of processed files"""
        self.logger.info("Forcing completion of analysis and file renaming...")
        
        # Process any remaining items in the threat analyzer queue
        if len(self.threat_analyzer.queue) > 0:
            self.logger.info(f"Processing remaining {len(self.threat_analyzer.queue)} items in threat analyzer queue")
            await self.threat_analyzer._process_queue()
        
        # Wait for any active processing to complete
        timeout = 30  # 30 second timeout
        wait_time = 0
        while self.threat_analyzer.processing and wait_time < timeout:
            self.logger.debug("Waiting for threat analyzer to complete processing...")
            await asyncio.sleep(1)
            wait_time += 1
        
        if self.threat_analyzer.processing:
            self.logger.warning("Timeout waiting for threat analyzer to complete. Forcing state reset.")
            self.threat_analyzer.processing = False
        
        # Now attempt to rename all queued files
        await self._rename_processed_files()
        
        self.logger.info(f"Force completion finished. Files remaining to rename: {len(self.files_to_rename)}")
    
    def get_status_info(self):
        """Get current status information for debugging"""
        return {
            'processed_files': list(self.processed_files),
            'files_to_rename': dict(self.files_to_rename),
            'file_positions': dict(self.file_positions),
            'threat_analyzer_processing': self.threat_analyzer.processing,
            'threat_analyzer_queue_length': len(self.threat_analyzer.queue),
            'running': self.running
        }
