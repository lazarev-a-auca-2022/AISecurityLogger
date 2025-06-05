"""
Performance and Load Testing for AI Security Logger
Tests system performance under various load conditions
"""

import pytest
import asyncio
import time
import tempfile
import os
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import psutil
import json
from datetime import datetime

# Import test fixtures
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from fixtures import (
    MockSettings, LogDataFactory, ThreatDataFactory, 
    DatabaseFixture, FileFixture, create_temp_database
)

# Import source modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from ingestor.log_ingestor import LogIngestor, LogFileHandler
from analyzer.threat_analyzer import ThreatAnalyzer
from storage.database import Database
from reporting.report_generator import ReportGenerator


class PerformanceMonitor:
    """Monitor system performance during tests"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.start_memory = None
        self.peak_memory = None
        self.cpu_percent = []
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start performance monitoring"""
        self.start_time = time.time()
        self.start_memory = psutil.virtual_memory().used
        self.peak_memory = self.start_memory
        self.cpu_percent = []
        self.monitoring = True
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        self.end_time = time.time()
    
    def _monitor_loop(self):
        """Monitor loop for collecting metrics"""
        while self.monitoring:
            current_memory = psutil.virtual_memory().used
            if current_memory > self.peak_memory:
                self.peak_memory = current_memory
            
            cpu = psutil.cpu_percent(interval=0.1)
            self.cpu_percent.append(cpu)
            
            time.sleep(0.1)
    
    def get_metrics(self):
        """Get collected performance metrics"""
        return {
            'duration': self.end_time - self.start_time if self.end_time else None,
            'memory_used_mb': (self.peak_memory - self.start_memory) / 1024 / 1024,
            'peak_memory_mb': self.peak_memory / 1024 / 1024,
            'avg_cpu_percent': sum(self.cpu_percent) / len(self.cpu_percent) if self.cpu_percent else 0,
            'max_cpu_percent': max(self.cpu_percent) if self.cpu_percent else 0
        }


@pytest.mark.performance
class TestLogIngestorPerformance:
    """Performance tests for LogIngestor"""
    
    def test_large_file_processing(self):
        """Test processing large log files"""
        settings = MockSettings()
        file_fixture = FileFixture()
        
        try:
            # Create large log file (10,000 entries)
            large_log = file_fixture.create_log_file(
                'large_test.log', 
                'syslog', 
                10000
            )
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Process large file
            ingestor = LogIngestor(settings)
            handler = LogFileHandler(large_log, settings)
            
            processed_count = 0
            for entry in handler.read_new_entries():
                processed_count += 1
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Assertions
            assert processed_count == 10000
            assert metrics['duration'] < 30  # Should complete within 30 seconds
            assert metrics['memory_used_mb'] < 100  # Should use less than 100MB
            
            print(f"Processed {processed_count} entries in {metrics['duration']:.2f}s")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
            print(f"CPU usage: {metrics['avg_cpu_percent']:.1f}%")
        
        finally:
            file_fixture.cleanup()
    
    def test_concurrent_file_processing(self):
        """Test processing multiple files concurrently"""
        settings = MockSettings()
        file_fixture = FileFixture()
        
        try:
            # Create multiple log files
            log_files = []
            for i in range(5):
                log_file = file_fixture.create_log_file(
                    f'concurrent_test_{i}.log',
                    'syslog',
                    1000
                )
                log_files.append(log_file)
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Process files concurrently
            def process_file(file_path):
                handler = LogFileHandler(file_path, settings)
                count = 0
                for entry in handler.read_new_entries():
                    count += 1
                return count
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(process_file, f) for f in log_files]
                results = [future.result() for future in as_completed(futures)]
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Assertions
            assert sum(results) == 5000  # 5 files * 1000 entries each
            assert metrics['duration'] < 20  # Should complete within 20 seconds
            assert metrics['memory_used_mb'] < 150  # Should use less than 150MB
            
            print(f"Processed {sum(results)} entries concurrently in {metrics['duration']:.2f}s")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
        
        finally:
            file_fixture.cleanup()
    
    def test_memory_usage_with_large_entries(self):
        """Test memory usage with very large log entries"""
        settings = MockSettings()
        file_fixture = FileFixture()
        
        try:
            # Create file with large entries (1KB each)
            large_entries = []
            for i in range(1000):
                large_entry = f"Dec  5 12:34:56 server1 app[{i}]: " + "X" * 1000
                large_entries.append(large_entry)
            
            log_file = os.path.join(file_fixture.base_dir, 'large_entries.log')
            with open(log_file, 'w') as f:
                f.write('\n'.join(large_entries))
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Process file
            handler = LogFileHandler(log_file, settings)
            processed_count = 0
            for entry in handler.read_new_entries():
                processed_count += 1
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Assertions
            assert processed_count == 1000
            assert metrics['memory_used_mb'] < 50  # Should handle large entries efficiently
            
            print(f"Processed {processed_count} large entries")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
        
        finally:
            file_fixture.cleanup()


@pytest.mark.performance
class TestDatabasePerformance:
    """Performance tests for Database operations"""
    
    def test_bulk_insert_performance(self):
        """Test bulk insert performance"""
        db_path = create_temp_database()
        
        try:
            database = Database(db_path)
            threats = ThreatDataFactory.create_threat_list(10000)
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Bulk insert threats
            for threat in threats:
                database.store_threat(
                    threat['timestamp'],
                    threat['source'],
                    threat['log_entry'],
                    threat['severity'],
                    threat['threat_type'],
                    threat['confidence'],
                    threat
                )
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Verify insertion
            total_count = database.get_threat_count()
            assert total_count == 10000
            
            # Performance assertions
            assert metrics['duration'] < 60  # Should complete within 60 seconds
            assert metrics['memory_used_mb'] < 200  # Should use less than 200MB
            
            print(f"Inserted {total_count} threats in {metrics['duration']:.2f}s")
            print(f"Rate: {total_count / metrics['duration']:.1f} threats/second")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
        
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
    
    def test_concurrent_database_access(self):
        """Test concurrent database access"""
        db_path = create_temp_database()
        
        try:
            def worker_function(worker_id, threat_count):
                """Worker function for concurrent access"""
                database = Database(db_path)
                threats = ThreatDataFactory.create_threat_list(threat_count)
                
                inserted = 0
                for threat in threats:
                    database.store_threat(
                        threat['timestamp'],
                        threat['source'],
                        threat['log_entry'],
                        threat['severity'],
                        threat['threat_type'],
                        threat['confidence'],
                        threat
                    )
                    inserted += 1
                
                return inserted
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Run concurrent workers
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(worker_function, i, 1000)
                    for i in range(5)
                ]
                results = [future.result() for future in as_completed(futures)]
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Verify results
            database = Database(db_path)
            total_count = database.get_threat_count()
            expected_total = sum(results)
            
            assert total_count == expected_total
            assert metrics['duration'] < 120  # Should complete within 2 minutes
            
            print(f"Concurrent insertion of {total_count} threats in {metrics['duration']:.2f}s")
            print(f"Rate: {total_count / metrics['duration']:.1f} threats/second")
        
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
    
    def test_query_performance_large_dataset(self):
        """Test query performance on large dataset"""
        db_fixture = DatabaseFixture()
        
        try:
            db_fixture.setup().add_sample_threats(50000)
            database = Database(db_fixture.db_path)
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Perform various queries
            total_count = database.get_threat_count()
            high_severity = database.get_threats(severity='HIGH')
            recent_threats = database.get_recent_threats(1000)
            severity_counts = database.get_threat_count_by_severity()
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Assertions
            assert total_count == 50000
            assert len(high_severity) > 0
            assert len(recent_threats) <= 1000
            assert sum(severity_counts.values()) == total_count
            
            # Performance assertions
            assert metrics['duration'] < 10  # Queries should be fast
            
            print(f"Executed queries on {total_count} threats in {metrics['duration']:.2f}s")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
        
        finally:
            db_fixture.cleanup()


@pytest.mark.performance
class TestReportGeneratorPerformance:
    """Performance tests for ReportGenerator"""
    
    def test_large_report_generation(self):
        """Test generating reports with large datasets"""
        db_fixture = DatabaseFixture()
        file_fixture = FileFixture()
        
        try:
            # Setup large dataset
            db_fixture.setup().add_sample_threats(10000)
            database = Database(db_fixture.db_path)
            
            settings = MockSettings(
                REPORT_DIRECTORY=file_fixture.base_dir
            )
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Generate reports
            generator = ReportGenerator(database, settings)
            html_report = generator.generate_html_report()
            json_report = generator.generate_json_report()
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Verify reports
            assert html_report is not None
            assert json_report is not None
            assert len(json_report['threats']) == 10000
            
            # Performance assertions
            assert metrics['duration'] < 30  # Should complete within 30 seconds
            assert metrics['memory_used_mb'] < 500  # Should use less than 500MB
            
            print(f"Generated reports for {len(json_report['threats'])} threats in {metrics['duration']:.2f}s")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
        
        finally:
            db_fixture.cleanup()
            file_fixture.cleanup()
    
    def test_concurrent_report_generation(self):
        """Test generating multiple reports concurrently"""
        db_fixture = DatabaseFixture()
        file_fixture = FileFixture()
        
        try:
            db_fixture.setup().add_sample_threats(5000)
            database = Database(db_fixture.db_path)
            
            settings = MockSettings(
                REPORT_DIRECTORY=file_fixture.base_dir
            )
            
            def generate_report_worker(worker_id):
                """Worker function for concurrent report generation"""
                generator = ReportGenerator(database, settings)
                html_report = generator.generate_html_report()
                json_report = generator.generate_json_report()
                return len(json_report['threats'])
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Generate reports concurrently
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(generate_report_worker, i)
                    for i in range(3)
                ]
                results = [future.result() for future in as_completed(futures)]
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Verify results
            assert all(result == 5000 for result in results)
            assert metrics['duration'] < 60  # Should complete within 60 seconds
            
            print(f"Generated {len(results)} concurrent reports in {metrics['duration']:.2f}s")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
        
        finally:
            db_fixture.cleanup()
            file_fixture.cleanup()


@pytest.mark.performance
class TestSystemPerformance:
    """End-to-end system performance tests"""
    
    def test_full_pipeline_performance(self):
        """Test performance of the complete processing pipeline"""
        settings = MockSettings()
        file_fixture = FileFixture()
        db_fixture = DatabaseFixture()
        
        try:
            # Setup
            db_fixture.setup()
            database = Database(db_fixture.db_path)
            
            # Create test log file
            log_file = file_fixture.create_log_file(
                'pipeline_test.log',
                'syslog',
                5000
            )
            
            monitor = PerformanceMonitor()
            monitor.start_monitoring()
            
            # Run full pipeline
            ingestor = LogIngestor(settings)
            handler = LogFileHandler(log_file, settings)
            
            # Process logs and simulate threat analysis
            processed_count = 0
            for entry in handler.read_new_entries():
                # Simulate threat analysis (without actual AI calls)
                if any(keyword in entry.lower() for keyword in settings.KEYWORDS):
                    threat_data = ThreatDataFactory.create_threat_dict(
                        source=log_file,
                        log_entry=entry
                    )
                    database.store_threat(
                        threat_data['timestamp'],
                        threat_data['source'],
                        threat_data['log_entry'],
                        threat_data['severity'],
                        threat_data['threat_type'],
                        threat_data['confidence'],
                        threat_data
                    )
                processed_count += 1
            
            # Generate report
            generator = ReportGenerator(database, settings)
            report = generator.generate_json_report()
            
            monitor.stop_monitoring()
            metrics = monitor.get_metrics()
            
            # Verify results
            assert processed_count == 5000
            assert database.get_threat_count() > 0
            assert report is not None
            
            # Performance assertions
            assert metrics['duration'] < 60  # Should complete within 60 seconds
            assert metrics['memory_used_mb'] < 300  # Should use less than 300MB
            
            print(f"Full pipeline processed {processed_count} entries in {metrics['duration']:.2f}s")
            print(f"Threats detected: {database.get_threat_count()}")
            print(f"Memory used: {metrics['memory_used_mb']:.2f}MB")
            print(f"Processing rate: {processed_count / metrics['duration']:.1f} entries/second")
        
        finally:
            file_fixture.cleanup()
            db_fixture.cleanup()
    
    def test_memory_leak_detection(self):
        """Test for memory leaks during extended operation"""
        settings = MockSettings()
        db_fixture = DatabaseFixture()
        
        try:
            db_fixture.setup()
            database = Database(db_fixture.db_path)
            
            initial_memory = psutil.virtual_memory().used
            memory_readings = []
            
            # Simulate extended operation
            for iteration in range(10):
                # Process batch of threats
                threats = ThreatDataFactory.create_threat_list(1000)
                for threat in threats:
                    database.store_threat(
                        threat['timestamp'],
                        threat['source'],
                        threat['log_entry'],
                        threat['severity'],
                        threat['threat_type'],
                        threat['confidence'],
                        threat
                    )
                
                # Generate report
                generator = ReportGenerator(database, settings)
                report = generator.generate_json_report()
                
                # Record memory usage
                current_memory = psutil.virtual_memory().used
                memory_readings.append(current_memory - initial_memory)
                
                # Small delay to allow garbage collection
                time.sleep(0.1)
            
            # Analyze memory usage trend
            memory_mb = [mem / 1024 / 1024 for mem in memory_readings]
            memory_growth = memory_mb[-1] - memory_mb[0]
            
            print(f"Memory usage over 10 iterations: {memory_mb}")
            print(f"Memory growth: {memory_growth:.2f}MB")
            
            # Assert no significant memory leak (less than 100MB growth)
            assert memory_growth < 100, f"Potential memory leak detected: {memory_growth:.2f}MB growth"
            
        finally:
            db_fixture.cleanup()


if __name__ == "__main__":
    # Run performance tests
    pytest.main([__file__, "-v", "-m", "performance"])
