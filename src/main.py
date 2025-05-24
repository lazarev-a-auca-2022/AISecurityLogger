import asyncio
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import Settings
from ingestor.log_ingestor import LogIngestor
from analyzer.threat_analyzer import ThreatAnalyzer
from storage.database import Database
from reporting.report_generator import ReportGenerator
from health_check import HealthCheckServer


class AISecurityLogger:
    """Main application class for AI Security Logger"""
    
    def __init__(self):
        self.settings = Settings()
        self.database = Database(self.settings.db_path)
        self.threat_analyzer = ThreatAnalyzer(self.settings, self.database)
        self.log_ingestor = LogIngestor(self.settings, self.threat_analyzer)
        self.report_generator = ReportGenerator(self.settings, self.database)
        self.running = False
        self.start_time = time.time()
        
        # Application status for health check
        self.app_status = {
            'uptime': '0:00:00',
            'logs_processed': 0,
            'threats_detected': 0,
            'api_calls': 0,
            'api_errors': 0,
            'last_report_time': None
        }
        
        # Health check server
        self.health_server = HealthCheckServer(app_status=self.app_status)
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
    def _setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Create logs directory if it doesn't exist
        log_dir = Path(self.settings.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, self.settings.log_level),
            format=log_format,
            handlers=[
                logging.FileHandler(self.settings.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    async def start(self):
        """Start the AI Security Logger"""
        self.logger.info("Starting AI Security Logger...")
        
        try:
            # Initialize database
            await self.database.initialize()
            
            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            self.running = True
            
            # Start health check server
            self.health_server.start()
            
            # Start status updater
            asyncio.create_task(self._update_status())
            
            # Start components
            tasks = [
                asyncio.create_task(self.log_ingestor.start()),
                asyncio.create_task(self.report_generator.start_scheduler())
            ]
            
            self.logger.info("AI Security Logger started successfully")
            
            # Wait for all tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            self.logger.error(f"Error starting AI Security Logger: {e}")
            raise
    
    async def stop(self):
        """Stop the AI Security Logger"""
        self.logger.info("Stopping AI Security Logger...")
        self.running = False
        
        # Stop components
        await self.log_ingestor.stop()
        await self.report_generator.stop()
        
        # Stop health check server
        self.health_server.stop()
        
        self.logger.info("AI Security Logger stopped")
    
    async def _update_status(self):
        """Update application status for health check"""
        while self.running:
            # Calculate uptime
            uptime_seconds = int(time.time() - self.start_time)
            uptime = str(timedelta(seconds=uptime_seconds))
            
            # Update status
            self.app_status['uptime'] = uptime
            
            # TODO: Add more metrics as needed
            
            await asyncio.sleep(15)  # Update every 15 seconds
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(self.stop())


async def main():
    """Main entry point"""
    app = AISecurityLogger()
    
    try:
        await app.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Application error: {e}")
        sys.exit(1)
    finally:
        await app.stop()


if __name__ == "__main__":
    asyncio.run(main())
