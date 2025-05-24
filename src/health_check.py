"""
Simple Health Check HTTP Server
"""

import asyncio
import json
import logging
import os
import socket
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Thread

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.settings import Settings


class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health check endpoints"""
    
    def __init__(self, *args, **kwargs):
        self.app_status = kwargs.pop('app_status', {})
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health' or self.path == '/':
            self._handle_health_check()
        elif self.path == '/metrics':
            self._handle_metrics()
        else:
            self.send_error(404, "Not Found")
    
    def _handle_health_check(self):
        """Handle health check request"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        status = {
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'uptime': self.app_status.get('uptime', 'unknown'),
            'version': '1.0.0'
        }
        
        self.wfile.write(json.dumps(status).encode('utf-8'))
    
    def _handle_metrics(self):
        """Handle metrics request"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        # Add more metrics as needed
        metrics = {
            'logs_processed': self.app_status.get('logs_processed', 0),
            'threats_detected': self.app_status.get('threats_detected', 0),
            'api_calls': self.app_status.get('api_calls', 0),
            'api_errors': self.app_status.get('api_errors', 0),
            'last_report_time': self.app_status.get('last_report_time', None),
            'system': {
                'hostname': socket.gethostname(),
                'memory_usage': self._get_memory_usage()
            }
        }
        
        self.wfile.write(json.dumps(metrics).encode('utf-8'))
    
    def _get_memory_usage(self):
        """Get current memory usage"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return {
                'rss': process.memory_info().rss / (1024 * 1024),  # MB
                'vms': process.memory_info().vms / (1024 * 1024)   # MB
            }
        except ImportError:
            return {'error': 'psutil not installed'}
        except Exception as e:
            return {'error': str(e)}
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logging.getLogger('health').info("%s - - [%s] %s",
            self.address_string(),
            self.log_date_time_string(),
            format % args)


class HealthCheckServer:
    """HTTP server for health checks"""
    
    def __init__(self, host='0.0.0.0', port=8080, app_status=None):
        self.host = host
        self.port = port
        self.app_status = app_status or {}
        self.server = None
        self.thread = None
        self.logger = logging.getLogger('health')
    
    def start(self):
        """Start the health check server in a separate thread"""
        if self.server:
            return
        
        self.logger.info(f"Starting health check server on {self.host}:{self.port}")
        
        def handler(*args):
            return HealthCheckHandler(*args, app_status=self.app_status)
        
        try:
            self.server = HTTPServer((self.host, self.port), handler)
            self.thread = Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()
            self.logger.info("Health check server started")
        except Exception as e:
            self.logger.error(f"Error starting health check server: {e}")
    
    def stop(self):
        """Stop the health check server"""
        if self.server:
            self.logger.info("Stopping health check server")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.thread = None
            self.logger.info("Health check server stopped")


def main():
    """Run the health check server for testing"""
    logging.basicConfig(level=logging.INFO)
    
    app_status = {
        'uptime': '0:10:00',
        'logs_processed': 1234,
        'threats_detected': 5,
        'api_calls': 20,
        'api_errors': 1,
        'last_report_time': datetime.now().isoformat()
    }
    
    server = HealthCheckServer(app_status=app_status)
    server.start()
    
    try:
        # Keep running until interrupted
        while True:
            asyncio.get_event_loop().run_until_complete(asyncio.sleep(1))
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
