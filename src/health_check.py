"""
Simple Health Check HTTP Server
"""

import asyncio
import json
import logging
import os
import socket
import sys
import subprocess
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

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/generate_logs':
            self._handle_generate_logs()
        else:
            self.send_error(404, "Not Found")
    
    def _handle_health_check(self):
        """Handle health check request"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') # Allow all origins for simplicity
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        status = {
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'uptime': self.app_status.get('uptime', 'unknown'),
            'version': '1.0.0'
        }
        
        self.wfile.write(json.dumps(status).encode('utf-8'))
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def _handle_metrics(self):
        """Handle metrics request"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') # Allow all origins for simplicity
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
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

    def _handle_generate_logs(self):
        """Handle log generation request"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            params = json.loads(post_data.decode('utf-8'))
            num_logs = params.get('num_logs', 10)
            interval = params.get('interval', 1.0)
            include_security = params.get('include_security', True)
            app_type = params.get('app_type', 'generic')
            
            # Use the log_file_name from the request or fallback to default naming pattern
            log_file_name = params.get('log_file_name', f"{app_type}_sample.log")
            
            # Make sure the path is absolute
            log_file_path = str(Path(__file__).parent.parent / "data" / "logs" / log_file_name)
            
            command = [
                sys.executable, # Use the current Python executable
                str(Path(__file__).parent.parent / "tools" / "generate_test_logs.py"),
                "-n", str(num_logs),
                "-i", str(interval),
                "-a", app_type,
                "-f", log_file_path
            ]
            if not include_security:
                command.append("--no-security")

            logging.getLogger('health').info(f"Executing log generation command: {' '.join(command)}")
            
            try:
                # Run the script in a non-blocking way
                process = subprocess.Popen(
                    command, 
                    cwd=Path(__file__).parent.parent,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE
                )
                
                # Start a thread to monitor the process output for any errors
                def monitor_process():
                    stdout, stderr = process.communicate()
                    if process.returncode != 0:
                        logging.getLogger('health').error(f"Log generation process failed with exit code {process.returncode}")
                        if stderr:
                            logging.getLogger('health').error(f"Error output: {stderr.decode('utf-8', errors='replace')}")
                
                monitor_thread = Thread(target=monitor_process)
                monitor_thread.daemon = True
                monitor_thread.start()
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*') # Allow all origins for simplicity
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                response = {'status': 'success', 'message': 'Log generation initiated.'}
                self.wfile.write(json.dumps(response).encode('utf-8'))
            except Exception as e:
                logging.getLogger('health').error(f"Failed to start log generation process: {e}")
                self.send_error(500, f"Internal Server Error: {e}")
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            logging.getLogger('health').error(f"Error generating logs: {e}")
            self.send_error(500, f"Internal Server Error: {e}")
    
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
    
    def __init__(self, host='0.0.0.0', port=5356, app_status=None):
        self.host = host
        self.port = int(os.environ.get('HEALTH_CHECK_PORT', port))  # Allow port override from environment
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
