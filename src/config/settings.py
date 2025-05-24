"""
Configuration settings for AI Security Logger
"""

import os
from pathlib import Path
from typing import List
from dotenv import load_dotenv


class Settings:
    """Application settings loaded from environment variables"""
    
    def __init__(self):
        # Load environment variables from .env file if it exists
        env_file = Path(__file__).parent.parent / '.env'
        if env_file.exists():
            load_dotenv(env_file)
        
        # OpenRouter API Configuration
        self.openrouter_api_key = os.getenv('OPENROUTER_API_KEY', '')
        self.openrouter_model_id = os.getenv('OPENROUTER_MODEL_ID', 'openai/gpt-3.5-turbo')
        self.openrouter_base_url = os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1')
        
        # Log Sources Configuration
        log_sources_str = os.getenv('LOG_SOURCES', '/var/log/syslog')
        self.log_sources = [path.strip() for path in log_sources_str.split(',')]
        self.processing_interval = int(os.getenv('PROCESSING_INTERVAL', '60'))
        
        # Keywords for pre-filtering
        keywords_str = os.getenv('SENSITIVITY_KEYWORDS', 'error,failed,denied,warning,critical')
        self.sensitivity_keywords = [kw.strip().lower() for kw in keywords_str.split(',')]
        
        # Database Configuration
        self.db_path = os.getenv('DB_PATH', '/app/data/db/threats.db')
        self.output_log_dir = os.getenv('OUTPUT_LOG_DIR', '/app/reports')
        
        # Redis Configuration
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', '6379'))
        self.redis_db = int(os.getenv('REDIS_DB', '0'))
        
        # Logging Configuration
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.log_file = os.getenv('LOG_FILE', '/app/data/logs/application.log')
        
        # Processing Configuration
        self.max_log_batch_size = int(os.getenv('MAX_LOG_BATCH_SIZE', '10'))
        self.ai_request_timeout = int(os.getenv('AI_REQUEST_TIMEOUT', '30'))
        self.max_retries = int(os.getenv('MAX_RETRIES', '3'))
        
        # Report Configuration
        self.report_schedule = os.getenv('REPORT_SCHEDULE', 'daily')
        self.report_email_enabled = os.getenv('REPORT_EMAIL_ENABLED', 'false').lower() == 'true'
        self.report_email_to = os.getenv('REPORT_EMAIL_TO', 'admin@example.com')
        
        # Validate required settings
        self._validate()
    
    def _validate(self):
        """Validate required configuration"""
        if not self.openrouter_api_key:
            raise ValueError("OPENROUTER_API_KEY is required")
        
        # Ensure directories exist
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.output_log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
