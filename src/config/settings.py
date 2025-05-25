"""
Configuration settings for AI Security Logger
"""

import os
from pathlib import Path
from typing import List, Dict, Any
from dotenv import load_dotenv


class Settings:
    """Application settings loaded from environment variables"""
    
    def __init__(self):
        # Load environment variables from .env file if it exists
        env_file = Path(__file__).parent.parent / '.env'
        if env_file.exists():
            load_dotenv(env_file)
        
        # AI Provider Configuration
        self.ai_provider = os.getenv('AI_PROVIDER', 'openrouter').lower()
        self.api_key = os.getenv(f'{self.ai_provider.upper()}_API_KEY', '')
        
        # Provider-specific configurations
        self._load_provider_settings()
        
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
        self.log_level = os.getenv('LOG_LEVEL', 'INFO') # Changed default to INFO for more visibility
        self.log_file = os.getenv('LOG_FILE', '/app/docker/application.log') # Changed log file path to /app/docker
        
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
    
    def _load_provider_settings(self):
        """Load provider-specific settings based on the selected AI provider"""
        # Default settings
        self.model_id = ''
        self.api_base_url = ''
        self.api_version = ''
        self.request_params = {}
        
        # OpenRouter settings
        if self.ai_provider == 'openrouter':
            self.model_id = os.getenv('OPENROUTER_MODEL_ID', 'openai/gpt-3.5-turbo')
            self.api_base_url = os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1')
        
        # OpenAI settings
        elif self.ai_provider == 'openai':
            self.model_id = os.getenv('OPENAI_MODEL_ID', 'gpt-3.5-turbo')
            self.api_base_url = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1')
            self.api_version = os.getenv('OPENAI_API_VERSION', '')
            self.organization_id = os.getenv('OPENAI_ORGANIZATION_ID', '')
        
        # Google AI settings
        elif self.ai_provider == 'google':
            self.model_id = os.getenv('GOOGLE_MODEL_ID', 'gemini-pro')
            self.api_base_url = os.getenv('GOOGLE_BASE_URL', 'https://generativelanguage.googleapis.com')
            self.api_version = os.getenv('GOOGLE_API_VERSION', 'v1')
        
        # Azure OpenAI settings
        elif self.ai_provider == 'azure':
            self.model_id = os.getenv('AZURE_MODEL_ID', 'gpt-35-turbo')
            self.api_base_url = os.getenv('AZURE_BASE_URL', '')  # e.g., https://<resource-name>.openai.azure.com/
            self.api_version = os.getenv('AZURE_API_VERSION', '2023-05-15')
            self.deployment_name = os.getenv('AZURE_DEPLOYMENT_NAME', '')
        
        # Anthropic settings
        elif self.ai_provider == 'anthropic':
            self.model_id = os.getenv('ANTHROPIC_MODEL_ID', 'claude-2')
            self.api_base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com')
            self.api_version = os.getenv('ANTHROPIC_API_VERSION', 'v1')
        
        # Custom provider settings
        elif self.ai_provider == 'custom':
            self.model_id = os.getenv('CUSTOM_MODEL_ID', '')
            self.api_base_url = os.getenv('CUSTOM_BASE_URL', '')
            self.api_version = os.getenv('CUSTOM_API_VERSION', '')
            
            # Load any custom parameters from environment variables
            for key, value in os.environ.items():
                if key.startswith('CUSTOM_PARAM_'):
                    param_name = key.replace('CUSTOM_PARAM_', '').lower()
                    self.request_params[param_name] = value
    
    def _validate(self):
        """Validate required configuration"""
        # Check that the API key for the selected provider is set
        api_key_env_var = f"{self.ai_provider.upper()}_API_KEY"
        if not self.api_key:
            raise ValueError(f"{api_key_env_var} is required for the {self.ai_provider} provider")
        
        # Provider-specific validation
        if self.ai_provider == 'azure' and not self.api_base_url:
            raise ValueError("AZURE_BASE_URL is required for Azure OpenAI")
            
        if self.ai_provider == 'custom' and not self.api_base_url:
            raise ValueError("CUSTOM_BASE_URL is required for custom provider")
        
        # Ensure directories exist
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.output_log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
