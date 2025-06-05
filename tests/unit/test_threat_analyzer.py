"""
Unit tests for the ThreatAnalyzer class
"""

import asyncio
import json
import pytest
import aiohttp
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from analyzer.threat_analyzer import ThreatAnalyzer


class MockSettings:
    """Mock settings for testing"""
    def __init__(self, provider='openrouter'):
        self.ai_provider = provider
        self.api_key = 'test_api_key'
        self.api_base_url = 'https://api.test.com'
        self.model_id = 'test-model'
        self.api_version = 'v1'
        self.deployment_name = 'test-deployment'
        self.max_tokens = 1000
        self.temperature = 0.3
        self.batch_size = 5
        self.batch_timeout = 30
        self.custom_headers = {}
        
        # Additional attributes needed by ThreatAnalyzer
        self.max_log_batch_size = 10
        self.organization_id = None
        self.request_params = {}
        self.max_retries = 3
        self.ai_request_timeout = 30


class TestThreatAnalyzer:
    """Test cases for ThreatAnalyzer"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_settings = MockSettings()
        self.mock_database = MagicMock()
        self.analyzer = ThreatAnalyzer(self.mock_settings, self.mock_database)

    def teardown_method(self):
        """Clean up after tests"""
        if hasattr(self.analyzer, 'session') and self.analyzer.session:
            asyncio.run(self.analyzer.close_session())

    def test_init_default_values(self):
        """Test analyzer initialization with default values"""
        analyzer = ThreatAnalyzer(self.mock_settings)
        assert analyzer.settings == self.mock_settings
        assert analyzer.database is None
        assert analyzer.session is None
        assert analyzer.queue == []
        assert analyzer.processing is False

    def test_init_with_database(self):
        """Test analyzer initialization with database"""
        assert self.analyzer.database == self.mock_database
        assert self.analyzer.settings == self.mock_settings

    def test_initialize_provider_handler_openrouter(self):
        """Test provider handler initialization for OpenRouter"""
        self.mock_settings.ai_provider = 'openrouter'
        analyzer = ThreatAnalyzer(self.mock_settings)
        
        assert analyzer.prepare_request == analyzer._prepare_openrouter_request
        assert analyzer.process_response == analyzer._process_openrouter_response
        assert 'chat/completions' in analyzer.api_url

    def test_initialize_provider_handler_openai(self):
        """Test provider handler initialization for OpenAI"""
        self.mock_settings.ai_provider = 'openai'
        analyzer = ThreatAnalyzer(self.mock_settings)
        
        assert analyzer.prepare_request == analyzer._prepare_openai_request
        assert analyzer.process_response == analyzer._process_openai_response
        assert 'chat/completions' in analyzer.api_url

    def test_initialize_provider_handler_google(self):
        """Test provider handler initialization for Google"""
        self.mock_settings.ai_provider = 'google'
        analyzer = ThreatAnalyzer(self.mock_settings)
        
        assert analyzer.prepare_request == analyzer._prepare_google_request
        assert analyzer.process_response == analyzer._process_google_response
        assert 'generateContent' in analyzer.api_url

    def test_initialize_provider_handler_azure(self):
        """Test provider handler initialization for Azure"""
        self.mock_settings.ai_provider = 'azure'
        analyzer = ThreatAnalyzer(self.mock_settings)
        
        assert analyzer.prepare_request == analyzer._prepare_azure_request
        assert analyzer.process_response == analyzer._process_azure_response
        assert 'deployments' in analyzer.api_url

    def test_initialize_provider_handler_anthropic(self):
        """Test provider handler initialization for Anthropic"""
        self.mock_settings.ai_provider = 'anthropic'
        analyzer = ThreatAnalyzer(self.mock_settings)
        
        assert analyzer.prepare_request == analyzer._prepare_anthropic_request
        assert analyzer.process_response == analyzer._process_anthropic_response
        assert 'messages' in analyzer.api_url

    def test_initialize_provider_handler_custom(self):
        """Test provider handler initialization for custom provider"""
        self.mock_settings.ai_provider = 'custom'
        analyzer = ThreatAnalyzer(self.mock_settings)
        
        assert analyzer.prepare_request == analyzer._prepare_custom_request
        assert analyzer.process_response == analyzer._process_custom_response
        assert analyzer.api_url == self.mock_settings.api_base_url

    def test_initialize_provider_handler_unsupported(self):
        """Test provider handler initialization with unsupported provider"""
        self.mock_settings.ai_provider = 'unsupported'
        
        with pytest.raises(ValueError, match="Unsupported AI provider"):
            ThreatAnalyzer(self.mock_settings)

    @pytest.mark.asyncio
    async def test_start_session(self):
        """Test HTTP session creation"""
        await self.analyzer.start_session()
        assert self.analyzer.session is not None
        assert isinstance(self.analyzer.session, aiohttp.ClientSession)

    @pytest.mark.asyncio
    async def test_close_session(self):
        """Test HTTP session closure"""
        await self.analyzer.start_session()
        session = self.analyzer.session
        
        await self.analyzer.close_session()
        assert session.closed

    @pytest.mark.asyncio
    async def test_close_session_when_none(self):
        """Test closing session when it's None"""
        self.analyzer.session = None
        await self.analyzer.close_session()  # Should not raise exception

    def test_contains_urgent_keywords_true(self):
        """Test urgent keyword detection - positive cases"""
        log_entry = {"message": "CRITICAL error occurred", "raw_line": "Detected unauthorized access attempt"}
        assert self.analyzer._contains_urgent_keywords(log_entry)

        log_entry = {"message": "Authentication failed", "raw_line": "unauthorized auth error"}
        assert self.analyzer._contains_urgent_keywords(log_entry)

        log_entry = {"message": "Security breach detected", "raw_line": "security breach detected"}
        assert self.analyzer._contains_urgent_keywords(log_entry)

    def test_contains_urgent_keywords_false(self):
        """Test urgent keyword detection - negative cases"""
        log_entry = {"message": "Info: Normal operation", "raw_line": "info log"}
        assert not self.analyzer._contains_urgent_keywords(log_entry)

        log_entry = {"message": "Debug trace", "raw_line": "debug"}
        assert not self.analyzer._contains_urgent_keywords(log_entry)

    def test_format_log_entries_single(self):
        """Test formatting single log entry"""
        log_entries = [{
            "source_file": "app.log", 
            "log_type": "application",
            "raw_line": "2024-01-01 Test message"
        }]
        formatted = self.analyzer._format_log_entries(log_entries)
        
        assert "app.log" in formatted
        assert "application" in formatted
        assert "2024-01-01 Test message" in formatted

    def test_format_log_entries_multiple(self):
        """Test formatting multiple log entries"""
        log_entries = [
            {
                "source_file": "app.log", 
                "log_type": "application",
                "raw_line": "2024-01-01 First message"
            },
            {
                "source_file": "system.log", 
                "log_type": "system",
                "raw_line": "2024-01-02 Second message"
            }
        ]
        formatted = self.analyzer._format_log_entries(log_entries)
        
        assert "First message" in formatted
        assert "Second message" in formatted
        assert "app.log" in formatted
        assert "system.log" in formatted
        assert formatted.count("---") >= 1  # Separator between entries

    def test_prepare_openrouter_request(self):
        """Test OpenRouter request preparation"""
        prompt = "Test prompt"
        headers, payload = self.analyzer._prepare_openrouter_request(prompt)
        
        assert "model" in payload
        assert "messages" in payload
        assert payload["messages"][1]["content"] == prompt
        assert headers["Authorization"] == f"Bearer {self.mock_settings.api_key}"

    def test_prepare_openai_request(self):
        """Test OpenAI request preparation"""
        prompt = "Test prompt"
        headers, payload = self.analyzer._prepare_openai_request(prompt)
        
        assert "model" in payload
        assert "messages" in payload
        assert payload["messages"][1]["content"] == prompt
        assert headers["Authorization"] == f"Bearer {self.mock_settings.api_key}"

    def test_prepare_google_request(self):
        """Test Google request preparation"""
        prompt = "Test prompt"
        payload, headers = self.analyzer._prepare_google_request(prompt)
        
        assert "contents" in payload
        assert payload["contents"][0]["parts"][0]["text"] == prompt
        assert headers["x-goog-api-key"] == self.mock_settings.api_key

    def test_prepare_azure_request(self):
        """Test Azure request preparation"""
        prompt = "Test prompt"
        payload, headers = self.analyzer._prepare_azure_request(prompt)
        
        assert "model" in payload
        assert "messages" in payload
        assert payload["messages"][0]["content"] == prompt
        assert headers["api-key"] == self.mock_settings.api_key

    def test_prepare_anthropic_request(self):
        """Test Anthropic request preparation"""
        prompt = "Test prompt"
        payload, headers = self.analyzer._prepare_anthropic_request(prompt)
        
        assert "model" in payload
        assert "messages" in payload
        assert payload["messages"][0]["content"] == prompt
        assert headers["x-api-key"] == self.mock_settings.api_key

    def test_prepare_custom_request(self):
        """Test custom provider request preparation"""
        prompt = "Test prompt"
        payload, headers = self.analyzer._prepare_custom_request(prompt)
        
        assert "prompt" in payload
        assert payload["prompt"] == prompt

    def test_process_openrouter_response_success(self):
        """Test OpenRouter response processing - success"""
        response_json = {
            "choices": [{"message": {"content": '{"threat_detected": true}'}}]
        }
        result = self.analyzer._process_openrouter_response(response_json)
        assert result == '{"threat_detected": true}'

    def test_process_openrouter_response_empty(self):
        """Test OpenRouter response processing - empty response"""
        response_json = {"choices": []}
        result = self.analyzer._process_openrouter_response(response_json)
        assert result is None

    def test_process_openai_response_success(self):
        """Test OpenAI response processing - success"""
        response_json = {
            "choices": [{"message": {"content": '{"threat_detected": false}'}}]
        }
        result = self.analyzer._process_openai_response(response_json)
        assert result == '{"threat_detected": false}'

    def test_process_google_response_success(self):
        """Test Google response processing - success"""
        response_json = {
            "candidates": [{"content": {"parts": [{"text": '{"severity": "INFO"}'}]}}]
        }
        result = self.analyzer._process_google_response(response_json)
        assert result == '{"severity": "INFO"}'

    def test_process_azure_response_success(self):
        """Test Azure response processing - success"""
        response_json = {
            "choices": [{"message": {"content": '{"severity": "WARNING"}'}}]
        }
        result = self.analyzer._process_azure_response(response_json)
        assert result == '{"severity": "WARNING"}'

    def test_process_anthropic_response_success(self):
        """Test Anthropic response processing - success"""
        response_json = {
            "content": [{"text": '{"severity": "ERROR"}'}]
        }
        result = self.analyzer._process_anthropic_response(response_json)
        assert result == '{"severity": "ERROR"}'

    def test_process_custom_response_success(self):
        """Test custom response processing - success"""
        response_json = {"response": '{"severity": "CRITICAL"}'}
        result = self.analyzer._process_custom_response(response_json)
        assert result == '{"severity": "CRITICAL"}'

    @pytest.mark.asyncio
    async def test_analyze_log_urgent(self):
        """Test analyze_log with urgent keywords"""
        log_entry = {"message": "CRITICAL error", "timestamp": "2024-01-01"}
        
        with patch.object(self.analyzer, '_process_queue', new_callable=AsyncMock) as mock_process:
            mock_process.return_value = {"threat_detected": True}
            result = await self.analyzer.analyze_log(log_entry)
            
            assert result == {"threat_detected": True}
            assert log_entry in self.analyzer.queue

    @pytest.mark.asyncio
    async def test_analyze_log_non_urgent(self):
        """Test analyze_log with non-urgent entry"""
        log_entry = {"message": "Info message", "timestamp": "2024-01-01"}
        
        result = await self.analyzer.analyze_log(log_entry)
        assert result is None
        assert log_entry in self.analyzer.queue

    @pytest.mark.asyncio
    async def test_process_queue_success(self):
        """Test successful queue processing"""
        # Add test entries to queue
        self.analyzer.queue = [
            {"message": "Test 1", "timestamp": "2024-01-01"},
            {"message": "Test 2", "timestamp": "2024-01-02"}
        ]
        
        mock_response = {
            "threat_detected": True,
            "severity": "WARNING",
            "summary": "Test threat"
        }
        
        with patch.object(self.analyzer, 'start_session', new_callable=AsyncMock), \
             patch('aiohttp.ClientSession.post') as mock_post:
            
            # Mock successful API response
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json.return_value = {"choices": [{"message": {"content": json.dumps(mock_response)}}]}
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            result = await self.analyzer._process_queue()
            
            assert result == mock_response
            assert len(self.analyzer.queue) == 0  # Queue should be cleared

    @pytest.mark.asyncio
    async def test_process_queue_api_error(self):
        """Test queue processing with API error"""
        self.analyzer.queue = [{"message": "Test", "timestamp": "2024-01-01"}]
        
        with patch.object(self.analyzer, 'start_session', new_callable=AsyncMock), \
             patch('aiohttp.ClientSession.post') as mock_post:
            
            # Mock API error response
            mock_resp = AsyncMock()
            mock_resp.status = 500
            mock_resp.text.return_value = "Internal Server Error"
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            result = await self.analyzer._process_queue()
            assert result is None

    @pytest.mark.asyncio
    async def test_process_queue_json_parse_error(self):
        """Test queue processing with JSON parse error"""
        self.analyzer.queue = [{"message": "Test", "timestamp": "2024-01-01"}]
        
        with patch.object(self.analyzer, 'start_session', new_callable=AsyncMock), \
             patch('aiohttp.ClientSession.post') as mock_post:
            
            # Mock response with invalid JSON
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json.return_value = {"choices": [{"message": {"content": "invalid json"}}]}
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            result = await self.analyzer._process_queue()
            assert result is None

    @pytest.mark.asyncio
    async def test_check_processing_status_idle(self):
        """Test processing status check when idle"""
        result = await self.analyzer.check_processing_status()
        expected = {
            "processing": False,
            "queue_size": 0,
            "last_processed": None
        }
        assert result == expected

    @pytest.mark.asyncio
    async def test_check_processing_status_with_queue(self):
        """Test processing status check with items in queue"""
        self.analyzer.queue = [{"test": "entry"}]
        result = await self.analyzer.check_processing_status()
        
        assert result["processing"] is False
        assert result["queue_size"] == 1

    def test_prompt_template_format(self):
        """Test that prompt template contains required placeholders"""
        assert "{log_entries}" in self.analyzer.prompt_template
        assert "JSON" in self.analyzer.prompt_template
        assert "threat_detected" in self.analyzer.prompt_template
        assert "severity" in self.analyzer.prompt_template

    @pytest.mark.asyncio
    async def test_concurrent_analyze_log_calls(self):
        """Test concurrent analyze_log calls"""
        log_entries = [
            {"message": "CRITICAL error 1", "timestamp": "2024-01-01"},
            {"message": "CRITICAL error 2", "timestamp": "2024-01-02"},
            {"message": "CRITICAL error 3", "timestamp": "2024-01-03"}
        ]
        
        with patch.object(self.analyzer, '_process_queue', new_callable=AsyncMock) as mock_process:
            mock_process.return_value = {"threat_detected": True}
            
            # Run analyze_log concurrently
            tasks = [self.analyzer.analyze_log(entry) for entry in log_entries]
            results = await asyncio.gather(*tasks)
            
            # All should return results
            assert all(result == {"threat_detected": True} for result in results)
            # Queue should contain all entries
            assert len(self.analyzer.queue) == 3

    @pytest.mark.asyncio
    async def test_large_batch_processing(self):
        """Test processing large batches"""
        # Add many entries to queue
        large_batch = [{"message": f"Entry {i}", "timestamp": f"2024-01-{i:02d}"} 
                      for i in range(1, 11)]
        self.analyzer.queue = large_batch
        
        with patch.object(self.analyzer, 'start_session', new_callable=AsyncMock), \
             patch('aiohttp.ClientSession.post') as mock_post:
            
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": '{"threat_detected": false}'}}]
            }
            mock_post.return_value.__aenter__.return_value = mock_resp
            
            result = await self.analyzer._process_queue()
            assert result == {"threat_detected": False}


if __name__ == '__main__':
    pytest.main([__file__])
