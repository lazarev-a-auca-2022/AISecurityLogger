"""
Threat Analyzer - Analyzes log entries for security threats using OpenRouter API
"""

import asyncio
import json
import logging
import time
from typing import Dict, Any, Optional, List

import aiohttp


class ThreatAnalyzer:
    """
    Threat Analyzer that processes log entries and sends them to OpenRouter API
    for security threat analysis
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.queue = []
        self.processing = False
        
        # Create a prompt template for the OpenRouter API
        self.prompt_template = """
        You are a cybersecurity expert analyzing server logs for potential security threats, 
        errors, or anomalies. 
        
        Please analyze the following log entries and provide:
        1. A concise summary of any potential security threats or critical errors detected
        2. The severity level (INFO, WARNING, ERROR, CRITICAL)
        3. Any recommended actions if applicable
        
        Log entries:
        {log_entries}
        
        Format your response as JSON with the following structure:
        {{
            "threat_detected": true/false,
            "severity": "INFO/WARNING/ERROR/CRITICAL",
            "summary": "Brief description of the threat or issue",
            "details": "More detailed explanation",
            "recommended_actions": "Steps to address the issue"
        }}
        """
    
    async def start_session(self):
        """Start the HTTP session"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
    
    async def close_session(self):
        """Close the HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
    
    async def analyze_log(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Add a log entry to the processing queue and process
        if enough entries are collected or if it's urgent
        """
        # Add to queue
        self.queue.append(log_entry)
        
        # Process if queue is large enough or contains urgent keywords
        if len(self.queue) >= self.settings.max_log_batch_size or self._contains_urgent_keywords(log_entry):
            return await self._process_queue()
        
        return None
    
    def _contains_urgent_keywords(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry contains urgent keywords that require immediate processing"""
        urgent_keywords = ["attack", "breach", "malware", "unauthorized", "root", "sudo"]
        log_text = log_entry.get('raw_line', '').lower()
        return any(keyword in log_text for keyword in urgent_keywords)
    
    async def _process_queue(self) -> Optional[Dict[str, Any]]:
        """Process the current queue of log entries"""
        if not self.queue or self.processing:
            return None
        
        self.processing = True
        
        try:
            # Take a batch of logs from the queue
            batch_size = min(len(self.queue), self.settings.max_log_batch_size)
            batch = self.queue[:batch_size]
            self.queue = self.queue[batch_size:]
            
            # Format log entries for the prompt
            log_entries_text = self._format_log_entries(batch)
            
            # Call OpenRouter API
            result = await self._call_openrouter_api(log_entries_text)
            
            if result:
                # Process the result and store in database
                analysis_result = self._process_ai_response(result, batch)
                
                if analysis_result and analysis_result.get('threat_detected'):
                    self.logger.warning(f"Threat detected: {analysis_result.get('summary')}")
                    # Here we would store the result in database (to be implemented in storage module)
                    # await self.database.store_threat(analysis_result)
                
                return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error processing log queue: {e}")
        
        finally:
            self.processing = False
        
        return None
    
    def _format_log_entries(self, log_entries: List[Dict[str, Any]]) -> str:
        """Format log entries for the API prompt"""
        formatted_entries = []
        
        for entry in log_entries:
            source = entry.get('source_file', 'unknown')
            log_type = entry.get('log_type', 'unknown')
            raw_line = entry.get('raw_line', '')
            
            formatted_entry = f"[Source: {source}, Type: {log_type}] {raw_line}"
            formatted_entries.append(formatted_entry)
        
        return "\n".join(formatted_entries)
    
    async def _call_openrouter_api(self, log_entries_text: str) -> Optional[str]:
        """Call the OpenRouter API to analyze log entries"""
        if not self.settings.openrouter_api_key:
            self.logger.error("OpenRouter API key not configured")
            return None
        
        await self.start_session()
        
        prompt = self.prompt_template.format(log_entries=log_entries_text)
        
        headers = {
            "Authorization": f"Bearer {self.settings.openrouter_api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.settings.openrouter_model_id,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing server logs."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }
        
        retries = 0
        while retries < self.settings.max_retries:
            try:
                async with self.session.post(
                    f"{self.settings.openrouter_base_url}/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=self.settings.ai_request_timeout
                ) as response:
                    if response.status == 200:
                        response_json = await response.json()
                        return response_json['choices'][0]['message']['content']
                    else:
                        error_text = await response.text()
                        self.logger.error(f"OpenRouter API error: {response.status} - {error_text}")
                        if response.status == 429:  # Rate limit
                            retries += 1
                            wait_time = 2 ** retries  # Exponential backoff
                            self.logger.warning(f"Rate limited, retrying in {wait_time} seconds...")
                            await asyncio.sleep(wait_time)
                            continue
                        return None
            except asyncio.TimeoutError:
                self.logger.error(f"OpenRouter API timeout (attempt {retries+1}/{self.settings.max_retries})")
                retries += 1
                await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Error calling OpenRouter API: {e}")
                return None
        
        return None
    
    def _process_ai_response(self, response_text: str, log_entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Process the AI response and format the result"""
        try:
            # Parse JSON response
            response_data = json.loads(response_text)
            
            # Create result object
            result = {
                "timestamp": time.time(),
                "threat_detected": response_data.get("threat_detected", False),
                "severity": response_data.get("severity", "INFO"),
                "summary": response_data.get("summary", "No summary provided"),
                "details": response_data.get("details", ""),
                "recommended_actions": response_data.get("recommended_actions", ""),
                "log_entries": log_entries
            }
            
            return result
            
        except json.JSONDecodeError:
            self.logger.error(f"Failed to parse AI response as JSON: {response_text}")
        except Exception as e:
            self.logger.error(f"Error processing AI response: {e}")
        
        return None
