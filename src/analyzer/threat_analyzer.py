"""
Threat Analyzer - Analyzes log entries for security threats using AI APIs
"""

import asyncio
import json
import logging
import time
import re
from typing import Dict, Any, Optional, List

import aiohttp


class ThreatAnalyzer:
    """
    Threat Analyzer that processes log entries and sends them to AI providers
    for security threat analysis
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.queue = []
        self.processing = False
        
        # Create a prompt template for the AI API
        self.prompt_template = """
        You are a cybersecurity expert analyzing server logs for potential security threats, 
        errors, or anomalies. 
        
        Please analyze the following log entries and provide:
        1. A concise summary of any potential security threats or critical errors detected
        2. The severity level (INFO, WARNING, ERROR, CRITICAL)
        3. Any recommended actions if applicable
        
        Log entries:
        {log_entries}
        
        EXTREMELY IMPORTANT INSTRUCTIONS:
        
        1. Your ENTIRE response must be a single, valid JSON object with this exact structure:
        {{
            "threat_detected": true/false,
            "severity": "INFO/WARNING/ERROR/CRITICAL",
            "summary": "Brief description of the threat or issue",
            "details": "More detailed explanation",
            "recommended_actions": "Steps to address the issue"
        }}
        
        2. Do NOT include any explanations, markdown formatting, or additional text outside the JSON.
        3. Do NOT use triple backticks around the JSON.
        4. Ensure all JSON keys and values are properly quoted.
        5. The response MUST be valid, parseable JSON.
        
        Return ONLY the JSON object as your complete response.
        """
        
        # Initialize the appropriate provider handler
        self._initialize_provider_handler()
    
    def _initialize_provider_handler(self):
        """Initialize the appropriate handler based on the configured AI provider"""
        provider = self.settings.ai_provider
        self.logger.info(f"Initializing threat analyzer with AI provider: {provider}")
        
        # Set up provider-specific configuration
        if provider == 'openrouter':
            self.prepare_request = self._prepare_openrouter_request
            self.process_response = self._process_openrouter_response
            self.api_url = f"{self.settings.api_base_url}/chat/completions"
        elif provider == 'openai':
            self.prepare_request = self._prepare_openai_request
            self.process_response = self._process_openai_response
            self.api_url = f"{self.settings.api_base_url}/chat/completions"
        elif provider == 'google':
            self.prepare_request = self._prepare_google_request
            self.process_response = self._process_google_response
            self.api_url = f"{self.settings.api_base_url}/{self.settings.api_version}/models/{self.settings.model_id}:generateContent"
        elif provider == 'azure':
            self.prepare_request = self._prepare_azure_request
            self.process_response = self._process_azure_response
            self.api_url = f"{self.settings.api_base_url}/openai/deployments/{self.settings.deployment_name}/chat/completions?api-version={self.settings.api_version}"
        elif provider == 'anthropic':
            self.prepare_request = self._prepare_anthropic_request
            self.process_response = self._process_anthropic_response
            self.api_url = f"{self.settings.api_base_url}/{self.settings.api_version}/messages"
        elif provider == 'custom':
            self.prepare_request = self._prepare_custom_request
            self.process_response = self._process_custom_response
            self.api_url = self.settings.api_base_url
        else:
            self.logger.error(f"Unsupported AI provider: {provider}")
            raise ValueError(f"Unsupported AI provider: {provider}")
    
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
    
    async def check_processing_status(self):
        """Check if processing is stuck and reset if necessary"""
        # If we're stuck in processing for more than 60 seconds, reset the state
        if hasattr(self, '_processing_start_time') and self.processing:
            current_time = time.time()
            if current_time - self._processing_start_time > 60:  # 60 seconds timeout
                self.logger.warning("Processing appears to be stuck, resetting state")
                self.processing = False
                self._processing_start_time = None
        
        # If we start processing, record the start time
        if self.processing and not hasattr(self, '_processing_start_time'):
            self._processing_start_time = time.time()
        
        # If we're done processing, clear the start time
        if not self.processing and hasattr(self, '_processing_start_time'):
            self._processing_start_time = None
    
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
        self._processing_start_time = time.time()  # Record start time
        result = None
        
        try:
            # Take a batch of logs from the queue
            batch_size = min(len(self.queue), self.settings.max_log_batch_size)
            batch = self.queue[:batch_size]
            self.queue = self.queue[batch_size:]
            
            # Format log entries for the prompt
            log_entries_text = self._format_log_entries(batch)
            
            # Call AI API
            result = await self._call_ai_api(log_entries_text)
            
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
            # Always reset processing flag when done
            self.processing = False
            self._processing_start_time = None  # Clear processing start time
        
        return result
    
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
    
    # --- Provider-specific request preparation ---
    
    def _prepare_openrouter_request(self, prompt: str) -> tuple:
        """Prepare a request for OpenRouter API"""
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.settings.model_id,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }
        
        return headers, data
    
    def _prepare_openai_request(self, prompt: str) -> tuple:
        """Prepare a request for OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json"
        }
        
        if self.settings.organization_id:
            headers["OpenAI-Organization"] = self.settings.organization_id
        
        data = {
            "model": self.settings.model_id,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }
        
        return headers, data
    
    def _prepare_google_request(self, prompt: str) -> tuple:
        """Prepare a request for Google AI API"""
        headers = {
            "Content-Type": "application/json"
        }
        
        # Google uses "?key=" parameter rather than authorization header
        if "?" in self.api_url:
            self.api_url += f"&key={self.settings.api_key}"
        else:
            self.api_url += f"?key={self.settings.api_key}"
        
        data = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": f"You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting.\n\n{prompt}"
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.8,
                "topK": 40
            }
        }
        
        return headers, data
    
    def _prepare_azure_request(self, prompt: str) -> tuple:
        """Prepare a request for Azure OpenAI API"""
        headers = {
            "api-key": self.settings.api_key,
            "Content-Type": "application/json"
        }
        
        data = {
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "response_format": {"type": "json_object"}
        }
        
        return headers, data
    
    def _prepare_anthropic_request(self, prompt: str) -> tuple:
        """Prepare a request for Anthropic API"""
        headers = {
            "x-api-key": self.settings.api_key,
            "anthropic-version": self.settings.api_version,
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.settings.model_id,
            "messages": [
                {
                    "role": "user",
                    "content": f"You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting.\n\n{prompt}"
                }
            ],
            "temperature": 0.3,
            "system": "You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting."
        }
        
        return headers, data
    
    def _prepare_custom_request(self, prompt: str) -> tuple:
        """Prepare a request for a custom API"""
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json"
        }
        
        # Apply any custom headers from settings
        for key, value in self.settings.request_params.items():
            if key.startswith('header_'):
                header_name = key.replace('header_', '')
                headers[header_name] = value
        
        # Basic payload
        data = {
            "model": self.settings.model_id,
            "prompt": prompt,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing server logs. You MUST respond with ONLY a valid JSON object with no additional text or formatting."},
                {"role": "user", "content": prompt}
            ]
        }
        
        # Apply any custom parameters from settings
        for key, value in self.settings.request_params.items():
            if not key.startswith('header_'):
                try:
                    # Try to parse JSON values
                    json_value = json.loads(value)
                    data[key] = json_value
                except json.JSONDecodeError:
                    # Use as string if not valid JSON
                    data[key] = value
        
        return headers, data
    
    # --- Provider-specific response processing ---
    
    def _process_openrouter_response(self, response_json: Dict[str, Any]) -> Optional[str]:
        """Process response from OpenRouter API"""
        try:
            return response_json['choices'][0]['message']['content']
        except (KeyError, IndexError) as e:
            self.logger.error(f"Error extracting content from OpenRouter response: {e}")
            return None
    
    def _process_openai_response(self, response_json: Dict[str, Any]) -> Optional[str]:
        """Process response from OpenAI API"""
        try:
            return response_json['choices'][0]['message']['content']
        except (KeyError, IndexError) as e:
            self.logger.error(f"Error extracting content from OpenAI response: {e}")
            return None
    
    def _process_google_response(self, response_json: Dict[str, Any]) -> Optional[str]:
        """Process response from Google AI API"""
        try:
            return response_json['candidates'][0]['content']['parts'][0]['text']
        except (KeyError, IndexError) as e:
            self.logger.error(f"Error extracting content from Google response: {e}")
            return None
    
    def _process_azure_response(self, response_json: Dict[str, Any]) -> Optional[str]:
        """Process response from Azure OpenAI API"""
        try:
            return response_json['choices'][0]['message']['content']
        except (KeyError, IndexError) as e:
            self.logger.error(f"Error extracting content from Azure response: {e}")
            return None
    
    def _process_anthropic_response(self, response_json: Dict[str, Any]) -> Optional[str]:
        """Process response from Anthropic API"""
        try:
            return response_json['content'][0]['text']
        except (KeyError, IndexError) as e:
            self.logger.error(f"Error extracting content from Anthropic response: {e}")
            return None
    
    def _process_custom_response(self, response_json: Dict[str, Any]) -> Optional[str]:
        """Process response from custom API"""
        try:
            # Default extraction paths to try
            extraction_paths = [
                lambda r: r['choices'][0]['message']['content'],  # OpenAI-like
                lambda r: r['candidates'][0]['content']['parts'][0]['text'],  # Google-like
                lambda r: r['content'][0]['text'],  # Anthropic-like
                lambda r: r['response'],  # Simple response field
                lambda r: r['output'],    # Simple output field
                lambda r: r['result'],    # Simple result field
                lambda r: r['generated_text']  # Simple generated text field
            ]
            
            # Try each extraction path
            for extract in extraction_paths:
                try:
                    result = extract(response_json)
                    if result:
                        return result
                except (KeyError, IndexError, TypeError):
                    continue
            
            # If none of the standard paths worked, look for any field that might contain the response
            for key, value in response_json.items():
                if isinstance(value, str) and len(value) > 10:  # Simple heuristic for finding content
                    return value
                    
            # If all else fails, return the entire response as a string
            return json.dumps(response_json)
            
        except Exception as e:
            self.logger.error(f"Error extracting content from custom response: {e}")
            return None
    
    async def _call_ai_api(self, log_entries_text: str) -> Optional[str]:
        """Call the configured AI API to analyze log entries"""
        if not self.settings.api_key:
            self.logger.error(f"{self.settings.ai_provider.upper()} API key not configured")
            return None
        
        await self.start_session()
        
        prompt = self.prompt_template.format(log_entries=log_entries_text)
        
        # Prepare the request using the provider-specific method
        headers, data = self.prepare_request(prompt)
        
        retries = 0
        while retries < self.settings.max_retries:
            try:
                async with self.session.post(
                    self.api_url,
                    headers=headers,
                    json=data,
                    timeout=self.settings.ai_request_timeout
                ) as response:
                    if response.status == 200:
                        response_json = await response.json()
                        # Process the response using the provider-specific method
                        content = self.process_response(response_json)
                        return content
                    else:
                        error_text = await response.text()
                        self.logger.error(f"{self.settings.ai_provider} API error: {response.status} - {error_text}")
                        if response.status == 429:  # Rate limit
                            retries += 1
                            wait_time = 2 ** retries  # Exponential backoff
                            self.logger.warning(f"Rate limited, retrying in {wait_time} seconds...")
                            await asyncio.sleep(wait_time)
                            continue
                        return None
            except asyncio.TimeoutError:
                self.logger.error(f"{self.settings.ai_provider} API timeout (attempt {retries+1}/{self.settings.max_retries})")
                retries += 1
                await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Error calling {self.settings.ai_provider} API: {e}")
                return None
        
        return None
    
    def _extract_json_from_text(self, text: str) -> Optional[str]:
        """
        Extract JSON object from text, even if it's embedded within other content
        """
        # First, try to find JSON between triple backticks (common in markdown code blocks)
        json_pattern = r'```(?:json)?\s*({.*?})\s*```'
        matches = re.findall(json_pattern, text, re.DOTALL)
        if matches:
            for match in matches:
                try:
                    # Validate it's proper JSON
                    json.loads(match)
                    return match
                except:
                    continue
        
        # Next, try to find { "threat_detected": ... } pattern
        try:
            # Look for {...} patterns that might be JSON
            brace_pattern = r'{[^{]*"threat_detected"[^}]*}'
            matches = re.findall(brace_pattern, text, re.DOTALL)
            if matches:
                for match in matches:
                    try:
                        # Validate it's proper JSON
                        json.loads(match)
                        return match
                    except:
                        continue
        except:
            pass
        
        # If still not found, try more general JSON object pattern
        try:
            # Match any JSON-like object
            general_pattern = r'({[\s\S]*?})'
            matches = re.findall(general_pattern, text)
            if matches:
                for match in matches:
                    if len(match) > 10:  # Avoid small fragments
                        try:
                            data = json.loads(match)
                            # Check if it has at least some of our expected keys
                            expected_keys = ["threat_detected", "severity", "summary", "details"]
                            if any(key in data for key in expected_keys):
                                return match
                        except:
                            continue
        except:
            pass
        
        # Last resort: try to construct a valid JSON from the text
        try:
            # Look for key-value pairs that might be part of our JSON
            threat_detected = re.search(r'"threat_detected"\s*:\s*(true|false)', text)
            severity = re.search(r'"severity"\s*:\s*"([^"]+)"', text)
            summary = re.search(r'"summary"\s*:\s*"([^"]+)"', text)
            details = re.search(r'"details"\s*:\s*"([^"]+)"', text)
            actions = re.search(r'"recommended_actions"\s*:\s*"([^"]+)"', text)
            
            if threat_detected or severity or summary:
                constructed_json = {
                    "threat_detected": True if threat_detected and "true" in threat_detected.group(1) else False,
                    "severity": severity.group(1) if severity else "INFO",
                    "summary": summary.group(1) if summary else "No summary provided",
                    "details": details.group(1) if details else "",
                    "recommended_actions": actions.group(1) if actions else ""
                }
                return json.dumps(constructed_json)
        except:
            pass
        
        return None
    
    def _process_ai_response(self, response_text: str, log_entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Process the AI response and format the result"""
        try:
            # Try to parse the response as JSON directly
            try:
                self.logger.debug("Attempting to parse AI response as JSON directly")
                response_data = json.loads(response_text)
                self.logger.debug("Successfully parsed response as JSON directly")
            except json.JSONDecodeError as e:
                self.logger.debug(f"Direct JSON parsing failed: {str(e)}")
                
                # If direct parsing fails, try to extract JSON from the text
                self.logger.debug("Attempting to extract JSON from the response text")
                json_str = self._extract_json_from_text(response_text)
                
                if json_str:
                    self.logger.debug(f"Extracted potential JSON: {json_str[:100]}...")
                    response_data = json.loads(json_str)
                    self.logger.debug("Successfully parsed extracted JSON")
                else:
                    # Log the full response for debugging (truncated for log readability)
                    truncated_response = response_text[:500] + "..." if len(response_text) > 500 else response_text
                    self.logger.error(f"Failed to parse AI response as JSON. Full response: \n{truncated_response}")
                    
                    # Create a fallback response if we can't parse the JSON
                    self.logger.warning("Using fallback response with detected severity from text")
                    
                    # Try to infer the severity from the response
                    severity = "INFO"
                    if "CRITICAL" in response_text.upper():
                        severity = "CRITICAL"
                    elif "ERROR" in response_text.upper():
                        severity = "ERROR"
                    elif "WARNING" in response_text.upper():
                        severity = "WARNING"
                    
                    # Create a basic fallback response
                    return {
                        "timestamp": time.time(),
                        "threat_detected": "CRITICAL" in response_text.upper() or "ERROR" in response_text.upper(),
                        "severity": severity,
                        "summary": "AI response parsing failed - potential security issue detected",
                        "details": "The AI analyzer detected potential security issues but the response could not be properly parsed.",
                        "recommended_actions": "Please manually review the logs for security issues.",
                        "log_entries": log_entries
                    }
            
            # Create result object from the successfully parsed JSON
            result = {
                "timestamp": time.time(),
                "threat_detected": response_data.get("threat_detected", False),
                "severity": response_data.get("severity", "INFO"),
                "summary": response_data.get("summary", "No summary provided"),
                "details": response_data.get("details", ""),
                "recommended_actions": response_data.get("recommended_actions", ""),
                "log_entries": log_entries
            }
            
            self.logger.debug(f"Successfully processed AI response: {result['summary']}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing AI response: {str(e)}")
            self.logger.error(f"Response snippet: {response_text[:100]}...")
        
        return None
