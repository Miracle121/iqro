"""
Data Sender Module
Sends scan results to the backend API
"""

import logging
import requests
import json
import time
from typing import Dict, Any, Optional
from urllib.parse import urljoin
import ssl
from cryptography.fernet import Fernet


class DataSender:
    """Sends scan data to the backend"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('hbvm_agent.data_sender')
        
        # Backend configuration
        self.backend_config = config.get('backend', {})
        self.base_url = self.backend_config.get('url', 'http://localhost:3000')
        self.endpoint = self.backend_config.get('endpoint', '/api/scan')
        self.timeout = self.backend_config.get('timeout', 30)
        self.retry_attempts = self.backend_config.get('retry_attempts', 3)
        
        # Security configuration
        self.security_config = config.get('security', {})
        self.ssl_verify = self.security_config.get('ssl_verify', True)
        self.encryption_key = self.security_config.get('encryption_key', '')
        
        # Agent configuration
        self.agent_config = config.get('agent', {})
        self.api_key = self.agent_config.get('api_key', '')
        
        # Initialize session
        self.session = self._create_session()
        
        # Initialize encryption if configured
        self.cipher = None
        if self.encryption_key:
            try:
                self.cipher = Fernet(self.encryption_key.encode())
            except Exception as e:
                self.logger.error(f"Failed to initialize encryption: {e}")
        
        self.logger.info(f"Data sender initialized for backend: {self.base_url}")
    
    def _create_session(self) -> requests.Session:
        """Create configured HTTP session"""
        session = requests.Session()
        
        # Set headers
        session.headers.update({
            'User-Agent': 'HBVM-Agent/1.0.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Add API key if configured
        if self.api_key:
            session.headers['Authorization'] = f'Bearer {self.api_key}'
            # Also add as X-API-Key for compatibility
            session.headers['X-API-Key'] = self.api_key
        
        # Configure SSL verification
        if not self.ssl_verify:
            session.verify = False
            # Disable SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        return session
    
    def send(self, scan_data: Dict[str, Any]) -> bool:
        """Send scan data to backend with retry logic"""
        self.logger.info("Sending scan data to backend")
        
        # Prepare data for transmission
        prepared_data = self._prepare_data(scan_data)
        if not prepared_data:
            self.logger.error("Failed to prepare scan data")
            return False
        
        # Construct full URL
        url = urljoin(self.base_url, self.endpoint)
        
        # Attempt to send with retries
        for attempt in range(1, self.retry_attempts + 1):
            try:
                self.logger.debug(f"Sending data (attempt {attempt}/{self.retry_attempts})")
                
                response = self.session.post(
                    url,
                    json=prepared_data,
                    timeout=self.timeout
                )
                
                # Check response
                if response.status_code == 200:
                    self.logger.info("Scan data sent successfully")
                    
                    # Log response details if available
                    try:
                        response_data = response.json()
                        if 'message' in response_data:
                            self.logger.info(f"Backend response: {response_data['message']}")
                        if 'scan_id' in response_data:
                            self.logger.info(f"Scan ID: {response_data['scan_id']}")
                    except:
                        pass
                    
                    return True
                
                elif response.status_code == 401:
                    self.logger.error("Authentication failed - check API key")
                    return False
                
                elif response.status_code == 429:
                    self.logger.warning("Rate limited by backend")
                    if attempt < self.retry_attempts:
                        wait_time = 2 ** attempt  # Exponential backoff
                        self.logger.info(f"Waiting {wait_time} seconds before retry")
                        time.sleep(wait_time)
                        continue
                    else:
                        return False
                
                else:
                    self.logger.warning(f"Backend returned status {response.status_code}: {response.text}")
                    if attempt < self.retry_attempts:
                        wait_time = 2 ** attempt
                        self.logger.info(f"Retrying in {wait_time} seconds")
                        time.sleep(wait_time)
                        continue
                    else:
                        return False
                        
            except requests.exceptions.ConnectionError as e:
                self.logger.error(f"Connection error (attempt {attempt}): {e}")
                if attempt < self.retry_attempts:
                    wait_time = 2 ** attempt
                    self.logger.info(f"Retrying in {wait_time} seconds")
                    time.sleep(wait_time)
                    continue
                else:
                    return False
                    
            except requests.exceptions.Timeout as e:
                self.logger.error(f"Timeout error (attempt {attempt}): {e}")
                if attempt < self.retry_attempts:
                    wait_time = 2 ** attempt
                    self.logger.info(f"Retrying in {wait_time} seconds")
                    time.sleep(wait_time)
                    continue
                else:
                    return False
                    
            except Exception as e:
                self.logger.error(f"Unexpected error sending data (attempt {attempt}): {e}")
                if attempt < self.retry_attempts:
                    wait_time = 2 ** attempt
                    self.logger.info(f"Retrying in {wait_time} seconds")
                    time.sleep(wait_time)
                    continue
                else:
                    return False
        
        return False
    
    def _prepare_data(self, scan_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Prepare scan data for transmission"""
        try:
            # Create a copy to avoid modifying original data
            prepared_data = scan_data.copy()
            
            # Add metadata
            prepared_data['agent_metadata'] = {
                'version': '1.0.0',
                'transmission_time': time.time(),
                'compression': None,
                'encryption': self.cipher is not None
            }
            
            # Validate required fields
            required_fields = ['host_id', 'timestamp']
            for field in required_fields:
                if field not in prepared_data:
                    self.logger.error(f"Missing required field: {field}")
                    return None
            
            # Encrypt sensitive data if encryption is configured
            if self.cipher:
                prepared_data = self._encrypt_sensitive_data(prepared_data)
            
            # Compress large data if needed
            data_size = len(json.dumps(prepared_data))
            if data_size > 1024 * 1024:  # 1MB
                self.logger.info(f"Large data detected ({data_size} bytes), considering compression")
                # Could implement compression here if needed
            
            # Sanitize data
            prepared_data = self._sanitize_data(prepared_data)
            
            return prepared_data
            
        except Exception as e:
            self.logger.error(f"Error preparing data: {e}")
            return None
    
    def _encrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields in scan data"""
        try:
            # Fields that should be encrypted
            sensitive_fields = ['services', 'packages', 'cves']
            
            for field in sensitive_fields:
                if field in data and data[field]:
                    # Convert to JSON string, encrypt, then base64 encode
                    field_json = json.dumps(data[field])
                    encrypted_data = self.cipher.encrypt(field_json.encode())
                    data[f'{field}_encrypted'] = encrypted_data.decode()
                    
                    # Remove original unencrypted data
                    del data[field]
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error encrypting data: {e}")
            return data
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize data to remove potentially sensitive information"""
        try:
            # Create a deep copy for sanitization
            import copy
            sanitized_data = copy.deepcopy(data)
            
            # Remove or mask sensitive fields
            sensitive_patterns = [
                'password', 'passwd', 'secret', 'key', 'token',
                'credential', 'auth', 'private'
            ]
            
            def sanitize_dict(d):
                if isinstance(d, dict):
                    for key, value in list(d.items()):
                        key_lower = key.lower()
                        
                        # Check if key contains sensitive patterns
                        if any(pattern in key_lower for pattern in sensitive_patterns):
                            d[key] = '[REDACTED]'
                        elif isinstance(value, (dict, list)):
                            sanitize_dict(value)
                        elif isinstance(value, str) and len(value) > 100:
                            # Truncate very long strings
                            d[key] = value[:100] + '...[TRUNCATED]'
                
                elif isinstance(d, list):
                    for item in d:
                        sanitize_dict(item)
            
            sanitize_dict(sanitized_data)
            return sanitized_data
            
        except Exception as e:
            self.logger.error(f"Error sanitizing data: {e}")
            return data
    
    def test_connection(self) -> bool:
        """Test connection to backend"""
        self.logger.info("Testing connection to backend")
        
        try:
            # Try to reach a health check endpoint
            health_url = urljoin(self.base_url, '/api/health')
            
            response = self.session.get(health_url, timeout=10)
            
            if response.status_code == 200:
                self.logger.info("Backend connection test successful")
                return True
            else:
                self.logger.warning(f"Backend health check returned {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            self.logger.error("Cannot connect to backend - connection refused")
            return False
        except requests.exceptions.Timeout:
            self.logger.error("Backend connection timeout")
            return False
        except Exception as e:
            self.logger.error(f"Backend connection test failed: {e}")
            return False
    
    def send_heartbeat(self, host_id: str) -> bool:
        """Send heartbeat to indicate agent is alive"""
        try:
            heartbeat_url = urljoin(self.base_url, '/api/heartbeat')
            
            heartbeat_data = {
                'host_id': host_id,
                'timestamp': time.time(),
                'status': 'alive',
                'agent_version': '1.0.0'
            }
            
            response = self.session.post(
                heartbeat_url,
                json=heartbeat_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.debug("Heartbeat sent successfully")
                return True
            else:
                self.logger.warning(f"Heartbeat failed with status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.debug(f"Heartbeat failed: {e}")
            return False
    
    def get_agent_config(self, host_id: str) -> Optional[Dict[str, Any]]:
        """Get updated configuration from backend"""
        try:
            config_url = urljoin(self.base_url, f'/api/agents/{host_id}/config')
            
            response = self.session.get(config_url, timeout=15)
            
            if response.status_code == 200:
                config_data = response.json()
                self.logger.info("Retrieved updated configuration from backend")
                return config_data
            elif response.status_code == 404:
                self.logger.info("No configuration updates available")
                return None
            else:
                self.logger.warning(f"Failed to get config: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting agent config: {e}")
            return None
    
    def report_error(self, host_id: str, error_type: str, error_message: str) -> bool:
        """Report an error to the backend"""
        try:
            error_url = urljoin(self.base_url, '/api/errors')
            
            error_data = {
                'host_id': host_id,
                'timestamp': time.time(),
                'error_type': error_type,
                'error_message': error_message,
                'agent_version': '1.0.0'
            }
            
            response = self.session.post(
                error_url,
                json=error_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.debug("Error reported to backend")
                return True
            else:
                self.logger.warning(f"Error reporting failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.debug(f"Failed to report error: {e}")
            return False