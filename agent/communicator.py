"""
Communication module for HBVM Agent
Handles secure API communication with the backend
"""
import logging
import requests
import json
import jwt
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import config

logger = logging.getLogger(__name__)


class BackendCommunicator:
    """Handles communication with the HBVM backend"""
    
    def __init__(self):
        self.session = self._create_session()
        self.base_url = config.backend_url.rstrip('/')
        self.api_key = config.api_key
        self.agent_id = config.agent_id
        self._token = None
        self._token_expires = None
        
    def _create_session(self) -> requests.Session:
        """Create a configured requests session with retries"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set timeout and SSL verification
        session.timeout = config.request_timeout
        session.verify = config.verify_ssl
        
        return session
    
    def register_agent(self, host_info: Dict[str, Any]) -> bool:
        """Register the agent with the backend"""
        try:
            endpoint = f"{self.base_url}/api/v1/agents/register"
            
            payload = {
                'hostname': host_info.get('hostname'),
                'os_info': host_info.get('os'),
                'system_info': host_info.get('system_info'),
                'agent_version': '1.0.0',
                'capabilities': ['vulnerability_scan', 'system_info', 'configuration_check']
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'HBVM-Agent/1.0.0'
            }
            
            if self.api_key:
                headers['X-API-Key'] = self.api_key
            
            logger.info(f"Registering agent with backend: {endpoint}")
            response = self.session.post(endpoint, json=payload, headers=headers)
            
            if response.status_code == 201:
                data = response.json()
                self.agent_id = data.get('agent_id')
                logger.info(f"Agent registered successfully with ID: {self.agent_id}")
                return True
            elif response.status_code == 409:
                # Agent already exists
                data = response.json()
                self.agent_id = data.get('agent_id')
                logger.info(f"Agent already registered with ID: {self.agent_id}")
                return True
            else:
                logger.error(f"Agent registration failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Agent registration failed: {e}")
            return False
    
    def authenticate(self) -> bool:
        """Authenticate with the backend and get JWT token"""
        try:
            endpoint = f"{self.base_url}/api/v1/auth/agent"
            
            payload = {
                'agent_id': self.agent_id,
                'hostname': config.hostname
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'HBVM-Agent/1.0.0'
            }
            
            if self.api_key:
                headers['X-API-Key'] = self.api_key
            
            response = self.session.post(endpoint, json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                self._token = data.get('token')
                
                # Decode token to get expiration
                try:
                    decoded = jwt.decode(self._token, options={"verify_signature": False})
                    self._token_expires = datetime.fromtimestamp(decoded.get('exp', 0))
                    logger.info("Authentication successful")
                    return True
                except Exception as e:
                    logger.error(f"Failed to decode JWT token: {e}")
                    return False
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False
    
    def _is_token_valid(self) -> bool:
        """Check if the current token is valid and not expired"""
        if not self._token or not self._token_expires:
            return False
        
        # Check if token expires within the next 5 minutes
        return datetime.now() < (self._token_expires - timedelta(minutes=5))
    
    def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid authentication token"""
        if not self._is_token_valid():
            return self.authenticate()
        return True
    
    def send_scan_results(self, scan_data: Dict[str, Any]) -> bool:
        """Send vulnerability scan results to the backend"""
        try:
            if not self._ensure_authenticated():
                logger.error("Failed to authenticate before sending scan results")
                return False
            
            endpoint = f"{self.base_url}/api/v1/scans"
            
            payload = {
                'agent_id': self.agent_id,
                'scan_data': scan_data
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self._token}',
                'User-Agent': 'HBVM-Agent/1.0.0'
            }
            
            logger.info(f"Sending scan results to backend: {scan_data['scan_id']}")
            response = self.session.post(endpoint, json=payload, headers=headers)
            
            if response.status_code in [200, 201]:
                logger.info("Scan results sent successfully")
                return True
            else:
                logger.error(f"Failed to send scan results: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send scan results: {e}")
            return False
    
    def get_scan_schedule(self) -> Optional[Dict[str, Any]]:
        """Get scan schedule configuration from backend"""
        try:
            if not self._ensure_authenticated():
                logger.error("Failed to authenticate before getting scan schedule")
                return None
            
            endpoint = f"{self.base_url}/api/v1/agents/{self.agent_id}/schedule"
            
            headers = {
                'Authorization': f'Bearer {self._token}',
                'User-Agent': 'HBVM-Agent/1.0.0'
            }
            
            response = self.session.get(endpoint, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get scan schedule: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to get scan schedule: {e}")
            return None
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to backend to indicate agent is alive"""
        try:
            if not self._ensure_authenticated():
                logger.error("Failed to authenticate before sending heartbeat")
                return False
            
            endpoint = f"{self.base_url}/api/v1/agents/{self.agent_id}/heartbeat"
            
            payload = {
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'active'
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self._token}',
                'User-Agent': 'HBVM-Agent/1.0.0'
            }
            
            response = self.session.post(endpoint, json=payload, headers=headers)
            
            if response.status_code in [200, 201]:
                logger.debug("Heartbeat sent successfully")
                return True
            else:
                logger.warning(f"Failed to send heartbeat: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")
            return False
    
    def check_backend_health(self) -> bool:
        """Check if backend is accessible"""
        try:
            endpoint = f"{self.base_url}/api/v1/health"
            response = self.session.get(endpoint, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Backend health check failed: {e}")
            return False