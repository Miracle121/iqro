"""
Configuration module for HBVM Agent
"""
import os
from typing import Optional
from pydantic import BaseSettings, Field


class AgentConfig(BaseSettings):
    """Agent configuration settings"""
    
    # Backend connection
    backend_url: str = Field(default="https://api.hbvm.local", env="HBVM_BACKEND_URL")
    api_key: Optional[str] = Field(default=None, env="HBVM_API_KEY")
    
    # Agent identification
    agent_id: Optional[str] = Field(default=None, env="HBVM_AGENT_ID")
    hostname: str = Field(default_factory=lambda: os.uname().nodename)
    
    # Scanning configuration
    scan_interval_hours: int = Field(default=24, env="HBVM_SCAN_INTERVAL")
    max_scan_duration_minutes: int = Field(default=60, env="HBVM_MAX_SCAN_DURATION")
    
    # Security settings
    verify_ssl: bool = Field(default=True, env="HBVM_VERIFY_SSL")
    request_timeout: int = Field(default=30, env="HBVM_REQUEST_TIMEOUT")
    
    # Logging
    log_level: str = Field(default="INFO", env="HBVM_LOG_LEVEL")
    log_file: str = Field(default="/var/log/hbvm-agent.log", env="HBVM_LOG_FILE")
    
    # Data directories
    data_dir: str = Field(default="/var/lib/hbvm-agent", env="HBVM_DATA_DIR")
    cache_dir: str = Field(default="/var/cache/hbvm-agent", env="HBVM_CACHE_DIR")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global configuration instance
config = AgentConfig()