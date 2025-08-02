"""
Utility functions for HBVM Agent
"""

import os
import sys
import uuid
import socket
import platform
import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any, Optional


def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """Setup logging configuration"""
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO').upper())
    log_file = log_config.get('file', 'logs/agent.log')
    max_size = _parse_size(log_config.get('max_size', '10MB'))
    backup_count = log_config.get('backup_count', 5)
    
    # Create logs directory
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure logger
    logger = logging.getLogger('hbvm_agent')
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_size, backupCount=backup_count
    )
    file_handler.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


def get_host_id(config: Dict[str, Any]) -> str:
    """Generate or retrieve host ID"""
    agent_config = config.get('agent', {})
    configured_id = agent_config.get('host_id')
    
    if configured_id and configured_id != "auto":
        return configured_id
    
    # Auto-generate based on system characteristics
    hostname = socket.gethostname()
    
    # Try to get MAC address for uniqueness
    try:
        import uuid
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                       for elements in range(0, 2*6, 2)][::-1])
        return f"{hostname}-{mac[:8]}"
    except:
        # Fallback to hostname + system info
        system_info = f"{platform.system()}-{platform.machine()}"
        return f"{hostname}-{hash(system_info) & 0xffffff:06x}"


def _parse_size(size_str: str) -> int:
    """Parse size string like '10MB' to bytes"""
    size_str = size_str.upper().strip()
    
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }
    
    for suffix, multiplier in multipliers.items():
        if size_str.endswith(suffix):
            try:
                number = float(size_str[:-len(suffix)])
                return int(number * multiplier)
            except ValueError:
                break
    
    # Default to 10MB if parsing fails
    return 10 * 1024 * 1024


def get_system_info() -> Dict[str, Any]:
    """Get basic system information"""
    try:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "architecture": platform.architecture(),
            "python_version": platform.python_version()
        }
    except Exception as e:
        return {"error": str(e)}


def is_root() -> bool:
    """Check if running with root/admin privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False


def safe_run_command(command: str, timeout: int = 30) -> Optional[str]:
    """Safely run a system command with timeout"""
    import subprocess
    import signal
    
    def timeout_handler(signum, frame):
        raise TimeoutError("Command timeout")
    
    try:
        # Set timeout signal (Unix only)
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
        
        # Run command
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)  # Cancel alarm
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None
            
    except (subprocess.TimeoutExpired, TimeoutError, Exception):
        return None


def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration structure"""
    required_sections = ['agent', 'backend', 'scanning']
    
    for section in required_sections:
        if section not in config:
            return False
    
    # Validate backend URL
    backend_url = config.get('backend', {}).get('url')
    if not backend_url or not backend_url.startswith(('http://', 'https://')):
        return False
    
    return True


def format_bytes(bytes_val: int) -> str:
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem operations"""
    import re
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    return filename or 'unnamed'