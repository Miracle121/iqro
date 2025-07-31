"""
Main HBVM Agent Module
Orchestrates vulnerability scanning, scheduling, and communication
"""
import logging
import schedule
import time
import signal
import sys
import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import threading

from .config import config
from .scanner import VulnerabilityScanner
from .communicator import BackendCommunicator

logger = logging.getLogger(__name__)


class HBVMAgent:
    """Main HBVM Agent class"""
    
    def __init__(self):
        self.scanner = VulnerabilityScanner()
        self.communicator = BackendCommunicator()
        self.running = False
        self.last_scan_time = None
        self.last_heartbeat_time = None
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Ensure data directories exist
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        directories = [config.data_dir, config.cache_dir]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, config.log_level.upper()),
            format=log_format,
            handlers=[
                logging.FileHandler(config.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Set specific loggers to appropriate levels
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    def initialize(self) -> bool:
        """Initialize the agent"""
        try:
            logger.info("Initializing HBVM Agent")
            
            # Check backend connectivity
            if not self.communicator.check_backend_health():
                logger.error("Backend is not accessible")
                return False
            
            # Get system information for registration
            host_info = {
                'hostname': self.scanner.os_info.get('hostname'),
                'os': self.scanner.os_info,
                'system_info': self.scanner._get_system_info()
            }
            
            # Register with backend
            if not self.communicator.register_agent(host_info):
                logger.error("Failed to register agent with backend")
                return False
            
            # Authenticate
            if not self.communicator.authenticate():
                logger.error("Failed to authenticate with backend")
                return False
            
            # Get scan schedule from backend (fallback to config)
            schedule_config = self.communicator.get_scan_schedule()
            if schedule_config:
                scan_interval = schedule_config.get('interval_hours', config.scan_interval_hours)
            else:
                scan_interval = config.scan_interval_hours
            
            # Setup scan schedule
            self._setup_scan_schedule(scan_interval)
            
            # Setup heartbeat schedule (every 5 minutes)
            schedule.every(5).minutes.do(self._send_heartbeat)
            
            logger.info("Agent initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Agent initialization failed: {e}")
            return False
    
    def _setup_scan_schedule(self, interval_hours: int):
        """Setup the vulnerability scan schedule"""
        logger.info(f"Setting up scan schedule: every {interval_hours} hours")
        
        # Clear existing scan jobs
        schedule.clear('scan')
        
        # Schedule scan
        schedule.every(interval_hours).hours.do(self._perform_scan).tag('scan')
        
        # Also schedule an immediate scan if it's been more than the interval
        if self._should_perform_immediate_scan(interval_hours):
            schedule.every().minute.do(self._perform_immediate_scan).tag('immediate')
    
    def _should_perform_immediate_scan(self, interval_hours: int) -> bool:
        """Check if an immediate scan should be performed"""
        last_scan_file = os.path.join(config.data_dir, 'last_scan.json')
        
        try:
            if os.path.exists(last_scan_file):
                with open(last_scan_file, 'r') as f:
                    data = json.load(f)
                    last_scan = datetime.fromisoformat(data.get('timestamp', ''))
                    
                    # Check if it's been longer than the interval
                    if datetime.utcnow() - last_scan > timedelta(hours=interval_hours):
                        return True
            else:
                # No previous scan recorded
                return True
                
        except Exception as e:
            logger.warning(f"Failed to check last scan time: {e}")
            return True
        
        return False
    
    def _perform_immediate_scan(self):
        """Perform an immediate scan and remove the job"""
        logger.info("Performing immediate scan")
        self._perform_scan()
        
        # Remove the immediate scan job
        schedule.clear('immediate')
    
    def _perform_scan(self):
        """Perform vulnerability scan and send results"""
        try:
            logger.info("Starting scheduled vulnerability scan")
            scan_start = datetime.utcnow()
            
            # Perform the scan
            scan_results = self.scanner.scan_vulnerabilities()
            
            # Save scan results locally
            self._save_scan_results(scan_results)
            
            # Send results to backend
            if self.communicator.send_scan_results(scan_results):
                logger.info("Scan results sent to backend successfully")
                self.last_scan_time = scan_start
                
                # Update last scan timestamp
                self._update_last_scan_timestamp(scan_start)
            else:
                logger.error("Failed to send scan results to backend")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
    
    def _save_scan_results(self, scan_results: Dict[str, Any]):
        """Save scan results to local storage"""
        try:
            # Save to data directory
            scan_file = os.path.join(
                config.data_dir, 
                f"scan_{scan_results.get('scan_id', 'unknown')}.json"
            )
            
            with open(scan_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            
            logger.debug(f"Scan results saved to {scan_file}")
            
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
    
    def _update_last_scan_timestamp(self, timestamp: datetime):
        """Update the last scan timestamp"""
        try:
            last_scan_file = os.path.join(config.data_dir, 'last_scan.json')
            data = {
                'timestamp': timestamp.isoformat(),
                'scan_id': f"scan_{int(timestamp.timestamp())}"
            }
            
            with open(last_scan_file, 'w') as f:
                json.dump(data, f)
                
        except Exception as e:
            logger.error(f"Failed to update last scan timestamp: {e}")
    
    def _send_heartbeat(self):
        """Send heartbeat to backend"""
        try:
            if self.communicator.send_heartbeat():
                self.last_heartbeat_time = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")
    
    def _cleanup_old_scans(self):
        """Clean up old scan files"""
        try:
            # Keep scans for 30 days
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            
            for filename in os.listdir(config.data_dir):
                if filename.startswith('scan_') and filename.endswith('.json'):
                    file_path = os.path.join(config.data_dir, filename)
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_date:
                        os.remove(file_path)
                        logger.debug(f"Removed old scan file: {filename}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old scans: {e}")
    
    def run(self):
        """Main agent run loop"""
        try:
            self._setup_logging()
            logger.info("Starting HBVM Agent")
            
            if not self.initialize():
                logger.error("Agent initialization failed, exiting")
                sys.exit(1)
            
            self.running = True
            logger.info("Agent is running and monitoring for scheduled tasks")
            
            # Schedule cleanup task (daily)
            schedule.every().day.at("02:00").do(self._cleanup_old_scans)
            
            # Main event loop
            while self.running:
                try:
                    schedule.run_pending()
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    time.sleep(60)
            
            logger.info("Agent shutdown completed")
            
        except Exception as e:
            logger.error(f"Agent failed: {e}")
            sys.exit(1)
    
    def run_single_scan(self) -> Dict[str, Any]:
        """Run a single scan and return results (for testing/manual runs)"""
        self._setup_logging()
        logger.info("Running single vulnerability scan")
        
        return self.scanner.scan_vulnerabilities()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            'running': self.running,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
            'last_heartbeat_time': self.last_heartbeat_time.isoformat() if self.last_heartbeat_time else None,
            'agent_id': self.communicator.agent_id,
            'backend_url': config.backend_url,
            'scan_interval_hours': config.scan_interval_hours
        }