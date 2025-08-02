#!/usr/bin/env python3
"""
HBVM Agent - Vulnerability Scanner
Scans host for vulnerabilities and reports to backend
"""

import os
import sys
import json
import logging
import platform
import socket
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path

import yaml
import schedule
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .os_scanner import OSScanner
from .port_scanner import PortScanner
from .service_scanner import ServiceScanner
from .cve_lookup import CVELookup
from .data_sender import DataSender
from .utils import setup_logging, get_host_id


class VulnerabilityScanner:
    """Main vulnerability scanner orchestrating all scanning components"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "config/config.yaml"
        self.config = self._load_config()
        self.logger = setup_logging(self.config)
        
        # Initialize scanning components
        self.os_scanner = OSScanner(self.config)
        self.port_scanner = PortScanner(self.config)
        self.service_scanner = ServiceScanner(self.config)
        self.cve_lookup = CVELookup(self.config)
        self.data_sender = DataSender(self.config)
        
        # Host identification
        self.host_id = get_host_id(self.config)
        
        self.logger.info(f"HBVM Agent initialized for host: {self.host_id}")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            print(f"Config file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error parsing config file: {e}")
            sys.exit(1)
    
    def perform_scan(self) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scan"""
        self.logger.info("Starting comprehensive vulnerability scan")
        scan_start = datetime.now(timezone.utc)
        
        scan_data = {
            "host_id": self.host_id,
            "timestamp": scan_start.isoformat(),
            "scan_type": "full",
            "agent_version": "1.0.0"
        }
        
        try:
            # Parallel execution of scanning tasks
            with ThreadPoolExecutor(max_workers=4) as executor:
                # Submit scanning tasks
                futures = {
                    executor.submit(self._scan_os_info): "os_info",
                    executor.submit(self._scan_ports): "ports",
                    executor.submit(self._scan_services): "services",
                    executor.submit(self._scan_packages): "packages"
                }
                
                # Collect results
                for future in as_completed(futures):
                    task_name = futures[future]
                    try:
                        result = future.result(timeout=300)  # 5 minute timeout
                        scan_data.update(result)
                        self.logger.info(f"Completed {task_name} scan")
                    except Exception as e:
                        self.logger.error(f"Error in {task_name} scan: {e}")
                        scan_data[f"{task_name}_error"] = str(e)
            
            # CVE lookup based on collected data
            if 'packages' in scan_data or 'services' in scan_data:
                cve_results = self._lookup_cves(scan_data)
                scan_data.update(cve_results)
            
            # Calculate scan duration
            scan_end = datetime.now(timezone.utc)
            scan_data["scan_duration"] = (scan_end - scan_start).total_seconds()
            scan_data["completed_at"] = scan_end.isoformat()
            
            self.logger.info(f"Scan completed in {scan_data['scan_duration']:.2f} seconds")
            return scan_data
            
        except Exception as e:
            self.logger.error(f"Critical error during scan: {e}")
            scan_data["error"] = str(e)
            scan_data["status"] = "failed"
            return scan_data
    
    def _scan_os_info(self) -> Dict[str, Any]:
        """Scan OS information"""
        try:
            return {"os": self.os_scanner.scan()}
        except Exception as e:
            self.logger.error(f"OS scan failed: {e}")
            return {"os_error": str(e)}
    
    def _scan_ports(self) -> Dict[str, Any]:
        """Scan open ports"""
        if not self.config.get('scanning', {}).get('enable_port_scan', True):
            return {"ports": []}
        
        try:
            return {"ports": self.port_scanner.scan()}
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return {"ports_error": str(e)}
    
    def _scan_services(self) -> Dict[str, Any]:
        """Scan running services"""
        if not self.config.get('scanning', {}).get('enable_service_detection', True):
            return {"services": []}
        
        try:
            return {"services": self.service_scanner.scan()}
        except Exception as e:
            self.logger.error(f"Service scan failed: {e}")
            return {"services_error": str(e)}
    
    def _scan_packages(self) -> Dict[str, Any]:
        """Scan installed packages"""
        if not self.config.get('scanning', {}).get('enable_package_scan', True):
            return {"packages": []}
        
        try:
            return {"packages": self.os_scanner.get_installed_packages()}
        except Exception as e:
            self.logger.error(f"Package scan failed: {e}")
            return {"packages_error": str(e)}
    
    def _lookup_cves(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Lookup CVEs for discovered software"""
        try:
            cves = self.cve_lookup.lookup_vulnerabilities(scan_data)
            return {"cves": cves, "cve_count": len(cves)}
        except Exception as e:
            self.logger.error(f"CVE lookup failed: {e}")
            return {"cves_error": str(e)}
    
    def send_results(self, scan_data: Dict[str, Any]) -> bool:
        """Send scan results to backend"""
        try:
            success = self.data_sender.send(scan_data)
            if success:
                self.logger.info("Scan results sent successfully")
            else:
                self.logger.error("Failed to send scan results")
            return success
        except Exception as e:
            self.logger.error(f"Error sending results: {e}")
            return False
    
    def run_scheduled_scan(self):
        """Run a scheduled scan and send results"""
        self.logger.info("Starting scheduled scan")
        scan_results = self.perform_scan()
        
        # Save results locally as backup
        self._save_scan_backup(scan_results)
        
        # Send to backend
        self.send_results(scan_results)
    
    def _save_scan_backup(self, scan_data: Dict[str, Any]):
        """Save scan results locally as backup"""
        try:
            backup_dir = Path("logs/scans")
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"scan_{timestamp}.json"
            
            with open(backup_file, 'w') as f:
                json.dump(scan_data, f, indent=2)
            
            self.logger.debug(f"Scan backup saved: {backup_file}")
        except Exception as e:
            self.logger.error(f"Failed to save scan backup: {e}")
    
    def start_scheduler(self):
        """Start the scheduled scanning"""
        interval = self.config.get('agent', {}).get('scan_interval', 3600)
        self.logger.info(f"Starting scheduler with {interval} second interval")
        
        # Schedule the scan
        schedule.every(interval).seconds.do(self.run_scheduled_scan)
        
        # Run initial scan
        self.run_scheduled_scan()
        
        # Keep scheduler running
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute


def main():
    """Main entry point for the scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="HBVM Vulnerability Scanner Agent")
    parser.add_argument("--config", "-c", default="config/config.yaml",
                       help="Path to configuration file")
    parser.add_argument("--scan-only", action="store_true",
                       help="Run single scan and exit")
    parser.add_argument("--no-send", action="store_true",
                       help="Don't send results to backend")
    parser.add_argument("--output", "-o", 
                       help="Save scan results to file")
    
    args = parser.parse_args()
    
    try:
        scanner = VulnerabilityScanner(args.config)
        
        if args.scan_only:
            # Single scan mode
            results = scanner.perform_scan()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
            
            if not args.no_send:
                scanner.send_results(results)
        else:
            # Scheduled mode
            scanner.start_scheduler()
            
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()