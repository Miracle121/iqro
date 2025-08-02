"""
Service Scanner Module
Detects running services and processes
"""

import os
import logging
import platform
from typing import Dict, List, Any, Optional
import psutil
from .utils import safe_run_command


class ServiceScanner:
    """Scans for running services and processes"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('hbvm_agent.service_scanner')
        self.system = platform.system().lower()
        
        # Check if psutil is available
        self.use_psutil = self._check_psutil_available()
        if not self.use_psutil:
            self.logger.warning("psutil not available, using system commands only")
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform service scan and return running services"""
        self.logger.info("Starting service scan")
        
        services = []
        
        if self.use_psutil:
            services.extend(self._scan_processes_psutil())
        
        # Get system-specific services
        if self.system == 'linux':
            services.extend(self._scan_linux_services())
        elif self.system == 'windows':
            services.extend(self._scan_windows_services())
        elif self.system == 'darwin':
            services.extend(self._scan_macos_services())
        
        # Remove duplicates based on name and pid
        unique_services = self._deduplicate_services(services)
        
        self.logger.info(f"Service scan completed, found {len(unique_services)} services")
        return unique_services
    
    def _scan_processes_psutil(self) -> List[Dict[str, Any]]:
        """Scan processes using psutil"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status', 
                                           'create_time', 'cpu_percent', 'memory_info',
                                           'username', 'exe']):
                try:
                    pinfo = proc.info
                    
                    # Skip kernel threads and very short-lived processes
                    if not pinfo['name'] or pinfo['name'].startswith('['):
                        continue
                    
                    service_info = {
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "status": pinfo['status'],
                        "cmdline": " ".join(pinfo['cmdline']) if pinfo['cmdline'] else "",
                        "username": pinfo.get('username', 'unknown'),
                        "executable": pinfo.get('exe', ''),
                        "scanner": "psutil"
                    }
                    
                    # Add resource usage if available
                    if pinfo.get('cpu_percent') is not None:
                        service_info["cpu_percent"] = pinfo['cpu_percent']
                    
                    if pinfo.get('memory_info'):
                        service_info["memory_rss"] = pinfo['memory_info'].rss
                        service_info["memory_vms"] = pinfo['memory_info'].vms
                    
                    # Add creation time
                    if pinfo.get('create_time'):
                        service_info["create_time"] = pinfo['create_time']
                    
                    # Try to identify service type
                    service_info.update(self._identify_service_type(service_info))
                    
                    processes.append(service_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error processing {proc}: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error scanning processes with psutil: {e}")
        
        return processes
    
    def _scan_linux_services(self) -> List[Dict[str, Any]]:
        """Scan Linux-specific services"""
        services = []
        
        # Try systemctl for systemd services
        systemd_services = self._get_systemd_services()
        if systemd_services:
            services.extend(systemd_services)
        
        # Try service command for SysV services
        sysv_services = self._get_sysv_services()
        if sysv_services:
            services.extend(sysv_services)
        
        return services
    
    def _get_systemd_services(self) -> List[Dict[str, Any]]:
        """Get systemd services"""
        services = []
        
        try:
            # Get all active services
            output = safe_run_command("systemctl list-units --type=service --state=active --no-pager --no-legend")
            if not output:
                return services
            
            for line in output.split('\n'):
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        service_name = parts[0]
                        load_state = parts[1]
                        active_state = parts[2]
                        sub_state = parts[3]
                        
                        service_info = {
                            "name": service_name,
                            "type": "systemd_service",
                            "load_state": load_state,
                            "active_state": active_state,
                            "sub_state": sub_state,
                            "scanner": "systemctl"
                        }
                        
                        # Get additional service details
                        service_details = self._get_systemd_service_details(service_name)
                        if service_details:
                            service_info.update(service_details)
                        
                        services.append(service_info)
        
        except Exception as e:
            self.logger.debug(f"Error getting systemd services: {e}")
        
        return services
    
    def _get_systemd_service_details(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a systemd service"""
        try:
            output = safe_run_command(f"systemctl show {service_name}")
            if not output:
                return None
            
            details = {}
            for line in output.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    if key in ['MainPID', 'ExecStart', 'Description', 'User', 'Group']:
                        details[key.lower()] = value
            
            return details
        
        except Exception:
            return None
    
    def _get_sysv_services(self) -> List[Dict[str, Any]]:
        """Get SysV init services"""
        services = []
        
        try:
            # Try service --status-all
            output = safe_run_command("service --status-all")
            if output:
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('['):
                        # Parse service status format: [ + ] service_name
                        status_char = line[2] if len(line) > 2 else '?'
                        service_name = line[6:].strip() if len(line) > 6 else 'unknown'
                        
                        if service_name and service_name != 'unknown':
                            status = 'running' if status_char == '+' else 'stopped'
                            
                            services.append({
                                "name": service_name,
                                "type": "sysv_service",
                                "status": status,
                                "scanner": "service"
                            })
        
        except Exception as e:
            self.logger.debug(f"Error getting SysV services: {e}")
        
        return services
    
    def _scan_windows_services(self) -> List[Dict[str, Any]]:
        """Scan Windows services"""
        services = []
        
        try:
            # Use PowerShell to get services
            powershell_cmd = (
                "Get-Service | Select-Object Name, Status, DisplayName, ServiceType | "
                "ConvertTo-Json"
            )
            
            output = safe_run_command(f'powershell -Command "{powershell_cmd}"')
            if output:
                import json
                service_data = json.loads(output)
                
                if isinstance(service_data, list):
                    for service in service_data:
                        services.append({
                            "name": service.get('Name', ''),
                            "display_name": service.get('DisplayName', ''),
                            "status": service.get('Status', ''),
                            "type": "windows_service",
                            "service_type": service.get('ServiceType', ''),
                            "scanner": "powershell"
                        })
                elif isinstance(service_data, dict):
                    services.append({
                        "name": service_data.get('Name', ''),
                        "display_name": service_data.get('DisplayName', ''),
                        "status": service_data.get('Status', ''),
                        "type": "windows_service",
                        "service_type": service_data.get('ServiceType', ''),
                        "scanner": "powershell"
                    })
        
        except Exception as e:
            self.logger.debug(f"Error getting Windows services: {e}")
        
        return services
    
    def _scan_macos_services(self) -> List[Dict[str, Any]]:
        """Scan macOS services"""
        services = []
        
        try:
            # Use launchctl to get services
            output = safe_run_command("launchctl list")
            if output:
                lines = output.split('\n')[1:]  # Skip header
                
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            pid = parts[0] if parts[0] != '-' else None
                            status = parts[1]
                            label = parts[2]
                            
                            services.append({
                                "name": label,
                                "pid": int(pid) if pid and pid.isdigit() else None,
                                "status": status,
                                "type": "launchd_service",
                                "scanner": "launchctl"
                            })
        
        except Exception as e:
            self.logger.debug(f"Error getting macOS services: {e}")
        
        return services
    
    def _identify_service_type(self, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Identify the type of service based on name and command line"""
        additional_info = {}
        
        name = service_info.get('name', '').lower()
        cmdline = service_info.get('cmdline', '').lower()
        
        # Database services
        db_indicators = {
            'mysql': 'database',
            'postgres': 'database',
            'redis': 'database',
            'mongodb': 'database',
            'elasticsearch': 'search_engine',
            'mariadb': 'database'
        }
        
        # Web services
        web_indicators = {
            'apache': 'web_server',
            'nginx': 'web_server',
            'httpd': 'web_server',
            'tomcat': 'application_server',
            'node': 'application_server'
        }
        
        # System services
        system_indicators = {
            'ssh': 'system_service',
            'cron': 'system_service',
            'systemd': 'system_service',
            'dbus': 'system_service',
            'udev': 'system_service'
        }
        
        # Check all indicator dictionaries
        all_indicators = {**db_indicators, **web_indicators, **system_indicators}
        
        for indicator, service_type in all_indicators.items():
            if indicator in name or indicator in cmdline:
                additional_info['service_type'] = service_type
                additional_info['category'] = self._get_service_category(service_type)
                break
        
        # Try to detect version from command line
        version = self._extract_version_from_cmdline(cmdline)
        if version:
            additional_info['version'] = version
        
        return additional_info
    
    def _get_service_category(self, service_type: str) -> str:
        """Get service category for grouping"""
        categories = {
            'database': 'data_storage',
            'web_server': 'network_service',
            'application_server': 'network_service',
            'search_engine': 'data_storage',
            'system_service': 'system'
        }
        
        return categories.get(service_type, 'other')
    
    def _extract_version_from_cmdline(self, cmdline: str) -> Optional[str]:
        """Try to extract version information from command line"""
        import re
        
        # Common version patterns
        version_patterns = [
            r'--version[=\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'-v[=\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'version[=\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'([0-9]+\.[0-9]+\.[0-9]+)',
            r'([0-9]+\.[0-9]+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, cmdline, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _deduplicate_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate services based on name and PID"""
        seen = set()
        unique_services = []
        
        for service in services:
            # Create a key for deduplication
            key_parts = [
                service.get('name', ''),
                str(service.get('pid', ''))
            ]
            key = '|'.join(key_parts)
            
            if key not in seen:
                seen.add(key)
                unique_services.append(service)
        
        return unique_services
    
    def _check_psutil_available(self) -> bool:
        """Check if psutil is available"""
        try:
            import psutil
            return True
        except ImportError:
            return False
    
    def get_network_services(self) -> List[Dict[str, Any]]:
        """Get services that have network connections"""
        if not self.use_psutil:
            return []
        
        network_services = []
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            # Group by PID
            pid_connections = {}
            for conn in connections:
                if conn.pid:
                    if conn.pid not in pid_connections:
                        pid_connections[conn.pid] = []
                    pid_connections[conn.pid].append(conn)
            
            # Get process info for each PID with connections
            for pid, conns in pid_connections.items():
                try:
                    proc = psutil.Process(pid)
                    
                    service_info = {
                        "pid": pid,
                        "name": proc.name(),
                        "cmdline": " ".join(proc.cmdline()),
                        "username": proc.username(),
                        "connections": []
                    }
                    
                    # Add connection details
                    for conn in conns:
                        conn_info = {
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                            "status": conn.status,
                            "family": conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                            "type": conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                        }
                        service_info["connections"].append(conn_info)
                    
                    network_services.append(service_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error getting network services: {e}")
        
        return network_services