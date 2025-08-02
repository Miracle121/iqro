"""
Port Scanner Module
Scans for open ports and running services
"""

import socket
import logging
import threading
import time
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap


class PortScanner:
    """Scans for open ports and services"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('hbvm_agent.port_scanner')
        self.scanning_config = config.get('scanning', {})
        
        # Port scanning configuration
        self.enable_port_scan = self.scanning_config.get('enable_port_scan', True)
        self.port_range = self._parse_port_range(
            self.scanning_config.get('port_range', '1-1000')
        )
        self.scan_timeout = 5  # seconds per port
        self.max_threads = 100
        
        # Initialize nmap if available
        self.use_nmap = self._check_nmap_available()
        if self.use_nmap:
            self.nm = nmap.PortScanner()
            self.logger.info("Using nmap for port scanning")
        else:
            self.logger.info("Using basic socket scanning (nmap not available)")
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform port scan and return open ports with service info"""
        if not self.enable_port_scan:
            self.logger.info("Port scanning disabled")
            return []
        
        self.logger.info(f"Starting port scan on range {self.port_range[0]}-{self.port_range[1]}")
        start_time = time.time()
        
        if self.use_nmap:
            open_ports = self._nmap_scan()
        else:
            open_ports = self._socket_scan()
        
        scan_duration = time.time() - start_time
        self.logger.info(f"Port scan completed in {scan_duration:.2f}s, found {len(open_ports)} open ports")
        
        return open_ports
    
    def _nmap_scan(self) -> List[Dict[str, Any]]:
        """Use nmap for comprehensive port scanning"""
        try:
            # Construct port range for nmap
            port_range_str = f"{self.port_range[0]}-{self.port_range[1]}"
            
            # Run nmap scan with service detection
            self.nm.scan(
                hosts='127.0.0.1',
                ports=port_range_str,
                arguments='-sV -sS --version-intensity 5'  # Service version detection
            )
            
            open_ports = []
            
            for host in self.nm.all_hosts():
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        
                        if port_info['state'] == 'open':
                            port_data = {
                                "port": port,
                                "protocol": protocol,
                                "state": port_info['state'],
                                "service": port_info.get('name', 'unknown'),
                                "version": port_info.get('version', ''),
                                "product": port_info.get('product', ''),
                                "extrainfo": port_info.get('extrainfo', ''),
                                "reason": port_info.get('reason', ''),
                                "scanner": "nmap"
                            }
                            
                            # Add CPE information if available
                            if 'cpe' in port_info:
                                port_data['cpe'] = port_info['cpe']
                            
                            open_ports.append(port_data)
            
            return open_ports
            
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            # Fallback to socket scanning
            return self._socket_scan()
    
    def _socket_scan(self) -> List[Dict[str, Any]]:
        """Use basic socket scanning as fallback"""
        open_ports = []
        start_port, end_port = self.port_range
        
        # Limit the range for socket scanning to avoid too many threads
        if end_port - start_port > 5000:
            self.logger.warning("Large port range detected, limiting to first 5000 ports")
            end_port = start_port + 5000
        
        # Common ports to prioritize
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            3389, 5432, 3306, 1433, 27017, 6379, 9200, 8080, 8443
        ]
        
        # Scan common ports first, then others
        ports_to_scan = []
        for port in common_ports:
            if start_port <= port <= end_port:
                ports_to_scan.append(port)
        
        # Add remaining ports
        for port in range(start_port, end_port + 1):
            if port not in ports_to_scan:
                ports_to_scan.append(port)
        
        # Parallel socket scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit scanning tasks
            future_to_port = {
                executor.submit(self._scan_port, port): port 
                for port in ports_to_scan
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result(timeout=self.scan_timeout)
                    if result:
                        open_ports.append(result)
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")
        
        return open_ports
    
    def _scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port using socket"""
        try:
            # TCP scan
            tcp_result = self._scan_tcp_port(port)
            if tcp_result:
                return tcp_result
            
            # UDP scan for common UDP ports
            if port in [53, 67, 68, 69, 123, 161, 162, 514]:
                udp_result = self._scan_udp_port(port)
                if udp_result:
                    return udp_result
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return None
    
    def _scan_tcp_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Scan a TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                # Port is open, try to get service info
                service_info = self._get_service_info(port, 'tcp')
                
                port_data = {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service_info.get('service', 'unknown'),
                    "banner": service_info.get('banner', ''),
                    "scanner": "socket"
                }
                
                return port_data
            
            return None
            
        except Exception:
            return None
    
    def _scan_udp_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Scan a UDP port (basic check)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            # Send empty packet
            sock.sendto(b'', ('127.0.0.1', port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()
                
                service_info = self._get_service_info(port, 'udp')
                
                return {
                    "port": port,
                    "protocol": "udp",
                    "state": "open",
                    "service": service_info.get('service', 'unknown'),
                    "scanner": "socket"
                }
                
            except socket.timeout:
                # No response doesn't necessarily mean closed for UDP
                sock.close()
                return None
                
        except Exception:
            return None
    
    def _get_service_info(self, port: int, protocol: str) -> Dict[str, Any]:
        """Get service information for a port"""
        # Common service mappings
        tcp_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 3389: "rdp", 5432: "postgresql", 3306: "mysql",
            1433: "mssql", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch",
            8080: "http-alt", 8443: "https-alt"
        }
        
        udp_services = {
            53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
            123: "ntp", 161: "snmp", 162: "snmp-trap", 514: "syslog"
        }
        
        service_map = tcp_services if protocol == 'tcp' else udp_services
        service_name = service_map.get(port, f"unknown-{port}")
        
        service_info = {"service": service_name}
        
        # Try to get banner for common services
        if protocol == 'tcp' and port in [21, 22, 25, 80, 443]:
            banner = self._get_service_banner(port)
            if banner:
                service_info["banner"] = banner
        
        return service_info
    
    def _get_service_banner(self, port: int) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', port))
            
            # Send appropriate request based on port
            if port == 80:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP usually sends banner immediately
            elif port == 22:
                pass  # SSH sends banner immediately
            elif port == 25:
                pass  # SMTP sends banner immediately
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200] if banner else None  # Limit banner length
            
        except Exception:
            return None
    
    def _parse_port_range(self, port_range_str: str) -> Tuple[int, int]:
        """Parse port range string like '1-1000' or '80,443,8080'"""
        try:
            if '-' in port_range_str:
                start, end = port_range_str.split('-', 1)
                return int(start.strip()), int(end.strip())
            elif ',' in port_range_str:
                # For comma-separated ports, just take min and max
                ports = [int(p.strip()) for p in port_range_str.split(',')]
                return min(ports), max(ports)
            else:
                # Single port
                port = int(port_range_str.strip())
                return port, port
        except ValueError:
            self.logger.warning(f"Invalid port range: {port_range_str}, using default 1-1000")
            return 1, 1000
    
    def _check_nmap_available(self) -> bool:
        """Check if nmap is available and accessible"""
        try:
            # Try to import and initialize nmap
            import nmap
            nm = nmap.PortScanner()
            
            # Test if nmap binary is available
            nm.nmap_version()
            return True
            
        except (ImportError, nmap.PortScannerError, Exception):
            return False
    
    def get_listening_services(self) -> List[Dict[str, Any]]:
        """Get services that are actively listening (alternative method)"""
        try:
            import psutil
            
            listening_services = []
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    try:
                        # Get process info
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        
                        service_info = {
                            "port": conn.laddr.port,
                            "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                            "address": conn.laddr.ip,
                            "state": "listening",
                            "pid": conn.pid,
                            "process": proc.name() if proc else "unknown",
                            "cmdline": " ".join(proc.cmdline()) if proc else "",
                            "scanner": "psutil"
                        }
                        
                        # Get service name from port
                        service_map = self._get_service_info(conn.laddr.port, "tcp")
                        service_info.update(service_map)
                        
                        listening_services.append(service_info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            return listening_services
            
        except ImportError:
            self.logger.warning("psutil not available for listening services detection")
            return []
        except Exception as e:
            self.logger.error(f"Error getting listening services: {e}")
            return []