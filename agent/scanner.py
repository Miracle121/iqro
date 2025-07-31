"""
Vulnerability Scanner Module for HBVM Agent
"""
import logging
import subprocess
import json
import re
import distro
import psutil
from typing import List, Dict, Any, Optional
from datetime import datetime
from packaging import version
import os

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self):
        self.os_info = self._get_os_info()
        self.package_manager = self._detect_package_manager()
        
    def _get_os_info(self) -> Dict[str, Any]:
        """Get operating system information"""
        try:
            os_info = {
                'name': distro.name(),
                'version': distro.version(),
                'codename': distro.codename(),
                'id': distro.id(),
                'like': distro.like(),
                'kernel': os.uname().release,
                'architecture': os.uname().machine,
                'hostname': os.uname().nodename
            }
            logger.info(f"Detected OS: {os_info['name']} {os_info['version']}")
            return os_info
        except Exception as e:
            logger.error(f"Failed to get OS info: {e}")
            return {}
    
    def _detect_package_manager(self) -> str:
        """Detect the package manager used by the system"""
        managers = {
            'apt': '/usr/bin/apt',
            'yum': '/usr/bin/yum',
            'dnf': '/usr/bin/dnf',
            'zypper': '/usr/bin/zypper',
            'pacman': '/usr/bin/pacman'
        }
        
        for manager, path in managers.items():
            if os.path.exists(path):
                logger.info(f"Detected package manager: {manager}")
                return manager
        
        logger.warning("No supported package manager detected")
        return 'unknown'
    
    def scan_vulnerabilities(self) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scan"""
        logger.info("Starting vulnerability scan")
        scan_start = datetime.utcnow()
        
        try:
            vulnerabilities = []
            
            # Scan installed packages
            packages = self._get_installed_packages()
            
            # Check for known vulnerabilities
            for package in packages:
                vulns = self._check_package_vulnerabilities(package)
                vulnerabilities.extend(vulns)
            
            # Additional system checks
            system_vulns = self._check_system_vulnerabilities()
            vulnerabilities.extend(system_vulns)
            
            scan_end = datetime.utcnow()
            scan_duration = (scan_end - scan_start).total_seconds()
            
            result = {
                'scan_id': f"scan_{int(scan_start.timestamp())}",
                'timestamp': scan_start.isoformat(),
                'duration_seconds': scan_duration,
                'host_info': {
                    'hostname': self.os_info.get('hostname'),
                    'os': self.os_info,
                    'system_info': self._get_system_info()
                },
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'total_vulnerabilities': len(vulnerabilities),
                    'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                    'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                    'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                    'low': len([v for v in vulnerabilities if v.get('severity') == 'low'])
                }
            }
            
            logger.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities in {scan_duration:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {
                'scan_id': f"scan_{int(scan_start.timestamp())}_failed",
                'timestamp': scan_start.isoformat(),
                'error': str(e),
                'vulnerabilities': [],
                'summary': {'total_vulnerabilities': 0}
            }
    
    def _get_installed_packages(self) -> List[Dict[str, str]]:
        """Get list of installed packages"""
        packages = []
        
        try:
            if self.package_manager == 'apt':
                packages = self._get_apt_packages()
            elif self.package_manager in ['yum', 'dnf']:
                packages = self._get_rpm_packages()
            elif self.package_manager == 'zypper':
                packages = self._get_zypper_packages()
            elif self.package_manager == 'pacman':
                packages = self._get_pacman_packages()
            
            logger.info(f"Found {len(packages)} installed packages")
            return packages
            
        except Exception as e:
            logger.error(f"Failed to get installed packages: {e}")
            return []
    
    def _get_apt_packages(self) -> List[Dict[str, str]]:
        """Get packages from APT (Debian/Ubuntu)"""
        try:
            # Use dpkg-query for accurate package information
            cmd = ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${Status}\n']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            packages = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 4 and 'installed' in parts[3]:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'architecture': parts[2],
                            'manager': 'apt'
                        })
            
            return packages
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get APT packages: {e}")
            return []
    
    def _get_rpm_packages(self) -> List[Dict[str, str]]:
        """Get packages from RPM (RHEL/CentOS/Fedora)"""
        try:
            cmd = ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            packages = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'architecture': parts[2],
                            'manager': 'rpm'
                        })
            
            return packages
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get RPM packages: {e}")
            return []
    
    def _get_zypper_packages(self) -> List[Dict[str, str]]:
        """Get packages from Zypper (openSUSE)"""
        try:
            cmd = ['zypper', 'pa', '-i', '--details']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            packages = []
            # Parse zypper output (skip headers)
            lines = result.stdout.strip().split('\n')[2:]
            for line in lines:
                if line and not line.startswith('-'):
                    parts = line.split('|')
                    if len(parts) >= 4:
                        packages.append({
                            'name': parts[1].strip(),
                            'version': parts[3].strip(),
                            'architecture': parts[2].strip(),
                            'manager': 'zypper'
                        })
            
            return packages
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get Zypper packages: {e}")
            return []
    
    def _get_pacman_packages(self) -> List[Dict[str, str]]:
        """Get packages from Pacman (Arch Linux)"""
        try:
            cmd = ['pacman', '-Q']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            packages = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(' ')
                    if len(parts) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'architecture': 'x86_64',  # Default, could be improved
                            'manager': 'pacman'
                        })
            
            return packages
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get Pacman packages: {e}")
            return []
    
    def _check_package_vulnerabilities(self, package: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check if a package has known vulnerabilities"""
        # This is a placeholder for actual vulnerability checking
        # In a real implementation, this would query vulnerability databases
        vulnerabilities = []
        
        # Example logic for common vulnerable packages
        vulnerable_packages = {
            'openssl': {
                'cve': 'CVE-2022-0778',
                'affected_versions': ['< 1.1.1n'],
                'severity': 'high'
            },
            'sudo': {
                'cve': 'CVE-2021-3156',
                'affected_versions': ['< 1.9.5p2'],
                'severity': 'critical'
            }
        }
        
        package_name = package['name']
        if package_name in vulnerable_packages:
            vuln_info = vulnerable_packages[package_name]
            vulnerabilities.append({
                'cve_id': vuln_info['cve'],
                'package_name': package_name,
                'installed_version': package['version'],
                'severity': vuln_info['severity'],
                'description': f"Vulnerability in {package_name}",
                'affected_versions': vuln_info['affected_versions'],
                'detection_method': 'package_scan'
            })
        
        return vulnerabilities
    
    def _check_system_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for system-level vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check kernel version
            kernel_vulns = self._check_kernel_vulnerabilities()
            vulnerabilities.extend(kernel_vulns)
            
            # Check for insecure configurations
            config_vulns = self._check_configuration_vulnerabilities()
            vulnerabilities.extend(config_vulns)
            
        except Exception as e:
            logger.error(f"System vulnerability check failed: {e}")
        
        return vulnerabilities
    
    def _check_kernel_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for kernel vulnerabilities"""
        vulnerabilities = []
        kernel_version = self.os_info.get('kernel', '')
        
        # Example kernel vulnerability checks
        if kernel_version:
            # Check for known kernel vulnerabilities
            # This would typically query a vulnerability database
            if version.parse(kernel_version.split('-')[0]) < version.parse('5.4.0'):
                vulnerabilities.append({
                    'cve_id': 'CVE-2020-14386',
                    'component': 'kernel',
                    'installed_version': kernel_version,
                    'severity': 'high',
                    'description': 'Kernel memory corruption vulnerability',
                    'detection_method': 'kernel_version_check'
                })
        
        return vulnerabilities
    
    def _check_configuration_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for configuration-based vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check SSH configuration
            ssh_vulns = self._check_ssh_configuration()
            vulnerabilities.extend(ssh_vulns)
            
            # Check file permissions
            perm_vulns = self._check_file_permissions()
            vulnerabilities.extend(perm_vulns)
            
        except Exception as e:
            logger.error(f"Configuration check failed: {e}")
        
        return vulnerabilities
    
    def _check_ssh_configuration(self) -> List[Dict[str, Any]]:
        """Check SSH configuration for security issues"""
        vulnerabilities = []
        ssh_config_file = '/etc/ssh/sshd_config'
        
        try:
            if os.path.exists(ssh_config_file):
                with open(ssh_config_file, 'r') as f:
                    config_content = f.read()
                
                # Check for root login enabled
                if 'PermitRootLogin yes' in config_content:
                    vulnerabilities.append({
                        'cve_id': 'CONFIG-SSH-001',
                        'component': 'ssh_configuration',
                        'severity': 'medium',
                        'description': 'SSH root login is enabled',
                        'detection_method': 'configuration_check',
                        'file': ssh_config_file
                    })
                
                # Check for password authentication
                if 'PasswordAuthentication yes' in config_content:
                    vulnerabilities.append({
                        'cve_id': 'CONFIG-SSH-002',
                        'component': 'ssh_configuration',
                        'severity': 'low',
                        'description': 'SSH password authentication is enabled',
                        'detection_method': 'configuration_check',
                        'file': ssh_config_file
                    })
        
        except Exception as e:
            logger.error(f"SSH configuration check failed: {e}")
        
        return vulnerabilities
    
    def _check_file_permissions(self) -> List[Dict[str, Any]]:
        """Check for insecure file permissions"""
        vulnerabilities = []
        
        # Critical files to check
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers'
        ]
        
        try:
            for file_path in critical_files:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    perms = oct(stat_info.st_mode)[-3:]
                    
                    # Check for world-readable sensitive files
                    if file_path == '/etc/shadow' and perms[-1] != '0':
                        vulnerabilities.append({
                            'cve_id': 'CONFIG-PERM-001',
                            'component': 'file_permissions',
                            'severity': 'high',
                            'description': f'Sensitive file {file_path} has insecure permissions: {perms}',
                            'detection_method': 'permission_check',
                            'file': file_path,
                            'permissions': perms
                        })
        
        except Exception as e:
            logger.error(f"File permission check failed: {e}")
        
        return vulnerabilities
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get additional system information"""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': {
                    path: {
                        'total': psutil.disk_usage(path).total,
                        'used': psutil.disk_usage(path).used,
                        'free': psutil.disk_usage(path).free
                    } for path in ['/'] if os.path.exists(path)
                },
                'network_interfaces': [
                    iface for iface in psutil.net_if_addrs().keys()
                ],
                'boot_time': psutil.boot_time()
            }
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}