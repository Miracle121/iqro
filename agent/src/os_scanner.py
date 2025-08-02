"""
OS Scanner Module
Detects operating system information and installed packages
"""

import os
import platform
import subprocess
import logging
from typing import Dict, List, Any, Optional
import distro
from packaging import version
from .utils import safe_run_command, get_system_info


class OSScanner:
    """Scans operating system and installed packages"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('hbvm_agent.os_scanner')
        self.system = platform.system().lower()
        
    def scan(self) -> Dict[str, Any]:
        """Perform OS scan and return system information"""
        self.logger.info("Starting OS scan")
        
        os_info = get_system_info()
        
        # Add detailed OS information
        if self.system == 'linux':
            os_info.update(self._scan_linux())
        elif self.system == 'windows':
            os_info.update(self._scan_windows())
        elif self.system == 'darwin':
            os_info.update(self._scan_macos())
        
        # Add kernel information
        os_info.update(self._get_kernel_info())
        
        self.logger.info(f"OS scan completed: {os_info.get('distribution', 'Unknown')} "
                        f"{os_info.get('version', 'Unknown')}")
        
        return os_info
    
    def _scan_linux(self) -> Dict[str, Any]:
        """Scan Linux-specific information"""
        try:
            info = {
                "distribution": distro.name(),
                "version": distro.version(),
                "codename": distro.codename(),
                "id": distro.id(),
                "kernel": platform.release()
            }
            
            # Get additional system info
            info.update(self._get_linux_details())
            
            return info
        except Exception as e:
            self.logger.error(f"Error scanning Linux OS: {e}")
            return {"error": str(e)}
    
    def _scan_windows(self) -> Dict[str, Any]:
        """Scan Windows-specific information"""
        try:
            import winreg
            
            info = {
                "distribution": "Windows",
                "version": platform.version(),
                "release": platform.release(),
                "edition": self._get_windows_edition()
            }
            
            return info
        except Exception as e:
            self.logger.error(f"Error scanning Windows OS: {e}")
            return {"error": str(e)}
    
    def _scan_macos(self) -> Dict[str, Any]:
        """Scan macOS-specific information"""
        try:
            info = {
                "distribution": "macOS",
                "version": platform.mac_ver()[0],
                "release": platform.release()
            }
            
            return info
        except Exception as e:
            self.logger.error(f"Error scanning macOS: {e}")
            return {"error": str(e)}
    
    def _get_kernel_info(self) -> Dict[str, Any]:
        """Get kernel/system version information"""
        try:
            kernel_info = {
                "kernel_version": platform.release(),
                "kernel_build": platform.version()
            }
            
            if self.system == 'linux':
                # Get more detailed kernel info
                uname_output = safe_run_command("uname -a")
                if uname_output:
                    kernel_info["uname"] = uname_output
            
            return kernel_info
        except Exception as e:
            self.logger.error(f"Error getting kernel info: {e}")
            return {}
    
    def _get_linux_details(self) -> Dict[str, Any]:
        """Get additional Linux system details"""
        details = {}
        
        try:
            # Get systemd info if available
            systemd_version = safe_run_command("systemctl --version")
            if systemd_version:
                details["systemd"] = systemd_version.split('\n')[0]
            
            # Get init system
            if os.path.exists("/proc/1/comm"):
                with open("/proc/1/comm", 'r') as f:
                    details["init_system"] = f.read().strip()
            
            # Get CPU info
            cpu_info = self._get_cpu_info()
            if cpu_info:
                details["cpu"] = cpu_info
            
            # Get memory info
            mem_info = self._get_memory_info()
            if mem_info:
                details["memory"] = mem_info
                
        except Exception as e:
            self.logger.error(f"Error getting Linux details: {e}")
        
        return details
    
    def _get_cpu_info(self) -> Optional[Dict[str, Any]]:
        """Get CPU information"""
        try:
            cpu_info = {}
            
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", 'r') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    if line.startswith("model name"):
                        cpu_info["model"] = line.split(":")[1].strip()
                        break
                
                # Count cores
                core_count = sum(1 for line in lines if line.startswith("processor"))
                cpu_info["cores"] = core_count
            
            return cpu_info if cpu_info else None
        except Exception:
            return None
    
    def _get_memory_info(self) -> Optional[Dict[str, Any]]:
        """Get memory information"""
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", 'r') as f:
                    meminfo = f.read()
                
                mem_info = {}
                for line in meminfo.split('\n'):
                    if line.startswith("MemTotal:"):
                        # Convert kB to bytes
                        total_kb = int(line.split()[1])
                        mem_info["total_bytes"] = total_kb * 1024
                        mem_info["total_mb"] = total_kb // 1024
                        break
                
                return mem_info
        except Exception:
            return None
    
    def _get_windows_edition(self) -> str:
        """Get Windows edition information"""
        try:
            import winreg
            
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            )
            
            try:
                edition = winreg.QueryValueEx(key, "EditionID")[0]
                return edition
            finally:
                winreg.CloseKey(key)
                
        except Exception:
            return "Unknown"
    
    def get_installed_packages(self) -> List[Dict[str, Any]]:
        """Get list of installed packages/software"""
        self.logger.info("Scanning installed packages")
        
        if self.system == 'linux':
            return self._get_linux_packages()
        elif self.system == 'windows':
            return self._get_windows_packages()
        elif self.system == 'darwin':
            return self._get_macos_packages()
        else:
            self.logger.warning(f"Package scanning not supported for {self.system}")
            return []
    
    def _get_linux_packages(self) -> List[Dict[str, Any]]:
        """Get installed packages on Linux"""
        packages = []
        
        # Try different package managers
        package_managers = [
            ("dpkg", self._get_dpkg_packages),
            ("rpm", self._get_rpm_packages),
            ("pacman", self._get_pacman_packages),
            ("apk", self._get_apk_packages)
        ]
        
        for pm_name, pm_function in package_managers:
            if self._command_exists(pm_name):
                try:
                    pm_packages = pm_function()
                    packages.extend(pm_packages)
                    self.logger.info(f"Found {len(pm_packages)} packages via {pm_name}")
                except Exception as e:
                    self.logger.error(f"Error getting packages via {pm_name}: {e}")
        
        return packages
    
    def _get_dpkg_packages(self) -> List[Dict[str, Any]]:
        """Get packages via dpkg (Debian/Ubuntu)"""
        packages = []
        
        output = safe_run_command("dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Status}\\n'")
        if not output:
            return packages
        
        for line in output.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 4 and 'installed' in parts[3]:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "architecture": parts[2],
                        "package_manager": "dpkg"
                    })
        
        return packages
    
    def _get_rpm_packages(self) -> List[Dict[str, Any]]:
        """Get packages via RPM (RHEL/CentOS/Fedora)"""
        packages = []
        
        output = safe_run_command("rpm -qa --queryformat '%{NAME}|%{VERSION}|%{ARCH}\\n'")
        if not output:
            return packages
        
        for line in output.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "architecture": parts[2],
                        "package_manager": "rpm"
                    })
        
        return packages
    
    def _get_pacman_packages(self) -> List[Dict[str, Any]]:
        """Get packages via pacman (Arch Linux)"""
        packages = []
        
        output = safe_run_command("pacman -Q")
        if not output:
            return packages
        
        for line in output.split('\n'):
            if ' ' in line:
                name, version = line.split(' ', 1)
                packages.append({
                    "name": name,
                    "version": version,
                    "package_manager": "pacman"
                })
        
        return packages
    
    def _get_apk_packages(self) -> List[Dict[str, Any]]:
        """Get packages via apk (Alpine Linux)"""
        packages = []
        
        output = safe_run_command("apk list --installed")
        if not output:
            return packages
        
        for line in output.split('\n'):
            if '{' in line and '}' in line:
                # Parse format: package-name-version {repo} (arch) [status]
                name_version = line.split(' ')[0]
                if '-' in name_version:
                    # Split name and version (complex due to dashes in names)
                    parts = name_version.split('-')
                    # Assume last two parts are version and revision
                    if len(parts) >= 2:
                        version_parts = parts[-2:]
                        name = '-'.join(parts[:-2])
                        version = '-'.join(version_parts)
                        
                        packages.append({
                            "name": name,
                            "version": version,
                            "package_manager": "apk"
                        })
        
        return packages
    
    def _get_windows_packages(self) -> List[Dict[str, Any]]:
        """Get installed programs on Windows"""
        packages = []
        
        try:
            # Use PowerShell to get installed programs
            powershell_cmd = (
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                "Select-Object DisplayName, DisplayVersion, Publisher | "
                "Where-Object {$_.DisplayName} | ConvertTo-Json"
            )
            
            output = safe_run_command(f"powershell -Command \"{powershell_cmd}\"")
            if output:
                import json
                programs = json.loads(output)
                
                if isinstance(programs, list):
                    for program in programs:
                        if program.get('DisplayName'):
                            packages.append({
                                "name": program.get('DisplayName', ''),
                                "version": program.get('DisplayVersion', ''),
                                "publisher": program.get('Publisher', ''),
                                "package_manager": "windows_registry"
                            })
                elif isinstance(programs, dict) and programs.get('DisplayName'):
                    packages.append({
                        "name": programs.get('DisplayName', ''),
                        "version": programs.get('DisplayVersion', ''),
                        "publisher": programs.get('Publisher', ''),
                        "package_manager": "windows_registry"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error getting Windows packages: {e}")
        
        return packages
    
    def _get_macos_packages(self) -> List[Dict[str, Any]]:
        """Get installed applications on macOS"""
        packages = []
        
        try:
            # Get applications from /Applications
            apps_output = safe_run_command("ls -la /Applications")
            if apps_output:
                for line in apps_output.split('\n'):
                    if line.endswith('.app'):
                        app_name = line.split()[-1].replace('.app', '')
                        packages.append({
                            "name": app_name,
                            "version": "unknown",
                            "package_manager": "macos_applications"
                        })
            
            # Try to get Homebrew packages if available
            if self._command_exists("brew"):
                brew_output = safe_run_command("brew list --versions")
                if brew_output:
                    for line in brew_output.split('\n'):
                        if ' ' in line:
                            parts = line.split(' ', 1)
                            packages.append({
                                "name": parts[0],
                                "version": parts[1] if len(parts) > 1 else "unknown",
                                "package_manager": "homebrew"
                            })
                            
        except Exception as e:
            self.logger.error(f"Error getting macOS packages: {e}")
        
        return packages
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            result = subprocess.run(
                ["which", command] if self.system != 'windows' else ["where", command],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False