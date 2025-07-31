#!/usr/bin/env python3
"""
Installation script for the Vulnerability Scanner Agent
Handles cross-platform setup and dependency installation
"""

import os
import sys
import platform
import subprocess
import json
import shutil
from pathlib import Path


class ScannerInstaller:
    """Handles installation and setup of the vulnerability scanner"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.python_executable = sys.executable
        self.install_dir = Path.cwd()
        
    def install(self):
        """Main installation process"""
        print("🔧 Installing Vulnerability Scanner Agent...")
        print(f"📊 Detected OS: {platform.platform()}")
        print(f"🐍 Python executable: {self.python_executable}")
        
        try:
            # Install Python dependencies
            self._install_dependencies()
            
            # Create necessary directories
            self._create_directories()
            
            # Set up configuration
            self._setup_config()
            
            # Set up logging
            self._setup_logging()
            
            # Create service files (systemd for Linux, Task Scheduler for Windows)
            self._setup_service()
            
            # Set permissions
            self._set_permissions()
            
            print("✅ Installation completed successfully!")
            self._print_usage_instructions()
            
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            sys.exit(1)
    
    def _install_dependencies(self):
        """Install required Python packages"""
        print("📦 Installing Python dependencies...")
        
        try:
            subprocess.check_call([
                self.python_executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ])
            print("✅ Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to install dependencies: {e}")
    
    def _create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories...")
        
        directories = [
            'scan_results',
            'logs',
            'config',
            'scripts'
        ]
        
        for directory in directories:
            dir_path = self.install_dir / directory
            dir_path.mkdir(exist_ok=True)
            print(f"  ✓ Created {directory}/")
    
    def _setup_config(self):
        """Set up configuration files"""
        print("⚙️  Setting up configuration...")
        
        # Move config to config directory if it exists
        config_src = self.install_dir / 'scanner_config.json'
        config_dst = self.install_dir / 'config' / 'scanner_config.json'
        
        if config_src.exists():
            shutil.move(str(config_src), str(config_dst))
            print(f"  ✓ Moved config to {config_dst}")
        
        # Create a local config override file
        local_config = {
            "api_endpoint": "http://localhost:8080/api/vulnerability-reports",
            "log_file": "logs/vulnerability_scanner.log",
            "output": {
                "output_directory": "./scan_results"
            }
        }
        
        local_config_path = self.install_dir / 'config' / 'local_config.json'
        with open(local_config_path, 'w') as f:
            json.dump(local_config, f, indent=2)
        
        print(f"  ✓ Created local config at {local_config_path}")
    
    def _setup_logging(self):
        """Set up logging configuration"""
        print("📝 Setting up logging...")
        
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                }
            },
            "handlers": {
                "default": {
                    "level": "INFO",
                    "formatter": "standard",
                    "class": "logging.handlers.RotatingFileHandler",
                    "filename": "logs/vulnerability_scanner.log",
                    "maxBytes": 10485760,
                    "backupCount": 5
                },
                "console": {
                    "level": "INFO",
                    "formatter": "standard",
                    "class": "logging.StreamHandler"
                }
            },
            "loggers": {
                "": {
                    "handlers": ["default", "console"],
                    "level": "INFO",
                    "propagate": False
                }
            }
        }
        
        log_config_path = self.install_dir / 'config' / 'logging.json'
        with open(log_config_path, 'w') as f:
            json.dump(log_config, f, indent=2)
        
        print(f"  ✓ Created logging config at {log_config_path}")
    
    def _setup_service(self):
        """Set up system service for automatic scanning"""
        print("🔄 Setting up system service...")
        
        if self.system == 'linux':
            self._setup_systemd_service()
        elif self.system == 'windows':
            self._setup_windows_service()
        else:
            print(f"  ⚠️  Service setup not supported for {self.system}")
    
    def _setup_systemd_service(self):
        """Set up systemd service for Linux"""
        service_content = f"""[Unit]
Description=Vulnerability Scanner Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={self.install_dir}
ExecStart={self.python_executable} vulnerability_scanner.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
        
        service_path = self.install_dir / 'scripts' / 'vulnerability-scanner.service'
        with open(service_path, 'w') as f:
            f.write(service_content)
        
        print(f"  ✓ Created systemd service file at {service_path}")
        print("  ℹ️  To install the service, run:")
        print(f"     sudo cp {service_path} /etc/systemd/system/")
        print("     sudo systemctl enable vulnerability-scanner")
        print("     sudo systemctl start vulnerability-scanner")
    
    def _setup_windows_service(self):
        """Set up Windows Task Scheduler task"""
        script_content = f"""@echo off
cd /d "{self.install_dir}"
"{self.python_executable}" vulnerability_scanner.py
"""
        
        batch_path = self.install_dir / 'scripts' / 'run_scanner.bat'
        with open(batch_path, 'w') as f:
            f.write(script_content)
        
        # Create PowerShell script to set up scheduled task
        ps_script = f"""
$Action = New-ScheduledTaskAction -Execute "{batch_path}"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

Register-ScheduledTask -TaskName "VulnerabilityScanner" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Host-based vulnerability scanner"
"""
        
        ps_path = self.install_dir / 'scripts' / 'setup_scheduled_task.ps1'
        with open(ps_path, 'w') as f:
            f.write(ps_script)
        
        print(f"  ✓ Created Windows service scripts:")
        print(f"     Batch file: {batch_path}")
        print(f"     PowerShell setup: {ps_path}")
        print("  ℹ️  To install the scheduled task, run as Administrator:")
        print(f"     powershell -ExecutionPolicy Bypass -File {ps_path}")
    
    def _set_permissions(self):
        """Set appropriate file permissions"""
        print("🔒 Setting file permissions...")
        
        if self.system in ['linux', 'darwin']:  # Unix-like systems
            try:
                # Make main script executable
                os.chmod('vulnerability_scanner.py', 0o755)
                
                # Set directory permissions
                os.chmod('scan_results', 0o755)
                os.chmod('logs', 0o755)
                os.chmod('config', 0o755)
                
                print("  ✓ Set Unix permissions")
            except Exception as e:
                print(f"  ⚠️  Warning: Could not set permissions: {e}")
    
    def _print_usage_instructions(self):
        """Print usage instructions"""
        print("\n" + "="*60)
        print("🎉 INSTALLATION COMPLETE!")
        print("="*60)
        print("\n📋 Usage Instructions:")
        print(f"1. Edit configuration: {self.install_dir}/config/scanner_config.json")
        print(f"2. Run single scan:    {self.python_executable} vulnerability_scanner.py --once")
        print(f"3. Run continuously:   {self.python_executable} vulnerability_scanner.py")
        print(f"4. View logs:          tail -f logs/vulnerability_scanner.log")
        print(f"5. Check results:      ls -la scan_results/")
        
        if self.system == 'linux':
            print("\n🔄 To enable automatic scanning:")
            print("   sudo cp scripts/vulnerability-scanner.service /etc/systemd/system/")
            print("   sudo systemctl enable vulnerability-scanner")
            print("   sudo systemctl start vulnerability-scanner")
        elif self.system == 'windows':
            print("\n🔄 To enable automatic scanning (run as Administrator):")
            print("   powershell -ExecutionPolicy Bypass -File scripts/setup_scheduled_task.ps1")
        
        print(f"\n📖 Documentation: See README.md for more details")
        print("⚠️  Remember to configure your API endpoint and authentication!")


def main():
    """Main entry point"""
    installer = ScannerInstaller()
    installer.install()


if __name__ == '__main__':
    main()