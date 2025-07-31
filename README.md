# Host-based Vulnerability Scanner Agent

A comprehensive Python-based vulnerability scanner that monitors your host for installed packages, running services, and open ports, then matches them against known CVEs using external APIs.

## 🚀 Features

- **Cross-platform support**: Works on Linux and Windows
- **Modular architecture**: Object-oriented design with separate modules for different scanning functions
- **Multiple package managers**: Supports dpkg, rpm, pacman, pip, and Windows installer
- **CVE matching**: Integrates with Vulners API and can be extended for NVD API
- **Network scanning**: Detects open ports and associated processes
- **Scheduled scanning**: Supports cron-like scheduling and simple intervals
- **JSON output**: Structured results ready for API submission
- **Comprehensive logging**: Detailed logging with rotation support
- **Error handling**: Robust error handling and recovery mechanisms

## 📋 Requirements

- Python 3.7+
- Administrative privileges (recommended for complete system access)
- Internet connection (for CVE database queries)

## 🔧 Installation

### Quick Installation

1. Clone or download the scanner files
2. Run the installation script:

```bash
python install.py
```

The installer will:
- Install Python dependencies
- Create necessary directories
- Set up configuration files
- Configure system services (systemd for Linux, Task Scheduler for Windows)
- Set appropriate permissions

### Manual Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create directories:
```bash
mkdir -p scan_results logs config scripts
```

3. Copy configuration file:
```bash
cp scanner_config.json config/
```

## ⚙️ Configuration

Edit `config/scanner_config.json` to customize the scanner:

```json
{
  "scan_interval": 3600,
  "api_endpoint": "https://your-api.com/vulnerability-reports",
  "api_key": "your-api-key",
  "log_level": "INFO",
  "enable_cve_matching": true,
  "max_packages_to_scan": 50,
  "vulners_api_key": "",
  "schedule": {
    "cron_expression": "0 2 * * *",
    "daily_at": "02:00",
    "interval_hours": 6
  }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `scan_interval` | Scan interval in seconds | 3600 |
| `api_endpoint` | Backend API endpoint for results | Required for API submission |
| `api_key` | API authentication key | Optional |
| `log_level` | Logging level (DEBUG, INFO, WARNING, ERROR) | INFO |
| `enable_cve_matching` | Enable CVE vulnerability matching | true |
| `max_packages_to_scan` | Limit packages for CVE scanning | 50 |
| `vulners_api_key` | Vulners API key for enhanced scanning | Optional |

## 🏃‍♂️ Usage

### Single Scan

Run a one-time scan:

```bash
python vulnerability_scanner.py --once
```

Save results to specific file:

```bash
python vulnerability_scanner.py --once --output my_scan_results.json
```

### Continuous Scanning

Run continuous scanning with configured interval:

```bash
python vulnerability_scanner.py
```

### Custom Configuration

Use a custom configuration file:

```bash
python vulnerability_scanner.py --config /path/to/custom_config.json
```

## 📊 Output Format

The scanner generates JSON output with the following structure:

```json
{
  "scan_id": "scan_1234567890",
  "timestamp": "2024-01-15T10:30:00Z",
  "system_info": {
    "hostname": "server01",
    "platform": "Linux-5.4.0-ubuntu",
    "cpu_count": 4,
    "memory_total": 8589934592
  },
  "packages": [
    {
      "name": "openssl",
      "version": "1.1.1f-1ubuntu2.19",
      "package_manager": "dpkg"
    }
  ],
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "process_name": "sshd"
    }
  ],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-1234",
      "title": "OpenSSL vulnerability",
      "severity": "high",
      "cvss_score": 7.5,
      "package_name": "openssl",
      "package_version": "1.1.1f"
    }
  ],
  "scan_duration": 45.2,
  "errors": []
}
```

## 🔄 Scheduling

### System Service (Linux)

Enable automatic scanning with systemd:

```bash
sudo cp scripts/vulnerability-scanner.service /etc/systemd/system/
sudo systemctl enable vulnerability-scanner
sudo systemctl start vulnerability-scanner
```

Check service status:

```bash
sudo systemctl status vulnerability-scanner
```

### Task Scheduler (Windows)

Set up scheduled task (run as Administrator):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_scheduled_task.ps1
```

### Custom Scheduling

Configure advanced scheduling in `scanner_config.json`:

```json
{
  "schedule": {
    "cron_expression": "0 2 * * *",
    "multiple_schedules": [
      {"type": "daily", "time": "02:00"},
      {"type": "interval", "hours": 6},
      {"type": "weekly", "day": "sunday", "time": "01:00"}
    ]
  }
}
```

## 🔍 Scanning Modules

### System Information Collector
- Hostname, OS details, hardware specs
- Network interfaces and disk usage
- Timestamp and system metadata

### Package Collector
- **Linux**: dpkg, rpm, pacman packages
- **Windows**: Installed programs via WMI
- **Python**: pip packages via pkg_resources

### Network Scanner
- Open TCP/UDP ports using psutil
- Associated process information
- Listening addresses and protocols

### CVE Matcher
- Vulners API integration
- CVSS score calculation
- Severity classification (critical, high, medium, low)

## 🔧 API Integration

### Backend API Format

The scanner can POST results to your backend API. Expected endpoint:

```
POST /api/vulnerability-reports
Content-Type: application/json
Authorization: Bearer <api_key>
```

### API Response Handling

The scanner expects a 200 status code for successful submission. Configure retry logic in the configuration file.

## 📝 Logging

Logs are written to:
- `logs/vulnerability_scanner.log` (configurable)
- Console output (INFO level and above)

Log rotation is configured automatically with:
- Maximum file size: 10MB
- Backup files: 5
- Compression: Optional

## 🐛 Troubleshooting

### Common Issues

1. **Permission denied errors**
   - Run with elevated privileges
   - Check file permissions in scan directories

2. **Package detection fails**
   - Ensure package managers are installed
   - Check PATH environment variable

3. **CVE API errors**
   - Verify internet connection
   - Check API rate limits
   - Configure API keys if required

4. **High CPU usage**
   - Reduce `max_packages_to_scan`
   - Increase `scan_interval`
   - Disable CVE matching for testing

### Debug Mode

Enable debug logging:

```json
{
  "log_level": "DEBUG"
}
```

## 🔒 Security Considerations

- Run with minimal required privileges
- Secure API keys and endpoints
- Monitor log files for sensitive information
- Configure firewall rules for API communication
- Regularly update dependencies

## 📈 Performance Tuning

- Adjust `max_packages_to_scan` based on system resources
- Configure appropriate scan intervals
- Use local CVE databases for better performance
- Implement result caching for repeated scans

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process and system monitoring
- [requests](https://github.com/psf/requests) - HTTP library for API communication
- [schedule](https://github.com/dbader/schedule) - Simple job scheduling
- [Vulners](https://vulners.com/) - Vulnerability database API