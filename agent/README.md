# HBVM Agent

The HBVM Agent is a Python-based vulnerability scanner that runs on host machines to detect OS-level vulnerabilities and security misconfigurations.

## Features

- **Multi-Platform Support**: Supports Debian/Ubuntu (APT), RHEL/CentOS/Fedora (RPM), openSUSE (Zypper), and Arch Linux (Pacman)
- **Comprehensive Scanning**: Detects package vulnerabilities, kernel issues, and configuration problems
- **Scheduled Scanning**: Automated vulnerability scans based on configurable intervals
- **Secure Communication**: JWT-based authentication and TLS encryption
- **Resilient Operation**: Automatic retry logic, graceful error handling, and local data caching

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd hbvm-system/agent

# Install dependencies
pip install -r requirements.txt

# Copy configuration template
cp .env.example .env

# Edit configuration
nano .env
```

### System Package (Recommended for Production)

```bash
# Create package
python setup.py sdist bdist_wheel

# Install system-wide
sudo pip install dist/hbvm-agent-1.0.0.tar.gz

# Install systemd service
sudo cp systemd/hbvm-agent.service /etc/systemd/system/
sudo systemctl enable hbvm-agent
sudo systemctl start hbvm-agent
```

## Configuration

The agent uses environment variables for configuration. Copy `.env.example` to `.env` and modify:

### Required Settings

- `HBVM_BACKEND_URL`: URL of the HBVM backend API
- `HBVM_API_KEY`: API key for backend authentication

### Optional Settings

- `HBVM_SCAN_INTERVAL`: Scan interval in hours (default: 24)
- `HBVM_LOG_LEVEL`: Logging level (default: INFO)
- `HBVM_DATA_DIR`: Data storage directory (default: /var/lib/hbvm-agent)

## Usage

### Running the Agent

```bash
# Run as daemon (production)
python -m agent

# Run single scan (testing)
python -m agent --scan

# Check agent status
python -m agent --status

# Test backend connection
python -m agent --test-connection

# Enable verbose logging
python -m agent --verbose
```

### As a System Service

```bash
# Start service
sudo systemctl start hbvm-agent

# Check status
sudo systemctl status hbvm-agent

# View logs
sudo journalctl -u hbvm-agent -f
```

## Architecture

### Core Components

1. **Scanner Module** (`scanner.py`)
   - Detects installed packages using native package managers
   - Checks for known vulnerabilities
   - Performs system configuration audits
   - Generates comprehensive scan reports

2. **Communicator Module** (`communicator.py`)
   - Handles secure API communication with backend
   - Manages JWT authentication
   - Implements retry logic and error handling
   - Sends scan results and heartbeats

3. **Agent Module** (`agent.py`)
   - Orchestrates scanning and communication
   - Manages scheduling and task execution
   - Handles graceful shutdown and error recovery
   - Maintains local data storage

4. **Configuration Module** (`config.py`)
   - Centralizes configuration management
   - Validates configuration parameters
   - Provides environment-based settings

### Vulnerability Detection

The agent detects vulnerabilities through multiple methods:

1. **Package Analysis**
   - Queries system package managers (APT, RPM, Zypper, Pacman)
   - Cross-references installed packages with vulnerability databases
   - Identifies outdated packages with known CVEs

2. **System Configuration Checks**
   - SSH configuration analysis
   - File permission audits
   - Service configuration reviews
   - Kernel version assessments

3. **Runtime Security Checks**
   - Process analysis
   - Network configuration review
   - User and group audits
   - System hardening verification

### Data Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   OS Package    │───▶│   Vulnerability │───▶│   Risk Score    │
│   Information   │    │   Detection     │    │   Calculation   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Local Cache   │    │   Scan Report   │    │   Backend API   │
│   Storage       │    │   Generation    │    │   Transmission  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Considerations

### Authentication
- JWT-based authentication with the backend
- API key validation for initial registration
- Token refresh and expiration handling

### Communication Security
- TLS encryption for all HTTP communications
- Certificate validation (configurable)
- Request timeout and retry mechanisms

### Data Protection
- Local scan data encryption (optional)
- Secure temporary file handling
- Audit logging for all operations

### System Privileges
- Runs with minimal required privileges
- Supports running as non-root user where possible
- Capability-based permission model

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```bash
   # Ensure agent has read access to package databases
   sudo usermod -a -G adm hbvm-agent
   ```

2. **Backend Connection Issues**
   ```bash
   # Test connectivity
   python -m agent --test-connection
   
   # Check SSL configuration
   export HBVM_VERIFY_SSL=false
   ```

3. **Package Manager Detection**
   ```bash
   # Verify package manager availability
   which apt dpkg rpm zypper pacman
   ```

### Logging

Logs are written to both file and console:

- **File**: `/var/log/hbvm-agent.log` (configurable)
- **Console**: Standard output/error
- **Systemd**: `journalctl -u hbvm-agent`

Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

### Performance Tuning

1. **Scan Optimization**
   ```bash
   # Adjust scan interval
   export HBVM_SCAN_INTERVAL=12  # 12 hours
   
   # Limit scan duration
   export HBVM_MAX_SCAN_DURATION=30  # 30 minutes
   ```

2. **Resource Usage**
   ```bash
   # Monitor resource usage
   ps aux | grep hbvm-agent
   iotop -p $(pgrep -f hbvm-agent)
   ```

## Development

### Setting Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black agent/
flake8 agent/
```

### Testing

```bash
# Unit tests
python -m pytest tests/unit/

# Integration tests
python -m pytest tests/integration/

# Coverage report
python -m pytest --cov=agent tests/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## API Reference

### Agent Status Response

```json
{
  "running": true,
  "last_scan_time": "2024-01-15T10:30:00Z",
  "last_heartbeat_time": "2024-01-15T10:35:00Z",
  "agent_id": "agent_12345",
  "backend_url": "https://api.hbvm.local",
  "scan_interval_hours": 24
}
```

### Scan Results Format

```json
{
  "scan_id": "scan_1705312200",
  "timestamp": "2024-01-15T10:30:00Z",
  "duration_seconds": 45.2,
  "host_info": {
    "hostname": "web-server-01",
    "os": {
      "name": "Ubuntu",
      "version": "20.04",
      "kernel": "5.4.0-150-generic"
    }
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-1234",
      "package_name": "openssl",
      "severity": "high",
      "description": "Buffer overflow vulnerability"
    }
  ],
  "summary": {
    "total_vulnerabilities": 5,
    "critical": 0,
    "high": 2,
    "medium": 2,
    "low": 1
  }
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.