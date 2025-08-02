# HBVM Installation Guide

## Overview

This guide will help you install and configure the Host-Based Vulnerability Management (HBVM) system. The system consists of three main components:

1. **Python Agent** - Scans hosts for vulnerabilities
2. **Node.js Backend** - Processes scan data and provides API
3. **React Frontend** - Web dashboard for viewing results (pending implementation)

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python**: 3.8 or higher
- **Node.js**: 16.0 or higher  
- **MongoDB**: 5.0 or higher
- **Memory**: Minimum 2GB RAM
- **Storage**: Minimum 5GB free space

### Required Software

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip nodejs npm mongodb

# CentOS/RHEL
sudo yum install python3 python3-pip nodejs npm mongodb-server

# macOS (using Homebrew)
brew install python node mongodb/brew/mongodb-community

# Windows
# Install Python from python.org
# Install Node.js from nodejs.org  
# Install MongoDB from mongodb.com
```

## Installation Steps

### 1. Clone and Setup Project

```bash
# Clone the repository (if using git)
git clone <repository-url>
cd hbvm

# Or create the directory structure manually
mkdir hbvm && cd hbvm
```

### 2. Setup MongoDB

```bash
# Start MongoDB service
sudo systemctl start mongod
sudo systemctl enable mongod

# Verify MongoDB is running
mongo --eval "db.adminCommand('ismaster')"
```

Create MongoDB database and user:

```javascript
// Connect to MongoDB shell
mongo

// Create database and user
use hbvm
db.createUser({
  user: "hbvm_user",
  pwd: "secure_password",
  roles: ["readWrite"]
})

// Exit MongoDB shell
exit
```

### 3. Setup Backend (Node.js)

```bash
cd backend

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit configuration file
nano .env
```

Update the `.env` file with your settings:

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://hbvm_user:secure_password@localhost:27017/hbvm
JWT_SECRET=your-super-secret-jwt-key-here-min-32-chars
AGENT_API_KEY=your-secure-agent-api-key-here
ALLOWED_ORIGINS=http://localhost:3001,https://your-domain.com
```

Start the backend:

```bash
# Development mode
npm run dev

# Production mode
npm start
```

Verify backend is running:

```bash
curl http://localhost:3000/api/health
```

### 4. Setup Python Agent

```bash
cd ../agent

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy configuration
cp config/config.yaml config/config.local.yaml

# Edit agent configuration
nano config/config.local.yaml
```

Update the agent configuration:

```yaml
agent:
  host_id: "auto"
  scan_interval: 3600
  api_key: "your-secure-agent-api-key-here"

backend:
  url: "http://localhost:3000"
  endpoint: "/api/scan"
  timeout: 30
  retry_attempts: 3

cve_sources:
  nvd:
    enabled: true
    api_key: ""  # Optional but recommended
  vulners:
    enabled: false  # Requires API key
    api_key: ""
```

### 5. Test Agent Installation

Run a test scan:

```bash
# Test scan without sending to backend
python src/scanner.py --scan-only --no-send --output test_scan.json

# Test scan with backend communication
python src/scanner.py --scan-only
```

### 6. Production Deployment

#### Backend as Service (systemd)

Create service file:

```bash
sudo nano /etc/systemd/system/hbvm-backend.service
```

```ini
[Unit]
Description=HBVM Backend Service
After=network.target mongodb.service

[Service]
Type=simple
User=hbvm
WorkingDirectory=/opt/hbvm/backend
Environment=NODE_ENV=production
ExecStart=/usr/bin/node src/app.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hbvm-backend
sudo systemctl start hbvm-backend
```

#### Agent as Service

Create service file:

```bash
sudo nano /etc/systemd/system/hbvm-agent.service
```

```ini
[Unit]
Description=HBVM Agent Service
After=network.target

[Service]
Type=simple
User=hbvm
WorkingDirectory=/opt/hbvm/agent
Environment=PYTHONPATH=/opt/hbvm/agent
ExecStart=/opt/hbvm/agent/venv/bin/python src/scanner.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hbvm-agent
sudo systemctl start hbvm-agent
```

### 7. Security Configuration

#### Firewall Setup

```bash
# Allow backend port
sudo ufw allow 3000/tcp

# For production, use reverse proxy
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

#### API Key Generation

Generate secure API keys:

```bash
# Generate strong API key
openssl rand -hex 32

# Generate JWT secret
openssl rand -base64 48
```

#### SSL/TLS Setup (Production)

Use a reverse proxy like Nginx:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /api/ {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Verification

### 1. Check Backend Health

```bash
curl -X GET http://localhost:3000/api/health
```

Expected response:
```json
{
  "status": "OK",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 123.45,
  "database": "connected",
  "version": "1.0.0",
  "environment": "production"
}
```

### 2. Test Agent Scan

```bash
cd agent
python src/scanner.py --scan-only --output verification_scan.json
```

### 3. Check Database

```bash
mongo hbvm
db.hosts.find().pretty()
```

## Monitoring and Logs

### Log Locations

- **Backend logs**: `backend/logs/`
- **Agent logs**: `agent/logs/`
- **System logs**: `/var/log/syslog` or `journalctl`

### Monitoring Commands

```bash
# Check service status
sudo systemctl status hbvm-backend
sudo systemctl status hbvm-agent

# View logs
sudo journalctl -u hbvm-backend -f
sudo journalctl -u hbvm-agent -f

# Backend logs
tail -f backend/logs/combined-$(date +%Y-%m-%d).log

# Agent logs  
tail -f agent/logs/agent.log
```

## Troubleshooting

### Common Issues

1. **MongoDB Connection Failed**
   ```bash
   sudo systemctl status mongod
   sudo systemctl start mongod
   ```

2. **Agent Can't Connect to Backend**
   - Check backend is running: `curl http://localhost:3000/api/health`
   - Verify API key matches in both configurations
   - Check firewall rules

3. **Permission Denied Errors**
   ```bash
   sudo chown -R hbvm:hbvm /opt/hbvm
   sudo chmod +x /opt/hbvm/agent/src/scanner.py
   ```

4. **Python Dependencies**
   ```bash
   cd agent
   source venv/bin/activate
   pip install --upgrade -r requirements.txt
   ```

### Debug Mode

Enable debug logging:

```bash
# Backend
export LOG_LEVEL=debug
npm start

# Agent
# Edit config.yaml: logging.level: "DEBUG"
python src/scanner.py --scan-only
```

## Updates and Maintenance

### Updating the System

```bash
# Stop services
sudo systemctl stop hbvm-agent hbvm-backend

# Update code
git pull  # or copy new files

# Update dependencies
cd backend && npm install
cd ../agent && source venv/bin/activate && pip install -r requirements.txt

# Restart services
sudo systemctl start hbvm-backend hbvm-agent
```

### Database Maintenance

```bash
# Backup database
mongodump --db hbvm --out backup/$(date +%Y-%m-%d)

# Restore database
mongorestore --db hbvm backup/2024-01-01/hbvm/
```

### Log Rotation

Logs are automatically rotated, but you can manually clean:

```bash
# Clean old logs (older than 30 days)
find backend/logs -name "*.log" -type f -mtime +30 -delete
find agent/logs -name "*.log" -type f -mtime +30 -delete
```

## Support

For issues and questions:

1. Check logs for error messages
2. Verify configuration files
3. Test network connectivity
4. Review system requirements
5. Check service status and permissions

## Next Steps

1. Configure CVE database API keys for enhanced vulnerability detection
2. Set up email notifications for critical vulnerabilities
3. Implement the React frontend dashboard
4. Configure backup and monitoring systems
5. Set up user authentication and role-based access