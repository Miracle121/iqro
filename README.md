# Host-Based Vulnerability Management System (HBVM)

A comprehensive vulnerability management solution consisting of a lightweight Python agent, Node.js backend, and React frontend for detecting and managing OS-level vulnerabilities on endpoints.

## Architecture

| Component | Technology | Purpose |
|-----------|------------|---------|
| Agent | Python | Scans hosts for vulnerabilities and sends data to backend |
| Backend | Node.js + Express | Processes scan data, calculates risk scores, provides API |
| Frontend | React | Admin dashboard for viewing hosts, vulnerabilities, and scores |
| Database | MongoDB | Stores scan results, CVEs, host data, and risk scores |

## Features

- **Automated Vulnerability Scanning**: Agent scans OS, services, and open ports
- **CVE Integration**: Matches findings against NVD and Vulners databases  
- **Risk Scoring**: Calculates risk scores using CVSS and exposure factors
- **Web Dashboard**: Visualizes vulnerabilities with filtering and charts
- **Secure Authentication**: JWT-based admin access
- **Export Capabilities**: PDF and CSV export options

## Risk Scoring Formula

```
risk_score = CVSS_severity × exposure_factor × weight_factor
```

**Score Ranges:**
- Low: 0-29
- Medium: 30-59  
- High: 60-79
- Critical: 80-100

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- MongoDB 5.0+

### Installation

1. **Agent Setup**
```bash
cd agent
pip install -r requirements.txt
python scanner.py --config config.json
```

2. **Backend Setup**
```bash
cd backend
npm install
npm start
```

3. **Frontend Setup**
```bash
cd frontend
npm install
npm start
```

## API Endpoints

- `POST /api/scan` - Receive agent scan data
- `GET /api/hosts` - List all hosts with risk scores
- `GET /api/vulnerabilities` - Get vulnerability details
- `GET /api/scores` - Risk score analytics

## Security

- JWT authentication for admin access
- Input validation on all API endpoints
- Secure communication between components
- Role-based access control

## Development

Built with AI assistance using Cursor AI and Claude for:
- Architecture design and code review
- CVE parsing and risk calculation logic  
- Real-time development assistance
- Modular component development