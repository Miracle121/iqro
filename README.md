# Host-Based Vulnerability Management (HBVM) System

A comprehensive vulnerability management system consisting of Python agents, Node.js backend, React frontend, and MongoDB database.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Host Agents   │───▶│   Backend API   │───▶│   Frontend UI   │
│   (Python)      │    │   (Node.js)     │    │   (React)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │    MongoDB      │              │
         └──────────────▶│   Database      │◀─────────────┘
                        └─────────────────┘
                                 │
                        ┌─────────────────┐
                        │  CVE Data APIs  │
                        │  (NVD/Vulners)  │
                        └─────────────────┘
```

## Components

### 1. Agent (Python)
- **Purpose**: Installed on host machines to perform vulnerability scans
- **Features**: 
  - OS-level vulnerability detection
  - Scheduled scanning
  - Secure communication with backend
  - Lightweight and efficient

### 2. Backend (Node.js)
- **Purpose**: Central API server for data processing and risk analysis
- **Features**:
  - Receive and process scan data from agents
  - CVSS-based risk scoring
  - CVE data integration
  - Authentication and authorization
  - RESTful API endpoints

### 3. Frontend (React)
- **Purpose**: Web dashboard for vulnerability management
- **Features**:
  - Host inventory display
  - Vulnerability visualization
  - Risk score dashboards
  - Real-time updates
  - Responsive design

### 4. Database (MongoDB)
- **Purpose**: Data persistence layer
- **Collections**:
  - Hosts
  - Vulnerabilities
  - Scan Results
  - Risk Scores
  - Users

## API Flow

1. **Agent Registration**: Agents register with backend on first startup
2. **Scheduled Scanning**: Agents perform vulnerability scans based on schedule
3. **Data Transmission**: Scan results sent to backend via secure API
4. **Risk Analysis**: Backend processes data and calculates risk scores
5. **CVE Enrichment**: Backend enriches vulnerabilities with CVE data
6. **Dashboard Updates**: Frontend displays updated information in real-time

## Security Features

- JWT-based authentication
- TLS encryption for all communications
- API rate limiting
- Input validation and sanitization
- Secure credential management

## Performance Features

- Asynchronous processing
- Database indexing
- Caching strategies
- Batch processing for large datasets
- Efficient data aggregation

## Quick Start

1. **Prerequisites**:
   - Node.js 18+
   - Python 3.8+
   - MongoDB 6.0+
   - Docker (optional)

2. **Installation**:
   ```bash
   # Clone repository
   git clone <repository-url>
   cd hbvm-system
   
   # Install dependencies
   npm run install-all
   
   # Setup environment
   npm run setup
   
   # Start services
   npm run dev
   ```

3. **Configuration**:
   - Copy `.env.example` to `.env` and configure
   - Update database connection strings
   - Set CVE API keys

## Project Structure

```
hbvm-system/
├── agent/                 # Python vulnerability agent
├── backend/              # Node.js API server
├── frontend/             # React dashboard
├── database/             # MongoDB schemas and migrations
├── docker/               # Docker configuration
├── docs/                 # Additional documentation
└── scripts/              # Deployment and utility scripts
```

## Documentation

- [Agent Documentation](./agent/README.md)
- [Backend API Documentation](./backend/README.md)
- [Frontend Documentation](./frontend/README.md)
- [Database Schema](./database/README.md)
- [Deployment Guide](./docs/deployment.md)
- [Security Guide](./docs/security.md)

## Contributing

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.