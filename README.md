# PAM System - Privileged Access Management

A comprehensive enterprise-grade PAM system built with modern technologies and security best practices.

## 🏗️ Architecture

### Backend (NestJS + Node.js)
- **Authentication**: Login, MFA (TOTP), OAuth2
- **Session Management**: WebSocket-based session control with replay capability
- **Vault**: AES-256 encrypted password storage
- **RBAC**: Role-based access control (Admin, Auditor, User, Vendor)
- **SIEM Integration**: Syslog/webhook support
- **Audit Logs**: Exportable JSON logs with 12+ month retention
- **Database**: PostgreSQL with encrypted data at rest

### Frontend (React + TailwindCSS)
- **Admin Dashboard**: Session analytics, user management, alerts
- **User Interface**: Access requests, session status monitoring
- **Session Monitor**: Live monitoring and session replay
- **MFA Integration**: TOTP input with countdown timers
- **REST API**: Axios-based API communication

### DevOps & Security
- **Containerization**: Docker with Nginx reverse proxy
- **CI/CD**: GitHub Actions pipeline
- **Secrets Management**: HashiCorp Vault integration
- **Security**: TLS 1.3, AES-256 encryption
- **Compliance**: ISO 27001, NIST 800-53 standards

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 14+
- Redis 6+

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd pam-system

# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install

# Start with Docker Compose
cd ..
docker-compose up -d
```

### Environment Variables

Create `.env` files in both backend and frontend directories using the provided `.env.example` templates.

## 📁 Project Structure

```
pam-system/
├── backend/                 # NestJS API server
│   ├── src/
│   │   ├── auth/           # Authentication module
│   │   ├── session/        # Session management
│   │   ├── vault/          # Password vault
│   │   ├── rbac/           # Role-based access control
│   │   ├── audit/          # Audit logging
│   │   └── siem/           # SIEM integration
│   ├── test/
│   └── package.json
├── frontend/               # React application
│   ├── src/
│   │   ├── components/     # Reusable components
│   │   ├── pages/          # Page components
│   │   ├── hooks/          # Custom React hooks
│   │   ├── services/       # API services
│   │   └── utils/          # Utility functions
│   ├── public/
│   └── package.json
├── devops/                 # DevOps configurations
│   ├── docker/             # Docker configurations
│   ├── nginx/              # Nginx configurations
│   ├── github-actions/     # CI/CD workflows
│   └── vault/              # HashiCorp Vault configs
├── docs/                   # Documentation
│   ├── api/                # API documentation
│   ├── deployment/         # Deployment guides
│   └── security/           # Security compliance docs
└── docker-compose.yml      # Development environment
```

## 🔐 Security Features

- **Multi-Factor Authentication**: TOTP-based MFA for all privileged users
- **Encryption**: AES-256 for data at rest, TLS 1.3 for data in transit
- **Session Security**: Secure session tokens with automatic expiration
- **Audit Trail**: Comprehensive logging of all system activities
- **Role-Based Access**: Granular permissions based on user roles
- **Compliance**: Built to meet ISO 27001 and NIST 800-53 requirements

## 👥 User Roles

- **Admin**: Full system access, user management, configuration
- **Auditor**: Read-only access to logs and audit trails
- **User**: Standard access to request privileged accounts
- **Vendor**: Limited access for external contractors

## 📊 Monitoring & Analytics

- Real-time session monitoring
- User activity dashboards
- Security event alerts
- Performance metrics
- Compliance reporting

## 🚀 Deployment

### Production Deployment
1. Configure environment variables
2. Set up SSL certificates
3. Deploy with Docker Compose
4. Configure HashiCorp Vault
5. Set up monitoring and alerting

### Development
```bash
npm run dev:backend
npm run dev:frontend
```

## 📈 API Documentation

API documentation is available at `/api/docs` when running the backend server.

## 🤝 Contributing

Please read our contributing guidelines and code of conduct before submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.