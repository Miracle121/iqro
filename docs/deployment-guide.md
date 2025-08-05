# PAM System Deployment Guide

## 🚀 Quick Start

### Prerequisites

- **Docker** 24.0+ and **Docker Compose** 2.0+
- **Node.js** 18+ (for local development)
- **PostgreSQL** 15+ (or use Docker container)
- **Redis** 7+ (or use Docker container)
- **HashiCorp Vault** (or use Docker container)

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd pam-system

# Copy environment files
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Generate secure keys
openssl rand -base64 32  # For ENCRYPTION_KEY
openssl rand -base64 64  # For JWT_SECRET
```

### 2. Configure Environment Variables

Edit `backend/.env` with your values:

```bash
# Required - Generate secure values
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
ENCRYPTION_KEY=your-32-char-encryption-key-here!

# Database
DB_HOST=postgres
DB_PASSWORD=your-secure-db-password

# Redis
REDIS_HOST=redis
REDIS_PASSWORD=your-redis-password

# Domain configuration
DOMAIN=pam.yourdomain.com
```

### 3. SSL Certificates

For HTTPS (required for production):

```bash
# Create SSL directory
mkdir -p devops/nginx/ssl

# Option 1: Self-signed (development only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout devops/nginx/ssl/key.pem \
  -out devops/nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=pam.local"

# Option 2: Let's Encrypt (production)
# Use certbot or similar tool
```

### 4. Start the System

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 5. Initialize the System

```bash
# Initialize HashiCorp Vault
docker-compose exec vault /vault/config/init-vault.sh

# Run database migrations
docker-compose exec backend npm run migrate

# Create admin user (if not created automatically)
docker-compose exec backend npm run seed:admin
```

### 6. Access the System

- **Frontend**: https://localhost (or your domain)
- **API**: https://localhost/api/v1
- **API Docs**: https://localhost/api/docs
- **Vault UI**: http://localhost:8200

Default admin credentials:
- Username: `admin`
- Password: `Admin123!`

---

## 🏗️ Production Deployment

### Infrastructure Requirements

#### Minimum System Requirements
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 100GB SSD
- **Network**: 1Gbps

#### Recommended Production Setup
- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Storage**: 500GB+ SSD with backup
- **Network**: Load balancer with SSL termination

### High Availability Setup

#### 1. Database High Availability

```yaml
# docker-compose.prod.yml
services:
  postgres-primary:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: master
      POSTGRES_REPLICATION_USER: replica_user
      POSTGRES_REPLICATION_PASSWORD: replica_password

  postgres-replica:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_MASTER_HOST: postgres-primary
      POSTGRES_REPLICATION_USER: replica_user
      POSTGRES_REPLICATION_PASSWORD: replica_password
```

#### 2. Application Load Balancing

```yaml
services:
  backend:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
```

#### 3. Vault High Availability

```hcl
# vault-ha.hcl
storage "consul" {
  address = "consul:8500"
  path = "vault/"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/ssl/cert.pem"
  tls_key_file = "/vault/ssl/key.pem"
}

api_addr = "https://vault.yourdomain.com:8200"
cluster_addr = "https://vault.yourdomain.com:8201"
ui = true
```

### Kubernetes Deployment

#### 1. Namespace and Secrets

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: pam-system
---
apiVersion: v1
kind: Secret
metadata:
  name: pam-secrets
  namespace: pam-system
type: Opaque
data:
  jwt-secret: <base64-encoded>
  encryption-key: <base64-encoded>
  db-password: <base64-encoded>
```

#### 2. Backend Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pam-backend
  namespace: pam-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pam-backend
  template:
    metadata:
      labels:
        app: pam-backend
    spec:
      containers:
      - name: backend
        image: ghcr.io/your-org/pam-backend:latest
        ports:
        - containerPort: 3000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: pam-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 3000
          initialDelaySeconds: 10
```

#### 3. Ingress Configuration

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pam-ingress
  namespace: pam-system
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - pam.yourdomain.com
    secretName: pam-tls
  rules:
  - host: pam.yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: pam-backend
            port:
              number: 3000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: pam-frontend
            port:
              number: 80
```

---

## 🔒 Security Configuration

### 1. SSL/TLS Setup

#### Production SSL Certificate

```bash
# Using Let's Encrypt with Certbot
certbot certonly --webroot \
  -w /var/www/html \
  -d pam.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos \
  --non-interactive

# Copy certificates to nginx
cp /etc/letsencrypt/live/pam.yourdomain.com/fullchain.pem devops/nginx/ssl/cert.pem
cp /etc/letsencrypt/live/pam.yourdomain.com/privkey.pem devops/nginx/ssl/key.pem
```

#### SSL Configuration Validation

```bash
# Test SSL configuration
openssl s_client -connect pam.yourdomain.com:443 -servername pam.yourdomain.com

# Check certificate expiration
openssl x509 -in devops/nginx/ssl/cert.pem -noout -dates
```

### 2. Firewall Configuration

```bash
# UFW (Ubuntu)
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (redirect to HTTPS)
ufw allow 443/tcp   # HTTPS
ufw deny 3000/tcp   # Block direct backend access
ufw deny 5432/tcp   # Block direct database access
ufw enable

# iptables alternative
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j DROP
```

### 3. Vault Security

#### Production Vault Configuration

```bash
# Initialize Vault with multiple key shares
vault operator init -key-shares=5 -key-threshold=3

# Store unseal keys securely (use cloud KMS in production)
export VAULT_UNSEAL_KEY_1="..."
export VAULT_UNSEAL_KEY_2="..."
export VAULT_UNSEAL_KEY_3="..."

# Unseal Vault
vault operator unseal $VAULT_UNSEAL_KEY_1
vault operator unseal $VAULT_UNSEAL_KEY_2
vault operator unseal $VAULT_UNSEAL_KEY_3
```

#### Auto-unseal with Cloud KMS

```hcl
# AWS KMS auto-unseal
seal "awskms" {
  region     = "us-west-2"
  kms_key_id = "alias/vault-unseal-key"
}

# Azure Key Vault auto-unseal
seal "azurekeyvault" {
  tenant_id      = "your-tenant-id"
  client_id      = "your-client-id"
  client_secret  = "your-client-secret"
  vault_name     = "your-key-vault"
  key_name       = "vault-unseal-key"
}
```

---

## 📊 Monitoring and Observability

### 1. Health Checks

```bash
# Application health
curl -f https://pam.yourdomain.com/health || exit 1

# Database connectivity
docker-compose exec backend npm run health:db

# Vault status
vault status
```

### 2. Logging Configuration

#### Centralized Logging with ELK Stack

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false

  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf

  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    ports:
      - "5601:5601"
```

#### Application Logging

```typescript
// backend/src/config/logging.ts
export const loggingConfig = {
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: '/var/log/pam/application.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    }),
  ],
};
```

### 3. Metrics and Monitoring

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pam-backend'
    static_configs:
      - targets: ['backend:3000']
    metrics_path: '/metrics'

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:8080']
    metrics_path: '/nginx_status'

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
```

#### Grafana Dashboards

```json
{
  "dashboard": {
    "title": "PAM System Overview",
    "panels": [
      {
        "title": "Active Sessions",
        "type": "stat",
        "targets": [
          {
            "expr": "pam_active_sessions_total"
          }
        ]
      },
      {
        "title": "Authentication Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(pam_authentication_total[5m])"
          }
        ]
      }
    ]
  }
}
```

---

## 🔄 Backup and Recovery

### 1. Database Backup

#### Automated Backup Script

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/var/backups/pam-system"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="pam_system"

# Create backup directory
mkdir -p $BACKUP_DIR

# PostgreSQL backup
pg_dump -h postgres -U pam_user -d $DB_NAME > $BACKUP_DIR/pam_db_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/pam_db_$DATE.sql

# Upload to cloud storage (AWS S3 example)
aws s3 cp $BACKUP_DIR/pam_db_$DATE.sql.gz s3://pam-backups/database/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

#### Backup Cron Job

```bash
# Add to crontab
0 2 * * * /opt/pam-system/scripts/backup-database.sh
0 6 * * 0 /opt/pam-system/scripts/backup-vault.sh  # Weekly Vault backup
```

### 2. Vault Backup

```bash
#!/bin/bash
# backup-vault.sh

BACKUP_DIR="/var/backups/vault"
DATE=$(date +%Y%m%d_%H%M%S)

# Vault snapshot
vault operator raft snapshot save $BACKUP_DIR/vault_snapshot_$DATE.snap

# Upload to secure storage
aws s3 cp $BACKUP_DIR/vault_snapshot_$DATE.snap s3://pam-backups/vault/ --sse
```

### 3. Disaster Recovery

#### Recovery Procedure

```bash
# 1. Restore database
gunzip -c pam_db_20231201_020000.sql.gz | psql -h postgres -U pam_user -d pam_system

# 2. Restore Vault
vault operator raft snapshot restore vault_snapshot_20231201_060000.snap

# 3. Restart services
docker-compose restart

# 4. Verify system health
curl -f https://pam.yourdomain.com/health
```

---

## ⚙️ Maintenance

### 1. Updates and Patches

#### Application Updates

```bash
# Pull latest images
docker-compose pull

# Update with zero downtime
docker-compose up -d --no-deps backend
docker-compose up -d --no-deps frontend

# Verify deployment
docker-compose ps
curl -f https://pam.yourdomain.com/health
```

#### Database Migrations

```bash
# Run database migrations
docker-compose exec backend npm run migrate

# Rollback if needed
docker-compose exec backend npm run migrate:revert
```

### 2. Certificate Renewal

#### Automated Certificate Renewal

```bash
#!/bin/bash
# renew-certificates.sh

certbot renew --quiet

# Copy new certificates
cp /etc/letsencrypt/live/pam.yourdomain.com/fullchain.pem devops/nginx/ssl/cert.pem
cp /etc/letsencrypt/live/pam.yourdomain.com/privkey.pem devops/nginx/ssl/key.pem

# Reload nginx
docker-compose exec nginx nginx -s reload
```

### 3. Log Rotation

```bash
# Configure logrotate
cat > /etc/logrotate.d/pam-system << EOF
/var/log/pam/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    postrotate
        docker-compose restart backend
    endscript
}
EOF
```

---

## 🚨 Troubleshooting

### Common Issues

#### 1. Database Connection Issues

```bash
# Check database status
docker-compose exec postgres pg_isready -U pam_user

# View database logs
docker-compose logs postgres

# Test connection from backend
docker-compose exec backend npm run test:db
```

#### 2. Vault Sealed

```bash
# Check Vault status
vault status

# Unseal Vault
vault operator unseal

# Verify Vault connectivity
curl -s http://localhost:8200/v1/sys/health
```

#### 3. SSL Certificate Issues

```bash
# Check certificate validity
openssl x509 -in devops/nginx/ssl/cert.pem -noout -dates

# Test SSL handshake
openssl s_client -connect pam.yourdomain.com:443

# Check nginx configuration
docker-compose exec nginx nginx -t
```

#### 4. High Memory Usage

```bash
# Check container resource usage
docker stats

# Analyze memory usage
docker-compose exec backend node --inspect=0.0.0.0:9229 dist/main.js

# Adjust container limits in docker-compose.yml
```

### Log Analysis

#### Important Log Locations

```bash
# Application logs
docker-compose logs backend
docker-compose logs frontend

# Nginx access logs
docker-compose exec nginx tail -f /var/log/nginx/access.log

# Security logs
docker-compose exec nginx tail -f /var/log/nginx/security.log

# Vault logs
docker-compose logs vault
```

### Performance Tuning

#### Database Optimization

```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Optimize frequently used indexes
CREATE INDEX CONCURRENTLY idx_sessions_user_active 
ON sessions(user_id, status) 
WHERE status = 'active';
```

#### Application Optimization

```bash
# Enable Node.js profiling
NODE_ENV=production node --prof dist/main.js

# Analyze CPU usage
node --prof-process isolate-0x*.log > processed.txt
```

---

## 📞 Support and Documentation

### Getting Help

- **Documentation**: `/docs` directory
- **API Documentation**: `https://pam.yourdomain.com/api/docs`
- **Health Status**: `https://pam.yourdomain.com/health`
- **Issue Tracker**: GitHub Issues

### Emergency Contacts

```bash
# Emergency shutdown
docker-compose down

# Emergency Vault seal
vault operator seal

# Service restart
docker-compose restart
```

This deployment guide provides comprehensive instructions for deploying, maintaining, and troubleshooting the PAM system in production environments.