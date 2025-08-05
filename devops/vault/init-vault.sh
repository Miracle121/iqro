#!/bin/bash

# HashiCorp Vault Initialization Script for PAM System
# This script initializes Vault and sets up the required secrets engines and policies

set -e

# Configuration
VAULT_ADDR="http://localhost:8200"
VAULT_TOKEN="myroot"  # Development token - use proper auth in production

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔐 Initializing HashiCorp Vault for PAM System${NC}"

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until curl -s "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; do
  echo "Waiting for Vault..."
  sleep 2
done

echo -e "${GREEN}✅ Vault is ready${NC}"

# Set Vault address and token
export VAULT_ADDR="$VAULT_ADDR"
export VAULT_TOKEN="$VAULT_TOKEN"

# Check if Vault is already initialized (for development mode)
if vault status | grep -q "Initialized.*true"; then
  echo -e "${YELLOW}⚠️  Vault is already initialized${NC}"
else
  echo -e "${RED}❌ Vault is not initialized. In dev mode, it should auto-initialize.${NC}"
  exit 1
fi

# Enable secrets engines
echo -e "${GREEN}🔧 Enabling secrets engines...${NC}"

# Enable KV v2 secrets engine for PAM configuration
vault secrets enable -path=pam -version=2 kv || echo "KV engine already enabled"

# Enable database secrets engine for dynamic database credentials
vault secrets enable database || echo "Database engine already enabled"

# Enable PKI secrets engine for certificate management
vault secrets enable pki || echo "PKI engine already enabled"

# Enable transit secrets engine for encryption as a service
vault secrets enable transit || echo "Transit engine already enabled"

# Configure PKI secrets engine
echo -e "${GREEN}🔑 Configuring PKI secrets engine...${NC}"

# Set PKI TTL to 1 year
vault secrets tune -max-lease-ttl=8760h pki

# Generate root CA certificate
vault write pki/root/generate/internal \
  common_name="PAM System Root CA" \
  ttl=8760h

# Configure PKI URLs
vault write pki/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pam/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pam/crl"

# Create a role for PAM system certificates
vault write pki/roles/pam-system \
  allowed_domains="pam.local,localhost" \
  allow_subdomains=true \
  max_ttl=720h

# Configure transit encryption for PAM data
echo -e "${GREEN}🔐 Configuring transit encryption...${NC}"

# Create encryption key for PAM vault data
vault write -f transit/keys/pam-vault-key

# Create encryption key for session data
vault write -f transit/keys/pam-session-key

# Store PAM system configuration secrets
echo -e "${GREEN}📝 Storing PAM system secrets...${NC}"

# Database configuration
vault kv put pam/database \
  host="postgres" \
  port="5432" \
  database="pam_system" \
  username="pam_user" \
  password="$(openssl rand -base64 32)"

# Redis configuration
vault kv put pam/redis \
  host="redis" \
  port="6379" \
  password="$(openssl rand -base64 32)"

# JWT secrets
vault kv put pam/jwt \
  secret="$(openssl rand -base64 64)" \
  refresh_secret="$(openssl rand -base64 64)"

# Encryption keys
vault kv put pam/encryption \
  key="$(openssl rand -base64 32)" \
  vault_key="$(openssl rand -base64 32)"

# MFA configuration
vault kv put pam/mfa \
  issuer="PAM-System" \
  window="2" \
  step="30"

# OAuth2 configuration
vault kv put pam/oauth2 \
  client_id="pam-system-client" \
  client_secret="$(openssl rand -base64 32)" \
  callback_url="https://pam.local/auth/callback"

# SIEM integration
vault kv put pam/siem \
  webhook_url="https://siem.company.com/webhook" \
  api_key="$(openssl rand -base64 32)" \
  syslog_host="siem.company.com" \
  syslog_port="514"

# Email configuration
vault kv put pam/email \
  host="smtp.company.com" \
  port="587" \
  username="noreply@company.com" \
  password="$(openssl rand -base64 32)" \
  from="PAM System <noreply@company.com>"

# Create policies for different environments
echo -e "${GREEN}📋 Creating Vault policies...${NC}"

# PAM Application Policy
cat > /tmp/pam-app-policy.hcl << EOF
# PAM Application Policy
# Read access to configuration secrets
path "pam/data/database" {
  capabilities = ["read"]
}

path "pam/data/redis" {
  capabilities = ["read"]
}

path "pam/data/jwt" {
  capabilities = ["read"]
}

path "pam/data/encryption" {
  capabilities = ["read"]
}

path "pam/data/mfa" {
  capabilities = ["read"]
}

path "pam/data/oauth2" {
  capabilities = ["read"]
}

path "pam/data/siem" {
  capabilities = ["read"]
}

path "pam/data/email" {
  capabilities = ["read"]
}

# Transit encryption access
path "transit/encrypt/pam-vault-key" {
  capabilities = ["update"]
}

path "transit/decrypt/pam-vault-key" {
  capabilities = ["update"]
}

path "transit/encrypt/pam-session-key" {
  capabilities = ["update"]
}

path "transit/decrypt/pam-session-key" {
  capabilities = ["update"]
}

# PKI certificate generation
path "pki/issue/pam-system" {
  capabilities = ["update"]
}
EOF

vault policy write pam-app /tmp/pam-app-policy.hcl

# PAM Admin Policy
cat > /tmp/pam-admin-policy.hcl << EOF
# PAM Admin Policy
# Full access to PAM secrets
path "pam/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Transit encryption management
path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# PKI management
path "pki/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Database secrets management
path "database/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

vault policy write pam-admin /tmp/pam-admin-policy.hcl

# Enable AppRole authentication for applications
echo -e "${GREEN}🔑 Configuring AppRole authentication...${NC}"

vault auth enable approle || echo "AppRole already enabled"

# Create AppRole for PAM application
vault write auth/approle/role/pam-app \
  token_policies="pam-app" \
  token_ttl=1h \
  token_max_ttl=4h \
  bind_secret_id=true

# Get role ID and secret ID for the application
ROLE_ID=$(vault read -field=role_id auth/approle/role/pam-app/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/pam-app/secret-id)

echo -e "${GREEN}🔑 AppRole credentials for PAM application:${NC}"
echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

# Create a script to retrieve secrets for the application
cat > /tmp/get-pam-secrets.sh << EOF
#!/bin/bash
# PAM System Secret Retrieval Script

VAULT_ADDR="$VAULT_ADDR"
ROLE_ID="$ROLE_ID"
SECRET_ID="$SECRET_ID"

# Authenticate with AppRole
VAULT_TOKEN=\$(curl -s \\
  --request POST \\
  --data "{\"role_id\":\"\$ROLE_ID\",\"secret_id\":\"\$SECRET_ID\"}" \\
  \$VAULT_ADDR/v1/auth/approle/login | jq -r '.auth.client_token')

if [ "\$VAULT_TOKEN" = "null" ] || [ -z "\$VAULT_TOKEN" ]; then
  echo "Failed to authenticate with Vault"
  exit 1
fi

# Function to get secret
get_secret() {
  local path=\$1
  local field=\$2
  
  curl -s \\
    --header "X-Vault-Token: \$VAULT_TOKEN" \\
    \$VAULT_ADDR/v1/pam/data/\$path | jq -r ".data.data.\$field"
}

# Example usage:
# DB_PASSWORD=\$(get_secret "database" "password")
# JWT_SECRET=\$(get_secret "jwt" "secret")

echo "Vault authentication successful. Token: \$VAULT_TOKEN"
EOF

chmod +x /tmp/get-pam-secrets.sh

# Store environment-specific secrets
echo -e "${GREEN}🌍 Storing environment-specific secrets...${NC}"

# Development environment
vault kv put pam/environments/development \
  debug="true" \
  log_level="debug" \
  session_timeout="3600" \
  mfa_required="false"

# Staging environment
vault kv put pam/environments/staging \
  debug="false" \
  log_level="info" \
  session_timeout="1800" \
  mfa_required="true"

# Production environment
vault kv put pam/environments/production \
  debug="false" \
  log_level="warn" \
  session_timeout="900" \
  mfa_required="true" \
  compliance_mode="strict"

# Cleanup temporary files
rm -f /tmp/pam-app-policy.hcl /tmp/pam-admin-policy.hcl

echo -e "${GREEN}✅ Vault initialization complete!${NC}"
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "1. Store the Role ID and Secret ID securely"
echo "2. Configure your PAM application to use these credentials"
echo "3. Use the get-pam-secrets.sh script to retrieve secrets"
echo "4. For production, enable TLS and use auto-unseal"

echo -e "${GREEN}🔗 Useful Vault commands:${NC}"
echo "vault kv get pam/database    # Get database secrets"
echo "vault kv list pam/           # List all PAM secrets"
echo "vault policy list            # List all policies"
echo "vault auth list              # List authentication methods"