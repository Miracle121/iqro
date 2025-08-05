# HashiCorp Vault Configuration for PAM System
# This configuration sets up Vault for development/testing
# For production, use a more robust storage backend and HA setup

# Storage configuration
storage "file" {
  path = "/vault/data"
}

# Listener configuration
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # Disable for development only
  # For production, enable TLS:
  # tls_cert_file = "/path/to/cert.pem"
  # tls_key_file  = "/path/to/key.pem"
}

# API address
api_addr = "http://127.0.0.1:8200"

# Cluster address
cluster_addr = "http://127.0.0.1:8201"

# UI configuration
ui = true

# Logging
log_level = "INFO"
log_format = "json"

# Disable mlock for development
disable_mlock = true

# Maximum lease TTL
max_lease_ttl = "768h"

# Default lease TTL
default_lease_ttl = "768h"

# Enable raw endpoint
raw_storage_endpoint = true

# Plugin directory
plugin_directory = "/vault/plugins"

# Seal configuration (for production, use auto-unseal)
# seal "awskms" {
#   region     = "us-west-2"
#   kms_key_id = "alias/vault-unseal-key"
# }