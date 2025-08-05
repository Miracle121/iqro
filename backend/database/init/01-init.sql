-- PAM System Database Initialization
-- This script creates the initial database structure

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create enums
CREATE TYPE user_role AS ENUM ('admin', 'auditor', 'user', 'vendor');
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended', 'locked');
CREATE TYPE session_status AS ENUM ('active', 'inactive', 'terminated', 'expired');
CREATE TYPE access_request_status AS ENUM ('pending', 'approved', 'denied', 'expired');
CREATE TYPE vault_entry_type AS ENUM ('password', 'ssh_key', 'certificate', 'api_key', 'other');

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role DEFAULT 'user',
    status user_status DEFAULT 'active',
    phone_number VARCHAR(20),
    department VARCHAR(100),
    job_title VARCHAR(100),
    manager_id UUID REFERENCES users(id),
    
    -- MFA Settings
    mfa_secret TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_backup_codes TEXT[],
    
    -- Security Settings
    require_password_change BOOLEAN DEFAULT FALSE,
    password_last_changed TIMESTAMP,
    locked_until TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    last_login_ip INET,
    last_login_at TIMESTAMP,
    last_activity_at TIMESTAMP,
    
    -- Compliance and Audit
    expires_at TIMESTAMP,
    requires_training BOOLEAN DEFAULT FALSE,
    training_completed_at TIMESTAMP,
    background_check_status VARCHAR(50),
    security_clearance VARCHAR(50),
    
    -- Metadata
    metadata JSONB,
    tags TEXT[],
    notes TEXT,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for users table
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_last_activity ON users(last_activity_at);

-- Create trigger to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_system VARCHAR(255) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER,
    target_username VARCHAR(100),
    session_type VARCHAR(50) DEFAULT 'ssh',
    status session_status DEFAULT 'active',
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    client_ip INET,
    recording_path TEXT,
    approval_id UUID,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_start_time ON sessions(start_time);
CREATE INDEX idx_sessions_target_system ON sessions(target_system);

CREATE TRIGGER update_sessions_updated_at 
    BEFORE UPDATE ON sessions 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create access_requests table
CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_system VARCHAR(255) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_username VARCHAR(100),
    access_type VARCHAR(50) NOT NULL,
    justification TEXT NOT NULL,
    status access_request_status DEFAULT 'pending',
    requested_duration_hours INTEGER DEFAULT 8,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMP,
    expires_at TIMESTAMP,
    auto_approve BOOLEAN DEFAULT FALSE,
    emergency_access BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_requests_user_id ON access_requests(user_id);
CREATE INDEX idx_access_requests_status ON access_requests(status);
CREATE INDEX idx_access_requests_expires_at ON access_requests(expires_at);

CREATE TRIGGER update_access_requests_updated_at 
    BEFORE UPDATE ON access_requests 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create vault_entries table
CREATE TABLE IF NOT EXISTS vault_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    entry_type vault_entry_type DEFAULT 'password',
    system_name VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    encrypted_data TEXT NOT NULL,
    tags TEXT[],
    owner_id UUID NOT NULL REFERENCES users(id),
    shared_with UUID[],
    auto_rotate BOOLEAN DEFAULT FALSE,
    rotation_interval_days INTEGER DEFAULT 90,
    last_rotated_at TIMESTAMP,
    expires_at TIMESTAMP,
    metadata JSONB,
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vault_entries_owner_id ON vault_entries(owner_id);
CREATE INDEX idx_vault_entries_system_name ON vault_entries(system_name);
CREATE INDEX idx_vault_entries_entry_type ON vault_entries(entry_type);
CREATE INDEX idx_vault_entries_tags ON vault_entries USING GIN(tags);

CREATE TRIGGER update_vault_entries_updated_at 
    BEFORE UPDATE ON vault_entries 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    session_id UUID REFERENCES sessions(id),
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    severity VARCHAR(20) DEFAULT 'info',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_event_category ON audit_logs(event_category);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity);

-- Create system_targets table
CREATE TABLE IF NOT EXISTS system_targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    port INTEGER DEFAULT 22,
    system_type VARCHAR(50) DEFAULT 'linux',
    environment VARCHAR(50) DEFAULT 'production',
    description TEXT,
    tags TEXT[],
    active BOOLEAN DEFAULT TRUE,
    auto_approve_requests BOOLEAN DEFAULT FALSE,
    max_session_duration_hours INTEGER DEFAULT 8,
    allowed_users UUID[],
    allowed_roles user_role[],
    connection_config JSONB,
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_system_targets_hostname ON system_targets(hostname);
CREATE INDEX idx_system_targets_ip_address ON system_targets(ip_address);
CREATE INDEX idx_system_targets_system_type ON system_targets(system_type);
CREATE INDEX idx_system_targets_environment ON system_targets(environment);
CREATE INDEX idx_system_targets_tags ON system_targets USING GIN(tags);

CREATE TRIGGER update_system_targets_updated_at 
    BEFORE UPDATE ON system_targets 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(50) DEFAULT 'info',
    read BOOLEAN DEFAULT FALSE,
    action_url TEXT,
    expires_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_read ON notifications(read);
CREATE INDEX idx_notifications_type ON notifications(type);
CREATE INDEX idx_notifications_created_at ON notifications(created_at);

-- Insert default admin user (password: Admin123!)
INSERT INTO users (
    username, 
    email, 
    password_hash, 
    first_name, 
    last_name, 
    role,
    password_last_changed
) VALUES (
    'admin',
    'admin@pamSystem.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/J9JGNRGhGb.pQRQGO', -- Admin123!
    'System',
    'Administrator',
    'admin',
    CURRENT_TIMESTAMP
) ON CONFLICT (username) DO NOTHING;

-- Create database views for reporting
CREATE OR REPLACE VIEW active_sessions_view AS
SELECT 
    s.*,
    u.username,
    u.first_name,
    u.last_name,
    u.department,
    st.name as target_name,
    st.environment
FROM sessions s
JOIN users u ON s.user_id = u.id
LEFT JOIN system_targets st ON s.target_system = st.name
WHERE s.status = 'active';

CREATE OR REPLACE VIEW user_activity_summary AS
SELECT 
    u.id,
    u.username,
    u.first_name,
    u.last_name,
    u.department,
    u.role,
    u.last_login_at,
    u.last_activity_at,
    COUNT(s.id) as total_sessions,
    COUNT(CASE WHEN s.status = 'active' THEN 1 END) as active_sessions,
    COUNT(ar.id) as pending_requests
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id
LEFT JOIN access_requests ar ON u.id = ar.user_id AND ar.status = 'pending'
WHERE u.status = 'active'
GROUP BY u.id, u.username, u.first_name, u.last_name, u.department, u.role, u.last_login_at, u.last_activity_at;

-- Create security policy functions
CREATE OR REPLACE FUNCTION check_password_complexity(password TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    -- Check minimum length (8 characters)
    IF LENGTH(password) < 8 THEN
        RETURN FALSE;
    END IF;
    
    -- Check for uppercase letter
    IF password !~ '[A-Z]' THEN
        RETURN FALSE;
    END IF;
    
    -- Check for lowercase letter
    IF password !~ '[a-z]' THEN
        RETURN FALSE;
    END IF;
    
    -- Check for digit
    IF password !~ '[0-9]' THEN
        RETURN FALSE;
    END IF;
    
    -- Check for special character
    IF password !~ '[^A-Za-z0-9]' THEN
        RETURN FALSE;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE sessions 
    SET status = 'expired', end_time = CURRENT_TIMESTAMP
    WHERE status = 'active' 
    AND start_time < CURRENT_TIMESTAMP - INTERVAL '24 hours';
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up old audit logs
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs 
    WHERE timestamp < CURRENT_TIMESTAMP - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMIT;