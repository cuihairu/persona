-- Initial database schema for Persona
-- Creates tables for identities, credentials, and user authentication

-- Identities table
CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    identity_type TEXT NOT NULL,
    description TEXT,
    email TEXT,
    phone TEXT,
    ssh_key TEXT,
    gpg_key TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    attributes TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Create indexes for identities
CREATE INDEX IF NOT EXISTS idx_identities_type ON identities(identity_type);
CREATE INDEX IF NOT EXISTS idx_identities_name ON identities(name);
CREATE INDEX IF NOT EXISTS idx_identities_active ON identities(is_active);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    name TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    security_level TEXT NOT NULL,
    url TEXT,
    username TEXT,
    encrypted_data BLOB NOT NULL,
    notes TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_accessed TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    is_favorite BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE
);

-- Create indexes for credentials
CREATE INDEX IF NOT EXISTS idx_credentials_identity ON credentials(identity_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_security ON credentials(security_level);
CREATE INDEX IF NOT EXISTS idx_credentials_active ON credentials(is_active);
CREATE INDEX IF NOT EXISTS idx_credentials_favorite ON credentials(is_favorite);
CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);

-- User authentication table
CREATE TABLE IF NOT EXISTS user_auth (
    user_id TEXT PRIMARY KEY,
    master_password_hash TEXT,
    enabled_factors TEXT NOT NULL DEFAULT '[]',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_auth TEXT,
    password_change_required BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    permissions TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (user_id) REFERENCES user_auth(user_id) ON DELETE CASCADE
);

-- Create indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Workspaces table (for future use)
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Create indexes for workspaces
CREATE INDEX IF NOT EXISTS idx_workspaces_name ON workspaces(name);
CREATE INDEX IF NOT EXISTS idx_workspaces_active ON workspaces(is_active);

-- Workspace members table (for future team features)
CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    permissions TEXT NOT NULL DEFAULT '[]',
    joined_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, identity_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE
);

-- Audit log table for security monitoring
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    identity_id TEXT,
    credential_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user_auth(user_id),
    FOREIGN KEY (identity_id) REFERENCES identities(id),
    FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

-- Create indexes for audit logs
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit_logs(success);