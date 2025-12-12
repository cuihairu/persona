-- Migration 008: Add auto-lock policy management using SQLite-compatible schema
-- This migration adds policy tables, augments the sessions table, and seeds sensible defaults.

-- Create table for configurable auto-lock policies
CREATE TABLE IF NOT EXISTS auto_lock_policies (
    id TEXT PRIMARY KEY NOT NULL DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL UNIQUE CHECK(length(trim(name)) > 0),
    description TEXT,
    security_level TEXT NOT NULL CHECK (security_level IN ('low', 'medium', 'high', 'maximum')),
    inactivity_timeout_secs INTEGER NOT NULL CHECK (inactivity_timeout_secs > 0),
    absolute_timeout_secs INTEGER NOT NULL CHECK (absolute_timeout_secs > 0),
    sensitive_operation_timeout_secs INTEGER NOT NULL CHECK (sensitive_operation_timeout_secs > 0),
    max_concurrent_sessions INTEGER NOT NULL CHECK (max_concurrent_sessions > 0),
    enable_warnings INTEGER NOT NULL DEFAULT 1 CHECK (enable_warnings IN (0, 1)),
    warning_time_secs INTEGER NOT NULL CHECK (warning_time_secs >= 0),
    force_lock_sensitive INTEGER NOT NULL DEFAULT 0 CHECK (force_lock_sensitive IN (0, 1)),
    activity_grace_period_secs INTEGER NOT NULL DEFAULT 5 CHECK (activity_grace_period_secs >= 0),
    background_check_interval_secs INTEGER NOT NULL DEFAULT 30 CHECK (background_check_interval_secs > 0),
    metadata TEXT NOT NULL DEFAULT '{}',
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_auto_lock_policies_security_level ON auto_lock_policies(security_level);
CREATE INDEX IF NOT EXISTS idx_auto_lock_policies_is_active ON auto_lock_policies(is_active);
CREATE INDEX IF NOT EXISTS idx_auto_lock_policies_is_default ON auto_lock_policies(is_default) WHERE is_default = 1;
CREATE INDEX IF NOT EXISTS idx_auto_lock_policies_name ON auto_lock_policies(name);

-- Keep updated_at fresh when rows are mutated outside the application layer
CREATE TRIGGER IF NOT EXISTS trg_auto_lock_policies_updated_at
AFTER UPDATE ON auto_lock_policies
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE auto_lock_policies
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = NEW.id;
END;

-- Table mapping users to their assigned policies
CREATE TABLE IF NOT EXISTS user_auto_lock_policies (
    user_id TEXT PRIMARY KEY NOT NULL,
    policy_id TEXT NOT NULL,
    assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (policy_id) REFERENCES auto_lock_policies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_auto_lock_policies_user_id ON user_auto_lock_policies(user_id);
CREATE INDEX IF NOT EXISTS idx_user_auto_lock_policies_policy_id ON user_auto_lock_policies(policy_id);

-- Extend existing sessions table with policy + lock metadata
ALTER TABLE sessions ADD COLUMN policy_id TEXT;
ALTER TABLE sessions ADD COLUMN last_sensitive_op TEXT;
ALTER TABLE sessions ADD COLUMN locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1));
ALTER TABLE sessions ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_sessions_policy_id ON sessions(policy_id);
CREATE INDEX IF NOT EXISTS idx_sessions_locked ON sessions(locked);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- Seed built-in policies that mirror typical Persona presets
INSERT INTO auto_lock_policies (
    name,
    description,
    security_level,
    inactivity_timeout_secs,
    absolute_timeout_secs,
    sensitive_operation_timeout_secs,
    max_concurrent_sessions,
    enable_warnings,
    warning_time_secs,
    force_lock_sensitive,
    metadata,
    is_active,
    is_default
) VALUES
(
    'Low Security Policy',
    'Recommended for personal devices with relaxed security requirements',
    'low',
    1800,
    7200,
    600,
    10,
    1,
    300,
    0,
    '{"tags":["personal","low-security"],"version":1,"is_system_policy":true}',
    1,
    0
),
(
    'Medium Security Policy',
    'Balanced security for general corporate use',
    'medium',
    900,
    3600,
    300,
    5,
    1,
    60,
    0,
    '{"tags":["corporate","medium-security"],"version":1,"is_system_policy":true}',
    1,
    1
),
(
    'High Security Policy',
    'Enhanced security for sensitive corporate environments',
    'high',
    600,
    1800,
    180,
    3,
    1,
    30,
    1,
    '{"tags":["corporate","high-security","sensitive"],"version":1,"is_system_policy":true}',
    1,
    0
),
(
    'Maximum Security Policy',
    'Highest security for critical environments and public access',
    'maximum',
    300,
    900,
    60,
    1,
    1,
    15,
    1,
    '{"tags":["high-security","public","critical"],"version":1,"is_system_policy":true}',
    1,
    0
);
