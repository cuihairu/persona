-- Create auto_lock_policies table for storing auto-lock policies
-- Migration 008: Add auto-lock policy management

CREATE TABLE auto_lock_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    security_level TEXT NOT NULL CHECK (security_level IN ('low', 'medium', 'high', 'maximum')),
    inactivity_timeout_secs BIGINT NOT NULL CHECK (inactivity_timeout_secs > 0),
    absolute_timeout_secs BIGINT NOT NULL CHECK (absolute_timeout_secs > 0),
    sensitive_operation_timeout_secs BIGINT NOT NULL CHECK (sensitive_operation_timeout_secs > 0),
    max_concurrent_sessions INTEGER NOT NULL CHECK (max_concurrent_sessions > 0),
    enable_warnings BOOLEAN NOT NULL DEFAULT true,
    warning_time_secs BIGINT NOT NULL CHECK (warning_time_secs >= 0),
    force_lock_sensitive BOOLEAN NOT NULL DEFAULT false,
    activity_grace_period_secs BIGINT NOT NULL DEFAULT 5 CHECK (activity_grace_period_secs >= 0),
    background_check_interval_secs BIGINT NOT NULL DEFAULT 30 CHECK (background_check_interval_secs > 0),
    metadata JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_auto_lock_policies_security_level ON auto_lock_policies(security_level);
CREATE INDEX idx_auto_lock_policies_is_active ON auto_lock_policies(is_active);
CREATE INDEX idx_auto_lock_policies_is_default ON auto_lock_policies(is_default) WHERE is_default = true;
CREATE INDEX idx_auto_lock_policies_name ON auto_lock_policies(name);

-- Create trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_auto_lock_policy_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_auto_lock_policies_updated_at
    BEFORE UPDATE ON auto_lock_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_auto_lock_policy_updated_at();

-- Create table for user policy assignments
CREATE TABLE user_auto_lock_policies (
    user_id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES auto_lock_policies(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index for user policy lookups
CREATE INDEX idx_user_auto_lock_policies_user_id ON user_auto_lock_policies(user_id);
CREATE INDEX idx_user_auto_lock_policies_policy_id ON user_auto_lock_policies(policy_id);

-- Create table for sessions with policy association
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    policy_id UUID REFERENCES auto_lock_policies(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_sensitive_op TIMESTAMP WITH TIME ZONE,
    locked BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT valid_expires_at CHECK (expires_at > created_at),
    CONSTRAINT valid_activity_order CHECK (last_activity >= created_at)
);

-- Create indexes for sessions
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_policy_id ON sessions(policy_id);
CREATE INDEX idx_sessions_locked ON sessions(locked);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity);

-- Insert default policies
INSERT INTO auto_lock_policies (name, description, security_level, inactivity_timeout_secs, absolute_timeout_secs, sensitive_operation_timeout_secs, max_concurrent_sessions, enable_warnings, warning_time_secs, force_lock_sensitive, is_default, metadata) VALUES
(
    'Low Security Policy',
    'Recommended for personal devices with relaxed security requirements',
    'low',
    1800,  -- 30 minutes inactivity
    7200,  -- 2 hours absolute
    600,   -- 10 minutes sensitive operations
    10,    -- 10 concurrent sessions
    true,
    300,   -- 5 minutes warning
    false,
    false,
    true,
    '{"tags": ["personal", "low-security"], "version": 1, "is_system_policy": true}'
),
(
    'Medium Security Policy',
    'Balanced security for general corporate use',
    'medium',
    900,   -- 15 minutes inactivity
    3600,  -- 1 hour absolute
    300,   -- 5 minutes sensitive operations
    5,     -- 5 concurrent sessions
    true,
    60,    -- 1 minute warning
    false,
    false,
    false,
    '{"tags": ["corporate", "medium-security"], "version": 1, "is_system_policy": true}'
),
(
    'High Security Policy',
    'Enhanced security for sensitive corporate environments',
    'high',
    600,   -- 10 minutes inactivity
    1800,  -- 30 minutes absolute
    180,   -- 3 minutes sensitive operations
    3,     -- 3 concurrent sessions
    true,
    30,    -- 30 seconds warning
    true,
    false,
    false,
    '{"tags": ["corporate", "high-security", "sensitive"], "version": 1, "is_system_policy": true}'
),
(
    'Maximum Security Policy',
    'Highest security for critical environments and public access',
    'maximum',
    300,   -- 5 minutes inactivity
    900,   -- 15 minutes absolute
    60,    -- 1 minute sensitive operations
    1,     -- 1 concurrent session
    true,
    15,    -- 15 seconds warning
    true,
    false,
    false,
    '{"tags": ["high-security", "public", "critical"], "version": 1, "is_system_policy": true}'
);

-- Add comments for documentation
COMMENT ON TABLE auto_lock_policies IS 'Auto-lock security policies with configurable timeouts and restrictions';
COMMENT ON TABLE user_auto_lock_policies IS 'Assignment of auto-lock policies to users';
COMMENT ON TABLE sessions IS 'User sessions with auto-lock tracking and policy association';

COMMENT ON COLUMN auto_lock_policies.security_level IS 'Security level: low, medium, high, or maximum';
COMMENT ON COLUMN auto_lock_policies.inactivity_timeout_secs IS 'Seconds of inactivity before auto-lock';
COMMENT ON COLUMN auto_lock_policies.absolute_timeout_secs IS 'Maximum session duration in seconds';
COMMENT ON COLUMN auto_lock_policies.sensitive_operation_timeout_secs IS 'Seconds before requiring re-auth for sensitive operations';
COMMENT ON COLUMN auto_lock_policies.max_concurrent_sessions IS 'Maximum number of concurrent sessions per user';
COMMENT ON COLUMN auto_lock_policies.enable_warnings IS 'Whether to show warnings before locking';
COMMENT ON COLUMN auto_lock_policies.warning_time_secs IS 'Seconds before lock to show warning';
COMMENT ON COLUMN auto_lock_policies.force_lock_sensitive IS 'Force lock after sensitive operation timeout';
COMMENT ON COLUMN auto_lock_policies.metadata IS 'Additional policy configuration as JSON';

COMMENT ON COLUMN sessions.policy_id IS 'Associated auto-lock policy';
COMMENT ON COLUMN sessions.locked IS 'Whether the session is currently locked';
COMMENT ON COLUMN sessions.last_sensitive_op IS 'Timestamp of last sensitive operation';
COMMENT ON COLUMN sessions.metadata IS 'Session-specific data as JSON';