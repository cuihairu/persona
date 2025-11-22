-- Change history schema for tracking all modifications
-- Creates table for version control and audit trail

-- Change history table
CREATE TABLE IF NOT EXISTS change_history (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    change_type TEXT NOT NULL,
    user_id TEXT,
    previous_state TEXT,
    new_state TEXT,
    changes_summary TEXT NOT NULL DEFAULT '{}',
    reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    is_reversible BOOLEAN NOT NULL DEFAULT 1
);

-- Create indexes for change history
CREATE INDEX IF NOT EXISTS idx_change_history_entity ON change_history(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_change_history_timestamp ON change_history(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_change_history_user ON change_history(user_id);
CREATE INDEX IF NOT EXISTS idx_change_history_change_type ON change_history(change_type);
CREATE INDEX IF NOT EXISTS idx_change_history_version ON change_history(entity_type, entity_id, version DESC);

-- Create composite index for common queries
CREATE INDEX IF NOT EXISTS idx_change_history_entity_time ON change_history(entity_type, entity_id, timestamp DESC);
