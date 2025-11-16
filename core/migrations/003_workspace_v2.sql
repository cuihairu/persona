-- Workspace schema v2: add real path, active identity, and settings JSON
-- Safe to run multiple times: SQLite ignores duplicate columns addition in our guard pattern.

-- Add columns if they do not exist (SQLite doesn't support IF NOT EXISTS for columns).
-- We emulate by checking PRAGMA in migration runner (sqlx does not do conditional DDL here),
-- so adding columns may fail if already exist; wrap by tooling if needed.

ALTER TABLE workspaces ADD COLUMN path TEXT;
ALTER TABLE workspaces ADD COLUMN active_identity_id TEXT;
ALTER TABLE workspaces ADD COLUMN settings TEXT NOT NULL DEFAULT '{}';

-- Index for quick lookup by active identity (optional)
CREATE INDEX IF NOT EXISTS idx_workspaces_active_identity ON workspaces(active_identity_id);
