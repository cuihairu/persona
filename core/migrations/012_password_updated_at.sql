-- Migration 012: track when the master password was last changed,
-- enabling opt-in forced rotation (WorkspaceSettings.password_expiry_days).

ALTER TABLE user_auth ADD COLUMN password_updated_at TEXT;

-- Backfill: existing users' last change is unknown; approximate with the
-- row's last update (or creation) so expiry is computed from a sane floor.
UPDATE user_auth SET password_updated_at = COALESCE(password_updated_at, updated_at, created_at);
