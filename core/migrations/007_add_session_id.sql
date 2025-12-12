-- Add session_id field to audit_logs table for enhanced auto-lock tracking
-- Migration 007: Add session tracking support

ALTER TABLE audit_logs
ADD COLUMN session_id TEXT;

-- Create index for session_id to improve query performance
CREATE INDEX idx_audit_logs_session_id ON audit_logs(session_id);

-- COMMENT ON statements are not supported in SQLite; documentation is kept in schema files.
