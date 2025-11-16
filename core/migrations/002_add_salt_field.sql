-- Add salt field to user_auth table for persistent salt management
-- This is required for proper key derivation and data consistency

ALTER TABLE user_auth ADD COLUMN master_key_salt TEXT;

-- Create index for salt lookups
CREATE INDEX IF NOT EXISTS idx_user_auth_salt ON user_auth(master_key_salt);