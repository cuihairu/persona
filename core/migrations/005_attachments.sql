-- Attachment storage schema
-- Creates tables for file attachments and chunks

-- Attachments table
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    storage_path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    is_encrypted BOOLEAN NOT NULL DEFAULT 0,
    encryption_key_id TEXT,
    chunk_count INTEGER NOT NULL DEFAULT 1,
    chunk_size INTEGER NOT NULL DEFAULT 0,
    tags TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_accessed TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
);

-- Create indexes for attachments
CREATE INDEX IF NOT EXISTS idx_attachments_credential ON attachments(credential_id);
CREATE INDEX IF NOT EXISTS idx_attachments_filename ON attachments(filename);
CREATE INDEX IF NOT EXISTS idx_attachments_mime_type ON attachments(mime_type);
CREATE INDEX IF NOT EXISTS idx_attachments_hash ON attachments(content_hash);
CREATE INDEX IF NOT EXISTS idx_attachments_active ON attachments(is_active);
CREATE INDEX IF NOT EXISTS idx_attachments_created ON attachments(created_at);

-- Attachment chunks table (for large files)
CREATE TABLE IF NOT EXISTS attachment_chunks (
    id TEXT PRIMARY KEY,
    attachment_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    size INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    is_encrypted BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES attachments(id) ON DELETE CASCADE,
    UNIQUE(attachment_id, chunk_index)
);

-- Create indexes for attachment chunks
CREATE INDEX IF NOT EXISTS idx_chunks_attachment ON attachment_chunks(attachment_id);
CREATE INDEX IF NOT EXISTS idx_chunks_index ON attachment_chunks(attachment_id, chunk_index);
