-- App-facing metadata for the vault file: which application build created it
-- and which build opened it last. Diagnostic provenance only — schema truth
-- lives in _sqlx_migrations, and no secret material is ever stored here.
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
