-- Add wrapped item key column to support per-item key hierarchy
ALTER TABLE credentials ADD COLUMN wrapped_item_key BLOB;
