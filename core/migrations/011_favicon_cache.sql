-- Migration: Add favicon cache
-- Description: 按需抓取的站点图标缓存，按 host 去重、跨条目/跨身份共享。
--              公开数据，明文 BLOB，不进加密体系（区别于 credentials/attachments）。
--              data 上限 524288 = 512 KiB，与 core/src/favicon.rs 的
--              MAX_FAVICON_BYTES 保持一致（改动需双方同步）。

CREATE TABLE IF NOT EXISTS favicon_cache (
    host TEXT PRIMARY KEY NOT NULL CHECK(length(trim(host)) > 0),
    mime_type TEXT NOT NULL,
    data BLOB NOT NULL CHECK(length(data) > 0 AND length(data) <= 524288),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
