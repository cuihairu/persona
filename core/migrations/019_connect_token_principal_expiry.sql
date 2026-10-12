-- Migration 019: Connect token 主体绑定与过期（架构校正批2）。
-- principal：绑定调用方身份（创建方填写的主体标识，如扩展/应用身份；
-- NULL = 旧数据未绑定）。expires_at：ISO8601 过期时刻，NULL = 永不过期
-- （旧数据语义不变）。两列均可空，旧行无需回填；过期判定在
-- PersonaService::connect_authenticate（吊销同形拒绝，节流记审计）。

ALTER TABLE connect_tokens ADD COLUMN principal TEXT;
ALTER TABLE connect_tokens ADD COLUMN expires_at TEXT;
