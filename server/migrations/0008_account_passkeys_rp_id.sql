-- M2 账号体系第一批收口：passkey 断言验证需要 rp_id。
-- rpIdHash 比对与 origin↔rp_id 校验（core crypto::passkey::verify_assertion）
-- 都以注册时声明的 rp_id 为锚；0007 建表时遗漏此列。
-- 可空：存根期写入的行 rp_id 为 NULL——无锚即无法完成断言验证，
-- fail-closed 视同凭据不可用（登录时 401，需重新注册 passkey）。

ALTER TABLE account_passkeys ADD COLUMN rp_id TEXT;
