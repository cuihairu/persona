# 安全特性

Persona 的安全模型以本地优先和零知识为核心：敏感身份材料在本地加密存储，CLI、桌面端、浏览器扩展和 SSH Agent 都通过同一套核心服务执行解锁、审计和策略检查。完整威胁模型见 [威胁模型与周期性安全审查](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md)。

## 核心保护

- **本地加密**：凭据明文使用 AES-256-GCM 加密；新凭据使用独立 item key，并由主密钥包裹，降低单项密钥泄露后的影响范围。
- **身份上下文隔离**：凭据、TOTP、SSH Key 等身份材料绑定到具体 identity，浏览器建议和填充默认按 active identity 过滤。
- **解锁与自动锁**：核心服务支持主密码解锁、自动锁、敏感操作再认证和生物识别 Provider 抽象。
- **浏览器桥接保护**：Native Messaging 协议要求配对、短期 session、HMAC 请求认证、origin binding 和 user gesture，避免后台页面静默读取凭据。
- **SSH Agent 策略**：Agent 支持 known_hosts、deny-all、速率限制、每密钥/每主机策略、确认和生物识别优先级。
- **审计与脱敏**：身份操作、凭据解密、导出和 SSH 签名会写入本地审计日志；日志脱敏测试覆盖常见 secret、token 和验证码形态。

## 默认安全边界

- 当前 OS 用户账户是主要本地边界；Persona 不防御已经完全控制该账户或内核的恶意软件。
- 可选 Server/Sync 只能处理密文、事件摘要或同步元数据，不得成为明文解密方。
- 非交互模式允许通过环境变量注入主密码，适合 CI，但调用方必须使用 secret store 并避免日志回显。
- 没有 URL 的浏览器凭据无法做严格来源绑定，高价值凭据应始终设置 URL。

## 复审要求

每个版本发布前必须运行 Rust/前端测试、供应链审计，并检查新增日志、审计 metadata、浏览器桥接和 SSH Agent 策略是否扩大敏感操作授权。KDF 参数、主密钥迁移、备份加密和威胁模型至少按季度复审一次。
