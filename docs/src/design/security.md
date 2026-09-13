# 安全设计

本文描述 Persona 当前实现应遵循的安全设计约束。更完整的资产、信任边界和 STRIDE 分析见 [威胁模型与周期性安全审查](../../THREAT_MODEL.md)。

## 分层安全边界

| 层 | 责任 | 关键控制 |
| --- | --- | --- |
| 客户端入口 | CLI、桌面端、浏览器扩展、SSH Agent 只负责交互和请求路由 | 不直接绕过 core 读写敏感明文 |
| 核心服务 | 身份、凭据、解锁、审计和策略统一入口 | 自动锁、敏感操作再认证、审计日志 |
| 加密层 | 主密钥派生、item key 包裹、AES-GCM 加解密 | 每项凭据独立 key，认证加密防篡改 |
| 存储层 | SQLite、附件、迁移和配置 | schema 迁移、`wrapped_item_key` 兼容、最小明文元数据 |
| 外部接口 | Native Messaging、SSH Agent socket/pipe、可选 server | 配对/HMAC、origin binding、known_hosts、只传密文或摘要 |

## 敏感操作授权

敏感操作必须显式经过授权路径，不能只依赖调用方 UI：

- 凭据 reveal、copy、fill、TOTP 获取必须验证解锁态，并尽量绑定 active identity。
- 浏览器 fill/copy/TOTP 必须要求 user gesture；有 URL 的凭据必须做 origin binding。
- SSH 签名必须经过 agent 策略检查；默认不得导出私钥。
- 导出包含敏感内容时必须确认解锁态和目标加密策略。
- 非交互模式必须由 `PERSONA_NON_INTERACTIVE` 和相关环境变量显式启用。

## 密钥与数据处理

- 新写入凭据使用随机 item key 加密明文，再用主密钥包裹 item key。
- 解锁后的主密钥服务只应保存在内存中，锁定时清理服务状态。
- 备份、导入导出和附件加密必须使用随机 salt/nonce，并验证解密失败路径。
- 审计日志可以记录资源 ID、动作、时间和摘要，不能记录明文密码、TOTP secret、SSH 私钥或完整待签名 payload。

## 设计约束

- 不新增绕过核心服务层的直接存储访问路径。
- 不把云端、server 或浏览器扩展作为明文信任根。
- 不为未来功能预留宽权限接口；新增能力必须先定义资产、授权条件和审计事件。
- 不在日志、错误消息、测试快照或 CI 输出中写入真实 secret。
