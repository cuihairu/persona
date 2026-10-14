> [English](ONEPASSWORD_FEATURES.md) | **中文**

# 1Password 功能清单（参考）

本清单按领域分组归纳 1Password 的主要功能，用于指导 Persona 的路线图规划，以及功能对齐/差距分析。

- 安全模型
  - 端到端加密，密钥由用户密钥（Secret Key + 主密码）派生
  - 零知识架构；基于 SRP 的远程认证
  - 客户端加密；逐条目密钥；条目共享时重加密
  - 生物识别解锁（Touch ID/Face ID/Windows Hello）；自动锁定；Travel Mode
- 保险库、条目与组织
  - 多个保险库；保险库集合；按保险库的权限
  - 条目类型：Login、Password、分身（Identity）、Secure Note、Credit Card、Bank Account、API Credential、SSH Key、Software License、Passkey（WebAuthn）（FIDO）
  - 条目元数据：标签、自定义字段、附件、条目历史与版本管理
  - 条目共享：直接授予成员/群组访问；限时链接；权限管理
- 自动填充与浏览器
  - 浏览器扩展（自动填充登录项、Passkey、TOTP）
  - 防钓鱼保护；域名匹配规则；隐私模式支持
- 密码与 Passkey
  - 密码生成器（规则、熵值计量）
  - Passkey（WebAuthn）的存储与自动填充
  - TOTP 生成器；2FA 设置二维码扫描；OTP 自动填充
- Watchtower 与健康
  - 泄露监控；重复使用/弱密码；即将过期的条目；2FA 可用性
  - 域名泄露告警；暗网监控（商业套餐）
- 共享、管理与恢复
  - 家庭/团队/企业账号；基于群组的 RBAC
  - 管理控制台、策略（密码策略、2FA 策略、设备审批）
  - 账号恢复流程；紧急访问
  - SCIM 开通；SSO 集成（Okta/Azure AD/Google）
- 客户端与界面
  - 原生客户端：macOS/Windows/Linux/iOS/Android；Web 客户端
  - CLI：条目 CRUD、接入 secrets automation；SSH agent 集成
  - Events API、审计日志；报表
- 开发者与自动化
  - 1Password CLI（op）；Connect 服务器（secrets automation）
  - SSH Agent：使用存储在 1Password 中的密钥进行签名
  - Shell 插件，用于向工具自动注入 secrets
  - Kubernetes/CI 集成；SDK；Terraform Provider
- 其他
  - 掩码邮箱（Fastmail 集成）
  - Travel Mode（从设备中移除保险库）
  - 本地条目历史；附件；文件安全存储

备注

- 1Password 本身不作为加密钱包，但可以把助记词/私钥作为 secret 存储。Persona 在此之上落地了该扩展：一等公民钱包支持（BIP32/44/SLIP-10 派生与签名）已于 2026-09 上线（`core/src/models/wallet.rs`、`core/src/crypto/wallet_crypto.rs`，含官方测试向量）。
