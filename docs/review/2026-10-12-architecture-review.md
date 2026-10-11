# Persona 架构评审：授权模型与受控自动化补齐

> 来源: ChatGPT 架构评审对话
> 日期: 2026-10-12
> 状态: 待实施

## 评审结论

当前架构方向正确，已有基础能力（加密核心、SSH Agent 策略、审计、Connect 自动化），但缺少：

1. **统一授权模型** — Principal/Resource/Action/Context/SecurityLevel/UnlockState 的完整决策链
2. **分级安全体系** — 不同安全等级对应不同保护要求
3. **受控自动化统一契约** — 主体认证、资源范围、操作范围、有效期、审计

## 核心建议

### 1. 完善 Principal 概念

| Principal 类型 | 识别方式                    | 示例                           |
| -------------- | --------------------------- | ------------------------------ |
| 用户           | 主密码解锁 + 生物识别       | 桌面端主动操作                 |
| CLI            | 本地进程 + 工作区权限       | `persona` 命令                 |
| SSH Agent      | Unix socket + 策略引擎      | ssh 签名请求                   |
| 浏览器扩展     | Native Messaging + 配对绑定 | 自动填充                       |
| 外部应用       | Connect Token + Scope       | Cockpit/Wingman/Croupier/Memex |

**关键区分**: Identity（身份）≠ Principal（主体）。Identity 是凭证归属，Principal 是发起操作者。

### 2. 统一 Policy → Action 授权路径

```
Decision = f(Principal, Resource, Action, Context, Security Level, Unlock State)
```

所有敏感操作必须经过核心授权入口：

- 读取密码 ≠ 导出私钥
- 使用私钥签名 ≠ 取得私钥原文
- 交互场景 ≠ 非交互场景（不同授权条件）

### 3. 安全等级模型

| 等级 | 示例                 | 保护要求                               |
| ---- | -------------------- | -------------------------------------- |
| 普通 | 网站密码             | 解锁即可读                             |
| 敏感 | API Key、服务器密码  | 解锁 + 确认                            |
| 高敏 | SSH 私钥、钱包助记词 | 解锁 + 确认 + 策略检查，默认拒绝自动化 |

### 4. 受控自动化契约（Connect 补齐）

当前 Connect 只有 Token + Scope，需补齐：

- **主体绑定**: Token 必须绑定明确 Principal（Cockpit 服务账号）
- **资源范围**: 指定可访问的 Identity + Credential 列表
- **操作范围**: read / use（签名）/ fill，区分读取与使用
- **有效期**: 短期 Token（5分钟）+ 长期 Token（可撤销）
- **审计**: 每次访问记录 Principal + Resource + Action + Context

## 实施清单

- [ ] 补全 `Principal` 类型定义与识别机制
- [ ] 核心增加统一授权入口 `authorize(principal, resource, action, context)`
- [ ] Credential 增加 `security_level` 字段（迁移）
- [ ] Connect Token 增加 `principal` + `resource_scope` + `action_scope` 绑定
- [ ] 审计日志记录完整授权决策链
- [ ] 更新架构图体现授权模型

## 对集成方的影响

| 集成方   | 所需能力                     | 当前状态                      |
| -------- | ---------------------------- | ----------------------------- |
| Cockpit  | SSH 私钥签名（use，非 read） | 需 Principal 识别 + use 权限  |
| Wingman  | 密码读取（read）             | 需 Connect Token + read scope |
| Croupier | API Key 读取（read）         | 需 Connect Token + read scope |
| Memex    | 凭据读取（read）             | 需 Connect Token + read scope |

## 下一步

1. 先落 `Principal` 和统一授权入口（core）
2. 再补 Connect Token 的 scope 绑定
3. 更新架构文档
