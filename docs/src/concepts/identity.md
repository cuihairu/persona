# 分身（Identity）

**一句话**：分身是同一个人的一个数字身份——是身份材料的**组织、切换与打包单位**。
它不是账号、不是密钥、不是加密边界。

```text
Person
 └─ Identity: Work
      ├─ GitHub（密码）
      ├─ AWS（API key）
      └─ 工作 SSH
 └─ Identity: OpenSource
      ├─ GitHub（密码，另一套）
      └─ 开源 GPG
 ```

同一个 GitHub 在不同分身下是**不同的凭据条目**——分身的隔离发生在数据层，
而不是让你记住「两套浏览资料」。

## 数据模型

身份是 SQLite `identities` 表的一行，其它身份材料表通过 `identity_id` 外键
挂到它下面（`ON DELETE CASCADE`）：

```
identities ──┬── credentials        （密码 / TOTP / API key / SSH key / 钱包条目）
             ├── crypto_wallets
             ├── passkeys
             ├── workspace_members  （工作区成员：身份是"分享单位"）
             └── workspaces.active_identity_id (唯一的"当前身份"指针)
```

完整字段、迁移表名与常见误解见 [用户手册：身份](/user/identity)。

## 它在授权链里的位置

在 [核心概念](./index) 的模型里，Identity 承接 Principal、向下挂载 Material：

```text
Principal → Identity → Material
    （谁）    （哪个分身）   （哪些材料）
```

一条关键性质：**身份不参与密钥派生**。每条凭据用独立 item key 加密，再由
主密码派生的 master key 包裹——切换身份不会解锁、不会重新解密、不改变加密
边界。所以「分身」是逻辑分组，不是另起炉灶的保险柜。

## 分身的两条隐藏语义

1. **全局切换指针**：`workspaces.active_identity_id` 存在库里，CLI、桌面端、
   浏览器扩展、SSH Agent 共享同一个「当前身份」——任何一处 `persona switch`，
   其它入口下次读到就是新的。
2. **旅行模式的打包单位**：`travel_marked` 的身份会被整体打进加密 sidecar
   移出本机 (core/src/travel.rs)——「整套带走/整套留下」的最小单位。

## 边界

- 分身之间**不共享任何授权**：一个分身的凭据不会出现在另一个分身的建议里；
- `identity_type`（Personal/Work/…）只驱动界面表现，**没有权限或安全含义**；
- 身份的远程能力（同步、服务端）由 `persona connect` 单独配置，与分身无关。