# 身份（Identity）

**一句话**：身份是你密码库里的一个**命名分组**，外加一个"当前选中哪个"的指针。
它是组织和切换的单位——**不是**账号、**不是**密钥、**不是**加密边界。

很多人第一次看到顶栏的"选择身份"会以为它像浏览器的"个人资料/账号切换"，
那会导致一堆错误预期（比如以为切换身份等于换一个加密空间）。这页把它的真实
含义讲清楚。

## 数据模型

身份是 SQLite 里的 `identities` 表一行（`core/migrations/001_initial.sql`）：

| 字段                              | 含义                                                             |
| --------------------------------- | ---------------------------------------------------------------- |
| `id`                              | UUID，主键                                                       |
| `name`                            | 你起的名字，CLI/desktop 都用它指代身份                           |
| `identity_type`                   | `Personal` / `Work` / `Social` / `Financial` / `Gaming` / 自定义 |
| `description` / `email` / `phone` | 自由备注，仅用于辨认，**不参与任何认证**                         |
| `ssh_key` / `gpg_key`             | 备注字段，只是贴了一段公钥文本，**不是**受管密钥                 |
| `tags` / `attributes`             | 自定义标签与键值对                                               |
| `is_active`                       | 历史字段，当前代码**不用**它做过滤（见下）                       |
| `travel_marked`                   | 旅行模式标记：这个身份要随身带走                                 |

其它表通过 `identity_id` 外键挂到身份上（`ON DELETE CASCADE`）：

```
identities ──┬── credentials        （密码 / TOTP / API key / SSH key 条目）
             ├── crypto_wallets     （加密钱包）
             ├── passkeys           （通行密钥）
             ├── workspace_members  （工作区成员，身份是"分享单位"）
             └── workspaces.active_identity_id（唯一的"当前身份"指针）
```

附件（`attachments`）不直接挂身份，而是挂凭据（`credential_id`）——所以它随凭据
一起归属到某个身份。

## 身份真正做的四件事

### 1. 分组与视图过滤

凭据列表按 `identity_id` 过滤（`PersonaService::get_credentials_for_identity`）。
切到"工作"身份，界面里只剩工作相关的凭据。这是身份最主要的用途。

### 2. 切换指针

`persona switch <name>` 和桌面端顶栏的切换器，最终都只做一件事：改写
`workspaces.active_identity_id` 这一个字段。

因为指针存在库里而不是某个客户端的本地状态，CLI、桌面应用、浏览器扩展、
SSH Agent 共享同一个"当前身份"——在任何一处切换，其它端下次读到就是新的。

### 3. 旅行模式的打包单位

这是身份最实用的一个隐藏用途。标记 `travel_marked` 后进入旅行模式，这个身份
以及挂在它下面的凭据、钱包、通行密钥、附件、成员行会被打进加密 sidecar 并从本机
数据库中删除（`core/src/travel.rs`）；退出旅行模式时原样恢复。

所以身份是"这套材料整体带走 / 整体留下"的最小单位——比单个条目更好用。

### 4. 分类标记

`identity_type` 只驱动界面表现：图标、颜色、筛选分组。它没有权限或安全含义，
红不红、黄不黄都不影响任何东西。

## 身份**不**做什么（常见误解）

| 误解                                | 事实                                                                                                                                                                                |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 切换身份 = 换一个加密空间           | 否。每条凭据用独立的 item key 加密，再由主密码派生的 master key 包装（见 [Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md)）。身份不参与密钥派生 |
| 切换身份需要重新解锁 / 换主密码     | 否。解锁状态由主密码决定，切换身份不解锁也不重新解密                                                                                                                                |
| 身份带 SSH / GPG 私钥               | 否。`ssh_key` / `gpg_key` 只是备注文本。私钥是独立的凭据条目（`CredentialType::SshKey`），由 SSH Agent 按需提供                                                                     |
| SSH Agent 会只提供当前身份的 key    | 否。`persona ssh` 的 `--identity` 参数在代码里标注为 "reserved for future use"，目前不过滤                                                                                          |
| `identities.is_active` 就是当前身份 | 否。这个字段存在但没有任何查询用它过滤。当前身份是 `workspaces.active_identity_id`                                                                                                  |
| 身份有远程账号 / 登录态             | 否。身份是纯本地数据。远程能力（同步、服务端）由 `persona connect` 单独配置，与身份无关                                                                                             |

## 为什么第一次打开没有默认身份

`persona init` / 桌面端首次初始化**不会**播种任何身份——身份是你自己建的分组，
凭空造一个 "Personal" 等于在你库里写你没要求过的数据。

有身份之后前端会自动选：优先取工作区的 active identity，取不到就兜底第一个，
并把它回写为 active（`usePersonaService.ts` 的 `loadIdentities`）。所以：

- 顶栏显示"选择身份"占位 = 当前**一个身份都没有**（新库），这是正常空态；
- 已经建过身份还显示占位 = 加载失败，看 [故障排除](./troubleshooting)。

想要开箱即用，建完第一个身份就会被立即选为当前身份；需要固定默认值就用
`persona switch` 显式指定。

## 怎么用

### CLI

```bash
persona add --name alice --identity-type Personal   # 新建身份
persona add --name alice --set-active               # 新建并立即切过去
persona list                                         # 列出全部身份
persona show <name>                                  # 看详情
persona switch <name>                                # 切到该身份（全局生效）
persona switch --previous                            # 切回上一个
persona switch --interactive                         # 交互选择
persona edit <name> --identity-type Work             # 改类型/备注
persona remove <name> --backup                       # 删除（见下方警告）

# 凭据默认落在当前身份下，也可显式指定
persona credential add --identity alice --name "GitHub" \
  --credential-type password --prompt-secret
persona credential list --identity alice
```

### 桌面应用

- 顶栏身份下拉或侧栏点选即可切换；
- 新建凭据时自动归到**当前身份**（弹窗里没有身份下拉——先切身份再新建）；
- 设置面板里管理身份：新建、编辑、删除、切换旅行标记。

## 三种容易互相搞混的东西

代码和界面里都出现"identity"，指的是三件事：

| 名字                          | 是什么                                                                   | 例                     |
| ----------------------------- | ------------------------------------------------------------------------ | ---------------------- |
| **身份 / Identity（本章）**   | 凭据分组 + 当前身份指针，库级实体，跨端共享                              | `persona switch alice` |
| **Identity 类凭据**           | 一种**凭据类型**，存姓名、地址、证件号码等个人资料（1Password 同名功能） | 新建凭据时选"Identity" |
| **设备身份 / DeviceIdentity** | 每台机器自己的密钥对，用于同步 oplog 签名                                | 自动生成，用户看不到   |

建凭据弹窗里的"Identity"选项是**第二种**（证件资料），不是本章讲的身份分组。
顺带一提：证件类凭据本身也归属于某个身份分组，所以一个身份下可以同时放
"alice 的工作身份"和"alice 的身份证件资料"。

## 删除身份会连带什么

删除身份时外键 `ON DELETE CASCADE` 会一并删除它名下的凭据、加密钱包、通行密钥、
工作区成员行；凭据删除又会清掉挂在它下面的附件文件（附件密文封装在该凭据的
item key 下，留着也解不开）。

**审计日志会保留**：删除前先把审计行的 `identity_id` 引用置空，历史记录不丢。
但被删的凭据内容不可恢复——删之前先 `persona export`。

## 相关页面

- [快速开始](./quick-start) — 建库、创建第一个身份
- [桌面应用](./desktop) — 切换器与统计页
- [核心功能](../overview/features) — 身份隔离视图
- [Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md) — 加密到底在哪一层
