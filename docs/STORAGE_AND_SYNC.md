# 存储与同步模式（用户指南）

Persona 是**本地优先**的：你的密码库永远是一台设备上的一个加密 SQLite 文件，
联网能力全部是**可选附件**。本文说明数据实际放在哪、有哪些同步/备份选项、
各自的配置方法与安全边界。

> 工程视角的架构设计见 [`CLIENT_COMMUNICATION_ARCHITECTURE.md`](./CLIENT_COMMUNICATION_ARCHITECTURE.md)
> （愿景设计稿）与 [`THREAT_MODEL.md`](./THREAT_MODEL.md)（威胁与不宣称事项）。

## 总览：三种模式

| 模式                             | 状态        | 你得到什么                          | 需要什么               |
| -------------------------------- | ----------- | ----------------------------------- | ---------------------- |
| **纯本地**（默认）               | ✅ 完整可用 | 零网络、全部功能                    | 什么都不配             |
| **自托管 Persona Server**        | ✅ 已实现   | 审计事件异地副本 + 整库加密备份保管 | 一台自己控制的服务器   |
| **网盘目录（iCloud/Dropbox/…）** | ⚠️ 仅限冷备 | 把加密备份文件放进云盘              | 手动拷贝（见下文警告） |

**当前没有凭据级实时同步**——两台设备上的库是各自独立的，服务器不帮忙
合并条目。多设备协作目前 = 各自备份到同一台服务器 + 按需整库恢复。
（凭据级同步是后续阶段的规划，见 TODO。）

## 你的数据放在哪

初始化后的 workspace 目录（默认 `~/.persona`，可经 `--path` 或
`PERSONA_WORKSPACE_PATH` 指定）：

| 路径                                     | 内容                                    | 加密与否                                                                     |
| ---------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------- |
| `identities.db`                          | 主库：身份/凭据/审计/设置等全部表       | 凭据载荷 per-item key 加密；**元数据列（名称、URL、用户名等）是明文 SQLite** |
| `attachments/`                           | 附件文件体                              | 密文（复用所属凭据的 item key）                                              |
| `backups/`、`exports/`、`temp/`、`logs/` | 工作目录（导出文件路径由 `--out` 自定） | 混合（导出可选加密）                                                         |
| `config.toml`                            | CLI 配置                                | **明文，不含密钥**                                                           |

密钥层级：每条凭据一个随机 item key（AES-256-GCM 加密载荷），item key 由
主密码派生的 master key 包裹——见 [`KEY_HIERARCHY.md`](./KEY_HIERARCHY.md)。
主密码不在任何文件里（验证用 Argon2 哈希）；启用指纹解锁后主密码托管进
OS 钥匙串（service 名 `persona-biometric`，详见 THREAT_MODEL「Biometric
Unlock」一节的固有暴露说明）。

> **注意**：主库的元数据列是明文。对元数据也保密的场景（共用机器、被
> 扣押设备），考虑 Travel Mode（见下文）或整盘加密。

## 模式一：纯本地（默认）

不配置任何服务器时 Persona **零外联**——没有遥测、没有更新检查、没有
任何网络调用。

冷备建议（按优先序）：

1. **加密导出**：`persona export --encrypt --out vault-backup.persenc`
   （Argon2id + AES-256-GCM，导出时设独立口令）。文件可随意拷贝到
   U 盘/云盘。
2. **整库加密备份**：需要模式二的服务器（`persona backup push` 没有
   "备份到本地文件"的路径；离线恢复可用 `persona backup restore --file`
   吃任何 `.persenc` 密文）。
3. OS 级快照：直接拷 `identities.db` 前请先锁定/退出 Persona（热拷贝
   活跃 SQLite 有损坏风险）。

## 模式二：自托管 Persona Server

### 你得到什么

1. **审计事件异地副本**：设备把操作审计（动作/资源类型/成败/时间戳等
   **元数据**，不含凭据名称、不含任何密文或明文密钥）批量上报，服务器
   存一份副本供事后查询。本地审计库仍是第一存证源，上报是尽力而为的
   复制（断网不丢本地记录，只丢异地副本的连续性）。
2. **整库加密备份保管**：`persona backup push` 把整库快照
   （VACUUM INTO → gzip → PERSENC1 加密）上传，服务器只见密文；
   `list/pull/restore/delete` 管理版本。

### 你得不到什么

- **实时同步/合并**——见总览。
- **服务器侧防篡改**：服务器操作者（也就是你自己，或攻破它的人）可以
  扣留、删除或回滚备份，客户端不做新鲜度校验（THREAT_MODEL「备份保管
  端点」明确不宣称）。

### 部署服务器

`persona-server` crate（axum），全部配置走环境变量：

| 变量                                 | 默认                  | 说明                                                         |
| ------------------------------------ | --------------------- | ------------------------------------------------------------ |
| `PERSONA_SERVER_HOST`                | `0.0.0.0`             | 监听地址（本机试玩用 `127.0.0.1`）                           |
| `PERSONA_SERVER_PORT`                | `3000`                | 监听端口                                                     |
| `PERSONA_SERVER_DB`                  | `./persona-server.db` | 服务器自己的元数据库                                         |
| `PERSONA_SERVER_TOKENS`              | —                     | **多设备令牌**：`"laptop:tok1,phone:tok2"`；非法格式启动即错 |
| `PERSONA_SERVER_TOKEN`               | —                     | legacy 单令牌（视为 "default" 设备）；建议迁移到 TOKENS      |
| `PERSONA_SERVER_BACKUP_DIR`          | `<DB 目录>/backups`   | 备份密文存放目录                                             |
| `PERSONA_SERVER_BACKUP_MAX_VERSIONS` | `0`（不限）           | 每设备保留版本数上限，超限删最旧                             |

**fail-closed**：`TOKENS`/`TOKEN` 都没配时 `/api/v1` 整体禁用（不是裸奔）。

HTTP 端点（除 health/metrics 外全部要求 Bearer 令牌）：

| 端点                  | 方法         | 用途                                            | 请求上限                          |
| --------------------- | ------------ | ----------------------------------------------- | --------------------------------- |
| `/api/v1/events`      | POST         | 上报审计事件批（单批 ≤500 条）                  | 线上 1 MiB（gzip）/ 解压后 10 MiB |
| `/api/v1/events`      | GET          | 查询已存事件（按动作/成败/时间过滤 + 游标分页） | —                                 |
| `/api/v1/backups`     | POST / GET   | 上传备份 / 列版本                               | 256 MiB                           |
| `/api/v1/backups/:id` | GET / DELETE | 下载 / 删除某版本                               | —                                 |
| `/health`、`/metrics` | GET          | 存活与指标                                      | 公开                              |

设备名由命中的令牌推导（客户端不可自报）；同设备与最新版本 sha256 相同
的 push 幂等去重。

### 配置客户端

**桌面应用**（设置 → 同步）：填 server URL + 设备令牌，开关启用。令牌
真值存 OS 钥匙串（service `persona-sync`），数据库里只留空占位——把
`identities.db` 拷到别的机器不会带走令牌，需重新输入。禁用即清钥匙串。

**CLI**：只认环境变量、**故意不落盘**——

```bash
export PERSONA_SERVER_URL="https://your-server:8443"
export PERSONA_SERVER_TOKEN="tok1"          # 与服务器 TOKENS 中某条匹配
export PERSONA_PAYLOAD_PASSPHRASE="..."     # 备份口令（交互输入也行）
persona backup push
```

两个通道**相互独立**：桌面设置页的同步配置只管事件上报；CLI 的 backup
命令只认自己的 env。想在桌面和 CLI 共用一台服务器，两处各配一次。

## 备份与恢复实操

> 备份/恢复目前**仅 CLI**——桌面应用暂无界面入口（桌面设置里的"同步"
> 只管事件上报）。

| 命令                                    | 作用                                       |
| --------------------------------------- | ------------------------------------------ |
| `persona backup push`                   | 快照当前库 → 加密 → 上传（无需解锁主密码） |
| `persona backup list`                   | 列出版本（新→旧，分页）                    |
| `persona backup pull <id> --out f`      | 下载密文到文件（不解密）                   |
| `persona backup restore <id>\|--file f` | 解密复验 → 留 `.bak` → 换库                |
| `persona backup delete <id>`            | 删除服务器上的版本                         |

要点：

- **备份口令与主密码相互独立**。恢复 = 下载密文 + 备份口令解密 + 主密码
  解锁。备份口令丢失 = 该备份永久不可恢复（无托管、无重置）。
- push 设双录确认、restore 不设（口令是既有的）；restore 前自动把现库
  拷为 `identities.bak`。
- **附件文件体不在 v1 备份内**：恢复后附件元数据在、文件体缺失（CLI 与
  桌面均明示此限制）。
- 备份是快照不是增量：恢复把库整体回到备份时刻。

## 网盘目录（iCloud / Dropbox / WebDAV…）

⚠️ **不要把活跃的 `identities.db` 放进云盘同步目录**。SQLite 假定独占
写文件，网盘的双向同步会产生冲突副本与损坏风险——这是最常见的踩坑。

正确姿势：云盘只放**密文成品**——

- `persona export --encrypt` 的导出文件，或
- `persona backup pull` 下载的 `.persenc` 备份密文。

两者都带独立口令，云盘供应商只见密文。代价是手动（或用脚本定时）执行，
以及恢复是整库级的。

（"文件系统同步 adapter"——本地服务监听变更、自动推拉加密 blob——是
[设计稿](./CLIENT_COMMUNICATION_ARCHITECTURE.md)中的未来项，当前未实现。）

## 多设备与 Travel Mode

- 多台设备各自 init、各自独立成库；共享的只有服务器上的备份版本池
  （每台设备用自己的令牌 push，版本按设备归组）。
- 把一台设备的库恢复成另一台的备份 = **整库替换**（含现有数据被
  `.bak` 换下），不是合并。
- [`Travel Mode`](./THREAT_MODEL.md#travel-mode-travelpersenc-sidecar2026-09)
  （`persona travel …` / 桌面设置 → 安全）用于暂时把若干身份**整包移出**
  一台设备（加密 sidecar 随身带走），回来时口令恢复——多设备场景下
  控制单台设备数据暴露面的工具。

## 本机自动化（Connect API）

让本机的脚本 / CI / 命令行工具**只读**读取 vault 条目的 HTTP 接口。默认
关闭；开启后只监听 `127.0.0.1`（端口由系统分配），请求永不离开本机。
详见 [`CONNECT_AUTOMATION_DESIGN.md`](./CONNECT_AUTOMATION_DESIGN.md)
与 [THREAT_MODEL](./THREAT_MODEL.md#connect-本机自动化端点127001-http2026-09-secrets-automation)。

**两步用起来：**

1. 创建 token（明文只展示一次，丢了只能吊销重建）：

   ```bash
   # 桌面：设置 → 安全 → Connect 本机自动化 → 创建 Token
   # CLI（默认授权全部身份的全部可授权类型，只读）：
   persona connect token create --label "我的 CI 脚本"
   # 收窄 scope（给了限定就收窄，缺省 = 全部）：
   persona connect token create --label "deploy" --identity work --type password --type api_key
   ```

2. 启动监听（前台进程，Ctrl-C 退出；桌面版在设置里开关）：

   ```bash
   persona connect serve            # 或 --port 8737 固定端口
   ```

**curl 快速上手**（`$TOKEN` 为创建时保存的 `pconn_…` 明文，`$PORT` 见
serve 启动输出）：

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/health
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/identities
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/items
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/api/v1/connect/items/<id>/totp
```

边界（诚实版）：

- **只读**。写路径不存在；scope 只能收窄不能提权；passkey / wallet /
  SSH 密钥 / 自定义类型**永远不可**经此接口授权。
- token 只存 SHA-256 哈希，列表只见指纹；`persona connect token revoke`
  （id 或指纹均可）即时生效、幂等。
- 限速 120 请求/分钟；vault 锁定时返回 503（锁定不消耗限额）。
- 防线只对本机浏览器侧攻击（恶意网页）有效——**不要**把 token 交给浏览
  器扩展或任何网页可达的存储；本机恶意进程本来就在信任边界之外。

## 故障后果速查

| 场景                 | 后果                 | 能否补救                                         |
| -------------------- | -------------------- | ------------------------------------------------ |
| 主密码丢失           | 库内所有凭据不可解密 | ❌（无托管、无重置）                             |
| 备份口令丢失         | 该备份不可恢复       | ❌（其他版本不受影响）                           |
| 误删身份/凭据        | 本地即删             | ✅ 整库 restore 到旧备份（快照点之后的数据全丢） |
| `identities.db` 损坏 | 本地库不可用         | ✅ restore；但**最后一次 push 之后的变更丢失**   |
| 服务器数据被删/回滚  | 备份版本池受损       | ❌ 不宣称防服务器操作者；本地库仍是第一事实源    |
| Travel sidecar 丢失  | 被移出身份永久丢失   | ❌（THREAT_MODEL「Travel Mode」红色警告场景）    |

原则一句话：**本地库是第一事实源，一切备份手段都只是在别处多放一份
密文**——把"定期 push/export"纳入习惯，其他交给威胁模型里的诚实边界。
