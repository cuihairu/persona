> [English](EXTERNAL_INTEGRATION.md) | **中文**

# 外部项目接入 Persona（External Integration）

> **状态：当前现状（2026-10-12 实测）**。本文每一处 JSON / 输出均来自真实冒烟运行（隔离 workspace + `persona connect serve` + curl），非手写示意。设计背景见 [`CONNECT_AUTOMATION_DESIGN.md`](./CONNECT_AUTOMATION_DESIGN.md)，简版速查见 [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#local-automation-connect-api)。

外部项目（CI 脚本、deploy 工具、其他本地服务）读取 Persona 保险库的**正式接口形态二选一**：

| 形态                         | 适合                                                                                                 | 依赖                                   |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------- |
| **HTTP（Connect API）**      | 跨进程消费者：CI、后台服务、任何语言的程序                                                           | `persona connect serve` 监听中 + token |
| **CLI（`persona secrets`）** | shell 脚本、Makefile、Terraform/K8s 声明式工具                                                       | 仅 persona CLI 在 PATH                 |
| ~~库引用~~                   | **不推荐**：core crate 无稳定 API/版本承诺，且要求消费者进程拿到主密码才能解锁——等价于交出整个保险库 | —                                      |

权限模型对两种形态一致：授权由 `core/src/authz.rs` 的统一裁决点 `authorize(principal, resource, action, ctx)` 执行（动词 `read/use/export/sign`；Connect token 主体只能拿到 `read/use`，经 HTTP 只暴露 `read`）。export（明文批量导出）与 sign（SSH 签名）对 token 主体**不可授予**。

---

## 三步接入（HTTP 形态）

### 第 1 步：发 token（保险库属主操作，一次性）

```bash
persona connect token create --label "other-project" \
  --identity ci-project --type password --type totp --expires-in 30d
```

实测输出（明文 `pconn_…` **只展示这一次**，丢了只能吊销重建）：

```
🔑 Connect token created
pconn_C-LUE7XcPUhlPMdbh6v7Rx_Z6GzrbDqRDqx_DN_1Yrg
⚠️  Copy it now — the plaintext is shown only once and cannot be recovered.
   label:      other-project
   id:         20a19e6d-9d42-4851-b2e7-d8da03f9049b
   fingerprint: 4b322627054123fd
   scope:      1 identity · password,totp · read-only
   expires at: 2026-11-11T15:09:47.568039674+00:00
```

**令牌发放与到期语义：**

- 存储只落 **SHA-256 哈希**；列表与日志只见 16 hex 指纹，明文不可恢复。
- `--expires-in <N><s|m|h|d>`：相对当前时刻的存活期（如 `30d`、`12h`、`30m`、`45s`）。**缺省 = 永不过期**——给外部项目的 token 强烈建议必设。
- 参数在主密码解锁**之前**解析：写错单位/负数/`1h30m` 这类复合式直接报 `Error: invalid duration "1h30m": unknown unit "h30m" (valid: s, m, h, d)`，不触发密码提示。
- 到期即拒：`expires_at` 过后请求得与未知 token **同形**的 401（实测 `--expires-in 1s` 三秒后 curl → 401 `invalid token`）。
- 吊销（即时生效、幂等；收 **id（UUID）或指纹（hex）**，不收明文）：

  ```bash
  persona connect token revoke 20a19e6d-9d42-4851-b2e7-d8da03f9049b   # 或 4b322627054123fd
  ```

  实测：revoke 成功输出 `✓ Token 67474c13-3496-4f71-a08c-1dc01644b2b7 revoked`，随后该 token 的请求立刻 401。

- `persona connect token list` 状态列：`active`（绿）/ `revoked`（红）/ `expired`（黄，按 `expires_at` 现算），附 `never used` / `last used …` / `revoked at …` 与 `expires at …` 行。

### 第 2 步：起 listener（本机后台，一次性）

```bash
persona connect serve --port 8737        # 默认 loopback TCP：--port 0 由 OS 分配；Ctrl-C 退出
persona connect serve --unix-socket      # Unix domain socket（unix 平台）：$XDG_RUNTIME_DIR/persona/connect.sock
persona connect serve --unix-socket /run/user/1000/p.sock   # 显式 socket 路径
```

两种传输，二选一：

- **loopback TCP（默认）**：只监听 `127.0.0.1`，请求不出本机。`--port` 仅对
  此传输生效（`--port` 与 `--unix-socket` 同给是错误——unix socket 没有 TCP 端口）。
- **Unix domain socket**（`--unix-socket`，unix 平台；Windows 上报错并给出
  TCP 替代指引）：socket 文件 `0600`，**且**每个接受的连接在 accept 层核对
  socket 属主 uid（`SO_PEERCRED`，异 uid 连接在进入 HTTP 解析前即被丢弃）。
  不开端口。`Host` 白名单不适用于 socket 路径（无 DNS rebinding 面——文件
  路径不可被域名解析）；`Origin`、token、限额三条防线在两种传输上原样生效。

保险库需处于解锁态——前台终端用 `--passphrase-env <VAR>` 指定读哪个环境变量
（须已设且非空），桌面版在设置里开关。非交互解锁的完整说明见
[`NON_INTERACTIVE_MODE.md`](./NON_INTERACTIVE_MODE.md)。

- listener 进程与消费者进程解耦：token 校验每请求进行，保险库锁定时返回 503（见错误码表）。

#### 可选：以 systemd 用户单元运行

`connect serve` 刻意保持前台命令形态——不做 daemon 化（DR-1，见
[`CONNECT_AUTOMATION_DESIGN.zh.md`](./CONNECT_AUTOMATION_DESIGN.zh.md)：
解锁态只存在于宿主进程内）。要随登录会话自启，systemd 用户单元**由你自己
配置**；以下是设计文档承诺的示例：

```ini
# ~/.config/systemd/user/persona-connect.service
[Unit]
Description=Persona Connect API (local automation endpoint)

[Service]
# 工作区命令是 local-by-default：需要当前目录有 config.toml（或显式
# --config）。把 cwd 指向你用 `persona init` 初始化过的工作区。
WorkingDirectory=%h/.persona
# 解锁用的主密码——只有一个变量，绝不进命令行：
#   printf '%s\n' 'PERSONA_MASTER_PASSWORD=...' > ~/.config/persona-connect.env
#   chmod 600 ~/.config/persona-connect.env
# 前导 '-' 让 systemd 对缺失文件不报错；若密码最终不可得，serve 在解锁处
# 失败退出（无 TTY 可交互提示）。
EnvironmentFile=-%h/.config/persona-connect.env
# 按 `persona` 实际安装位置调整。
ExecStart=%h/.local/bin/persona connect serve --unix-socket
# systemd stop 发 SIGTERM → 优雅关停：listener 任务收尾、socket 文件移除、
# 退出码 0。只对崩溃重启；RestartSec 防止密码错误变成紧密重启循环。
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now persona-connect.service
systemctl --user stop persona-connect.service   # 优雅关停：socket 文件已移除
```

行为注记：

- **先绑定后解锁**：单元一起来 `/health` 即可探测，数据面在 argon2 解锁
  完成（数秒）前如实返回 `503 vault_locked`。消费者按「保险库已锁定」处理
  即可——退避重试（见错误码表）。
- `--unix-socket` 绑定 `$XDG_RUNTIME_DIR/persona/connect.sock`（systemd
  用户单元自带 `XDG_RUNTIME_DIR`）；socket 文件 `0600`，**且**每个接受的
  连接在 accept 层核对属主 uid——不开 TCP 端口。
- 崩溃留下的陈旧 socket（SIGKILL、OOM）自愈：下次启动接管。正常停止——
  含 `systemctl --user stop`——会移除该文件。
- headless 主机：`loginctl enable-linger $USER` 让单元在无交互登录时也运行；
  此时密码必须来自 `EnvironmentFile`（没有 TTY 可提示）。

经 socket 调用：

```bash
curl -s --unix-socket "$XDG_RUNTIME_DIR/persona/connect.sock" \
  -H "Authorization: Bearer $TOKEN" http://localhost/api/v1/connect/health
```

### 第 3 步：调用（消费者侧，任何 HTTP 客户端）

```bash
TOKEN=pconn_C-LUE7XcPUhlPMdbh6v7Rx_Z6GzrbDqRDqx_DN_1Yrg   # 第 1 步保存
B=http://127.0.0.1:8737/api/v1/connect

curl -s -H "Authorization: Bearer $TOKEN" $B/health
curl -s -H "Authorization: Bearer $TOKEN" $B/identities
curl -s -H "Authorization: Bearer $TOKEN" $B/items
curl -s -H "Authorization: Bearer $TOKEN" $B/items/<id>
curl -s -X POST -H "Authorization: Bearer $TOKEN" $B/items/<id>/totp
```

**就这些。** token 之外无注册、无握手、无 SDK 必需品。

---

## 端点参考（实测响应）

所有响应带 `content-type: application/json` 与 `cache-control: no-store`；成功包络 `{"ok":true,"data":…}`，错误包络 `{"ok":false,"error":{"code","message"}}`。

### `GET /health` — 免认证存活探针

```json
{ "data": { "service": "persona-connect", "version": "0.1.0" }, "ok": true }
```

不携带任何保险库信息，供监听探活。

### `GET /identities` — scope 内身份列表

```json
{
  "data": [
    { "id": "b5b6b785-08a1-4d30-85cc-b5854915af3e", "name": "ci-project" }
  ],
  "ok": true
}
```

### `GET /items` — scope 内条目列表（仅元数据）

```json
{
  "data": [
    {
      "id": "d4ac3439-c311-4454-ac49-a669c0034a9e",
      "title": "Deploy dashboard 2FA",
      "type": "totp",
      "updated_at": "2026-10-12T15:09:40.314861814+00:00",
      "urls": []
    },
    {
      "id": "134a2c8e-e129-486e-8b09-31b85eefc954",
      "title": "Deploy dashboard login",
      "type": "password",
      "updated_at": "2026-10-12T15:09:18.610407644+00:00",
      "urls": ["https://dash.example.com/login"]
    }
  ],
  "ok": true
}
```

`type` 为 snake_case。列表**不含**秘密字段。

### `GET /items/{id}` — 条目详情（含解密后的秘密）

```json
{
  "data": {
    "data": {
      "Password": {
        "email": null,
        "password": "smoke-secret-9f8e7d6c",
        "security_questions": []
      }
    },
    "id": "134a2c8e-e129-486e-8b09-31b85eefc954",
    "title": "Deploy dashboard login",
    "type": "password",
    "updated_at": "2026-10-12T15:09:18.610407644+00:00",
    "urls": ["https://dash.example.com/login"],
    "username": "deploy-bot"
  },
  "ok": true
}
```

注意 `data` 内字段名为 **PascalCase**（`Password` / `ApiKey` / …，serde 默认外部标签，无 rename_all）——消费者解析时按下条目类型取对应键。

### `POST /items/{id}/totp` — 现算 TOTP 验证码

```json
{ "data": { "code": "539466", "remaining_seconds": 8 }, "ok": true }
```

---

## 权限边界（token 能拿到的与永远拿不到的）

**三维 scope**：identities × item_types × verbs。`create` 时「缺省 = 全部合法集，给了限定就收窄」。scope 外的条目与不存在的条目返回**同一 404 形**（实测：password-only token 读 totp 条目 → `not_found`，与编造 id 无差别），不泄露存在性。

| 边界       | 语义                                                                                                                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| verbs      | 仅 `read` 可授予且 HTTP 仅暴露 `read`；`use` 已入授权模型但**暂无消费端点**（预留，勿依赖）；`export` / `sign` 对 token 主体不可授予                                                     |
| 类型排除   | ssh-key / crypto-wallet / custom **永不可授权**（不在可授权类型集）；passkey 不走此端点（独立 Unix socket 审批通道）                                                                     |
| 可授权类型 | password / api_key / totp / note / bank_card / server_config / certificate / game_account / identity / software_license                                                                  |
| 网络面     | TCP 传输：只监听 `127.0.0.1`，`Host` 头非 `127.0.0.1`/`localhost` → 421；Unix 传输：不开端口，socket 文件 `0600` + accept 层属主 uid 核对。两种传输下带 `Origin` 头（浏览器侧请求）→ 403 |
| 速率       | 每 token 120 请求/分钟（固定窗），超限 429                                                                                                                                               |
| 锁定       | 保险库锁定 → 503 `vault_locked`，不消耗限额                                                                                                                                              |
| 审计       | 每次 token 校验/拒绝留审计记录；解密路径与桌面/CLI 展示相同                                                                                                                              |

## 错误码表（实测形状）

| HTTP | code               | 实测 message                                  | 触发                                                                           |
| ---- | ------------------ | --------------------------------------------- | ------------------------------------------------------------------------------ |
| 401  | `unauthorized`     | `missing or malformed bearer token`           | 无/格式错 Authorization 头                                                     |
| 401  | `unauthorized`     | `invalid token`                               | 未知、已吊销、已过期的 token（三者同形）                                       |
| 403  | `origin_forbidden` | `browser-originated requests are not allowed` | 请求带 `Origin` 头                                                             |
| 404  | `not_found`        | `item not found`                              | 条目不存在 / 已归档 / scope 外（同形）                                         |
| 421  | `bad_host`         | `host not allowed`                            | `Host` 头非 `127.0.0.1`/`localhost`（仅 TCP 传输；unix socket 上该检查不生效） |
| 429  | `rate_limited`     | —                                             | 超过 120 req/min                                                               |
| 503  | `vault_locked`     | —                                             | 保险库锁定（不耗限额）                                                         |

重试纪律：401 不要重试（确定性拒绝，去查吊销/到期）；503 可退避重试（等属主解锁）；429 按分钟窗退避。

## 消费者侧建议（Do / Don't）

- **必做**：token 视同密码——环境变量或 secret 管理器注入，不进 git、不进日志、不进任何浏览器/网页可达存储（`Origin` 403 防的是恶意网页，不是交钥匙式许可）。
- **必做**：给 `--expires-in`，按轮换周期取值；到期后重新发放。
- **建议**：scope 最小化——只给需要的身份与类型（例：deploy 只需要 `--type password`）。
- **不要**：把 token 交给扩展或远程机器转发（接口只服务本机）。
- **不要**：用 HTTP 形态之外的「库引用」方式接入——core crate 无稳定 API 承诺，且进程内解锁等于把整个保险库交给消费者进程。

## 边界之外的形态

- **`persona secrets`（CLI 直读）**：同机 shell/CI 不想起 HTTP 时用。引用语法 `IDENTITY/ITEM/FIELD`，四个子命令（run / resolve / k8s / terraform-external）见 [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#secrets-automation-direct-cli-read)。
- **远程 persona-server**：跨机器读取是 **E2EE 同步客户端**领域（[`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md) / [`REMOTE_AUTH.md`](./REMOTE_AUTH.md)），不是普通 REST——Connect API 的 token/端点模型**不适用**于远程，勿混用。
- **浏览器扩展**：走 Native Messaging Host 桥（[`BRIDGE_PROTOCOL.md`](./BRIDGE_PROTOCOL.md)），**不经** Connect API。

## 开放问题（诚实版）

- `use` 动词的 HTTP 消费端点未实现（授权模型已预留）；写入路径未拍板，当前接口**只读**。
- 桌面端创建 token 的入口尚未传 `--expires-in` 等价物（恒永不过期）；外部项目请走 CLI 发 token。
