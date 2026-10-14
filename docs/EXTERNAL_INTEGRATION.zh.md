> [English](EXTERNAL_INTEGRATION.md) | **中文**

# 外部项目接入 Persona（External Integration）

> **状态：当前现状（2026-10-12 实测）**。本文每一处 JSON / 输出均来自真实冒烟运行（隔离 workspace + `persona connect serve` + curl），非手写示意。设计背景见 [`CONNECT_AUTOMATION_DESIGN.md`](./CONNECT_AUTOMATION_DESIGN.md)，简版速查见 [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#本机自动化connect-api)。

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
persona connect serve --port 8737        # 默认 --port 0 由 OS 分配；Ctrl-C 退出
```

- 只监听 `127.0.0.1`，请求不出本机；保险库需处于解锁态——前台终端用 `--passphrase-env <VAR>` 指定读哪个环境变量（须已设且非空），桌面版在设置里开关。非交互解锁的完整说明见 [`NON_INTERACTIVE_MODE.md`](./NON_INTERACTIVE_MODE.md)。
- listener 进程与消费者进程解耦：token 校验每请求进行，保险库锁定时返回 503（见错误码表）。

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

| 边界       | 语义                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| verbs      | 仅 `read` 可授予且 HTTP 仅暴露 `read`；`use` 已入授权模型但**暂无消费端点**（预留，勿依赖）；`export` / `sign` 对 token 主体不可授予 |
| 类型排除   | ssh-key / crypto-wallet / custom **永不可授权**（不在可授权类型集）；passkey 不走此端点（独立 Unix socket 审批通道）                 |
| 可授权类型 | password / api_key / totp / note / bank_card / server_config / certificate / game_account / identity / software_license              |
| 网络面     | 只监听 `127.0.0.1`；`Host` 头非 `127.0.0.1`/`localhost` → 421；带 `Origin` 头（浏览器侧请求）→ 403                                   |
| 速率       | 每 token 120 请求/分钟（固定窗），超限 429                                                                                           |
| 锁定       | 保险库锁定 → 503 `vault_locked`，不消耗限额                                                                                          |
| 审计       | 每次 token 校验/拒绝留审计记录；解密路径与桌面/CLI 展示相同                                                                          |

## 错误码表（实测形状）

| HTTP | code               | 实测 message                                  | 触发                                     |
| ---- | ------------------ | --------------------------------------------- | ---------------------------------------- |
| 401  | `unauthorized`     | `missing or malformed bearer token`           | 无/格式错 Authorization 头               |
| 401  | `unauthorized`     | `invalid token`                               | 未知、已吊销、已过期的 token（三者同形） |
| 403  | `origin_forbidden` | `browser-originated requests are not allowed` | 请求带 `Origin` 头                       |
| 404  | `not_found`        | `item not found`                              | 条目不存在 / 已归档 / scope 外（同形）   |
| 421  | `bad_host`         | `host not allowed`                            | `Host` 头非 `127.0.0.1`/`localhost`      |
| 429  | `rate_limited`     | —                                             | 超过 120 req/min                         |
| 503  | `vault_locked`     | —                                             | 保险库锁定（不耗限额）                   |

重试纪律：401 不要重试（确定性拒绝，去查吊销/到期）；503 可退避重试（等属主解锁）；429 按分钟窗退避。

## 消费者侧建议（Do / Don't）

- **必做**：token 视同密码——环境变量或 secret 管理器注入，不进 git、不进日志、不进任何浏览器/网页可达存储（`Origin` 403 防的是恶意网页，不是交钥匙式许可）。
- **必做**：给 `--expires-in`，按轮换周期取值；到期后重新发放。
- **建议**：scope 最小化——只给需要的身份与类型（例：deploy 只需要 `--type password`）。
- **不要**：把 token 交给扩展或远程机器转发（接口只服务本机）。
- **不要**：用 HTTP 形态之外的「库引用」方式接入——core crate 无稳定 API 承诺，且进程内解锁等于把整个保险库交给消费者进程。

## 边界之外的形态

- **`persona secrets`（CLI 直读）**：同机 shell/CI 不想起 HTTP 时用。引用语法 `IDENTITY/ITEM/FIELD`，四个子命令（run / resolve / k8s / terraform-external）见 [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#secrets-自动化cli-直读)。
- **远程 persona-server**：跨机器读取是 **E2EE 同步客户端**领域（[`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md) / [`REMOTE_AUTH.md`](./REMOTE_AUTH.md)），不是普通 REST——Connect API 的 token/端点模型**不适用**于远程，勿混用。
- **浏览器扩展**：走 Native Messaging Host 桥（[`BRIDGE_PROTOCOL.md`](./BRIDGE_PROTOCOL.md)），**不经** Connect API。

## 开放问题（诚实版）

- `use` 动词的 HTTP 消费端点未实现（授权模型已预留）；写入路径未拍板，当前接口**只读**。
- 桌面端创建 token 的入口尚未传 `--expires-in` 等价物（恒永不过期）；外部项目请走 CLI 发 token。
