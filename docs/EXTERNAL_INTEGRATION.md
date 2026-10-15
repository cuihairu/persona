# External project integration with Persona (External Integration)

> [English](EXTERNAL_INTEGRATION.md) | [中文](EXTERNAL_INTEGRATION.zh.md)

> **Status: current state (verified live on 2026-10-12)**. Every JSON snippet
> and output in this document comes from a real smoke run (isolated workspace +
> `persona connect serve` + curl), not hand-written illustration. For the design
> background see
> [`CONNECT_AUTOMATION_DESIGN.md`](./CONNECT_AUTOMATION_DESIGN.md); for a short
> quick-reference see
> [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#本机自动化connect-api).

External projects (CI scripts, deploy tools, other local services) read the
Persona vault through exactly one of **two supported interface forms**:

| Form                        | Best for                                                                                                                                                                                                    | Depends on                                |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| **HTTP (Connect API)**      | Cross-process consumers: CI, background services, programs in any language                                                                                                                                  | `persona connect serve` listening + token |
| **CLI (`persona secrets`)** | Shell scripts, Makefiles, Terraform/K8s declarative tooling                                                                                                                                                 | Only the persona CLI on PATH              |
| ~~Library linkage~~         | **Not recommended**: the core crate has no stable API or version promise, and it requires the consumer process to hold the master password in order to unlock — equivalent to handing over the entire vault | —                                         |

The authorization model is identical for both forms: enforcement happens at the
single adjudication point `authorize(principal, resource, action, ctx)` in
`core/src/authz.rs` (verbs `read/use/export/sign`; a Connect token principal can
only be granted `read/use`, and only `read` is exposed over HTTP). export (bulk
plaintext export) and sign (SSH signing) can **never be granted** to a token
principal.

---

## Three-step integration (HTTP form)

### Step 1: issue a token (vault owner action, one-time)

```bash
persona connect token create --label "other-project" \
  --identity ci-project --type password --type totp --expires-in 30d
```

Actual output (the plaintext `pconn_…` is **shown only this once** — if you lose
it, you can only revoke and re-create):

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

**Token issuance and expiry semantics:**

- Only the **SHA-256 hash** is stored; lists and logs show just a 16-hex
  fingerprint, and the plaintext cannot be recovered.
- `--expires-in <N><s|m|h|d>`: the lifetime relative to the current time (e.g.
  `30d`, `12h`, `30m`, `45s`). **Omitted = never expires** — for tokens given
  to external projects, setting it is strongly recommended.
- The argument is parsed **before** master-password unlock: a wrong unit, a
  negative number, or a compound form like `1h30m` fails immediately with
  `Error: invalid duration "1h30m": unknown unit "h30m" (valid: s, m, h, d)`
  and never triggers a passphrase prompt.
- Requests are rejected once expired: after `expires_at` the request gets a 401
  **identical in shape** to an unknown token (verified: `--expires-in 1s`, curl
  three seconds later → 401 `invalid token`).
- Revocation (takes effect immediately, idempotent; accepts **id (UUID) or
  fingerprint (hex)**, never the plaintext):

  ```bash
  persona connect token revoke 20a19e6d-9d42-4851-b2e7-d8da03f9049b   # or 4b322627054123fd
  ```

  Verified: a successful revoke prints
  `✓ Token 67474c13-3496-4f71-a08c-1dc01644b2b7 revoked`, and requests with
  that token get a 401 immediately afterwards.

- `persona connect token list` status column: `active` (green) / `revoked` (red)
  / `expired` (yellow, computed from `expires_at`), with `never used` /
  `last used …` / `revoked at …` and `expires at …` lines.

### Step 2: start the listener (local background, one-time)

```bash
persona connect serve --port 8737        # default --port 0 lets the OS assign; Ctrl-C to exit
```

- Listens only on `127.0.0.1`; requests never leave the machine; the vault must
  be unlocked — in a foreground terminal use `--passphrase-env <VAR>` to specify
  which environment variable to read (it must already be set and non-empty), and
  the desktop app toggles this in Settings. For the full non-interactive unlock
  story see [`NON_INTERACTIVE_MODE.md`](./NON_INTERACTIVE_MODE.md).
- The listener process is decoupled from the consumer process: token validation
  happens per request, and a locked vault returns 503 (see the error code table).

### Step 3: call it (consumer side, any HTTP client)

```bash
TOKEN=pconn_C-LUE7XcPUhlPMdbh6v7Rx_Z6GzrbDqRDqx_DN_1Yrg   # saved in step 1
B=http://127.0.0.1:8737/api/v1/connect

curl -s -H "Authorization: Bearer $TOKEN" $B/health
curl -s -H "Authorization: Bearer $TOKEN" $B/identities
curl -s -H "Authorization: Bearer $TOKEN" $B/items
curl -s -H "Authorization: Bearer $TOKEN" $B/items/<id>
curl -s -X POST -H "Authorization: Bearer $TOKEN" $B/items/<id>/totp
```

**That's all.** There is no registration, no handshake, and no required SDK
beyond the token.

---

## Endpoint reference (verified responses)

Every response carries `content-type: application/json` and
`cache-control: no-store`; success envelopes look like `{"ok":true,"data":…}`,
error envelopes like `{"ok":false,"error":{"code","message"}}`.

### `GET /health` — unauthenticated liveness probe

```json
{ "data": { "service": "persona-connect", "version": "0.1.0" }, "ok": true }
```

Carries no vault information; provided for listener health probing.

### `GET /identities` — identities in scope

```json
{
  "data": [
    { "id": "b5b6b785-08a1-4d30-85cc-b5854915af3e", "name": "ci-project" }
  ],
  "ok": true
}
```

### `GET /items` — items in scope (metadata only)

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

`type` is snake_case. The list contains **no** secret fields.

### `GET /items/{id}` — item detail (with the decrypted secret)

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

Note that the field names inside `data` are **PascalCase** (`Password` /
`ApiKey` / …, serde's default externally tagged representation, no rename_all) —
consumers parsing it should take the key matching the item's type.

### `POST /items/{id}/totp` — compute a TOTP code on demand

```json
{ "data": { "code": "539466", "remaining_seconds": 8 }, "ok": true }
```

---

## 权限边界（token 能拿到的与永远拿不到的）

**三维 scope**：identities × item_types × verbs。`create` 时「缺省 =
全部合法集，给了限定就收窄」。scope 外的条目与不存在的条目返回**同一
404 形**（实测：password-only token 读 totp 条目 → `not_found`，与编造
id 无差别），不泄露存在性。

| 边界       | 语义                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| verbs      | 仅 `read` 可授予且 HTTP 仅暴露 `read`；`use` 已入授权模型但**暂无消费端点**（预留，勿依赖）；`export` / `sign` 对 token 主体不可授予 |
| 类型排除   | ssh-key / crypto-wallet / custom **永不可授权**（不在可授权类型集）；passkey 不走此端点（独立 Unix socket 审批通道）                 |
| 可授权类型 | password / api_key / totp / note / bank_card / server_config / certificate / game_account / identity / software_license              |
| 网络面     | 只监听 `127.0.0.1`；`Host` 头非 `127.0.0.1`/`localhost` → 421；带 `Origin` 头（浏览器侧请求）→ 403                                   |
| 速率       | 每 token 120 请求/分钟（固定窗），超限 429                                                                                           |
| 锁定       | vault 锁定 → 503 `vault_locked`，不消耗限额                                                                                          |
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
| 503  | `vault_locked`     | —                                             | vault 锁定（不耗限额）                   |

重试纪律：401 不要重试（确定性拒绝，去查吊销/到期）；503 可退避重试
（等属主解锁）；429 按分钟窗退避。

## 消费者侧建议（Do / Don't）

- **必做**：token 视同密码——环境变量或 secret 管理器注入，不进 git、
  不进日志、不进任何浏览器/网页可达存储（`Origin` 403 防的是恶意网页，
  不是交钥匙许可）。
- **必做**：给 `--expires-in`，按轮换周期取值；到期后重新发放。
- **建议**：scope 最小化——只给需要的身份与类型（例：deploy 只需要
  `--type password`）。
- **不要**：把 token 交给扩展或远程机器转发（接口只服务本机）。
- **不要**：用 HTTP 形态之外的「库引用」方式接入——core crate 无稳定
  API 承诺，且进程内解锁等于把整个 vault 交给消费者进程。

## 边界之外的形态

- **`persona secrets`（CLI 直读）**：同机 shell/CI 不想起 HTTP 时用。
  引用语法 `IDENTITY/ITEM/FIELD`，四个子命令（run / resolve / k8s /
  terraform-external）见
  [`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md#secrets-自动化cli-直读)。
- **远程 persona-server**：跨机器读取是 **E2EE 同步客户端**领域
  （[`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md) /
  [`REMOTE_AUTH.md`](./REMOTE_AUTH.md)），不是普通 REST——Connect API
  的 token/端点模型**不适用**于远程，勿混用。
- **浏览器扩展**：走 Native Messaging Host 桥（
  [`BRIDGE_PROTOCOL.md`](./BRIDGE_PROTOCOL.md)），**不经** Connect API。

## 开放问题（诚实版）

- `use` 动词的 HTTP 消费端点未实现（授权模型已预留）；写入路径未拍板，
  当前接口**只读**。
- 桌面端创建 token 的入口尚未传 `--expires-in` 等价物（恒永不过期）；
  外部项目请走 CLI 发 token。
