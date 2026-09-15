# Persona Bridge Protocol v2

Persona Native Messaging Bridge Protocol 用于浏览器扩展与本地 CLI/Desktop 之间的安全通信。

## 概述

浏览器扩展通过 Chrome Native Messaging API 与本地运行的 `persona bridge` 进程通信。该协议支持：

- 状态查询（锁定/解锁状态）
- 自动填充建议获取
- 凭证填充请求
- TOTP 代码获取
- Passkey（WebAuthn）创建/断言/列表（v2 新增）
- 会话管理

## 传输层

### Native Messaging 帧格式

遵循 Chrome Native Messaging 标准：

```
[4 bytes: little-endian length][JSON payload]
```

- 长度字段为 32 位无符号整数（小端序）
- 最大消息大小：10MB（软限制 1MB）
- 编码：UTF-8 JSON

## 消息结构

### 请求格式

```json
{
  "request_id": "uuid-v4",
  "type": "message_type",
  "payload": { ... },
  "auth": { ... }
}
```

| 字段 | 类型 | 必需 | 描述 |
|------|------|------|------|
| `request_id` | string | 否 | 用于关联请求/响应的唯一 ID |
| `type` | string | 是 | 消息类型 |
| `payload` | object | 否 | 类型相关的负载数据 |
| `auth` | object | 否 | 消息认证（配对后，敏感操作必需） |

#### auth 字段（HMAC）

```json
{
  "session_id": "uuid-v4",
  "ts_ms": 1734660000000,
  "nonce": "uuid-v4",
  "signature": "base64url-no-pad"
}
```

| 字段 | 类型 | 必需 | 描述 |
|------|------|------|------|
| `session_id` | string | 是 | 由 `hello_response` 下发的短期会话 ID |
| `ts_ms` | number | 是 | 客户端时间戳（毫秒），服务端用于限制重放窗口 |
| `nonce` | string | 是 | 单次请求随机值 |
| `signature` | string | 是 | `HMAC-SHA256` 签名（base64url 无 padding） |

### 响应格式

```json
{
  "request_id": "uuid-v4",
  "type": "response_type",
  "ok": true,
  "error": null,
  "payload": { ... }
}
```

| 字段 | 类型 | 必需 | 描述 |
|------|------|------|------|
| `request_id` | string | 否 | 对应请求的 ID |
| `type` | string | 是 | 响应类型 |
| `ok` | boolean | 是 | 操作是否成功 |
| `error` | string | 否 | 错误描述（仅当 ok=false） |
| `payload` | object | 否 | 响应数据 |

## 消息类型

### 1. hello - 握手

用于初始化会话并获取服务器能力。

**请求：**
```json
{
  "type": "hello",
  "payload": {
    "extension_id": "abcdefghijklmnopabcdefghijklmnop",
    "extension_version": "1.0.0",
    "protocol_version": 2,
    "client_instance_id": "uuid-v4"
  }
}
```

**响应：**
```json
{
  "type": "hello_response",
  "ok": true,
  "payload": {
    "server_version": "0.1.0",
    "capabilities": ["status", "pairing_request", "pairing_finalize", "get_suggestions", "request_fill", "get_totp", "copy", "passkey_list", "passkey_create", "passkey_assert"],
    "pairing_required": true,
    "paired": false,
    "session_id": null,
    "session_expires_at_ms": null
  }
}
```

> 备注：当已经完成配对时，`pairing_required=false` 且会返回 `session_id`（短期会话，默认 24h）。

### 2. pairing_request - 申请配对码

扩展向本地桥申请一次性配对码（需用户在终端批准）。

**请求：**
```json
{
  "type": "pairing_request",
  "payload": {
    "extension_id": "abcdefghijklmnopabcdefghijklmnop",
    "client_instance_id": "uuid-v4"
  }
}
```

**响应：**
```json
{
  "type": "pairing_response",
  "ok": true,
  "payload": {
    "code": "123-456",
    "expires_at_ms": 1734660600000,
    "approval_command": "persona bridge --approve-code 123-456"
  }
}
```

### 3. pairing_finalize - 完成配对

用户执行 `approval_command` 后，扩展提交配对码完成绑定并获取配对密钥与会话信息。

**请求：**
```json
{
  "type": "pairing_finalize",
  "payload": {
    "extension_id": "abcdefghijklmnopabcdefghijklmnop",
    "client_instance_id": "uuid-v4",
    "code": "123-456"
  }
}
```

**响应：**
```json
{
  "type": "pairing_finalize_response",
  "ok": true,
  "payload": {
    "paired": true,
    "pairing_key_b64": "base64url-no-pad",
    "session_id": "uuid-v4",
    "session_expires_at_ms": 1734746400000
  }
}
```

### 4. status - 状态查询

获取当前解锁状态和活动身份。

**请求：**
```json
{
  "type": "status",
  "payload": {}
}
```

**响应：**
```json
{
  "type": "status_response",
  "ok": true,
  "payload": {
    "locked": false,
    "active_identity": "uuid-v4",
    "active_identity_name": "Work Profile"
  }
}
```

### 5. get_suggestions - 获取建议

根据当前页面 origin 获取匹配的凭证建议。

> 备注：建议默认基于当前 workspace 的 `active_identity_id` 过滤（可通过 `persona switch` 切换）。

**请求：**
```json
{
  "type": "get_suggestions",
  "payload": {
    "origin": "https://github.com",
    "form_type": "login"
  }
}
```

**响应：**
```json
{
  "type": "suggestions_response",
  "ok": true,
  "payload": {
    "suggesting_for": "github.com",
    "items": [
      {
        "item_id": "uuid-v4",
        "title": "GitHub (Work)",
        "username_hint": "user@example.com",
        "match_strength": 100,
        "credential_type": "password"
      }
    ]
  }
}
```

| match_strength | 含义 |
|----------------|------|
| 100 | 精确域名匹配 |
| 90 | 子域名匹配 |
| 80 | 域名包含匹配 |
| 60 | 顶级域名匹配 |

### 6. request_fill - 请求填充

请求特定凭证的实际值用于填充。

**请求：**
```json
{
  "type": "request_fill",
  "payload": {
    "origin": "https://github.com",
    "item_id": "uuid-v4",
    "user_gesture": true
  }
}
```

**响应：**
```json
{
  "type": "fill_response",
  "ok": true,
  "payload": {
    "username": "user@example.com",
    "password": "hunter2"
  }
}
```

**错误码：**
- `locked` - 保险库已锁定
- `not_found` - 凭证不存在
- `origin_mismatch` - 请求 origin 与凭证 URL 不匹配
- `user_confirmation_required` - 需要用户确认
- `authentication_failed` - 认证失败

### 7. get_totp - 获取 TOTP

获取关联凭证的当前 TOTP 代码。

> 注意：为了进行 Origin 绑定，TOTP 条目必须设置 URL（否则返回 `origin_binding_required`）。

**请求：**
```json
{
  "type": "get_totp",
  "payload": {
    "origin": "https://github.com",
    "item_id": "uuid-v4",
    "user_gesture": true
  }
}
```

**响应：**
```json
{
  "type": "totp_response",
  "ok": true,
  "payload": {
    "code": "123456",
    "remaining_seconds": 15,
    "period": 30
  }
}
```

### 8. copy - 复制到剪贴板

请求将特定字段复制到剪贴板（由 CLI/Desktop 执行）。

**请求：**
```json
{
  "type": "copy",
  "payload": {
    "origin": "https://github.com",
    "item_id": "uuid-v4",
    "field": "password",
    "user_gesture": true
  }
}
```

**响应：**
```json
{
  "type": "copy_response",
  "ok": true,
  "payload": {
    "copied": true,
    "clear_after_seconds": 30
  }
}
```

### 9. passkey_list - 列出 Passkey

列出某个 RP（relying party）下的 passkey 摘要（**不含任何密钥材料**，仅非敏感字段）。

**请求：**
```json
{
  "type": "passkey_list",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "rp_id": "example.com"
  }
}
```

> `rp_id` 缺省时按 origin 的 effective domain 推导；显式给出且与 origin 不符时返回 `passkey_rp_mismatch`。

**响应：**
```json
{
  "type": "passkey_list_response",
  "ok": true,
  "payload": {
    "items": [
      {
        "id": "uuid-v4",
        "rp_id": "example.com",
        "user_name": "alice@example.com",
        "user_display_name": "Alice",
        "identity_name": "Personal",
        "created_at": 1730000000
      }
    ]
  }
}
```

### 10. passkey_create - 创建 Passkey

为当前 active identity 在指定 RP 下创建软件 passkey，返回注册产物（attestationObject）。

**请求：**
```json
{
  "type": "passkey_create",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "request_json": {
      "rp": { "id": "example.com", "name": "Example" },
      "user": {
        "id": "b64url-user-handle",
        "name": "alice@example.com",
        "displayName": "Alice"
      },
      "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
    },
    "client_data_json_b64": "b64url-clientDataJSON"
  }
}
```

约定：

- `request_json` 是 `PublicKeyCredentialCreationOptions` 的 JSON 形态，所有 `BufferSource` 字段（`user.id`、`challenge`、`excludeCredentials[].id`）已由扩展序列化为 base64url 字符串
- `pubKeyCredParams` 必须包含 `{type: "public-key", alg: -7}`（ES256），否则返回 `passkey_alg_unsupported`
- `rp.id` 缺省时取 origin 的 effective domain；与 origin 不符时返回 `passkey_rp_mismatch`
- `client_data_json_b64` 是扩展侧构造的原始 clientDataJSON 字节；core 只做 SHA-256 哈希入签，不重组
- 桥接会话刚通过主密码认证，因此落库的 `uv_initialized=true` 属实
- 未设置 active identity 时返回 `no_active_identity`

**响应：**
```json
{
  "type": "passkey_create_response",
  "ok": true,
  "payload": {
    "item_id": "uuid-v4",
    "credential_id_b64": "b64url",
    "attestation_object_b64": "b64url",
    "client_data_json_b64": "b64url（原样回传）",
    "transports": ["internal"]
  }
}
```

### 11. passkey_assert - Passkey 断言

用指定的 passkey 对 ceremony 签名（不允许静默选钥：`item_id` 必填）。

**请求：**
```json
{
  "type": "passkey_assert",
  "payload": {
    "origin": "https://example.com",
    "user_gesture": true,
    "item_id": "uuid-v4",
    "client_data_json_b64": "b64url-clientDataJSON",
    "user_verification": true
  }
}
```

约定：

- `item_id` 缺省直接拒绝——扩展侧的选择 UI 必须让用户显式点选，即使只有单个候选
- `user_verification` 缺省 `true`；扩展将 WebAuthn 的 `discouraged` 映射为 `false`
- passkey 不存在返回 `passkey_item_not_found`；属于其他 identity 返回 `wrong_identity`
- origin 与 rp_id 不符返回 `passkey_rp_mismatch`

**响应：**
```json
{
  "type": "passkey_assert_response",
  "ok": true,
  "payload": {
    "item_id": "uuid-v4",
    "credential_id_b64": "b64url",
    "authenticator_data_b64": "b64url",
    "signature_der_b64": "b64url",
    "user_handle_b64": "b64url"
  }
}
```

> 签名对象为 `authenticatorData ‖ SHA-256(clientDataJSON)`，签名算法 ES256，输出 DER 编码。

## 安全机制

### Origin 绑定

所有涉及敏感数据的请求必须包含 `origin` 字段：

1. 扩展从 `window.location.origin` 获取当前页面 origin
2. CLI 验证 origin 与凭证 URL（或 passkey 的 rp_id）是否匹配
3. 不匹配时返回 `origin_mismatch`（凭证类）或 `passkey_rp_mismatch`（passkey 类）错误

### User Gesture 要求

`request_fill` / `get_totp` / `copy` / `passkey_*` 操作要求：

1. 必须由用户明确操作触发（点击、键盘快捷键）
2. 请求中应包含 `user_gesture: true` 表示这是用户主动操作（passkey 由扩展在 MAIN world 拦截点同步读取 `navigator.userActivation.isActive`）
3. CLI 可配置对未确认的请求要求桌面通知确认（见下节）

### 桌面审批（Passkey 确认闸门）

`passkey_create` / `passkey_assert` 在桌面应用运行时可要求第二道确认——独立于扩展的
user gesture 自报，扩展被攻破也无法静默签名（威胁模型见 `PASSKEYS_DESIGN.md` §10）。

**传输**：bridge（每个请求的短命进程）作为客户端连接 Unix domain socket
`<agent state dir>/passkey-approval.sock`（默认 `~/.persona/passkey-approval.sock`，
可用 `PERSONA_PASSKEY_APPROVAL_SOCKET` 覆盖；权限 0600）。一请求一连接、JSON 行协议：

请求（bridge → 桌面）：

```json
{"v":1,"op":"passkey_assert","rp_id":"github.com","origin":"https://github.com","user_name":"alice","item_id":"<uuid>"}
```

- `op` 仅接受 `passkey_create` / `passkey_assert`；`passkey_list` 非敏感不走审批

响应（桌面 → bridge）：

```json
{"approved":true}
{"approved":false,"reason":"denied"}
```

- `reason` 取值：`denied`（用户/前端拒绝）、`timeout`（桌面 120s 无应答；bridge 侧
  150s 兜底断开）、`locked`（桌面已锁定，直接拒绝不弹窗）、`unsupported`（坏 JSON /
  未知版本 / 未知 op）

**开关** `PERSONA_BRIDGE_DESKTOP_APPROVAL`（默认 `auto`）：

| 值 | 行为 |
| --- | --- |
| `auto` | socket 存在 → 必须桌面批准；桌面未运行/连接失败 → 现有行为（gesture 闸门照旧） |
| `require` | 策略强制：socket 不在也拒绝该 passkey 请求（fail closed） |
| `off` | 永不询问 |

拒绝时 bridge 对该请求返回错误 `passkey request denied by desktop approval (<reason>)`。

此协议是本地实现细节，不占用桥接协议版本号（`protocol_version` 保持 2；v3 的方向
见 `CLIENT_COMMUNICATION_ARCHITECTURE.md`）。

### 会话管理（可选）

当 `pairing_required: true` 时（默认开启，可用 `PERSONA_BRIDGE_REQUIRE_PAIRING=0` 关闭）：

1. 扩展首次连接时需要完成配对流程（`pairing_request` → 用户批准 → `pairing_finalize`）
2. 配对成功后生成配对密钥（扩展本地保存），并下发短期会话（默认 24 小时）
3. 对于敏感操作（建议/填充/TOTP/复制），扩展必须携带 `auth`（HMAC）字段
4. 本地桥持久化配对状态到 `~/.persona/bridge/state.json`（可通过 `--state-dir` 覆盖）

#### HMAC 签名输入

对每个需认证的请求，计算：

```
<type>\n<request_id>\n<payload_json>\n<session_id>\n<ts_ms>\n<nonce>
```

- `payload_json` 使用“键排序后的 JSON”序列化（canonical JSON）
- `signature = base64url_no_pad(HMAC_SHA256(pairing_key, signing_input))`

### 敏感操作确认

可通过策略配置要求以下操作需要用户确认：

- `confirm_on_unknown_origin` - 未知域名首次请求
- `confirm_on_fill` - 每次填充都需确认
- `require_biometric` - 敏感操作需要生物识别

## 审计日志

所有操作都会记录到审计日志：

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event": "bridge_fill_request",
  "origin": "https://github.com",
  "item_id": "uuid-v4",
  "result": "success",
  "extension_id": "chrome-extension://xxx"
}
```

## 错误处理

### 通用错误响应

```json
{
  "type": "error",
  "ok": false,
  "error": "error_code: Human readable message",
  "payload": null
}
```

### 错误码列表

| 错误码 | 描述 |
|--------|------|
| `invalid_json` | JSON 解析失败 |
| `unknown_type` | 未知的消息类型 |
| `locked` | 保险库已锁定，需要解锁 |
| `not_found` | 请求的资源不存在 |
| `origin_mismatch` | Origin 不匹配 |
| `origin_binding_required` | 条目未设置 URL，无法进行 Origin 绑定 |
| `authentication_failed` | 认证失败 |
| `wrong_identity` | 当前 active identity 不匹配 |
| `user_confirmation_required` | 需要用户确认 |
| `session_expired` | 会话已过期 |
| `rate_limited` | 请求过于频繁 |
| `user_gesture_required` | 缺少用户手势（v2） |
| `no_active_identity` | 未设置 active identity（v2） |
| `passkey_rp_mismatch` | origin 与 passkey 的 rp_id 不符（v2） |
| `passkey_alg_unsupported` | pubKeyCredParams 不含 ES256（v2） |
| `passkey_item_not_found` | 指定的 passkey 不存在（v2） |
| `passkey_origin_mismatch` | passkey origin 校验失败（预留）（v2） |

## 配置

### 环境变量

| 变量 | 描述 | 默认值 |
|------|------|--------|
| `PERSONA_MASTER_PASSWORD` | 主密码（自动化场景） | - |
| `PERSONA_DB_PATH` | 数据库路径 | `~/.persona/identities.db` |
| `PERSONA_BRIDGE_STATE_DIR` | Bridge 状态目录（pairing/session） | `~/.persona/bridge` |
| `PERSONA_BRIDGE_REQUIRE_PAIRING` | 是否强制 pairing + HMAC | `true` |
| `PERSONA_BRIDGE_REQUIRE_GESTURE` | 是否强制 user_gesture（fill/totp/copy） | `true` |
| `PERSONA_BRIDGE_AUTH_MAX_SKEW_MS` | HMAC 时间戳最大偏移（防重放） | `300000` |

### CLI 参数

```bash
persona bridge [OPTIONS]

OPTIONS:
    --db-path <PATH>    指定数据库路径
    --approve-code <C>  批准配对码（执行后退出）
    --state-dir <PATH>  配对状态目录（默认 ~/.persona/bridge）
```

## Native Host Manifest

### macOS

位置（按浏览器）：

- Chrome: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.persona.native.json`
- Chromium: `~/Library/Application Support/Chromium/NativeMessagingHosts/com.persona.native.json`
- Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.persona.native.json`
- Edge: `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.persona.native.json`

```json
{
  "name": "com.persona.native",
  "description": "Persona Password Manager Bridge",
  "path": "/path/to/persona-bridge-wrapper",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://YOUR_EXTENSION_ID/"
  ]
}
```

### Linux

位置（按浏览器）：

- Chrome: `~/.config/google-chrome/NativeMessagingHosts/com.persona.native.json`
- Chromium: `~/.config/chromium/NativeMessagingHosts/com.persona.native.json`
- Brave: `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.persona.native.json`
- Edge: `~/.config/microsoft-edge/NativeMessagingHosts/com.persona.native.json`

manifest 结构同上。

### Windows

注册表键（默认值为 manifest 文件路径）：

`HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.persona.native`

示例默认值：

`C:\Users\<YOU>\AppData\Local\Persona\native-messaging\com.persona.native.json`

manifest 文件内容示例：

```json
{
  "name": "com.persona.native",
  "description": "Persona Password Manager Bridge",
  "path": "C:\\Program Files\\Persona\\persona.exe",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://YOUR_EXTENSION_ID/"
  ]
}
```

## 版本兼容性

| Protocol Version | CLI Version | 功能 |
|------------------|-------------|------|
| 1 | 0.1.0+ | hello/status/pairing_request/pairing_finalize + HMAC auth + get_suggestions/request_fill/get_totp/copy |
| 2 | 0.1.0+ | v1 全部 + passkey_list/passkey_create/passkey_assert（软件 passkey 轨道） |
| 3 (计划) | - | biometric confirmation + richer policy prompts |

> v2 未改变帧格式与 HMAC 签名规则，只是新增消息类型并升级 `protocol_version`；v1 扩展对 v2 桥接发送的未知消息仍会得到 `unknown_type`，向后兼容。

## 安装脚本

- macOS / Linux: `scripts/native-messaging/install-native-host.sh <EXTENSION_ID>`
- Windows: `scripts/native-messaging/install-native-host.ps1 -ExtensionId <EXTENSION_ID>`

## 参考

- [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [1Password Browser Extension Architecture](https://support.1password.com/getting-started-browser/)
