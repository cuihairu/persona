# Persona SSH Agent - Feature Reference

> [English](SSH_AGENT_FEATURES.md) | [中文](SSH_AGENT_FEATURES.zh.md)

## Overview

Persona SSH Agent is a developer-friendly SSH agent implementation that stores SSH keys securely in the Persona encrypted vault, with enterprise-grade policy controls and biometric authentication.

## Features

### 1. SSH Agent Protocol Support

- **SSH Agent Protocol**: Full implementation of the core SSH Agent protocol subset
  - `SSH_AGENTC_REQUEST_IDENTITIES` (11): lists all available SSH keys
  - `SSH_AGENTC_SIGN_REQUEST` (13): sign data
  - `SSH_AGENT_IDENTITIES_ANSWER` (12): return the key list
  - `SSH_AGENT_SIGN_RESPONSE` (14): return the signature result
  - `SSH_AGENT_FAILURE` (5): failure response

- **Signature algorithms**:
  - ed25519 (sign/verify, `ed25519-dalek`)
  - RSA `rsa-sha2-256`/`rsa-sha2-512` (RFC 8332, dispatched per client flags)
  - ECDSA P-256 (`ecdsa-sha2-nistp256`, RFC 6979 deterministic signatures)

### 2. Cross-Platform Transport

- **UNIX domain socket** (macOS/Linux):
  - Default path: `persona-ssh-agent-<pid>.sock` under the system temp directory
  - The agent writes its actual listen address to `PERSONA_AGENT_STATE_DIR/ssh-agent.sock`
    and the process PID to `PERSONA_AGENT_STATE_DIR/ssh-agent.pid`
  - The listen address can be overridden via the `PERSONA_AGENT_SOCKET_PATH` environment variable

- **Windows named pipe** (Windows):
  - Default name: `persona-ssh-agent-<pid>`
  - Full cross-platform abstraction layer (`AgentStream`, `AgentListener`)

- **Automatic platform detection**: picks the right transport based on the target OS

### 3. Key Management

- **Loading keys from the Persona vault**:
  - Automatically loads all `CredentialType::SshKey` credentials from the encrypted database
  - Unlock with the master password (via the `PERSONA_MASTER_PASSWORD` environment variable)
  - Handles the locked state gracefully

- **Key formats**:
  - Public key: OpenSSH format (`ssh-ed25519 AAAAC3... comment`, etc.)
  - Private key: the vault convention is a Base64-encoded ed25519 seed (32 bytes); imported
    OpenSSH PEM private keys (ed25519/RSA/ECDSA) have their raw components extracted at load time
  - Automatically converted to the binary format required by the SSH Agent protocol

- **Key type display** (2026-10-07):
  - List/detail views compute the algorithm name, SHA256 fingerprint, and bit-size/curve label
    on the fly from the public key metadata (`ssh-keygen -l` style): ED25519→`256`, RSA→modulus
    bit length, ECDSA→curve names such as `P-256`, DSA→prime bit length; SK hardware keys follow
    their internal algorithm, and containers such as certificates are not shown
  - Import, generation, and in-vault list all share one parsing path, so the display is consistent

### 4. Policy System

#### 4.1 TOML-Based Configuration

Config file location:

- Default: `~/.persona/agent-policy.toml`
- Custom: point at another file via the `PERSONA_AGENT_POLICY_FILE` environment variable

#### 4.2 Global Policy (GlobalPolicy)

```toml
[global]
# 每次签名都要求用户确认
require_confirm = false

# 最小签名间隔(毫秒)
min_interval_ms = 0

# 强制检查 known_hosts
enforce_known_hosts = false

# 对未知主机提示确认
confirm_on_unknown_host = false

# 每小时最大签名次数(0 = 无限制)
max_signatures_per_hour = 0

# 紧急锁定模式(拒绝所有签名)
deny_all = false
```

#### 4.3 Per-Key Policy (KeyPolicy)

`key_policies` is a map-of-table keyed by credential_id (**not** a `[[key_policies]]`
array of tables — the array format is not parsed, and the affected keys silently fall
back to the default policy):

```toml
[key_policies."12345678-1234-5678-1234-567812345678"]
enabled = true
allowed_hosts = ["github.com", "gitlab.com", "*.company.com"]
denied_hosts = []
require_confirm = false
require_biometric = false
max_uses_per_day = 100
allowed_time_range = "09:00-18:00"  # 仅在工作时间允许
```

Features:

- **Host restrictions**: allow/deny specific hosts (glob patterns supported)
- **Time windows**: restrict the time window during which keys may be used
- **Usage limits**: daily maximum uses
- **Authentication requirements**: require confirmation or biometric authentication

#### 4.4 Per-Host Policy (HostPolicy)

`host_policies` is also a map-of-table, keyed by hostname (glob patterns supported):

```toml
[host_policies."prod-*.company.com"]
enabled = true
allowed_keys = []  # 空 = 允许所有密钥
require_confirm = true
max_connections_per_hour = 20
```

Features:

- **Key whitelist**: restrict a given host to the designated keys
- **Connection limits**: maximum connections per hour
- **Glob patterns**: wildcard hostname matching

#### 4.5 Policy Evaluation Order

```
1. 全局 deny_all (最高优先级)
2. 速率限制检查
3. 每密钥策略检查
4. 每主机策略检查
5. 认证要求判定: Biometric > Confirm > Allow
```

### 5. Biometric Authentication

#### 5.1 Platform Support

- **macOS**: Touch ID (the current implementation always selects Touch ID; the Face ID check is a stub and not wired in)
- **Windows**: Windows Hello
- **Linux**: polkit authentication (`auth_self` gate)
- **Platform mapping**: picks the matching biometric type for the compile-time target platform

#### 5.2 Authentication Flow

```rust
1. 策略检查 → require_biometric = true
2. 检查生物识别可用性
   ├─ 可用 → 执行生物识别认证
   │         ├─ 成功 → 允许签名
   │         └─ 失败 → 拒绝签名
   └─ 不可用 → 降级到手动确认
               ├─ 用户确认 → 允许签名
               └─ 用户拒绝 → 拒绝签名
```

#### 5.3 Integration

- Abstracted behind the `BiometricProvider` trait
- Built-in `MockBiometricProvider` defaults to `available=true` / `force_fail=false` (core/src/auth/biometric.rs:49-57)
- When no real platform implementation is injected (provider unavailable), it degrades to manual confirmation rather than refusing the signature outright (agents/ssh-agent/src/lib.rs:304-325, consistent with the §5.2 flow)
- Desktop and mobile apps can inject real platform-specific implementations

### 6. Rate Limiting

A multi-layered rate limiting mechanism:

1. **Global minimum interval** (`min_interval_ms`):
   - Minimum time between any two signatures
   - Thwarts brute-force attacks

2. **Global hourly cap** (`max_signatures_per_hour`):
   - Maximum signatures allowed per hour
   - Timestamps older than 1 hour are purged automatically

3. **Per-key daily cap** (`max_uses_per_day`):
   - Maximum uses per key per day
   - Resets automatically every 24 hours

4. **Per-host hourly cap** (`max_connections_per_hour`):
   - Maximum connections per host per hour
   - Resets automatically every hour

### 7. Audit Log

- **Signature auditing**: records every signing operation
  - Action type: `ssh_sign` (custom audit action)
  - Resource type: `Credential`
  - Metadata: SHA-256 hash of the signed data
  - Linked to: identity_id, credential_id
  - Timestamp: recorded automatically

- **Persistence**: stored in the `audit_log` table of the Persona database

### 8. Security Features

#### 8.1 Confirmation Prompts

- **Interactive confirmation**:
  - Prefers `/dev/tty` (Unix)
  - Falls back to stdin/stdout
  - Shows the target host information

- **Prompt text**:
  ```
  Allow SSH signature for host 'github.com'? [y/N]
  ```

#### 8.2 Known Hosts Verification

- **Environment variables**:
  - `PERSONA_AGENT_ENFORCE_KNOWN_HOSTS`: enforce the check
  - `PERSONA_AGENT_CONFIRM_ON_UNKNOWN`: prompt for confirmation on unknown hosts
  - `PERSONA_KNOWN_HOSTS_FILE`: custom known_hosts file path

- **Default path**: `~/.ssh/known_hosts`

### 9. Test Coverage

#### 9.1 Unit Tests (78)

Distribution by module: `policy.rs` 30, `lib.rs` 37, `transport.rs` 5, `daemon.rs` 3,
`approval.rs` 3. Covers default-policy allow, `deny_all` emergency lock, rate limits
(interval/hourly/daily/per-host), per-key and per-host policies, glob matching, time-window
limits, known_hosts enforcement and unknown-host confirmation, TOML and environment-variable
policy loading with fallback, and similar.

#### 9.2 Integration Tests (13)

**Protocol/E2E** (`agents/ssh-agent/tests/e2e_test.rs`, 10 tests):

- `test_ssh_protocol_format`: SSH protocol encoding/decoding
- `test_ed25519_public_key_encoding`: ed25519 public key encoding
- `test_ssh_agent_message_types`: SSH Agent message type constants
- `test_policy_config_format`: TOML policy config parsing
- `test_read_ssh_string_function`: SSH string reading
- `test_identities_answer_format`: SSH_AGENT_IDENTITIES_ANSWER message format
- Also covers agent subprocess round-trip and `sign_request` encoding; among them
  `test_agent_request_identities` / `test_ssh_github_connection` are marked
  `#[ignore]` (they need a running agent / external network and are skipped by default)

**daemon** (`agents/ssh-agent/tests/daemon_test.rs`, 3 tests): daemon startup and
identity/signature handling

**Total**: 91 tests (78 unit + 13 integration), all passing except the 2 networked
cases marked `#[ignore]` by default

### 10. Environment Variable Configuration

The agent supports the following environment variables:

```bash
# 数据库路径
PERSONA_DB_PATH=~/.persona/identities.db

# Agent 状态目录
PERSONA_AGENT_STATE_DIR=~/.persona

# Agent 监听路径(覆盖默认值)
PERSONA_AGENT_SOCKET_PATH=/custom/path/to/agent.sock

# 主密码(用于自动解锁)
PERSONA_MASTER_PASSWORD=your-master-password

# 策略配置文件
PERSONA_AGENT_POLICY_FILE=~/.persona/agent-policy.toml

# 目标主机(由 SSH 客户端或包装器设置)
PERSONA_AGENT_TARGET_HOST=github.com

# 目标主机提示(优先级低于 PERSONA_AGENT_TARGET_HOST)
PERSONA_AGENT_TARGET_HOST_HINT=gitlab.com

# SSH 目的地(user@host 形式会解析出主机)
PERSONA_AGENT_SSH_DEST=deploy@prod-1

# SSH 命令行(从中解析目标主机)
PERSONA_AGENT_SSH_COMMAND="ssh admin@intranet"

# 回退来源(未设置上述变量时依次尝试):
# SSH_CONNECTION / SSH_CLIENT / SSH_ORIGINAL_COMMAND / GIT_SSH_COMMAND

# 全局确认要求(简化配置)
PERSONA_AGENT_REQUIRE_CONFIRM=true

# 全局最小间隔(简化配置)
PERSONA_AGENT_MIN_INTERVAL_MS=1000

# Known hosts 强制检查
PERSONA_AGENT_ENFORCE_KNOWN_HOSTS=true

# 对未知主机确认
PERSONA_AGENT_CONFIRM_ON_UNKNOWN=true

# 自定义 known_hosts 文件
PERSONA_KNOWN_HOSTS_FILE=~/.ssh/my_known_hosts
```

## Architecture

### Module Layout

```
agents/ssh-agent/
├── src/
│   ├── main.rs          # 入口 shim(6 行, 调 lib 的 run_agent)
│   ├── lib.rs           # Agent 核心(协议处理、签名逻辑、密钥加载)
│   ├── daemon.rs        # 守护进程(监听循环、sock/pid 状态文件)
│   ├── approval.rs      # 签名确认处理器(TtyApprovalHandler 等)
│   ├── policy.rs        # 策略系统(PolicyEnforcer、决策逻辑)
│   └── transport.rs     # 跨平台传输层(Unix/Windows)
├── tests/
│   ├── e2e_test.rs      # 协议/E2E 测试
│   └── daemon_test.rs   # daemon 测试
├── Cargo.toml           # 依赖配置
└── agent-policy.example.toml  # 策略配置示例
```

### Core Components

#### Agent Struct

```rust
struct Agent {
    keys: Vec<AgentKey>,                              // 加载的密钥
    policy: Arc<Mutex<PolicyEnforcer>>,               // 策略执行器
    biometric_provider: Arc<dyn BiometricProvider>,   // 生物识别提供者
    approval_handler: Arc<dyn ApprovalHandler>,       // 签名确认处理器
}
```

#### AgentKey Struct

```rust
struct AgentKey {
    pub public_blob: Vec<u8>,            // OpenSSH 公钥 blob
    pub comment: String,                 // 密钥注释
    pub signing_key: SigningKeyMaterial, // 签名材料(见下)
    pub identity_id: Uuid,               // 关联的身份 ID
    pub credential_id: Uuid,             // 凭证 ID
}

enum SigningKeyMaterial {
    Ed25519 { seed: [u8; 32] },          // ed25519 seed(库内既有约定)
    Rsa(Arc<RsaPrivateKey>),             // RSA PKCS#1 v1.5
    EcdsaP256(SigningKey),               // ECDSA NIST P-256
}
```

#### Signature Decision

```rust
enum SignatureDecision {
    Allowed,                         // 直接允许
    RequireConfirm { reason: String },  // 需要手动确认
    RequireBiometric { reason: String }, // 需要生物识别
    Denied { reason: String },       // 拒绝
}
```

## Usage Examples

### 1. Starting the Agent

```bash
# 设置环境变量
export PERSONA_DB_PATH=~/.persona/identities.db
export PERSONA_MASTER_PASSWORD=your-password

# 启动 agent
cargo run -p persona-ssh-agent

# 输出:
# INFO persona-ssh-agent listening at /tmp/persona-ssh-agent-12345.sock
# INFO Loaded 3 SSH keys from Persona
# SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock
```

### 2. Configuring the SSH Client

```bash
# 设置 SSH_AUTH_SOCK
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock

# 测试连接
ssh -T git@github.com
```

#### Desktop: One-Click "SSH via the persona agent" (implemented, 2026-10-05)

The desktop **Settings → General** page provides an **SSH via persona agent** panel: it
detects the `IdentityAgent` configuration in `~/.ssh/config` and enables or disables it with
one click.

- **How it works**: the OpenSSH 8.3+ `IdentityAgent` directive pins an agent socket to a
  connection, equivalent to setting `SSH_AUTH_SOCK` per host; the anchor block carries
  `Host *`, so it applies to every connection (a hand-written `IdentityAgent` earlier in the
  file still wins under OpenSSH's "first match wins" semantics). The OpenSSH client bundled
  with Windows 10/11 supports it too (the socket is a named pipe,
  `\\.\pipe\persona-ssh-agent`).
- **Stable socket**: the desktop shell passes a stable path to the agent at startup via
  `PERSONA_AGENT_SOCKET_PATH` (Linux `$XDG_RUNTIME_DIR/persona/ssh-agent.sock`, falling back
  to `~/.persona/run/ssh-agent.sock`; Windows named pipe `persona-ssh-agent`). Unlike the
  CLI's per-PID path, the value written into the config survives restarts.
- **Anchor block**: enabling it writes the four lines below idempotently (a corrupted block
  converges on rewrite), and disabling removes the block in one piece; configuration outside
  the block is treated as read-only. The `Host *` line inside the block is not optional: the
  block is appended at the end of the file, so without it the setting would fall into the scope
  of the user's **last Host block** and every other host would silently get no persona agent:

  ```
  # persona managed begin
  Host *
  IdentityAgent /run/user/1000/persona/ssh-agent.sock
  # persona managed end
  ```

- **Three-state status**: enabled (anchor block points at the current socket) / disabled (no
  block) / misconfigured (a block exists but points elsewhere — re-enabling fixes it); if the
  lookup fails, the whole panel is hidden rather than reporting a wrong state.
- **Agent config analysis panel** (implemented, 2026-10-08): a read-only analysis inside the
  same panel on the settings page — parses `~/.ssh/config` (including recursive `Include`
  expansion: depth <= 5, cycles/missing files/excessive depth surface as an amber warning bar,
  relative paths resolve against `~/.ssh`, per-section glob `*`/`?`), identifies
  `IdentityAgent`/`ForwardAgent`/`AddKeysToAgent`/`ProxyAgent` entries and annotates their scope
  line and `file:line` (entries inside the persona anchor block are not counted as user entries);
  combined with the `SSH_AUTH_SOCK` environment variable and a Unix socket / named pipe
  reachability probe, it reports the **effective IdentityAgent** (the first top-level entry wins
  by "first match wins"; otherwise the anchor block value) and an **effective socket liveness
  light** (a process is listening = green / nobody listening = red / cannot tell = gray) plus a
  persona agent running light. If reading the config fails (permissions/IO/non-UTF-8) the error
  shows in a red bar and nothing crashes, and one-click enable refuses to write in that state
  (so a user's config is not overwritten).
- **Acceptance**: `ssh -G <host>` prints `identityagent <stable socket>` (the module test
  `ssh_g_resolves_identity_agent_from_managed_block` verifies a real OpenSSH round-trip,
  including hosts unrelated to the block; the end-to-end walkthrough `ssh_agent_walkthrough`
  covers enabling and disabling at the command layer, byte-for-byte restoration of the user's
  config, and the analyzed effective values flipping both ways as the config toggle changes).

Manual setup (if you would rather not use the desktop switch): paste the four lines above at the
end of `~/.ssh/config` (`Host *` makes it apply to every connection); setting the shell
environment variable `export SSH_AUTH_SOCK=<socket>` is equivalent.

### 3. Configuring Policies

Create `~/.persona/agent-policy.toml`:

```toml
[global]
require_confirm = false
max_signatures_per_hour = 100

# 生产环境密钥: 要求生物识别
[key_policies."prod-key-uuid-here"]
enabled = true
allowed_hosts = ["prod-*.company.com"]
require_biometric = true
max_uses_per_day = 50

# 开发环境密钥: 无限制
[key_policies."dev-key-uuid-here"]
enabled = true
allowed_hosts = ["dev-*.company.com", "github.com"]
require_confirm = false
max_uses_per_day = 0

# 生产环境主机: 严格控制
[host_policies."prod-*.company.com"]
enabled = true
allowed_keys = ["prod-key-uuid-here"]
require_confirm = true
max_connections_per_hour = 20
```

### 4. Testing Policies

```bash
# 连接到生产环境(将触发生物识别)
export PERSONA_AGENT_TARGET_HOST=prod-server.company.com
ssh user@prod-server.company.com

# 连接到开发环境(无额外确认)
export PERSONA_AGENT_TARGET_HOST=dev-server.company.com
ssh user@dev-server.company.com
```

### 5. git commit Signing (SSHSIG)

A vault SSH key in Persona can sign git commits directly (SSHSIG format, compatible with
`ssh-keygen -Y sign`). Copy or symlink the CLI as `persona-ssh-sign` and git will invoke it
as the signer:

```bash
# ① 安装 shim（与 persona-bridge 同一 argv[0] 注入机制）
cp target/debug/persona ~/.local/bin/persona-ssh-sign     # 或 ln -s

# ② git 配置（keyspec 推荐用 vault 凭据 UUID）
git config gpg.format ssh
git config gpg.ssh.program ~/.local/bin/persona-ssh-sign
git config user.signingkey "persona:ssh:<credential-uuid>"   # 或 ssh-ed25519 AAAA… 公钥行

# ③ 签名提交（整个 vault 只有一把 SSH key 时 -f 可省略；多把必须 -f 指定）
git commit -S

# 也可以直接用（与 ssh-keygen -Y sign 同参）
persona ssh gpg-sign -Y sign -n git -f <uuid|公钥行|文件> <文件> [-o 输出]

# 验证侧照常：gpg.ssh.allowedSignersFile + git log --show-signature
```

Notes: ed25519 is a deterministic signature, so the output is byte-for-byte identical to
`ssh-keygen -Y sign`; every signature records an audit log entry `ssh_sign`
(via=gpg-sign + namespace + sha256 digest). When the vault is encrypted, each git signature
unlocks it with the master password (`PERSONA_MASTER_PASSWORD` for non-interactive
scenarios).

### 6. Public Key Distribution (authorized_keys Management)

```bash
# 把身份名下的公钥加到目标机（幂等，重复执行不会写重复行）
persona ssh authorize --identity work --host deploy@prod-1.example.com

# 预览实际执行的 ssh 调用（不连网）
persona ssh authorize --identity work --host deploy@prod-1.example.com --dry-run

# 远端查看 / 撤销
persona ssh authorize --identity work --host deploy@prod-1.example.com --list
persona ssh authorize --identity work --host deploy@prod-1.example.com --remove

# 指定端口 / 远端路径
persona ssh authorize --identity work --host deploy@prod-1 --port 2222 \
  --remote-path /etc/ssh/authorized_keys/work
```

Trust model: transport and authentication use your own `ssh` binary (overridable via
`PERSONA_SSH_BINARY`), and the agent's host policies apply as usual for the duration of the
session; private keys never leave the vault. `add` is idempotent, `remove` only deletes lines
written by this tool (matched by the key blob field), and `--list` is read-only. Every
operation records an audit entry `ssh_authorize` (host + action).

## Performance Characteristics

- **Async processing**: fully asynchronous I/O built on Tokio
- **Concurrent connections**: each connection gets its own tokio task
- **Zero-copy**: efficient binary protocol handling
- **Low latency**: policy checks complete in microseconds
- **Memory safety**: Rust-guaranteed memory and thread safety

## Security Considerations

1. **Private keys live in memory**: private keys are decrypted from the encrypted vault at
   agent start and stay resident for the process lifetime with no zeroize wipe (known
   limitation); they remain encrypted in the database
2. **Encrypted storage**: all keys are stored encrypted in the database
3. **Full audit trail**: every signing operation is logged
4. **Policy first**: a policy denial overrides every other decision
5. **Biometric fallback**: fails closed when unavailable (signature refused by default) or
   degrades per policy
6. **Rate limiting**: layered protection against abuse
7. **known_hosts verification**: optional host validation

## Known Limitations and Future Work

### Current Limitations

1. **Key types**: ed25519, RSA (RFC 8332, rsa-sha2-256/512), and ECDSA P-256 are all supported
2. **Protocol**: only the core SSH Agent protocol subset is implemented
3. **Platforms**: biometric integration requires platform-specific implementations

### Planned Enhancements

1. **More curves**: ECDSA P-384/P-521 and others
2. **Full protocol**: support `SSH_AGENTC_ADD_IDENTITY`, `SSH_AGENTC_REMOVE_IDENTITY`
3. **Smart card integration**: support hardware security modules such as YubiKey
4. **Desktop UI**: graphical signature confirmation and policy configuration
5. **Cloud KMS**: integrate AWS KMS and Google Cloud KMS
6. **Session Recording**: record SSH sessions for auditing
7. **Conditional Access**: location-, time-, and device-based conditional access

## Contributor Guide

### Running Tests

```bash
# 运行所有测试
cargo test -p persona-ssh-agent

# 运行单元测试
cargo test -p persona-ssh-agent --lib

# 运行 E2E 测试
cargo test -p persona-ssh-agent --test e2e_test

# 运行特定测试
cargo test -p persona-ssh-agent test_key_policy_host_restrictions
```

### Code Quality Checks

```bash
# 格式化
cargo fmt -p persona-ssh-agent

# Linting
cargo clippy -p persona-ssh-agent

# 类型检查
cargo check -p persona-ssh-agent
```

## References

- [SSH Agent Protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-14)
- [OpenSSH Agent Source](https://github.com/openssh/openssh-portable/blob/master/authfd.c)
- [ed25519-dalek Documentation](https://docs.rs/ed25519-dalek/)
- [Persona Project README](../README.md)

## Changelog

### 2025-11-21 - v0.1.0 Initial Implementation

**Completed features**:

- SSH Agent protocol subset (request_identities, sign_request)
- ed25519 key support
- Cross-platform transport layer (Unix sockets + Windows named pipes)
- Policy system (global/per-key/per-host)
- Biometric authentication integration
- Rate limiting and audit log
- 13 unit and E2E tests

**Tech stack**:

- Rust 2021
- Tokio (async runtime)
- ed25519-dalek (cryptography)
- TOML (configuration)
- SQLx (database)

**Dependencies**:

- `persona-core`: core library
- `tokio`: async runtime
- `ed25519-dalek`: ed25519 signatures
- `byteorder`: binary serialization
- `toml`: configuration file parsing
- `glob-match`: Glob pattern matching
- `chrono`: time handling

---

**Maintainers**: Persona Team
**License**: MIT
**Repository**: https://github.com/your-org/persona
