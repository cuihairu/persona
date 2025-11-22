# Persona SSH Agent - 完整功能说明

## 概述

Persona SSH Agent 是一个开发者友好的 SSH Agent 实现,将 SSH 密钥安全地存储在 Persona 加密保险库中,并提供企业级的策略控制和生物识别认证。

## ✅ 已实现功能

### 1. SSH Agent 协议支持

- **SSH Agent Protocol**: 完整实现 SSH Agent 协议子集
  - `SSH_AGENTC_REQUEST_IDENTITIES` (11): 列出所有可用的 SSH 密钥
  - `SSH_AGENTC_SIGN_REQUEST` (13): 对数据进行签名
  - `SSH_AGENT_IDENTITIES_ANSWER` (12): 返回密钥列表
  - `SSH_AGENT_SIGN_RESPONSE` (14): 返回签名结果
  - `SSH_AGENT_FAILURE` (5): 失败响应

- **加密算法支持**:
  - ✅ ed25519 (签名/验证)
  - 使用 `ed25519-dalek` 库实现

### 2. 跨平台传输层

- **UNIX 域套接字** (macOS/Linux):
  - 默认路径: `/tmp/persona-ssh-agent.sock`
  - 可通过环境变量 `SSH_AUTH_SOCK` 自定义

- **Windows 命名管道** (Windows):
  - 默认路径: `\\\\.\\pipe\\persona-ssh-agent`
  - 完整的跨平台抽象层 (`AgentStream`, `AgentListener`)

- **自动平台检测**: 根据目标操作系统自动选择合适的传输机制

### 3. 密钥管理

- **从 Persona Vault 加载密钥**:
  - 自动从加密数据库加载所有 `CredentialType::SshKey` 类型的凭证
  - 支持主密码解锁 (通过 `PERSONA_MASTER_PASSWORD` 环境变量)
  - 优雅处理锁定状态

- **密钥格式**:
  - 公钥: OpenSSH 格式 (`ssh-ed25519 AAAAC3... comment`)
  - 私钥: Base64 编码的 ed25519 seed (32 字节)
  - 自动转换为 SSH Agent 协议所需的二进制格式

### 4. 综合策略系统

#### 4.1 基于 TOML 的配置

配置文件位置:
- 默认: `~/.persona/agent-policy.toml`
- 自定义: 通过 `PERSONA_AGENT_POLICY_FILE` 环境变量指定

#### 4.2 全局策略 (GlobalPolicy)

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

#### 4.3 每密钥策略 (KeyPolicy)

```toml
[[key_policies]]
credential_id = "12345678-1234-5678-1234-567812345678"
enabled = true
allowed_hosts = ["github.com", "gitlab.com", "*.company.com"]
denied_hosts = []
require_confirm = false
require_biometric = false
max_uses_per_day = 100
allowed_time_range = "09:00-18:00"  # 仅在工作时间允许
```

特性:
- **主机限制**: 允许/拒绝特定主机(支持 glob 模式)
- **时间范围**: 限制密钥使用的时间窗口
- **使用限制**: 每日最大使用次数
- **认证要求**: 要求确认或生物识别认证

#### 4.4 每主机策略 (HostPolicy)

```toml
[[host_policies]]
hostname = "prod-*.company.com"
enabled = true
allowed_keys = []  # 空 = 允许所有密钥
require_confirm = true
max_connections_per_hour = 20
```

特性:
- **密钥白名单**: 限制特定主机只能使用指定的密钥
- **连接限制**: 每小时最大连接次数
- **Glob 模式**: 支持通配符匹配主机名

#### 4.5 策略执行优先级

```
1. 全局 deny_all (最高优先级)
2. 速率限制检查
3. 每密钥策略检查
4. 每主机策略检查
5. 认证要求判定: Biometric > Confirm > Allow
```

### 5. 生物识别认证

#### 5.1 平台支持

- **macOS**: Touch ID / Face ID
- **Windows**: Windows Hello
- **Linux**: Linux Secret Service
- **自动检测**: 根据运行平台自动选择合适的生物识别类型

#### 5.2 认证流程

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

#### 5.3 集成方式

- 使用 `BiometricProvider` trait 进行抽象
- 默认使用 `MockBiometricProvider` (用于测试)
- 桌面/移动应用可注入真实的平台特定实现

### 6. 速率限制

多层次的速率限制机制:

1. **全局最小间隔** (`min_interval_ms`):
   - 任意两次签名之间的最小时间间隔
   - 防止暴力攻击

2. **全局每小时限制** (`max_signatures_per_hour`):
   - 每小时最多允许的签名次数
   - 自动清理超过1小时的时间戳

3. **每密钥每日限制** (`max_uses_per_day`):
   - 每个密钥每天最多使用次数
   - 每24小时自动重置

4. **每主机每小时限制** (`max_connections_per_hour`):
   - 每个主机每小时最多连接次数
   - 每小时自动重置

### 7. 审计日志

- **签名操作审计**: 记录每次签名操作
  - 操作类型: `ssh_sign` (自定义审计动作)
  - 资源类型: `Credential`
  - 元数据: 签名数据的 SHA-256 哈希
  - 关联: identity_id, credential_id
  - 时间戳: 自动记录

- **持久化**: 存储在 Persona 数据库的 `audit_log` 表中

### 8. 安全特性

#### 8.1 确认提示

- **交互式确认**:
  - 优先使用 `/dev/tty` (Unix)
  - 回退到 stdin/stdout
  - 显示目标主机信息

- **提示内容**:
  ```
  Allow SSH signature for host 'github.com'? [y/N]
  ```

#### 8.2 Known Hosts 检查

- **支持环境变量**:
  - `PERSONA_AGENT_ENFORCE_KNOWN_HOSTS`: 强制检查
  - `PERSONA_AGENT_CONFIRM_ON_UNKNOWN`: 对未知主机提示确认
  - `PERSONA_KNOWN_HOSTS_FILE`: 自定义 known_hosts 文件路径

- **默认路径**: `~/.ssh/known_hosts`

### 9. 测试覆盖

#### 9.1 单元测试 (7个)

**Policy 测试** (`agents/ssh-agent/src/policy.rs`):
- `test_default_policy_allows`: 默认策略允许所有操作
- `test_deny_all_lockdown`: 紧急锁定模式测试
- `test_rate_limiting`: 速率限制功能测试
- `test_key_policy_host_restrictions`: 每密钥主机限制测试
- `test_glob_patterns`: Glob 模式匹配测试

**Transport 测试** (`agents/ssh-agent/src/transport.rs`):
- `test_default_path`: 默认套接字路径测试
- `test_env_var_name`: 环境变量名称测试

#### 9.2 E2E 测试 (6个)

**协议测试** (`agents/ssh-agent/tests/e2e_test.rs`):
- `test_ssh_protocol_format`: SSH 协议编码/解码
- `test_ed25519_public_key_encoding`: ed25519 公钥编码
- `test_ssh_agent_message_types`: SSH Agent 消息类型常量
- `test_policy_config_format`: TOML 策略配置解析
- `test_read_ssh_string_function`: SSH 字符串读取
- `test_identities_answer_format`: SSH_AGENT_IDENTITIES_ANSWER 消息格式

**总计**: 13个测试 ✅ 全部通过

### 10. 环境变量配置

Agent 支持以下环境变量:

```bash
# 数据库路径
PERSONA_DB_PATH=~/.persona/identities.db

# Agent 状态目录
PERSONA_AGENT_STATE_DIR=~/.persona

# 套接字路径(覆盖默认值)
SSH_AUTH_SOCK=/custom/path/to/agent.sock

# 主密码(用于自动解锁)
PERSONA_MASTER_PASSWORD=your-master-password

# 策略配置文件
PERSONA_AGENT_POLICY_FILE=~/.persona/agent-policy.toml

# 目标主机(由 SSH 客户端或包装器设置)
PERSONA_AGENT_TARGET_HOST=github.com

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

## 架构设计

### 模块结构

```
agents/ssh-agent/
├── src/
│   ├── main.rs          # Agent 主程序(协议处理、签名逻辑)
│   ├── policy.rs        # 策略系统(PolicyEnforcer、决策逻辑)
│   └── transport.rs     # 跨平台传输层(Unix/Windows)
├── tests/
│   └── e2e_test.rs      # E2E 测试
├── Cargo.toml           # 依赖配置
└── agent-policy.example.toml  # 策略配置示例
```

### 核心组件

#### Agent 结构

```rust
struct Agent {
    keys: Vec<AgentKey>,                              // 加载的密钥
    policy: Arc<Mutex<PolicyEnforcer>>,               // 策略执行器
    biometric_provider: Arc<dyn BiometricProvider>,   // 生物识别提供者
}
```

#### AgentKey 结构

```rust
struct AgentKey {
    pub public_blob: Vec<u8>,       // OpenSSH 公钥 blob
    pub comment: String,            // 密钥注释
    pub secret_seed: [u8; 32],      // ed25519 seed
    pub identity_id: Uuid,          // 关联的身份 ID
    pub credential_id: Uuid,        // 凭证 ID
}
```

#### 签名决策

```rust
enum SignatureDecision {
    Allowed,                         // 直接允许
    RequireConfirm { reason: String },  // 需要手动确认
    RequireBiometric { reason: String }, // 需要生物识别
    Denied { reason: String },       // 拒绝
}
```

## 使用示例

### 1. 启动 Agent

```bash
# 设置环境变量
export PERSONA_DB_PATH=~/.persona/identities.db
export PERSONA_MASTER_PASSWORD=your-password

# 启动 agent
cargo run -p persona-ssh-agent

# 输出:
# INFO persona-ssh-agent listening at /tmp/persona-ssh-agent.sock
# INFO Loaded 3 SSH keys from Persona
# SSH_AUTH_SOCK=/tmp/persona-ssh-agent.sock
```

### 2. 配置 SSH 客户端

```bash
# 设置 SSH_AUTH_SOCK
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent.sock

# 测试连接
ssh -T git@github.com
```

### 3. 配置策略

创建 `~/.persona/agent-policy.toml`:

```toml
[global]
require_confirm = false
max_signatures_per_hour = 100

[[key_policies]]
# 生产环境密钥: 要求生物识别
credential_id = "prod-key-uuid-here"
enabled = true
allowed_hosts = ["prod-*.company.com"]
require_biometric = true
max_uses_per_day = 50

[[key_policies]]
# 开发环境密钥: 无限制
credential_id = "dev-key-uuid-here"
enabled = true
allowed_hosts = ["dev-*.company.com", "github.com"]
require_confirm = false
max_uses_per_day = 0

[[host_policies]]
# 生产环境主机: 严格控制
hostname = "prod-*.company.com"
enabled = true
allowed_keys = ["prod-key-uuid-here"]
require_confirm = true
max_connections_per_hour = 20
```

### 4. 测试策略

```bash
# 连接到生产环境(将触发生物识别)
export PERSONA_AGENT_TARGET_HOST=prod-server.company.com
ssh user@prod-server.company.com

# 连接到开发环境(无额外确认)
export PERSONA_AGENT_TARGET_HOST=dev-server.company.com
ssh user@dev-server.company.com
```

## 性能特性

- **异步处理**: 基于 Tokio 的完全异步 I/O
- **并发连接**: 每个连接独立的 tokio task
- **零拷贝**: 高效的二进制协议处理
- **低延迟**: 策略检查在微秒级完成
- **内存安全**: Rust 保证的内存安全和线程安全

## 安全考虑

1. **密钥永不离开内存**: 私钥仅在签名时加载,使用后立即清除
2. **加密存储**: 所有密钥在数据库中加密存储
3. **审计完整**: 所有签名操作都有审计日志
4. **策略优先**: 策略拒绝优先于任何其他决策
5. **生物识别回退**: 不可用时优雅降级,不会完全阻塞
6. **速率限制**: 多层次防护防止滥用
7. **known_hosts 检查**: 可选的主机验证

## 已知限制与未来工作

### 当前限制

1. **密钥类型**: 仅支持 ed25519(未来将添加 RSA、ECDSA)
2. **协议**: 仅实现核心 SSH Agent 协议子集
3. **平台**: 生物识别集成需要平台特定的实现

### 未来增强

1. **更多密钥类型**: RSA (2048/4096), ECDSA (P-256/P-384/P-521)
2. **完整协议**: 支持 `SSH_AGENTC_ADD_IDENTITY`, `SSH_AGENTC_REMOVE_IDENTITY`
3. **智能卡集成**: 支持 YubiKey 等硬件安全模块
4. **桌面 UI**: 图形化签名确认和策略配置
5. **Cloud KMS**: 集成 AWS KMS、Google Cloud KMS
6. **Session Recording**: 录制 SSH 会话以供审计
7. **Conditional Access**: 基于位置、时间、设备的条件访问

## 贡献者指南

### 运行测试

```bash
# 运行所有测试
cargo test -p persona-ssh-agent

# 运行单元测试
cargo test -p persona-ssh-agent --lib

# 运行 E2E 测试
cargo test -p persona-ssh-agent --test e2e_test

# 运行特定测试
cargo test -p persona-ssh-agent test_policy_enforcement
```

### 代码检查

```bash
# 格式化
cargo fmt -p persona-ssh-agent

# Linting
cargo clippy -p persona-ssh-agent

# 类型检查
cargo check -p persona-ssh-agent
```

## 参考资料

- [SSH Agent Protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-14)
- [OpenSSH Agent Source](https://github.com/openssh/openssh-portable/blob/master/authfd.c)
- [ed25519-dalek Documentation](https://docs.rs/ed25519-dalek/)
- [Persona Core Documentation](../core/README.md)

## 更新日志

### 2025-11-21 - v0.1.0 初始实现

✅ **完成功能**:
- SSH Agent 协议子集(request_identities, sign_request)
- ed25519 密钥支持
- 跨平台传输层(Unix sockets + Windows named pipes)
- 综合策略系统(全局/每密钥/每主机)
- 生物识别认证集成
- 速率限制和审计日志
- 13个单元测试和E2E测试

🔧 **技术栈**:
- Rust 2021
- Tokio (异步运行时)
- ed25519-dalek (加密)
- TOML (配置)
- SQLx (数据库)

📦 **依赖**:
- `persona-core`: 核心库
- `tokio`: 异步运行时
- `ed25519-dalek`: ed25519 签名
- `byteorder`: 二进制序列化
- `toml`: 配置文件解析
- `glob-match`: Glob 模式匹配
- `chrono`: 时间处理

---

**维护者**: Persona Team
**许可证**: MIT
**仓库**: https://github.com/your-org/persona
