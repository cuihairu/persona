# Persona SSH Agent - 完整功能说明

## 概述

Persona SSH Agent 是一个开发者友好的 SSH Agent 实现,将 SSH 密钥安全地存储在 Persona 加密保险库中,并提供企业级的策略控制和生物识别认证。

## 已实现功能

### 1. SSH Agent 协议支持

- **SSH Agent Protocol**: 完整实现 SSH Agent 协议子集
  - `SSH_AGENTC_REQUEST_IDENTITIES` (11): 列出所有可用的 SSH 密钥
  - `SSH_AGENTC_SIGN_REQUEST` (13): 对数据进行签名
  - `SSH_AGENT_IDENTITIES_ANSWER` (12): 返回密钥列表
  - `SSH_AGENT_SIGN_RESPONSE` (14): 返回签名结果
  - `SSH_AGENT_FAILURE` (5): 失败响应

- **加密算法支持**:
  - ed25519 (签名/验证, `ed25519-dalek`)
  - RSA `rsa-sha2-256`/`rsa-sha2-512` (RFC 8332, 按客户端 flags 分派)
  - ECDSA P-256 (`ecdsa-sha2-nistp256`, RFC 6979 确定性签名)

### 2. 跨平台传输层

- **UNIX 域套接字** (macOS/Linux):
  - 默认路径: 系统临时目录下的 `persona-ssh-agent-<pid>.sock`
  - Agent 会把实际监听地址写入 `PERSONA_AGENT_STATE_DIR/ssh-agent.sock`,
    进程 PID 写入 `PERSONA_AGENT_STATE_DIR/ssh-agent.pid`
  - 可通过环境变量 `PERSONA_AGENT_SOCKET_PATH` 自定义 Agent 监听地址

- **Windows 命名管道** (Windows):
  - 默认名称: `persona-ssh-agent-<pid>`
  - 完整的跨平台抽象层 (`AgentStream`, `AgentListener`)

- **自动平台检测**: 根据目标操作系统自动选择合适的传输机制

### 3. 密钥管理

- **从 Persona Vault 加载密钥**:
  - 自动从加密数据库加载所有 `CredentialType::SshKey` 类型的凭证
  - 支持主密码解锁 (通过 `PERSONA_MASTER_PASSWORD` 环境变量)
  - 优雅处理锁定状态

- **密钥格式**:
  - 公钥: OpenSSH 格式 (`ssh-ed25519 AAAAC3... comment` 等)
  - 私钥: 库内既有约定为 Base64 编码的 ed25519 seed (32 字节); 导入的
    OpenSSH PEM 私钥 (ed25519/RSA/ECDSA) 在加载时解出原始组件
  - 自动转换为 SSH Agent 协议所需的二进制格式

- **密钥类型展示** (2026-10-07):
  - 列表/详情按公钥元数据现算算法名、SHA256 指纹与位数/曲线标签
    (`ssh-keygen -l` 风格): ED25519→`256`、RSA→模长位长、ECDSA→`P-256` 等
    曲线名、DSA→素数位长; SK 硬件钥跟随内部算法, 证书等容器不显示
  - 导入、生成、库内列表三条路径同源解析, 展示口径一致

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

`key_policies` 是以 credential_id 为键的 map-of-table(**不是** `[[key_policies]]`
数组表——数组格式不会被解析, 对应密钥会静默回退默认策略):

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

特性:

- **主机限制**: 允许/拒绝特定主机(支持 glob 模式)
- **时间范围**: 限制密钥使用的时间窗口
- **使用限制**: 每日最大使用次数
- **认证要求**: 要求确认或生物识别认证

#### 4.4 每主机策略 (HostPolicy)

`host_policies` 同样是 map-of-table, 键 = 主机名(支持 glob 模式):

```toml
[host_policies."prod-*.company.com"]
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

- **macOS**: Touch ID (当前实现恒选 Touch ID; Face ID 检测是 stub, 未接入)
- **Windows**: Windows Hello
- **Linux**: polkit 认证 (`auth_self` 门禁)
- **平台映射**: 按编译目标平台选择对应的生物识别类型

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
- 默认 fail-closed: 内置 `MockBiometricProvider` (`available=false`,
  `force_fail=true`), 未注入真实平台实现时 `require_biometric` 一律拒绝签名
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

#### 9.1 单元测试 (78 个)

按模块分布: `policy.rs` 30、`lib.rs` 37、`transport.rs` 5、`daemon.rs` 3、
`approval.rs` 3。覆盖默认策略放行、`deny_all` 紧急锁定、速率限制
(间隔/每小时/每日/每主机)、每密钥与每主机策略、glob 匹配、时间窗限制、
known_hosts 强制与未知主机确认、TOML/环境变量策略加载与回退等。

#### 9.2 集成测试 (13 个)

**协议/E2E** (`agents/ssh-agent/tests/e2e_test.rs`, 10 个):

- `test_ssh_protocol_format`: SSH 协议编码/解码
- `test_ed25519_public_key_encoding`: ed25519 公钥编码
- `test_ssh_agent_message_types`: SSH Agent 消息类型常量
- `test_policy_config_format`: TOML 策略配置解析
- `test_read_ssh_string_function`: SSH 字符串读取
- `test_identities_answer_format`: SSH_AGENT_IDENTITIES_ANSWER 消息格式
- 另有 agent 子进程回环、`sign_request` 编码等用例; 其中
  `test_agent_request_identities` / `test_ssh_github_connection` 标记
  `#[ignore]`(需 agent 运行中 / 外网, 默认跳过)

**daemon** (`agents/ssh-agent/tests/daemon_test.rs`, 3 个): 守护进程启动与
身份/签名处理

**总计**: 91 个测试(单元 78 + 集成 13), 除 2 个默认 `#[ignore]` 的联网
用例外全部通过

### 10. 环境变量配置

Agent 支持以下环境变量:

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

## 架构设计

### 模块结构

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

### 核心组件

#### Agent 结构

```rust
struct Agent {
    keys: Vec<AgentKey>,                              // 加载的密钥
    policy: Arc<Mutex<PolicyEnforcer>>,               // 策略执行器
    biometric_provider: Arc<dyn BiometricProvider>,   // 生物识别提供者
    approval_handler: Arc<dyn ApprovalHandler>,       // 签名确认处理器
}
```

#### AgentKey 结构

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
# INFO persona-ssh-agent listening at /tmp/persona-ssh-agent-12345.sock
# INFO Loaded 3 SSH keys from Persona
# SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock
```

### 2. 配置 SSH 客户端

```bash
# 设置 SSH_AUTH_SOCK
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock

# 测试连接
ssh -T git@github.com
```

#### 桌面端：一键「SSH 走 persona agent」（已实现，2026-10-05）

桌面「设置 → 通用」提供 **SSH 走 persona agent** 区块：检测 `~/.ssh/config`
的 IdentityAgent 配置并一键启用/停用。

- **原理**：OpenSSH 8.3+ 的 `IdentityAgent` 指令为连接指定 agent socket，
  等效于对单个 host 单独设置 `SSH_AUTH_SOCK`；锚点块内带 `Host *`，对所有
  连接生效（写在文件更前面的手写 `IdentityAgent` 按 OpenSSH「先出现先生效」
  语义仍优先）。Windows 10/11 自带的 OpenSSH 客户端同样支持（socket 用
  命名管道 `\\.\pipe\persona-ssh-agent`）。
- **稳定 socket**：桌面壳启动 agent 时经 `PERSONA_AGENT_SOCKET_PATH` 注入
  稳定路径（Linux `$XDG_RUNTIME_DIR/persona/ssh-agent.sock`，缺省回退
  `~/.persona/run/ssh-agent.sock`；Windows 命名管道 `persona-ssh-agent`），
  与 CLI 每次 pid 化路径不同——写入 config 的值跨重启不变。
- **锚点块**：启用即幂等写入下面四行（损坏块自动收敛重写），停用整块移除；
  块外配置一律只读不动。块内 `Host *` 不可省：块追加在文件末尾，若无它会
  落入用户**最后一个 Host 块**的作用域，其余 host 静默拿不到 persona agent：

  ```
  # persona managed begin
  Host *
  IdentityAgent /run/user/1000/persona/ssh-agent.sock
  # persona managed end
  ```

- **状态三态**：已启用（锚点块指向当前 socket）/ 未启用（无块）/
  配置异常（块存在但指向别处——重新启用即修复）；查询失败时区块整体隐藏，
  不谎报状态。
- **验收**：`ssh -G <host>` 输出 `identityagent <稳定 socket>`（模块测试
  `ssh_g_resolves_identity_agent_from_managed_block` 以真实 OpenSSH 往返
  验证，含块外无关 host；端到端走查 `ssh_agent_walkthrough` 覆盖命令层
  启用/停用 + 用户配置逐字节还原）。

手动配置（不想用桌面开关）：把上面四行粘进 `~/.ssh/config` 文件末尾
（`Host *` 让它对所有连接生效）；shell 环境变量方案
`export SSH_AUTH_SOCK=<socket>` 等效。

### 3. 配置策略

创建 `~/.persona/agent-policy.toml`:

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

### 4. 测试策略

```bash
# 连接到生产环境(将触发生物识别)
export PERSONA_AGENT_TARGET_HOST=prod-server.company.com
ssh user@prod-server.company.com

# 连接到开发环境(无额外确认)
export PERSONA_AGENT_TARGET_HOST=dev-server.company.com
ssh user@dev-server.company.com
```

### 5. git commit 签名（SSHSIG）

Persona 的 vault SSH key 可以直接给 git commit 签名（`ssh-keygen -Y sign`
兼容的 SSHSIG 格式）。把 CLI 的一份拷贝/软链命名为 `persona-ssh-sign`，
git 会把它当作签名器调用：

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

说明：ed25519 是确定性签名，输出与 `ssh-keygen -Y sign` 逐字节一致；
每次签名在审计日志落一条 `ssh_sign`（via=gpg-sign + namespace + sha256
摘要）。加密保险库时 git 每次签名会走主密码解锁（非交互场景用
`PERSONA_MASTER_PASSWORD`）。

### 6. 公钥分发（authorized_keys 管理）

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

信任模型：传输与认证使用你自己的 `ssh` 二进制（可用 `PERSONA_SSH_BINARY`
覆盖），会话期间 agent 的 host 策略照常生效；私钥不出库。add 幂等、
remove 只删除本工具写入的行（按 key blob 字段匹配）、`--list` 只读。
每次操作落审计 `ssh_authorize`（host + action）。

## 性能特性

- **异步处理**: 基于 Tokio 的完全异步 I/O
- **并发连接**: 每个连接独立的 tokio task
- **零拷贝**: 高效的二进制协议处理
- **低延迟**: 策略检查在微秒级完成
- **内存安全**: Rust 保证的内存安全和线程安全

## 安全考虑

1. **私钥常驻内存**: 私钥在 agent 启动时从加密保险库解密加载,进程生命周期
   内常驻,无 zeroize 清除(已知限制); 数据库中仍为加密存储
2. **加密存储**: 所有密钥在数据库中加密存储
3. **审计完整**: 所有签名操作都有审计日志
4. **策略优先**: 策略拒绝优先于任何其他决策
5. **生物识别回退**: 不可用时 fail-closed(默认拒绝签名)或按策略降级
6. **速率限制**: 多层次防护防止滥用
7. **known_hosts 检查**: 可选的主机验证

## 已知限制与未来工作

### 当前限制

1. **密钥类型**: ed25519、RSA (RFC 8332, rsa-sha2-256/512)、ECDSA P-256
   三档均已支持
2. **协议**: 仅实现核心 SSH Agent 协议子集
3. **平台**: 生物识别集成需要平台特定的实现

### 未来增强

1. **更多曲线**: ECDSA P-384/P-521 等
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
cargo test -p persona-ssh-agent test_key_policy_host_restrictions
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

**完成功能**:

- SSH Agent 协议子集(request_identities, sign_request)
- ed25519 密钥支持
- 跨平台传输层(Unix sockets + Windows named pipes)
- 综合策略系统(全局/每密钥/每主机)
- 生物识别认证集成
- 速率限制和审计日志
- 13个单元测试和E2E测试

**技术栈**:

- Rust 2021
- Tokio (异步运行时)
- ed25519-dalek (加密)
- TOML (配置)
- SQLx (数据库)

**依赖**:

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
