# Persona SSH Agent

Enterprise-grade SSH Agent implementation with advanced policy enforcement, biometric authentication, and audit logging.

## Features

- ✅ **SSH Agent Protocol**: Full implementation of SSH Agent protocol (request_identities, sign_request)
- ✅ **ed25519 Support**: Secure ed25519 key generation, storage, and signing
- ✅ **Cross-Platform**: Unix sockets (macOS/Linux) and Named Pipes (Windows)
- ✅ **Policy Enforcement**: TOML-based configuration for per-key, per-host, and global policies
- ✅ **Biometric Authentication**: Touch ID (macOS), Windows Hello, and Linux Secret Service
- ✅ **Rate Limiting**: Multi-layered rate limiting (global, per-key, per-host)
- ✅ **Audit Logging**: Complete audit trail of all signing operations
- ✅ **Known Hosts Verification**: Optional known_hosts checking with confirmation prompts

## Quick Start

### 1. Build the Agent

```bash
cd agents/ssh-agent
cargo build --release
```

### 2. Generate an SSH Key

```bash
# Generate a new ed25519 key
persona ssh generate --identity alice --name "GitHub Key"
```

### 3. Start the Agent

```bash
# Start agent with master password
persona ssh start-agent --print-export

# Copy the export command and run it in your shell
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent.sock
```

### 4. Test the Connection

```bash
# Test with GitHub
ssh -T git@github.com

# Test with custom host
persona ssh run --host github.com -- ssh -T git@github.com
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `persona ssh generate` | Generate a new SSH key |
| `persona ssh list` | List SSH keys for an identity |
| `persona ssh list-all` | List all SSH keys across identities |
| `persona ssh import` | Import existing SSH key from seed |
| `persona ssh export-pub` | Export public key |
| `persona ssh start-agent` | Start the SSH agent |
| `persona ssh stop-agent` | Stop the running agent |
| `persona ssh agent-status` | Check agent status |
| `persona ssh run` | Run command with target host context |
| `persona ssh remove` | Remove an SSH key |

## Policy Configuration

Create `~/.persona/agent-policy.toml`:

```toml
[global]
require_confirm = false
min_interval_ms = 0
enforce_known_hosts = false
confirm_on_unknown_host = false
max_signatures_per_hour = 0
deny_all = false

[[key_policies]]
credential_id = "12345678-1234-5678-1234-567812345678"
enabled = true
allowed_hosts = ["github.com", "gitlab.com", "*.company.com"]
denied_hosts = []
require_confirm = false
require_biometric = false
max_uses_per_day = 100
allowed_time_range = "09:00-18:00"

[[host_policies]]
hostname = "prod-*.company.com"
enabled = true
allowed_keys = []
require_confirm = true
max_connections_per_hour = 20
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PERSONA_DB_PATH` | Database file path | `~/.persona/identities.db` |
| `PERSONA_MASTER_PASSWORD` | Master password for auto-unlock | - |
| `SSH_AUTH_SOCK` | Agent socket path | `/tmp/persona-ssh-agent.sock` |
| `PERSONA_AGENT_STATE_DIR` | Agent state directory | `~/.persona` |
| `PERSONA_AGENT_POLICY_FILE` | Policy configuration file | `~/.persona/agent-policy.toml` |
| `PERSONA_AGENT_TARGET_HOST` | Target hostname (set by CLI) | - |
| `PERSONA_AGENT_REQUIRE_CONFIRM` | Global confirmation requirement | `false` |
| `PERSONA_AGENT_MIN_INTERVAL_MS` | Minimum signing interval | `0` |
| `PERSONA_AGENT_ENFORCE_KNOWN_HOSTS` | Enforce known_hosts checking | `false` |
| `PERSONA_AGENT_CONFIRM_ON_UNKNOWN` | Confirm on unknown hosts | `false` |
| `PERSONA_KNOWN_HOSTS_FILE` | Custom known_hosts file | `~/.ssh/known_hosts` |

## Testing

### Run Unit Tests

```bash
# All tests
cargo test -p persona-ssh-agent

# Unit tests only
cargo test -p persona-ssh-agent --lib

# E2E tests only
cargo test -p persona-ssh-agent --test e2e_test
```

### Run E2E Tests

The E2E tests require a running agent:

```bash
# 1. Start the agent in one terminal
persona ssh start-agent --print-export
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent.sock

# 2. Generate and add a key
persona ssh generate --identity alice --name "Test Key"

# 3. Run ignored E2E tests in another terminal
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent.sock
cargo test -p persona-ssh-agent -- --ignored

# 4. Full GitHub E2E test (requires GitHub key setup)
cargo test -p persona-ssh-agent test_ssh_github_connection -- --ignored
```

## Architecture

### Module Structure

```
agents/ssh-agent/
├── src/
│   ├── main.rs          # Agent main program (protocol handling)
│   ├── policy.rs        # Policy enforcement system
│   └── transport.rs     # Cross-platform transport layer
├── tests/
│   └── e2e_test.rs      # E2E tests
├── Cargo.toml
└── agent-policy.example.toml
```

### Core Components

#### Agent

```rust
struct Agent {
    keys: Vec<AgentKey>,                              // Loaded SSH keys
    policy: Arc<Mutex<PolicyEnforcer>>,               // Policy enforcer
    biometric_provider: Arc<dyn BiometricProvider>,   // Biometric provider
}
```

#### AgentKey

```rust
struct AgentKey {
    pub public_blob: Vec<u8>,       // OpenSSH public key blob
    pub comment: String,            // Key comment
    pub secret_seed: [u8; 32],      // ed25519 seed
    pub identity_id: Uuid,          // Associated identity ID
    pub credential_id: Uuid,        // Credential ID
}
```

#### SignatureDecision

```rust
enum SignatureDecision {
    Allowed,                         // Directly allowed
    RequireConfirm { reason: String },  // Require user confirmation
    RequireBiometric { reason: String }, // Require biometric auth
    Denied { reason: String },       // Denied
}
```

## Security Features

1. **Zero-Memory Exposure**: Private keys are only loaded during signing and cleared immediately
2. **Encrypted Storage**: All keys stored encrypted in the vault
3. **Complete Audit Trail**: Every signature operation is logged with SHA-256 digest
4. **Policy Priority**: Denial policies take precedence over all other decisions
5. **Biometric Fallback**: Gracefully degrades to confirmation if biometric unavailable
6. **Multi-Layer Rate Limiting**: Global, per-key, and per-host rate limits
7. **Known Hosts Verification**: Optional SSH known_hosts checking

## Known Limitations

1. **Key Types**: Currently only ed25519 (RSA/ECDSA planned)
2. **Protocol**: Core SSH Agent protocol subset (add/remove identity not yet implemented)
3. **Platforms**: Biometric integration requires platform-specific implementation

## Future Enhancements

- [ ] RSA (2048/4096) and ECDSA (P-256/P-384/P-521) support
- [ ] Full protocol support (SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_REMOVE_IDENTITY)
- [ ] Smart card integration (YubiKey, etc.)
- [ ] Desktop UI for signature confirmation
- [ ] Cloud KMS integration (AWS KMS, Google Cloud KMS)
- [ ] Session recording for audit
- [ ] Conditional access based on location/time/device

## Contributing

Run checks before submitting:

```bash
# Format
cargo fmt -p persona-ssh-agent

# Lint
cargo clippy -p persona-ssh-agent

# Type check
cargo check -p persona-ssh-agent

# All tests
cargo test -p persona-ssh-agent
```

## References

- [SSH Agent Protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-14)
- [OpenSSH Agent Source](https://github.com/openssh/openssh-portable/blob/master/authfd.c)
- [ed25519-dalek Documentation](https://docs.rs/ed25519-dalek/)

## License

MIT License - See [LICENSE](../../LICENSE) for details
