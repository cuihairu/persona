# SSH Agent Testing Guide

Complete guide for testing the Persona SSH Agent.

## Quick Test Suite

```bash
# Run all unit tests
cargo test -p persona-ssh-agent --test e2e_test

# Expected output:
# test result: ok. 7 passed; 0 failed; 2 ignored
```

## Test Coverage

### Unit Tests (7 tests) ✅

All passing:

1. **test_ssh_protocol_format** - SSH wire protocol encoding/decoding
2. **test_ed25519_public_key_encoding** - ed25519 public key format
3. **test_ssh_agent_message_types** - Protocol message type constants
4. **test_policy_config_format** - TOML policy configuration parsing
5. **test_read_ssh_string_function** - SSH string reading utility
6. **test_identities_answer_format** - SSH_AGENT_IDENTITIES_ANSWER format
7. **test_sign_request_format** - SSH_AGENTC_SIGN_REQUEST format

### Integration Tests (2 tests, ignored by default)

These require a running agent:

1. **test_agent_request_identities** - Query agent for loaded keys
2. **test_ssh_github_connection** - Full SSH connection to GitHub

## Running Integration Tests

### Prerequisites

1. **Start the Agent**

```bash
# Terminal 1: Initialize workspace
persona init --path ~/PersonaTest --yes --encrypted --master-password "test123"

# Generate a test key
persona ssh generate --identity alice --name "Test Key"

# Start the agent
persona ssh start-agent --print-export

# Copy the export command (example):
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock
```

2. **Verify Agent Status**

```bash
# Terminal 2: Check agent is running
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock
persona ssh agent-status

# Expected output:
# Socket: /tmp/persona-ssh-agent-12345.sock
# PID: 12345
# Agent keys: 1
```

### Run Integration Tests

```bash
# Run ignored tests
cargo test -p persona-ssh-agent -- --ignored

# Expected output:
# test test_agent_request_identities ... ok
# test test_ssh_github_connection ... FAILED (if no GitHub key setup)
```

## Manual E2E Testing

### Test 1: Basic Agent Communication

```bash
# 1. Start agent
persona ssh start-agent --print-export
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock

# 2. Query agent identities
ssh-add -l

# Expected output:
# 256 SHA256:xxxxx... Test Key (ED25519)
```

### Test 2: GitHub SSH Connection

**Prerequisites:**
- GitHub account
- SSH key registered on GitHub

```bash
# 1. Generate key and get public key
persona ssh generate --identity alice --name "GitHub Key"
persona ssh list --identity alice
# Note the credential ID

# 2. Export public key
persona ssh export-pub --id <credential-id>

# 3. Add to GitHub
# Go to https://github.com/settings/keys
# Add the public key

# 4. Test connection
persona ssh run --host github.com -- ssh -T git@github.com

# Expected output:
# Hi <username>! You've successfully authenticated...
```

### Test 3: Policy Enforcement

**Test Confirmation Prompt:**

```bash
# 1. Enable confirmation requirement
export PERSONA_AGENT_REQUIRE_CONFIRM=1

# 2. Try SSH connection
ssh -T git@github.com

# Expected: Prompt appears
# Allow SSH signature for host 'github.com'? [y/N] y
```

**Test Rate Limiting:**

```bash
# 1. Set minimum interval (1 second)
export PERSONA_AGENT_MIN_INTERVAL_MS=1000

# 2. Try rapid SSH commands
ssh -T git@github.com
ssh -T git@github.com  # Should fail/throttle

# Expected: Second command denied or delayed
```

**Test Known Hosts:**

```bash
# 1. Enable known_hosts checking
export PERSONA_AGENT_ENFORCE_KNOWN_HOSTS=1

# 2. Try connecting to unlisted host
ssh -T unknown-host.com

# Expected: Connection denied (host not in known_hosts)

# 3. Add host to known_hosts
ssh-keyscan github.com >> ~/.ssh/known_hosts

# 4. Retry
ssh -T git@github.com
# Expected: Success
```

### Test 4: TOML Policy Configuration

**Create Policy File:**

```bash
cat > ~/.persona/agent-policy.toml <<'EOF'
[global]
require_confirm = false
max_signatures_per_hour = 10

[[key_policies]]
credential_id = "<your-credential-id>"
enabled = true
allowed_hosts = ["github.com", "gitlab.com"]
require_confirm = true

[[host_policies]]
hostname = "*.prod.example.com"
enabled = true
require_confirm = true
max_connections_per_hour = 5
EOF
```

**Test Policy:**

```bash
# 1. Set policy file
export PERSONA_AGENT_POLICY_FILE=~/.persona/agent-policy.toml

# 2. Restart agent (to load policy)
persona ssh stop-agent
persona ssh start-agent --print-export
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock

# 3. Try allowed host
ssh -T git@github.com
# Expected: Prompt for confirmation (per key_policies)

# 4. Try denied host
ssh -T git@example.com
# Expected: Denied (not in allowed_hosts)
```

### Test 5: Multi-Identity Keys

```bash
# 1. Create multiple identities
persona add --name alice --email alice@example.com
persona add --name bob --email bob@example.com

# 2. Generate keys for each
persona ssh generate --identity alice --name "Alice GitHub"
persona ssh generate --identity bob --name "Bob GitLab"

# 3. Restart agent
persona ssh stop-agent
persona ssh start-agent --print-export
export SSH_AUTH_SOCK=/tmp/persona-ssh-agent-12345.sock

# 4. List all keys
ssh-add -l
# Expected: 2 keys listed

persona ssh list-all
# Expected: Shows all keys with identity info
```

## Debugging Tests

### Enable Trace Logging

```bash
# Set log level to trace
export RUST_LOG=trace

# Start agent
persona-ssh-agent

# Observe detailed logging:
# TRACE persona_ssh_agent: Received SSH_AGENTC_REQUEST_IDENTITIES
# TRACE persona_ssh_agent: Signature decision: Allowed
```

### Check Agent State Files

```bash
# Agent state directory
ls -la ~/.persona/

# Expected files:
# - ssh-agent.sock  (socket path)
# - ssh-agent.pid   (process ID)
# - agent-target-host (current host, temporary)
```

### Test Socket Communication

```bash
# Manual socket test (Unix)
echo -ne '\x00\x00\x00\x01\x0b' | nc -U /tmp/persona-ssh-agent-12345.sock | xxd

# Expected output:
# 00000000: 0000 000d 0c00 0000 00             (IDENTITIES_ANSWER with 0 keys)
```

## CI/CD Testing

### GitHub Actions

```yaml
name: SSH Agent Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run unit tests
        run: cargo test -p persona-ssh-agent --test e2e_test

      - name: Check no warnings
        run: cargo clippy -p persona-ssh-agent -- -D warnings
```

## Known Issues & Limitations

### macOS

- Touch ID biometric requires proper entitlements (desktop app only)
- `/dev/tty` required for confirmation prompts

### Linux

- Biometric support depends on Secret Service availability
- May need `libdbus` for biometric integration

### Windows

- Named pipe path format: `\\.\pipe\persona-ssh-agent-<pid>`
- SSH client must support named pipes (OpenSSH 8.0+)

## Test Checklist

Use this checklist when validating a release:

- [ ] All unit tests pass: `cargo test -p persona-ssh-agent`
- [ ] No compiler warnings: `cargo clippy -p persona-ssh-agent`
- [ ] Agent starts and stops cleanly
- [ ] Keys load from vault correctly
- [ ] SSH connection works (GitHub/GitLab)
- [ ] Confirmation prompts display
- [ ] Rate limiting enforces delays
- [ ] Known hosts checking works
- [ ] TOML policy file loads
- [ ] Multi-identity keys work
- [ ] Agent status command accurate

## Performance Benchmarks

### Baseline Performance

```bash
# Measure signature latency
time ssh -T git@github.com

# Expected: < 500ms total (including network)
# Agent overhead: < 10ms
```

### Stress Test

```bash
# Rapid-fire signatures (should respect rate limits)
for i in {1..100}; do
  ssh -T git@github.com 2>&1 | head -1 &
done
wait

# Monitor agent CPU/memory
ps aux | grep persona-ssh-agent
```

## Troubleshooting

### Agent Not Starting

```bash
# Check if socket exists
ls -la /tmp/persona-ssh-agent*.sock

# Remove stale socket
rm /tmp/persona-ssh-agent*.sock

# Retry
persona ssh start-agent
```

### Permission Denied

```bash
# Check socket permissions
ls -l $SSH_AUTH_SOCK

# Should be: srwxr-xr-x (socket)
```

### Keys Not Loading

```bash
# Check database
sqlite3 ~/.persona/identities.db "SELECT id, name FROM credentials WHERE credential_type = 'SshKey';"

# Check master password
echo $PERSONA_MASTER_PASSWORD

# Try manual unlock
persona ssh list --identity alice
```

## Contributing Tests

When adding new features, include:

1. **Unit tests** in `tests/e2e_test.rs`
2. **Manual test steps** in this document
3. **Policy examples** in README

Example test addition:

```rust
#[test]
fn test_new_feature() {
    // Test logic here
    assert!(feature_works());
}
```

## Resources

- [SSH Agent Protocol Spec](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-14)
- [OpenSSH Source](https://github.com/openssh/openssh-portable)
- [Persona Core Tests](../../core/tests/)
