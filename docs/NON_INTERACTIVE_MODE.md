# CLI Non-Interactive Mode Guide

Persona CLI supports a non-interactive (headless) mode for use in CI/CD pipelines, automation scripts, and other scenarios where user interaction is not possible.

## Environment Variables

### Core Configuration

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| `PERSONA_NON_INTERACTIVE` | Disable all interactive prompts | `1` or `true` | `false` |
| `PERSONA_WORKSPACE_PATH` | Workspace directory path | `/path/to/workspace` | `~/.persona` |
| `PERSONA_MASTER_PASSWORD` | Master password for authentication | `your-password` | - |
| `PERSONA_DB_PATH` | Database file path (alternative) | `/path/to/db.sqlite` | `$WORKSPACE/identities.db` |

### Output Configuration

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| `PERSONA_OUTPUT_FORMAT` | Output format | `json`, `yaml`, `csv`, `table` | `table` |
| `PERSONA_NO_COLOR` | Disable colored output | `1` or `true` | `false` |
| `PERSONA_LOG_LEVEL` | Logging level | `trace`, `debug`, `info`, `warn`, `error` | `info` |

### Security Configuration

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| `PERSONA_ENCRYPTION_ENABLED` | Enable/disable encryption | `true` or `false` | `true` |
| `PERSONA_AUTO_LOCK_TIMEOUT` | Auto-lock timeout in seconds | `300` | `300` |

## CI/CD Integration

### GitHub Actions

```yaml
name: Persona Backup

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Persona
        run: cargo install persona-cli

      - name: Export identities
        env:
          PERSONA_NON_INTERACTIVE: "1"
          PERSONA_WORKSPACE_PATH: "/home/runner/persona"
          PERSONA_MASTER_PASSWORD: ${{ secrets.PERSONA_MASTER_PASSWORD }}
          PERSONA_OUTPUT_FORMAT: "json"
          PERSONA_NO_COLOR: "1"
        run: |
          persona export \
            --include-sensitive \
            --compression 9 \
            --encrypt \
            --output backup-$(date +%Y%m%d).json

      - name: Upload backup
        uses: actions/upload-artifact@v3
        with:
          name: persona-backup
          path: backup-*.json
```

### GitLab CI

```yaml
backup:
  stage: backup
  script:
    - export PERSONA_NON_INTERACTIVE=1
    - export PERSONA_WORKSPACE_PATH=/builds/persona-workspace
    - export PERSONA_MASTER_PASSWORD=$MASTER_PASSWORD
    - export PERSONA_OUTPUT_FORMAT=json
    - persona export --output backup.json --encrypt
  artifacts:
    paths:
      - backup.json
  only:
    - schedules
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        PERSONA_NON_INTERACTIVE = '1'
        PERSONA_WORKSPACE_PATH = "${WORKSPACE}/persona"
        PERSONA_MASTER_PASSWORD = credentials('persona-master-password')
        PERSONA_OUTPUT_FORMAT = 'json'
        PERSONA_NO_COLOR = '1'
    }

    stages {
        stage('Export') {
            steps {
                sh 'persona export --output backup.json'
            }
        }
    }
}
```

## Command-Line Usage

### Initialize Workspace (Non-Interactive)

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Initialize encrypted workspace
persona init \
  --path /path/to/workspace \
  --yes \
  --encrypted
```

### Add Identity (Non-Interactive)

```bash
export PERSONA_NON_INTERACTIVE=1

# All values must be provided via command-line arguments
persona add \
  --name "CI User" \
  --email "ci@example.com" \
  --identity-type "automation" \
  --yes
```

### Export Data (Non-Interactive)

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"
export PERSONA_OUTPUT_FORMAT="json"

persona export \
  --include-sensitive \
  --compression 9 \
  --encrypt \
  --output backup.json
```

### Import Data (Non-Interactive)

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Provide passphrase via environment or stdin
echo "passphrase" | persona import \
  backup.json \
  --decrypt \
  --mode merge \
  --yes
```

### Credential Operations (Non-Interactive)

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Add credential with all required fields
persona credential add \
  --identity "CI User" \
  --name "API Key" \
  --credential-type api_key \
  --secret "$API_KEY" \
  --yes

# List credentials in JSON format
export PERSONA_OUTPUT_FORMAT=json
persona credential list --identity "CI User"
```

### SSH Agent (Non-Interactive)

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Generate SSH key
persona ssh generate \
  --identity "CI User" \
  --name "Deployment Key" \
  --key-type ed25519

# Start agent in background
persona ssh start-agent &

# Export socket path
export SSH_AUTH_SOCK=$(cat ~/.persona/ssh-agent.sock)

# Use SSH
ssh git@github.com
```

## Docker Integration

### Dockerfile

```dockerfile
FROM rust:latest as builder

# Build persona
WORKDIR /build
COPY . .
RUN cargo build --release --bin persona

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /build/target/release/persona /usr/local/bin/

# Set environment variables
ENV PERSONA_NON_INTERACTIVE=1
ENV PERSONA_WORKSPACE_PATH=/persona
ENV PERSONA_OUTPUT_FORMAT=json
ENV PERSONA_NO_COLOR=1

# Create workspace directory
RUN mkdir -p /persona

# Entry point
ENTRYPOINT ["persona"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  persona-export:
    build: .
    environment:
      - PERSONA_NON_INTERACTIVE=1
      - PERSONA_MASTER_PASSWORD=${MASTER_PASSWORD}
      - PERSONA_OUTPUT_FORMAT=json
    volumes:
      - ./workspace:/persona
      - ./backups:/backups
    command: export --output /backups/backup.json
```

## Scripting Examples

### Bash Script

```bash
#!/bin/bash
set -euo pipefail

# Configuration
export PERSONA_NON_INTERACTIVE=1
export PERSONA_WORKSPACE_PATH="$HOME/.persona"
export PERSONA_OUTPUT_FORMAT="json"
export PERSONA_NO_COLOR=1

# Check if master password is set
if [ -z "${PERSONA_MASTER_PASSWORD:-}" ]; then
    echo "Error: PERSONA_MASTER_PASSWORD not set"
    exit 1
fi

# Export backup with timestamp
BACKUP_FILE="backup-$(date +%Y%m%d-%H%M%S).json"
persona export \
    --include-sensitive \
    --compression 9 \
    --encrypt \
    --output "$BACKUP_FILE"

echo "Backup created: $BACKUP_FILE"

# Upload to cloud storage (example)
# aws s3 cp "$BACKUP_FILE" s3://my-bucket/persona-backups/
# gcloud storage cp "$BACKUP_FILE" gs://my-bucket/persona-backups/
```

### Python Script

```python
#!/usr/bin/env python3
import os
import subprocess
import json
from datetime import datetime

# Configure non-interactive mode
os.environ['PERSONA_NON_INTERACTIVE'] = '1'
os.environ['PERSONA_OUTPUT_FORMAT'] = 'json'
os.environ['PERSONA_NO_COLOR'] = '1'

# Export credentials
result = subprocess.run(
    ['persona', 'credential', 'list', '--identity', 'CI User'],
    capture_output=True,
    text=True,
    check=True
)

# Parse JSON output
credentials = json.loads(result.stdout)

# Process credentials
for cred in credentials:
    print(f"Credential: {cred['name']}, Type: {cred['type']}")
```

## Error Handling

In non-interactive mode, the CLI will:

1. **Exit with non-zero code** on errors
2. **Output structured errors** in JSON format (if `PERSONA_OUTPUT_FORMAT=json`)
3. **Never prompt for input** - fail instead if required input is missing

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid command or arguments |
| 3 | Authentication failed |
| 4 | Workspace not initialized |
| 5 | Required input missing (in non-interactive mode) |

### JSON Error Format

```json
{
  "error": {
    "code": 5,
    "message": "Master password required but PERSONA_MASTER_PASSWORD not set",
    "details": "Run in interactive mode or set PERSONA_MASTER_PASSWORD environment variable"
  }
}
```

## Security Considerations

### Master Password Handling

⚠️ **Security Warning:** Setting `PERSONA_MASTER_PASSWORD` in environment variables can expose your password in:
- Process listings (`ps aux`)
- Shell history
- CI/CD logs
- Environment variable dumps

**Best Practices:**

1. **Use CI/CD secrets management:**
   - GitHub Actions: `${{ secrets.PERSONA_MASTER_PASSWORD }}`
   - GitLab CI: `$MASTER_PASSWORD` (protected variable)
   - Jenkins: `credentials('persona-master-password')`

2. **Clear environment variable after use:**
   ```bash
   unset PERSONA_MASTER_PASSWORD
   ```

3. **Use temporary files with restricted permissions:**
   ```bash
   echo "$MASTER_PASSWORD" > /tmp/pw
   chmod 600 /tmp/pw
   PERSONA_MASTER_PASSWORD=$(cat /tmp/pw) persona export ...
   rm /tmp/pw
   ```

4. **Avoid logging:**
   - Disable shell history: `set +o history`
   - Use `set -x` carefully (doesn't echo environment variables)

### Workspace Permissions

Ensure workspace directory has restricted permissions:

```bash
chmod 700 ~/.persona
chmod 600 ~/.persona/identities.db
```

## Troubleshooting

### Issue: "Interactive mode required"

**Cause:** Command requires user input but running in non-interactive mode.

**Solution:** Provide all required arguments via command-line flags.

```bash
# ❌ Missing arguments
persona add

# ✅ All arguments provided
persona add --name "User" --email "user@example.com" --yes
```

### Issue: "Master password required"

**Cause:** Workspace is encrypted but `PERSONA_MASTER_PASSWORD` not set.

**Solution:** Set the environment variable:

```bash
export PERSONA_MASTER_PASSWORD="your-password"
```

### Issue: "Workspace not found"

**Cause:** `PERSONA_WORKSPACE_PATH` points to non-existent directory.

**Solution:** Initialize workspace first:

```bash
export PERSONA_NON_INTERACTIVE=1
persona init --path /path/to/workspace --yes
```

## Testing Non-Interactive Mode

```bash
# Test non-interactive mode locally
export PERSONA_NON_INTERACTIVE=1
export PERSONA_OUTPUT_FORMAT=json

# This should work without prompts
persona list

# This should fail with clear error (no identity name)
persona add

# This should work (all required args)
persona add --name "Test" --email "test@example.com" --yes
```

## Related Documentation

- [Configuration Guide](./CONFIGURATION.md)
- [Environment Variables](./ENVIRONMENT_VARIABLES.md)
- [CI/CD Examples](./CI_CD_EXAMPLES.md)
- [Security Best Practices](./SECURITY.md)

---

**Note:** Non-interactive mode is designed for automation. For regular use, interactive mode provides better UX with prompts, confirmations, and helpful messages.
