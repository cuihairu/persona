> [English](NON_INTERACTIVE_MODE.md) | **中文**

# CLI 非交互模式指南

Persona CLI 支持非交互（无头）模式，用于 CI/CD 流水线、自动化脚本以及其他无法与用户交互的场景。

## 环境变量

### 核心配置

| 变量                      | 描述                                                     | 示例                 | 默认         |
| ------------------------- | -------------------------------------------------------- | -------------------- | ------------ |
| `PERSONA_NON_INTERACTIVE` | 禁用所有交互提示                                         | `1` 或 `true`        | `false`      |
| `PERSONA_WORKSPACE_PATH`  | 工作区目录路径                                           | `/path/to/workspace` | `~/.persona` |
| `PERSONA_MASTER_PASSWORD` | 用于身份验证的主密码                                     | `your-password`      | -            |
| `PERSONA_DB_PATH`         | SSH agent 子进程的数据库路径覆盖项（CLI 配置不读取此项） | `/path/to/db.sqlite` | -            |

### 输出配置

| 变量                    | 描述         | 示例                                      | 默认    |
| ----------------------- | ------------ | ----------------------------------------- | ------- |
| `PERSONA_OUTPUT_FORMAT` | 输出格式     | `json`、`yaml`、`csv`、`table`            | `table` |
| `PERSONA_NO_COLOR`      | 禁用彩色输出 | `1` 或 `true`                             | `false` |
| `PERSONA_LOG_LEVEL`     | 日志级别     | `trace`、`debug`、`info`、`warn`、`error` | `info`  |

### 安全配置

| 变量                         | 描述          | 示例              | 默认   |
| ---------------------------- | ------------- | ----------------- | ------ |
| `PERSONA_ENCRYPTION_ENABLED` | 启用/禁用加密 | `true` 或 `false` | `true` |

## CI/CD 集成

### GitHub Actions

```yaml
name: Persona Backup

on:
  schedule:
    - cron: "0 0 * * *" # Daily at midnight

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

## 命令行用法

### 初始化工作区（非交互）

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Initialize encrypted workspace
persona init \
  --path /path/to/workspace \
  --yes \
  --encrypted
```

### 添加分身（非交互）

```bash
export PERSONA_NON_INTERACTIVE=1

# All values must be provided via command-line arguments
persona add "CI User" \
  --email "ci@example.com" \
  --identity-type "automation" \
  --yes
```

### 导出数据（非交互）

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

### 导入数据（非交互）

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Provide passphrase via environment or stdin
echo "passphrase" | persona import \
  backup.json \
  --decrypt \
  --mode merge \
  --force
```

### 凭据操作（非交互）

```bash
export PERSONA_NON_INTERACTIVE=1
export PERSONA_MASTER_PASSWORD="your-password"

# Add credential with all required fields
persona credential add \
  --identity "CI User" \
  --name "API Key" \
  --credential-type api_key \
  --secret "$API_KEY"

# List credentials in JSON format
export PERSONA_OUTPUT_FORMAT=json
persona credential list --identity "CI User"
```

### SSH agent（非交互）

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

# Option 1: export the socket for generic ssh tooling
export SSH_AUTH_SOCK=$(cat "${PERSONA_AGENT_STATE_DIR:-$HOME/.persona}/ssh-agent.sock")
ssh git@github.com

# Option 2: use Persona's wrapper, which injects SSH_AUTH_SOCK automatically
persona ssh run --host github.com -- ssh git@github.com
```

## Docker 集成

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
version: "3.8"

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

## 脚本示例

### Bash 脚本

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

### Python 脚本

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

## 错误处理

在非交互模式下，CLI 会：

1. 出错时**以非零退出码退出**
2. **抑制交互式确认提示**（`ui.confirm`）——多数命令接受 `--yes`/`--force` 以跳过确认
3. **文本输入提示仍会触发**——`PERSONA_NON_INTERACTIVE` 只设置 `ui.interactive = false`（cli/src/config/mod.rs:140）；需要命令行未提供的值的命令（例如不带 `--note`/`--secret` 的 `credential add`）仍会调用 `ui.input` → dialoguer `interact_text()`（cli/src/utils/terminal_ui.rs:16）。请在命令行上提供所有必填字段，否则在非 TTY stdin 上提示会阻塞或失败。

### 退出码

| 退出码 | 含义                                           |
| ------ | ---------------------------------------------- |
| 0      | 成功                                           |
| 1      | 错误（任何失败：参数错误、身份验证、输入缺失） |

目前所有失败都汇集到一条路径：错误消息打印到 stderr，进程以 1 退出。目前还没有机器可读的错误封装，也没有按原因区分的退出码——需要区分错误类型的脚本应对消息文本做匹配。

## 安全注意事项

### 主密码处理

⚠️ **安全警告：** 在环境变量中设置 `PERSONA_MASTER_PASSWORD` 可能使你的密码暴露在：

- 进程列表（`ps aux`）
- Shell 历史
- CI/CD 日志
- 环境变量转储

**最佳实践：**

1. **使用 CI/CD 机密管理：**
   - GitHub Actions：`${{ secrets.PERSONA_MASTER_PASSWORD }}`
   - GitLab CI：`$MASTER_PASSWORD`（受保护变量）
   - Jenkins：`credentials('persona-master-password')`

2. **使用后清除环境变量：**

   ```bash
   unset PERSONA_MASTER_PASSWORD
   ```

3. **使用受限权限的临时文件：**

   ```bash
   echo "$MASTER_PASSWORD" > /tmp/pw
   chmod 600 /tmp/pw
   PERSONA_MASTER_PASSWORD=$(cat /tmp/pw) persona export ...
   rm /tmp/pw
   ```

4. **避免日志泄露：**
   - 禁用 shell 历史：`set +o history`
   - 谨慎使用 `set -x`（它不回显环境变量）

### 工作区权限

确保工作区目录具有受限权限：

```bash
chmod 700 ~/.persona
chmod 600 ~/.persona/identities.db
```

## 故障排查

### 问题："Interactive mode required"

**原因：** 命令需要用户输入，但运行在非交互模式。

**解决方案：** 通过命令行标志提供所有必填参数。

```bash
# Fails — missing arguments
persona add

# Passes — all arguments provided
persona add --name "User" --email "user@example.com" --yes
```

### 问题："Master password required"

**原因：** 工作区已加密但未设置 `PERSONA_MASTER_PASSWORD`。

**解决方案：** 设置环境变量：

```bash
export PERSONA_MASTER_PASSWORD="your-password"
```

### 问题："Workspace not found"

**原因：** `PERSONA_WORKSPACE_PATH` 指向不存在的目录。

**解决方案：** 先初始化工作区：

```bash
export PERSONA_NON_INTERACTIVE=1
persona init --path /path/to/workspace --yes
```

## 测试非交互模式

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

## 相关文档

- [威胁模型](./THREAT_MODEL.md)
- [自托管服务器](./SELF_HOST_SERVER.md)
- [README](../README.md) – CLI 用法示例（每个命令的非交互标志）

---

**注：** 非交互模式为自动化而设计。日常使用时，交互模式提供更好的 UX，带有提示、确认和有用的消息。
