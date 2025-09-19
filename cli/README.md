# Persona CLI

A powerful command-line interface for managing digital identities in the Persona system.

## Features

- 🆔 **Identity Management**: Create, edit, and remove digital identities
- 🔄 **Quick Switching**: Switch between identities seamlessly
- 📊 **Data Export/Import**: Backup and restore identity data
- 🔒 **Security**: Encrypted storage and secure operations
- 🎨 **Beautiful UI**: Colorful and intuitive command-line interface
- ⚡ **Fast**: Optimized for performance and responsiveness

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/persona.git
cd persona

# Build the CLI tool
cargo build --release --bin persona

# Install globally (optional)
cargo install --path cli
```

### Using Cargo

```bash
cargo install persona-cli
```

## Quick Start

### 1. Initialize Workspace

```bash
# Initialize a new persona workspace
persona init

# Initialize with custom path
persona init --workspace ~/my-personas
```

### 2. Create Your First Identity

```bash
# Interactive mode
persona add

# Quick mode
persona add personal --email john@example.com --type personal

# From file
persona add --from-file identity.json
```

### 3. List Identities

```bash
# List all identities
persona list

# List with details
persona list --detailed

# Filter by type
persona list --type work

# Search by name
persona list --search "john"
```

### 4. Switch Identity

```bash
# Switch to specific identity
persona switch work

# Interactive selection
persona switch --interactive

# Switch to previous identity
persona switch --previous
```

## Commands

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `init` | Initialize workspace | `persona init` |
| `add` | Create new identity | `persona add personal` |
| `list` | List identities | `persona list --type work` |
| `switch` | Switch active identity | `persona switch work` |
| `show` | Show identity details | `persona show personal` |
| `edit` | Edit identity | `persona edit personal --email new@email.com` |
| `remove` | Delete identity | `persona remove old-identity` |

### Data Management

| Command | Description | Example |
|---------|-------------|---------|
| `export` | Export identities | `persona export --format json` |
| `import` | Import identities | `persona import backup.json` |

### Global Options

| Option | Description | Example |
|--------|-------------|---------|
| `-v, --verbose` | Enable verbose logging | `persona -v list` |
| `-c, --config` | Custom config file | `persona -c ~/.persona/config.toml list` |

## Configuration

The CLI tool uses a configuration file located at `~/.persona/config.toml`:

```toml
[workspace]
default_path = "~/.persona"
auto_backup = true
backup_retention_days = 30

[security]
encryption_enabled = true
require_confirmation = true
session_timeout = 3600

[display]
default_format = "table"
show_sensitive = false
color_output = true

[sync]
enabled = false
server_url = ""
auto_sync = false
```

## Examples

### Basic Usage

```bash
# Initialize and create first identity
persona init
persona add personal --email john@personal.com --type personal

# Create work identity
persona add work --email john@company.com --type work --phone "+1234567890"

# List all identities
persona list

# Switch to work identity
persona switch work

# Show current identity details
persona show work
```

### Advanced Usage

```bash
# Export all identities to encrypted backup
persona export --format json --encrypt --output backup.json.enc

# Import with conflict resolution
persona import backup.json --mode merge --backup

# Edit identity interactively
persona edit personal --interactive

# Remove identity with confirmation
persona remove old-identity --force
```

### Batch Operations

```bash
# Export specific identities
persona export personal work --format yaml

# Import with dry run
persona import backup.json --dry-run

# List identities in JSON format
persona list --format json --output identities.json
```

## Identity Types

The CLI supports various identity types:

- **Personal**: Personal/private identities
- **Work**: Professional/work-related identities  
- **Social**: Social media and online presence
- **Financial**: Banking and financial services
- **Gaming**: Gaming platforms and accounts
- **Custom**: User-defined types

## Security Features

- 🔐 **Encryption**: All sensitive data is encrypted at rest
- 🔑 **Access Control**: Role-based permissions and access control
- 🛡️ **Secure Storage**: Protected configuration and data files
- 📝 **Audit Trail**: Comprehensive logging of all operations
- 🔒 **Session Management**: Automatic session timeout and cleanup

## Output Formats

The CLI supports multiple output formats:

- **Table**: Human-readable table format (default)
- **JSON**: Machine-readable JSON format
- **YAML**: YAML format for configuration files
- **CSV**: Comma-separated values for spreadsheets

## Error Handling

The CLI provides detailed error messages and suggestions:

```bash
$ persona switch nonexistent
Error: Identity 'nonexistent' not found

Available identities:
  • personal (Personal)
  • work (Work)
  
Suggestion: Use 'persona list' to see all identities
```

## Troubleshooting

### Common Issues

1. **Workspace not initialized**
   ```bash
   Error: Persona workspace not found
   Solution: Run 'persona init' to initialize workspace
   ```

2. **Permission denied**
   ```bash
   Error: Permission denied accessing workspace
   Solution: Check file permissions or run with appropriate privileges
   ```

3. **Identity conflicts**
   ```bash
   Error: Identity 'personal' already exists
   Solution: Use 'persona edit personal' or choose a different name
   ```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
persona -v command
```

### Reset Workspace

To completely reset your workspace:

```bash
# Backup first (optional)
persona export --output backup.json

# Remove workspace
rm -rf ~/.persona

# Reinitialize
persona init
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Support

- 📖 **Documentation**: [Full documentation](https://persona-docs.example.com)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/your-org/persona/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-org/persona/discussions)
- 📧 **Email**: support@persona.example.com