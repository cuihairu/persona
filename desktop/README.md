# Persona Desktop Application

A secure, cross-platform digital identity management application built with Tauri, React, and Rust.

## Features

### 🔐 Core Security
- **End-to-end encryption** using AES-256-GCM
- **Master password** protection with Argon2 hashing
- **Zero-knowledge architecture** - no plaintext data stored
- **Memory safety** with automatic sensitive data cleanup

### 👤 Identity Management
- **Multiple digital identities** (Personal, Work, Social, Financial, Gaming)
- **One-click identity switching**
- **Organized credential storage** by identity
- **Rich metadata** support (tags, notes, custom attributes)

### 🔑 Credential Types
- **Passwords** with security questions
- **Cryptocurrency wallets** with mnemonic phrases
- **SSH keys** with passphrase support
- **API keys** with permissions and expiration
- **Bank cards** and financial information
- **Server configurations** for DevOps
- **Digital certificates** and tokens
- **Two-factor authentication** codes

### 🎯 User Experience
- **Beautiful, modern UI** with Tailwind CSS
- **Fast search** across all credentials
- **Password generator** with customizable rules
- **Copy-to-clipboard** functionality
- **Security level indicators**
- **Favorite credentials** for quick access
- **Usage statistics** and insights

## Quick Start

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Node.js 18+ (install from [nodejs.org](https://nodejs.org/))
- npm or yarn

### Development Setup

1. **Clone and navigate to project**
   ```bash
   cd persona/desktop
   ```

2. **Install dependencies**
   ```bash
   # Install Node.js dependencies
   npm install

   # Install Tauri CLI if not already installed
   npm install -g @tauri-apps/cli
   ```

3. **Start development server**
   ```bash
   npm run tauri:dev
   ```

### Building for Production

```bash
# Build the application
npm run tauri:build

# The built application will be in src-tauri/target/release/bundle/
```

## Architecture

### Frontend (React + TypeScript)
- **React 18** with hooks and modern patterns
- **TypeScript** for type safety
- **Tailwind CSS** for styling
- **Zustand** for state management
- **React Hook Form** for forms
- **Headless UI** for accessible components

### Backend (Tauri + Rust)
- **Tauri** for native app wrapper
- **Persona Core** library for crypto and storage
- **SQLite** with encryption for data persistence
- **Async/await** throughout with Tokio

### Security Architecture
```
┌─────────────────────────────────────┐
│           Frontend (React)          │
│         Encrypted Display Only      │
├─────────────────────────────────────┤
│        Tauri Commands (Rust)        │
│         API Translation Layer       │
├─────────────────────────────────────┤
│      Persona Core Library           │
│   🔒 All Crypto Operations Here     │
├─────────────────────────────────────┤
│      Encrypted SQLite Database      │
│       No Plaintext Data Stored      │
└─────────────────────────────────────┘
```

## Usage Guide

### First Launch
1. **Set Master Password**: Choose a strong master password - this cannot be recovered
2. **Create Identity**: Start with your primary identity (Personal, Work, etc.)
3. **Add Credentials**: Begin storing your passwords, keys, and other sensitive data

### Identity Switching
- Use the identity switcher in the top toolbar
- Click to switch between identities instantly
- Create new identities for different contexts (work, personal, projects)

### Adding Credentials
1. **Click "Add Credential"** in the main interface
2. **Choose credential type** (Password, SSH Key, Crypto Wallet, etc.)
3. **Fill in details** - all sensitive data is encrypted before storage
4. **Set security level** to categorize importance
5. **Save** - data is immediately encrypted and stored

### Security Features
- **Auto-lock**: Application locks when closed
- **Copy protection**: Sensitive data copied to clipboard is automatically cleared
- **Security levels**: Visual indicators for credential importance
- **Audit trail**: Last accessed timestamps for all credentials

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + L` | Lock application |
| `Ctrl/Cmd + N` | New credential |
| `Ctrl/Cmd + F` | Search credentials |
| `Ctrl/Cmd + ,` | Open settings |
| `Escape` | Close modals |

## Configuration

### Database Location
- **Windows**: `%APPDATA%\\persona\\persona.db`
- **macOS**: `~/Library/Application Support/persona/persona.db`
- **Linux**: `~/.local/share/persona/persona.db`

### Custom Database Path
You can specify a custom database path during initialization for:
- **Portable installations**
- **Network storage** (with proper encryption)
- **Backup workflows**

## Security Best Practices

### Master Password
- Use a **unique, strong password** (16+ characters)
- Include **uppercase, lowercase, numbers, and symbols**
- Consider using a **passphrase** with multiple words
- **Never reuse** your master password elsewhere

### Backup Strategy
- **Export identities** regularly from the application
- Store backups in **encrypted storage** (separate from main database)
- Test backup restoration periodically
- Keep backups in **multiple locations**

### Operational Security
- **Lock the application** when stepping away
- Use **different identities** for different contexts
- Regularly **review and update** stored credentials
- **Monitor usage statistics** for unusual patterns

## Troubleshooting

### Common Issues

**Application won't start**
- Ensure all dependencies are installed
- Check that Rust and Node.js versions meet requirements
- Try `cargo clean` in the `src-tauri` directory

**Database corruption**
- Restore from a recent backup
- Check disk space and permissions
- Verify database file isn't locked by another process

**Performance issues**
- Check available RAM (application uses ~50-100MB)
- Ensure SSD storage for database
- Consider database vacuum if very large

### Getting Help
- Check the [GitHub Issues](https://github.com/cuihairu/persona/issues)
- Review the [Core Library Documentation](../core/examples/README.md)
- Join our community discussions

## Development

### Project Structure
```
desktop/
├── src/                    # React frontend
│   ├── components/         # UI components
│   ├── hooks/             # Custom React hooks
│   ├── stores/            # State management
│   ├── types/             # TypeScript definitions
│   └── utils/             # Helper functions
├── src-tauri/             # Rust backend
│   └── src/
│       ├── commands.rs    # Tauri command handlers
│       ├── types.rs       # Rust type definitions
│       └── main.rs        # Application entry point
└── dist/                  # Built frontend assets
```

### Contributing
1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** with proper tests
4. **Commit**: `git commit -m 'Add amazing feature'`
5. **Push**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Code Standards
- **Rust**: Follow `rustfmt` and `clippy` recommendations
- **TypeScript**: Use strict type checking
- **React**: Prefer hooks and functional components
- **CSS**: Use Tailwind utility classes

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

**⚠️ Security Notice**: This software is in active development. While we implement industry-standard security practices, please do not use for production-critical data without thorough testing in your environment.
