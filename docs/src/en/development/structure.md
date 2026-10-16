# Project Structure

## Monorepo Architecture

The project uses a **monorepo**: all related code lives in a single
repository, which makes code sharing, dependency management, and version
control straightforward.

```
persona/
├── docs/                  # Documentation site (VitePress) and design docs
├── core/                  # Rust core library (crypto, storage, auth, sync protocol)
├── cli/                   # Command-line client (reuses core)
├── desktop/               # Desktop app (Tauri + React, its own cargo workspace)
├── server/                # Optional sync server (Rust + Axum)
├── connect-server/        # Connect local automation endpoint (secrets automation)
├── agents/                # Agent processes (ssh-agent etc.)
├── browser/               # Browser extension and wasm components
├── mobile/                # Mobile (native iOS/Android/HarmonyOS projects, in-tree + CI)
├── website/               # Project website
├── scripts/               # Build and dev scripts
├── docker/                # Containerized deployment
├── Cargo.toml             # Rust workspace configuration
└── README.md              # Project README
```

## Architecture Design

### Layered Architecture

```
┌─────────────────────────────────────┐
│           User Interface            │
│  Desktop (Tauri+React) / CLI        │
│  Mobile (native Swift / Kotlin)     │
├─────────────────────────────────────┤
│           Business Logic            │
│         Core Library (Rust)         │
│  ┌─────────┬─────────┬─────────┐    │
│  │ Crypto  │ Storage │  Auth   │    │
│  └─────────┴─────────┴─────────┘    │
├─────────────────────────────────────┤
│           Data Storage              │
│  SQLCipher + filesystem encryption  │
├─────────────────────────────────────┤
│           System Interface          │
│  OS APIs + hardware security module │
└─────────────────────────────────────┘
```

### Tech Stack

#### Core Library (Rust)

- **Responsibilities**: core crypto, storage, and authentication logic
- **Strengths**: memory safety, high performance, cross-platform
- **Dependencies**: ring, argon2, aes-gcm, sqlx (SQLite goes through sqlx, no rusqlite)

#### Desktop App (Tauri + React)

- **Responsibilities**: desktop user interface
- **Strengths**: lightweight, secure, modern UI
- **Dependencies**: React, TypeScript, Tailwind CSS

#### Mobile App (native, planned)

- **Responsibilities**: mobile user interface
- **Technical decision**: iOS, Android, and HarmonyOS are each developed with
  **platform-native technology** — iOS Swift/SwiftUI (LocalAuthentication +
  CryptoKit Secure Enclave), Android Kotlin/Jetpack Compose (BiometricPrompt +
  Android Keystore), HarmonyOS ArkTS/ArkUI (userIAM userAuth + HUKS). No
  Flutter/Rust FFI middle layer: biometric unlock and key storage are deep
  platform features where only native APIs expose the full semantics, while a
  bridging layer just loses semantics and widens the attack surface. See
  `docs/biometric-unlock-design.md` §7.2.

#### Sync Server (Rust + Axum)

- **Responsibilities**: optional end-to-end encrypted sync
- **Strengths**: end-to-end encryption (the server only ever sees ciphertext),
  high performance
- **Dependencies**: axum, sqlx, tokio

## Data Flow Design

### Local Data Flow

```
User input → UI layer → Core library → Encrypted storage → Local database
```

### Cross-Device Sync Flow

```
Device A → end-to-end encryption → sync server → end-to-end decryption → Device B
```

### Security Boundaries

- **UI layer**: user interaction; never handles sensitive data
- **Core layer**: all cryptographic operations and sensitive-data handling
- **Storage layer**: persists encrypted data
- **Network layer**: transports encrypted data only

## Development Workflow

### Build Commands

```bash
# Build the core library
cargo build -p persona-core

# Desktop app in dev mode
pnpm --filter persona-desktop run tauri:dev

# Run the server
cargo run -p persona-server

# Run the full test suite
cargo test --workspace
```

### Dependency Management

- **Rust**: managed centrally as a Cargo workspace
- **Node.js**: pnpm workspace (root package.json + pnpm-workspace.yaml)

### Code Sharing Strategy

- **Core logic**: the Rust core library
- **Data models**: core models (the sync envelope protocol stays identical
  across platforms)
- **UI components**: implemented separately per platform (React on desktop,
  native on mobile)

## Security Considerations

### Code Isolation

- **Sensitive operations**: implemented in the core library only
- **UI layer**: never handles keys or sensitive data directly
- **Network layer**: transports encrypted data only

### Build Security

- **Dependency locking**: Cargo.lock, pnpm-lock.yaml
- **Security audits**: cargo audit, pnpm audit
- **Code signing**: release builds are digitally signed

### Runtime Security

- **Memory protection**: zeroize wipes sensitive data
- **Process isolation**: each component runs in its own process
- **Least privilege**: only the necessary permissions are requested

## Deployment Strategy

### Desktop App

- **Packaging**: Tauri bundle
- **Distribution**: GitHub Releases + app stores
- **Updates**: built-in auto-update

### Mobile App

- **Packaging**: native builds via Xcode / Android Studio
- **Distribution**: App Store + Google Play
- **Updates**: store-driven update mechanism

### Server

- **Containerization**: Docker deployment
- **Cloud platforms**: runs on the major clouds
- **Monitoring**: logging and performance monitoring

## Roadmap

The authoritative current status lives in the repo's `TODO.md` (each item
carries a completion date and how it was verified); only the phase split is
kept here:

1. **Desktop** (shipped and under continuous iteration): vault, encrypted
   storage, sync, SSH agent, passkey, biometric gating with hardware binding,
   the wrapper layer around them, and more
2. **Server and automation**: self-hosted sync server, Connect secrets
   automation
3. **Mobile**: native iOS / Android apps (including platform biometric unlock,
   see the technical decision above)
4. **Enterprise features**: team sharing, enterprise policy, audit reports

What this monorepo structure buys us:

1. **Unified management**: all code in one repository
2. **Code sharing**: the core library is reused by multiple clients
3. **Version alignment**: no version-skew problems across components
4. **Simpler CI/CD**: one unified build-and-deploy pipeline
5. **Easier refactoring**: cross-project refactors become practical
