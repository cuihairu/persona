# Persona Client Communication & Storage Modes

This document explains how Persona’s clients (CLI, desktop/Tauri app, browser extension, SSH agent, and future mobile apps) communicate with the core vault, and how users can choose between local-only, self-hosted, or Persona-managed storage/sync options.

## Goals

1. **Single source of truth** – all clients talk to the same local workspace (encrypted SQLite + blob store) via a shared Rust core library.
2. **Consistent IPC boundary** – expose the core via a lightweight local service so every client reuses the same API surface.
3. **Transport parity** – use Unix Domain Sockets on every desktop platform (including Windows 10+), falling back to named pipes only when required.
4. **User-controlled sync** – keep the local vault functional without any server, while allowing optional sync adapters (self-hosted cloud or Persona server).

## Architecture Overview

```
             +------------------------------+
             | Persona Local Service (Rust) |
             | - Unlock/session state       |
             | - Workspace DB + blobs       |
             | - Audit/log pipeline         |
             +---------------+--------------+
                             ^
          Unix socket / pipe | RPC (Protobuf/JSON-RPC/etc.)
                             |
  +-----------+   +----------+----------+   +-------------------+
  | CLI       |   | Desktop / Tauri    |   | SSH Agent process  |
  +-----------+   +--------------------+   +-------------------+
         ^                    ^                         ^
         | Native messaging   | WebExtension bridge     |
  +------+---------+          |                         |
  | Browser add-on |----------+-------------------------+
  +----------------+
```

- The **local service** embeds the Rust core crate and exposes RPC commands (identity CRUD, credential ops, SSH signing, policy queries, etc.).
- **CLI** links a minimal client SDK that connects to the Unix socket for every command (avoids direct DB access).
- **Desktop app** either links the core via Tauri commands or, preferably, reuses the same IPC client to guarantee parity.
- **SSH agent** is a thin wrapper around the same service; it receives SSH protocol requests on one socket and forwards signing requests via the RPC channel.
- **Browser extensions** communicate through a Native Messaging host that proxies requests to the local service, so no secrets live inside browser storage.

## IPC Transport Strategy

- **Primary transport: Unix Domain Socket**  
  - macOS/Linux: standard paths under `~/Library/Application Support/Persona/run/` or `/run/user/<uid>/persona/`.  
  - Windows 10 build 17063+: Windows now supports `AF_UNIX`; we use `\\?\pipe\persona-<uid>.sock` style paths to keep semantics consistent.  
- **Fallback: Named Pipe (Windows)**  
  - Only required on legacy Windows versions (pre-17063) or corporate environments that forbid AF_UNIX.  
  - The same protocol messages run over the pipe without changes.
- **Security**  
  - Socket directory permissions are locked down to the current user.  
  - High-risk RPCs (e.g., revealing credentials, SSH signing) can trigger biometric or system-password prompts even after the socket connection is established.  
  - Clients may present a short-lived access token issued by the service to prevent untrusted local processes from invoking RPCs silently.

## Storage & Sync Modes

| Mode | Description | Notes |
|------|-------------|-------|
| Local-only | All data resides under `~/.persona` (or platform-specific path). No network calls. | Best for air-gapped usage. Backups handled manually or via OS-level snapshots. |
| Self-hosted cloud | Users can point Persona at their own iCloud Drive, Dropbox, WebDAV, or S3 bucket. The sync adapter pushes/pulls encrypted blobs; the service handles conflict resolution. | Cloud only sees ciphertext; encryption keys never leave the device. |
| Persona server (optional) | Connect to a Persona-managed or self-hosted server for realtime sync, approvals, and automation workflows. | Still zero-knowledge: payloads are envelope-encrypted locally before upload. |

### Sync Adapter Design

- The local service emits change events (e.g., item created, attachment updated) into a queue.  
- A sync worker (plugin) subscribes to events and handles upload/download for the selected mode.  
- Switching modes only swaps the adapter; the rest of the stack (CLI/Desktop/Browser) remains untouched.  
- Conflict resolution happens in the core library: multi-version concurrency control plus application-specific merge rules.

## Implementation Roadmap

1. **Extract service crate** – wrap `core` into a daemon exposing RPC handlers.  
2. **Client SDK** – provide a thin Rust crate (and Native Messaging host) for CLI/desktop/browser/agent to call the service.  
3. **Protocol spec** – document message schemas, version negotiation, and security requirements.  
4. **Transport rollout** – ship Unix socket support for macOS/Linux/Windows, with optional Named Pipe fallback.  
5. **Sync adapters** – implement `local`, `filesystem-cloud` (e.g., iCloud), and `persona-server` adapters, each using the same encrypted payload format.  
6. **Documentation & samples** – update README/docs to point contributors to this architecture, making it easier to add new clients or automations.

## References

- [`TODO.md`](../TODO.md) – tracking tasks for this document and related implementation.  
- [`docs/MONOREPO.md`](./MONOREPO.md) – overall repo layout where this service will live (likely under `core` + a new `service` crate).  
- [`docs/REMOTE_AUTH.md`](./REMOTE_AUTH.md) – complementary details for remote authentication flows that sit on top of this communication model.
