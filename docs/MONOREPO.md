# Persona Monorepo

Persona is organized as a polyglot monorepo: Rust workspace for core/CLI/server/agents, JS workspace for desktop (Tauri+React), and shared docs.

Structure
- core (Rust crate) – crypto, storage, service layer
- cli (Rust crate) – user-facing CLI
- server (Rust crate) – optional sync/events API (Axum)
- agents/ssh-agent (Rust crate) – SSH Agent daemon (developer feature)
- desktop (Tauri+React app) – cross-platform desktop UI
- mobile (Flutter/Rust bridge placeholder) – future mobile app
- docs – specs, roadmap, and design docs (see `docs/KEY_HIERARCHY.md` for crypto details, `docs/REMOTE_AUTH.md` for SRP auth, and `docs/BIOMETRIC_HOOKS.md`)

Tooling
- Rust: Cargo workspace (root Cargo.toml)
- JS: pnpm workspace (root package.json; `desktop`, `browser/chromium-extension`)
- Makefile: convenience targets for common dev flows

Build
- Rust: `cargo build --workspace`
- JS workspaces: `pnpm install`
- Desktop: `pnpm --filter desktop run dev`

Contrib
- Follow Rust 2021 edition style; run `cargo fmt && cargo clippy`
- For desktop/browser, run ESLint + Jest via pnpm; PRs must include tests for core logic
