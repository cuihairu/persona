# Persona Monorepo

Persona is organized as a polyglot monorepo: Rust workspace for core/CLI/server/agents, JS workspace for desktop (Tauri+React), and shared docs.

Structure

- core (Rust crate) – crypto, storage, service layer
- cli (Rust crate) – user-facing CLI
- server (Rust crate) – optional sync/events API (Axum)
- agents/ssh-agent (Rust crate) – SSH Agent daemon (developer feature)
- connect-server (Rust crate) – local automation endpoint embedded in host apps
- desktop (Tauri+React app) – cross-platform desktop UI
- mobile – native clients (iOS, Android, HarmonyOS) sharing the `mobile/rust` bridge crate; no Flutter or other cross-platform UI layers (see `mobile/README.md`)
- docs – specs, roadmap, and design docs (see `docs/KEY_HIERARCHY.md` for crypto details, `docs/REMOTE_AUTH.md` for SRP auth, and `docs/BIOMETRIC_HOOKS.md`)

Tooling

- Rust: Cargo workspace (root Cargo.toml; members: `core`, `cli`, `server`, `agents/ssh-agent`, `connect-server`, `mobile/rust`)
- JS: pnpm workspace (root package.json; `desktop`, `browser/chromium-extension`, `website`)
- Makefile: convenience targets for common dev flows

Build

- Rust: `cargo build --workspace`
- JS workspaces: `pnpm install`
- Desktop: `pnpm --filter persona-desktop run dev`

Testing

- Build the whole workspace before running CLI integration tests:
  `cargo test -p persona-cli` does not rebuild `persona-ssh-agent`, and the
  SSH agent tests spawn the sibling binary found next to
  `target/debug/persona`. A stale agent (built before a newer migration
  landed) fails against fresh databases with a confusing
  `migration N was previously applied but is missing in the resolved
  migrations` error.

Contrib

- Follow Rust 2021 edition style; run `cargo fmt && cargo clippy`
- For desktop/browser, run ESLint + Jest via pnpm; PRs must include tests for core logic
