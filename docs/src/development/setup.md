# Setup

The toolchain and steps needed to build Persona (CLI + SSH Agent + desktop app)
from source. Version requirements follow the repo's own pins — nothing here is
guessed from generic advice.

## Prerequisites

| Tool              | Version                               | Notes                                                                                   |
| ----------------- | ------------------------------------- | --------------------------------------------------------------------------------------- |
| Rust              | **1.97.0** (repo-pinned)              | Install [rustup](https://rustup.rs); the version switches automatically inside the repo |
| Node.js           | 24 (same major version as CI)         | Frontend builds and scripts                                                             |
| pnpm              | 10.22.0 (pinned via `packageManager`) | Aligns automatically after `corepack enable pnpm`                                       |
| Tauri system deps | webkit2gtk / gtk3 etc.                | Desktop app only; on Linux see the apt list below                                       |
| docker / podman   | any recent version                    | Optional — server images and reproducible build containers                              |

Linux desktop build dependencies (Debian/Ubuntu):

```bash
sudo apt install build-essential libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev
```

## Clone and Build

```bash
git clone git@github.com:cuihairu/persona.git
cd persona

# Rust side: CLI + server + SSH agent (rustup picks 1.97.0 from rust-toolchain.toml automatically)
cargo build --workspace

# JS side: desktop app + browser extension
corepack enable pnpm
pnpm install
```

## Run It

```bash
# CLI: initialize an encrypted workspace
cargo run -p persona-cli -- init --path ~/Persona --yes --encrypted \
  --master-password "your-master-password"

# Desktop app in dev mode
pnpm --filter persona-desktop run dev
```

The CLI and the desktop app share the same vault format and can be mixed
freely (see Quick Start).

## Quality Gates (Same Bar as CI)

```bash
make ci                        # the full set: install + lint + test + vulnerability scan

# Formatting: two scopes (desktop is a standalone workspace, so run both)
cargo fmt --all
cargo fmt                      # run again inside desktop/src-tauri/

# Clippy: warnings are failures
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --all-targets -- -D warnings   # run again inside desktop/src-tauri/
```

> A full Rust test run takes roughly 12–16 minutes (it is dense with Argon2
> key derivation). Before touching CI, save time by running just the relevant
> crate with `cargo test -p <crate>`.

## Build Artifacts

- **Reproducible deb**: `scripts/build-repro.sh` (or add `--docker` to build
  inside the standard container). Details in
  [REPRODUCIBLE_BUILDS.md](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md).
- **Server image**: `docker build -f docker/Dockerfile.server .`

## Next Steps

- Project Structure — the monorepo layout and
  crate responsibilities
- [Engineering docs](https://github.com/cuihairu/persona/tree/main/docs) — the
  full set of design documents
