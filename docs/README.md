# Persona Docs

> [English](README.md) | [中文](README.zh.md)

**Master your digital identity. Switch freely with one click.**

This directory is the entry point for Persona's design and security documentation. Milestones: [ROADMAP](./ROADMAP.md). Daily tasks: [TODO](../TODO.md) at the repo root.

## Product & Boundaries

- [BOUNDARY](../BOUNDARY.md) – Product boundaries: definitions of Principal / Identity / identity material, and where the wallet sits (deferred: reach 1Password-grade password features first, then the wallet)
- [ROADMAP](./ROADMAP.md) – Milestones and priority policy
- [MONOREPO](./MONOREPO.md) – Monorepo layout and toolchain

## Benchmarking & Gaps

- [ONEPASSWORD_FEATURES](./ONEPASSWORD_FEATURES.md) – Full 1Password feature list (benchmark checklist)
- [FEATURE_GAP_ANALYSIS](./FEATURE_GAP_ANALYSIS.md) – Persona vs 1Password, current state
- [DOC_SOURCE_CONSISTENCY_AUDIT](./DOC_SOURCE_CONSISTENCY_AUDIT.md) – Docs-vs-source consistency audit table (three discrepancy buckets, 67 items, 2026-10-13; twin: [审计-文档一致性](./审计-文档一致性.md))

## Architecture

- [STORAGE_AND_SYNC](./STORAGE_AND_SYNC.md) – Storage and sync modes user guide (pure local / self-hosted Persona Server / end-to-end encrypted credential sync, including a two-device demo script / cold backup to cloud storage; backup-restore walkthrough and the consequences of failure)
- [CLIENT_COMMUNICATION_ARCHITECTURE](./CLIENT_COMMUNICATION_ARCHITECTURE.md) – Unified client communication architecture (CLI, desktop, browser and agent share one local service and one IPC protocol)
- [LOCAL_SERVICE](./LOCAL_SERVICE.md) – Local service, IPC transport (Unix socket preferred) and the three storage/sync modes (pure local / self-hosted cloud / Persona-server-assisted)
- [BRIDGE_PROTOCOL](./BRIDGE_PROTOCOL.md) – Browser extension Native Messaging protocol
- [NON_INTERACTIVE_MODE](./NON_INTERACTIVE_MODE.md) – Non-interactive mode guide for CI/CD
- [REMOTE_AUTH](./REMOTE_AUTH.md) – Remote authentication abstraction
- [KEY_HIERARCHY](./KEY_HIERARCHY.md) – Key hierarchy and KDF paths
- [E2EE_SYNC_DESIGN](./E2EE_SYNC_DESIGN.md) – E2EE sync design (stages 1–4 landed: device keys / SRP choice / group-key envelope / four conflict-resolution decisions — status and evidence in §10)
- [sync-group-mode](./sync-group-mode.md) – Sync-group mode (default sync method): dynamic-password + PAKE pairing with no accounts; implementation status marked per batch (S1 protocol + relay implemented, desktop wiring and S2+ not implemented)
- [SELF_HOST_SERVER](./SELF_HOST_SERVER.md) – Self-hosted server (deployment, environment variables, API endpoints)
- [CONNECT_AUTOMATION_DESIGN](./CONNECT_AUTOMATION_DESIGN.md) – Local Connect automation endpoint design (127.0.0.1 HTTP + scope tokens)
- [CONTEXT_AWARE_DESIGN](./CONTEXT_AWARE_DESIGN.md) – Context-aware identity suggestions design

## Security

- [THREAT_MODEL](./THREAT_MODEL.md) – Threat model and recurring security reviews
- [SSH_AGENT_FEATURES](./SSH_AGENT_FEATURES.md) – SSH Agent, full documentation
- [BIOMETRIC_HOOKS](./BIOMETRIC_HOOKS.md) – Biometric unlock abstraction
- [biometric-unlock-design](./biometric-unlock-design.md) – Biometric unlock design
- [PASSKEYS_DESIGN](./PASSKEYS_DESIGN.md) – Passkey (WebAuthn) design
- [PASSKEY_GATE_AUDIT](./PASSKEY_GATE_AUDIT.md) – Passkey gate audit
- [SUPPLY_CHAIN_SECURITY](./SUPPLY_CHAIN_SECURITY.md) – Supply-chain security checks

## Build & Release

- [REPRODUCIBLE_BUILDS](./REPRODUCIBLE_BUILDS.md) – Reproducible builds (pinned toolchain)
- [WINDOWS_INSTALLER](./WINDOWS_INSTALLER.md) – Windows installer
- [CONTRIBUTING](./CONTRIBUTING.md) – Contributing guide (Conventional Commits, PR requirements)
- [UNINSTALL](./UNINSTALL.md) – Uninstall and data retention (uninstall keeps data, reinstall resumes; explicit purge steps)

## Branding

- [branding](./branding/README.md) – Logo, wordmark, palette and usage guidelines

---

_The early scenario-analysis docs (scenarios-analysis / security-requirements) are no longer maintained separately; their content has been merged into [BOUNDARY](../BOUNDARY.md) and [THREAT_MODEL](./THREAT_MODEL.md)._
