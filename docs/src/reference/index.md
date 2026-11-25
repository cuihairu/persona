# Engineering Reference

Design documents, runbooks, and feature specs maintained at the repository
root (`docs/*.md`). They are mounted into the site from a **single source** —
the files you read here and the files in the GitHub repository are the same
files (edited once, visible in both places).

## Core design documents

| Document                                         | About                                              |
| ------------------------------------------------ | -------------------------------------------------- |
| [Threat Model](./THREAT_MODEL)                   | Assets, trust boundaries, STRIDE, periodic reviews |
| [E2EE Sync Design](./E2EE_SYNC_DESIGN)           | Sync protocol, key hierarchy, snapshot compaction  |
| [Supply Chain Security](./SUPPLY_CHAIN_SECURITY) | Dependency audits, license policy, CI gates        |
| [Key Hierarchy](./KEY_HIERARCHY)                 | Master key derivation and item-key wrapping        |
| [Reproducible Builds](./REPRODUCIBLE_BUILDS)     | Digest-pinned images, verifiable artifacts         |
| [Storage and Sync](./STORAGE_AND_SYNC)           | Local storage internals and sync state             |
| [Roadmap](./ROADMAP)                             | Milestones and detailed plan                       |

## More reference documents

[Wallet Design](./WALLET_DESIGN) · [Self-Host Server](./SELF_HOST_SERVER) ·
[Bridge Protocol](./BRIDGE_PROTOCOL) · [SSH Agent Features](./SSH_AGENT_FEATURES) ·
[Context-Aware Design](./CONTEXT_AWARE_DESIGN) · [Connect Automation](./CONNECT_AUTOMATION_DESIGN) ·
[Local Service](./LOCAL_SERVICE) · [Monorepo](./MONOREPO) ·
[External Integration](./EXTERNAL_INTEGRATION) · [Remote Auth](./REMOTE_AUTH) ·
[Non-Interactive Mode](./NON_INTERACTIVE_MODE) · [Client Communication Architecture](./CLIENT_COMMUNICATION_ARCHITECTURE) ·
[Sync Group Mode](./sync-group-mode) · [Cloud Drive Sync](./CLOUD_DRIVE_SYNC) ·
[Boundary](https://github.com/cuihairu/persona/blob/main/BOUNDARY.md) (repo root)

Point-in-time audit and review records live in
[docs/review](https://github.com/cuihairu/persona/tree/main/docs/review) on
GitHub.
