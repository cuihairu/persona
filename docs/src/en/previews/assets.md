# Asset Inventory and Gap List

This page serves design and documentation maintenance: it records **where the
checked-in design assets came from and how they changed**, plus a **list of
views still missing assets** (to be added once delivered).

::: danger Asset red line
Never generate, redraw, or replace any SVG / design asset on your own. Views on
the gap list always wait for delivery from the design side; automated
walkthrough screenshots are not design prototypes and do not enter the asset
set.
:::

## Checked-in Assets (Provenance)

| Asset                       | Location (all tracked)                      | First checked in     | Latest change                                      | Dimensions | Notes                                                        |
| --------------------------- | ------------------------------------------- | -------------------- | -------------------------------------------------- | ---------- | ------------------------------------------------------------ |
| light-full.png              | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51 (2026-09-30) | Same as first check-in                             | 3200×2000  | Light theme full window (three-pane layout)                  |
| dark-full.png               | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51 (2026-09-30) | Same as first check-in                             | 3200×2000  | Dark theme full window                                       |
| light-sidebar.png           | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51 (2026-09-30) | Same as first check-in                             | 528×2000   | Light sidebar close-up (group navigation)                    |
| dark-sidebar.png            | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51 (2026-09-30) | Same as first check-in                             | 528×2000   | Dark sidebar close-up                                        |
| sidebar-before-redesign.png | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51 (2026-09-30) | Same as first check-in                             | 512×2000   | Sidebar form before the redesign (for comparison)            |
| persona-logo.svg            | `docs/src/public/persona-logo.svg`          | 1c85352 (2026-09-25) | 47e008a (2026-09-26) user-provided viewfinder icon | —          | Site favicon / nav / homepage hero                           |
| logo.svg                    | `docs/branding/logo.svg`                    | 1c85352 (2026-09-25) | 47e008a (2026-09-26) same as above                 | —          | Brand directory logo source                                  |
| wordmark-horizontal.svg     | `docs/branding/wordmark-horizontal.svg`     | 1c85352 (2026-09-25) | No further changes                                 | —          | Horizontal wordmark (`Persona 数钥`, the Chinese brand name) |

Two spots are easy to misread when reading the history:

- The commit subject of `1c85352` is a CI fix (Windows test hang, isolated step
  by step); the three SVGs hitched a ride into that commit — it is not a brand
  commit.
- The five PNGs are stored once each in `docs/branding/ui/` (source) and
  `docs/src/public/ui/` (site copy), and the two copies are **byte-identical**
  (same sha256). When an image changes, both sides must be synced, or the site
  and the brand directory will drift apart.

::: tip Asset conventions
For new PNG/JPG assets: put them in `docs/branding/ui/`, sync a copy to
`docs/src/public/ui/`, then add a caption row in both
[UI previews](/en/previews/ui) and this page. The site references them via
`/ui/*.png` (`base: /persona/` adds the prefix automatically).
:::

## Prototype Gap List (Waiting for Delivery)

The following key views have neither design prototype files
(`.fig`/`.sketch`/`.xd`/`.ai`/`.psd`) nor matching screenshots in the repo; they
will be added once the design side delivers:

| View                               | Current status                                 | Suggested delivery format                                                                         |
| ---------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| SSH Agent panel                    | No matching prototype / screenshot in the repo | PNG/JPG (both light and dark themes: managed key list, agent start/stop, signing approval dialog) |
| Settings · Security Center         | Same as above                                  | PNG/JPG (change master password, biometric unlock, auto-lock, travel mode)                        |
| Settings · Sync Devices            | Same as above                                  | PNG/JPG (device enrollment / authorization / revocation, conflict resolution queue)               |
| Item Detail · Reveal Secret        | Same as above                                  | PNG/JPG (masked → re-authentication → plaintext reveal flow, keeping the operation details)       |
| New / Edit Credential Dialog       | Same as above                                  | PNG/JPG (categorized fields, password generator, form validation error states)                    |
| Statistics / Security Watch        | Same as above                                  | PNG/JPG (in-vault metadata, weak / reused password detection)                                     |
| Quick Access                       | Same as above                                  | PNG/JPG (quick-lookup panel summoned by a global hotkey)                                          |
| CLI terminal sessions              | Same as above                                  | PNG/JPG (terminal recordings of key `persona` CLI commands, light or dark, one or both)           |
| Browser extension                  | Same as above                                  | PNG/JPG (fill suggestion popover, identity switching)                                             |
| Mobile (Android / iOS / HarmonyOS) | Same as above                                  | PNG/JPG (native UIs of all three platforms, key views)                                            |

The `docs/src/design/` directory exists but holds only text design documents
(`architecture.md`, `security.md`), not prototype assets; the `docs/` root also
carries twenty-some design/protocol Markdown files (`E2EE_SYNC_DESIGN.md`,
`PASSKEYS_DESIGN.md`, `THREAT_MODEL.md`, etc.), none of which are prototypes
either.

## Where Walkthrough Screenshots Stand

Runtime walkthroughs (`shots-walk*/` under `~/.cache/persona-ui-shots/`) produce
**automated regression screenshots**, used to verify that interaction flows
work end to end. They are **not design prototypes** and are not merged into the
`docs/` asset set.

## Dependency Update Track (Dependabot)

- The repo-level `.github/dependabot.yml` reached the default branch with
  `7b1c08a` (2026-10-02): 4 entries in total — npm `/`, npm `/docs`, cargo `/`,
  github-actions `/` — all weekly, dev-dependency grouping, PR prefix
  `build` / `ci` (dependabot's default `Bump …` titles fail this repo's
  semantic check in `conventional-commits.yml`, so the prefix must be set
  explicitly).
- **Proven in practice**: 3 minutes after the config landed, PRs #22–#32 were
  produced — 10 cargo ones (`argon2`, `sha2`, `ed25519-dalek`, `tokio-util`,
  `dirs`, etc.) and 1 actions one (`ci: bump dtolnay/rust-toolchain`), with the
  `build:` / `ci:` prefixes in their titles. A single cargo entry covers the
  whole workspace, so member crates' `Cargo.toml` files all appear in the PR.
- **The npm track is proven too**: 19 minutes after landing, PRs #33–#41 were
  produced — including a dev-deps grouped aggregate PR (19 updates at once,
  touching `package.json` in `desktop` / `website` / `browser/chromium-extension`
  plus the root `pnpm-lock.yaml`) and single-package PRs (`zod`,
  `react-hot-toast`, `tauri-apps/api`, etc.). This overturned the doubts from
  the landing phase: although the root `package.json` itself has 0
  dependencies, the pnpm workspace members (desktop 41 / website 9 /
  chromium-extension 7) are covered wholesale by the root entry and the
  lockfile is updated in sync — no per-package `directory` needed (that would
  instead trip the pnpm root-lockfile desync issue in dependabot-core #11135).
  The `/docs` entry with its independent npm lockfile had not produced a PR at
  the time (`vue` 3.5.38→3.5.43, `rimraf` 6.0.1→6.1.3 have in-range updates);
  a standalone entry queues further back, to be re-checked on the next weekly
  run.
- Platform-level security updates (`automated-security-fixes`) are a separate
  track on the repo-settings side; this file does not affect them, and they
  stay at their defaults.

## The docs Lockfile Rule

`docs/` is installed with npm (`npm ci` + `package-lock.json`) and must be
installed **standalone** (`--ignore-workspace`): installing from the root
workspace hits the root esbuild override and poisons the docs site build.
`docs.yml` has a guard step that fails outright once a `pnpm-lock.yaml` or
`yarn.lock` shows up under `docs/` — a second lockfile is guaranteed to drift.
