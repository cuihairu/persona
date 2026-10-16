# Reproducible Builds

> [English](REPRODUCIBLE_BUILDS.md) | [中文](REPRODUCIBLE_BUILDS.zh.md)

Status: **deb artifacts are byte-for-byte reproducible on the same machine** (measured against the
2026-09-24 baseline); the toolchain is pinned (1.97.0), build-machine paths are remapped
(`scripts/build-repro.sh`), so cross-machine artifacts should match, but **true cross-machine
re-verification has not been done** (see "Remaining Gaps"). This document records the
measurement method, the measured data, and the re-verification commands.

## Scope

- Artifact: the `desktop/src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb` produced by `tauri build --bundles deb` (embedding a 46MB main binary + desktop/icon/polkit resources).
- Definition: **same-machine reproduction** (same machine, same toolchain, same source tree, only the time differs) is verified by measurement; cross-machine consistency has supporting evidence (path remapping + pinning) but has not been measured across machines.
- AppImage / rpm have been measured (content reproducible, byte-level not — see "Remaining Gaps" 4);
  dmg cannot be built on Linux (macOS-only toolchain); the Windows NSIS installer is untested.

## Measured Baseline (2026-09-24)

Method: two consecutive `tauri build --bundles deb` runs on the same source tree (before the second, `touch src-tauri/src/main.rs` to force recompiling the main crate + relinking), comparing artifacts layer by layer.

| Layer                                      | Result                                                                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Frontend `dist/` (tsc + vite build)        | **Byte-identical across both runs** (4 files, content-hash named, no timestamps)                                               |
| Binary `target/release/persona-desktop`    | **Byte-identical across both runs** (46,447,992 bytes; proven transitively by the normalized deb hash matching, see below)    |
| `debian-binary` ar member inside the deb   | Identical across both runs (fixed `2.0`)                                                                                       |
| `control.tar.gz` / `data.tar.gz` inside the deb | **Differ across the two runs** — the only differences are two: tar entry **mtime = build time** and tar entry **owner = build user**; entry order, paths, sizes, and permission bits are all identical |
| gzip headers (both tar.gz layers)          | Identical across both runs: the bundler already zeroes the gzip mtime and sets the OS byte to 0xff (tauri-bundler 2.x uses flate2, no time traces) |
| Raw deb as a whole                         | `d777883b…` vs `3fd1d15f…` (**not reproducible**; the only source is the tar-layer differences above)                          |

Conclusion: **all irreproducibility is concentrated in the tar mtime and owner at the deb packaging layer**; compilation and frontend artifacts are already deterministic.

## Normalization: `scripts/normalize-deb.sh`

A post-processing script zeroes out the tar-layer differences so two builds produce byte-identical debs:

```bash
tauri build --bundles deb
scripts/normalize-deb.sh \
  desktop/src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb \
  Persona_0.1.0_amd64.deb   # 规范化产物
```

Three layers of processing:

1. **`ar` member headers**: `ar -rD` explicit deterministic mode (zeroing member timestamps/uid/gid).
2. **`tar` content**: entries sorted by name, mtime unified to `SOURCE_DATE_EPOCH` (default 0), owner unified to `root:0`; permission bits preserved as-is via `tar -p` (the 755 on `/usr/bin/persona-desktop` must not be lost).
3. **`gzip` header**: `gzip -n` (writes no mtime and no original filename; this spot is already clean in the original artifact — the script guarantees immunity to upstream changes).

Measured: two raw-different debs normalize to the same
`29a0c8490a831b2c4b6b3222df7deb806956a8365123488a23d706fdc7f47797`;
`dpkg-deb --info` structural validation passes (control/md5sums intact).

### Re-verification Commands

```bash
# 两次构建（第二次前 touch 主入口强制重链），分别留档 raw deb
sha256sum <deb1> <deb2>                      # raw：预期不同
scripts/normalize-deb.sh <deb1> /tmp/n1.deb
scripts/normalize-deb.sh <deb2> /tmp/n2.deb
sha256sum /tmp/n1.deb /tmp/n2.deb            # 规范化后：预期相同
```

## One-Command Reproducible Build: `scripts/build-repro.sh`

Collapses the two steps above (remap + build + normalize) into a single command:

```bash
scripts/build-repro.sh [输出.deb]   # 缺省仓库根 Persona_0.1.0_amd64.deb
```

- `RUSTFLAGS="--remap-path-prefix=$HOME=/repro-home"`: panic locations and
  similar no longer carry the real user path (measured: `/home/<user>` ×1006 → **0**,
  all registry absolute paths ×916 become the `/repro-home` prefix) — with the same
  toolchain, cross-machine compilation artifacts converge. Opt-in: it applies only to
  this script's process; everyday `cargo build` is unaffected.
- `SOURCE_DATE_EPOCH` is anchored to the current HEAD commit time (degrades to 0 outside a git environment).
- Internally calls `normalize-deb.sh` to normalize the tar layer.

Measured (2026-09-24, pinned toolchain 1.97.0): the first round and the forced
recompile/relink round were about 10 minutes apart, and both normalized deb hashes are
`2cf482056afe1de58c89b96261b0c0f1dfd8e0708e8141f29658bc8fa347f7b9`.

## Build Container: `docker/Dockerfile.repro` + `--docker` Mode (2026-09-24)

The formal definition of cross-machine reproducibility: builds run **inside the same container**
on different host machines (with different glibc/linker/system libraries — this baseline host,
Ubuntu 26.04, is the example). Inside the container `$HOME` is always `/root`, so the
`RUSTFLAGS` remap target is constant across hosts.

```bash
scripts/build-repro.sh --docker                       # 产物写仓库根
PERSONA_REPRO_RUNTIME=podman scripts/build-repro.sh --docker   # podman 亦可
```

- Container contents: `debian:bookworm-slim` (digest-pinned, same base as Dockerfile.server)
  + tauri v2 official Linux dependencies + node 24 (via `COPY --from` of an official image,
  same major version as CI setup-node) + corepack with pnpm pinned to 10.22.0
  (`COREPACK_HOME` inside the image layer, so the container runs offline) + rustup 1.97.0
  (same version as `rust-toolchain.toml`; an upgrade means changing the toolchain file + rebuilding the image).
- **A separate `CARGO_TARGET_DIR=/tmp/repro-target` is a correctness prerequisite**: the container
  and host have different glibc, and cargo's incremental fingerprints do not distinguish toolchain
  environments, so accidentally reusing the host `target/` would bake a heterogeneous cache into
  the artifact. Container builds are therefore always full builds (the first compile takes about 15–25 minutes).
- Dependency installation: `pnpm install --frozen-lockfile` inside the container (the host's
  already-installed `node_modules` is mounted and reused — both are linux-x64, so binary
  compatible; a clean environment installs everything).
- Image rebuild: `docker build -f docker/Dockerfile.repro -t persona-repro .`; base-image
  upgrades follow the same digest lookup method as the "Container Pinning" section.

### In-Container Measurement (2026-09-24)

Three full builds (`--docker` mode; in-container cargo full build 9m40s–12m12s per round):

| Round | Configuration                        | Normalized artifact sha256 (first 8 chars) |
| ----- | ------------------------------------ | ------------------------------------------ |
| R1    | Initial image (no git)               | `211cc36a…`                                |
| R2    | Image + git (final verification)     | `000a5265…`                                |
| R3    | Same as R2 (re-verification, independent cargo cache) | `000a5265…` (**byte-identical to R2**) |

- Defect exposed and fixed by R1: debian slim has no git, so `build-repro.sh`'s
  `SOURCE_DATE_EPOCH` HEAD anchoring silently degraded to 0 — git is now in the
  image's required-packages list (after anchoring was restored the hash changed from
  `211cc36a…` to `000a5265…`, as expected: the tar mtime anchor differs).
- R2 == R3: two independent full builds under the same container definition, about 30
  minutes apart (the container `--rm` clears the cargo cache every time), produced
  byte-identical hashes — **same-machine reproduction inside the container passes**.
- The host-path artifact (`2cf48205…`, same SOURCE_DATE_EPOCH = HEAD but a different
  build environment) has a different hash, as expected — **the comparable cross-machine
  baseline is in-container builds**.
- The remaining half-step: "different physical machine × same container" re-verification
  (run `--docker` once on each of two machines; the `sha256sum` comparison should land
  at `000a5265…` — with the same HEAD the epoch is identical and artifacts should match),
  which needs a second machine to execute.

## Remaining Gaps (Written Honestly)

1. ~~Cross-machine path embedding~~ **closed** (2026-09-24): `scripts/build-repro.sh`
   remaps `$HOME` with `--remap-path-prefix`; measured in-binary `/home/<user>`
   count 1006 → 0, and all registry paths become a constant prefix.
2. ~~Toolchain not pinned~~ **closed** (2026-09-24): the root repo's `rust-toolchain.toml`
   pins 1.97.0 (rustup searches upward, so both workspaces are covered) + seven CI uses of
   `dtolnay/rust-toolchain@1.99.0` (five in `ci.yml` + two in `desktop-build.yml`,
   raised from 1.97.0 to 1.99.0 as of 2026-10-11, with officially supported version refs); an upgrade means changing both places together.
3. **Upstream bundler does not normalize**: tar mtime/owner is written by tauri-bundler; the
   repo side covers it with `normalize-deb.sh` post-processing. If upstream adds
   `SOURCE_DATE_EPOCH` support, the script can degrade to a validator.
4. **AppImage: content reproducible, byte-level not** (2026-09-24 A/B measured): two
   pure-packaging rounds of `tauri build --bundles appimage`, compared by unpacking layer by
   layer with unsquashfs — file contents are **byte-identical** (including the GTK3/webkit2gtk
   dependency libraries that linuxdeploy deploys into the package); the only difference is
   **846 inode mtimes** (= build time); and it propagates chain-style into the whole package:
   inode mtime → different squashfs bytes → the runtime ELF's `.digest_md5`
   section (the squashfs MD5 computed by appimagetool at packaging time, the 16 bytes at
   ELF offset 0xe3900) differs accordingly. Normalization would require repacking with
   `mksquashfs -all-time/-mkfs-fixed-time` and recomputing the digest section, or upstream
   appimagetool supporting `SOURCE_DATE_EPOCH` (long unmerged in AppImageKit) — **no repo-side
   hack was done**; deb remains the main deliverable reproducible artifact.

   **rpm: content reproducible, byte-level not** (2026-09-24 A/B measured, same method):
   two pure-packaging rounds of `tauri build --bundles rpm`; the whole-package comparison
   shows only **64 bytes of difference, all concentrated in the header area** —

   | Difference source                  | Location (tag)             | Measured                                                        |
   | ---------------------------------- | -------------------------- | --------------------------------------------------------------- |
   | SHA256 hex string in the signature header | sig tag 273 (64 chars ASCII) | 56/64 characters differ (the hashed object is the main header, which varies chain-wise with the timestamps below) |
   | Main header `BUILDTIME`            | tag 1006 (INT32)           | 403s apart across the two rounds, 2 bytes differ                |
   | Main header `FILEMTIMES`           | tag 1034 (INT32×5)         | the first 2 entries = packaging time (varies per round); the last 3 entries = static resource mtimes, unchanged |

   **The payload is byte-identical** (the whole-package cmp matches apart from the 64 bytes
   above). Same story as AppImage: every difference derives from build time, and normalization
   requires the upstream rpm header writer to respect `SOURCE_DATE_EPOCH`; no header-rewriting
   hack was done on the repo side. dmg cannot be built on Linux; untested.

5. **True cross-machine verification not done (only this half-step remains)**: remapping + pinning
   + build container are all in place, and **same-machine reproduction inside the container is
   measured passing** (2026-09-24; R2/R3 are two independent full builds with byte-identical
   hash `000a5265…`, see "In-Container Measurement"). The closing action = run
   `scripts/build-repro.sh --docker` once on each of two machines and compare `sha256sum`
   (with the same HEAD it should match `000a5265…` — SOURCE_DATE_EPOCH is git-anchored to the same commit).

## Dependency Input Pinning Status

- `Cargo.lock` ×2 (root workspace + desktop/src-tauri) committed;
- `pnpm-lock.yaml` committed; tauri-cli 2.12.1 / vite ^8.3.4 pinned by lockfiles;
- Static resources such as icons and polkit policy committed (no generated artifacts);
- **Container pinning (2026-09-24)**: both FROM lines of `docker/Dockerfile.server` are
  digest-pinned (closing the CI release surface's float) —
  - `rust:1-bookworm@sha256:93ce27a8…`
  - `debian:bookworm-slim@sha256:3783cc01…`

  What is pinned is the **system layer** (the parts that drift as upstream rebuilds: glibc,
  linker, preinstalled tools); the actual cargo version is unaffected — inside the builder,
  rustup reads the in-repo `rust-toolchain.toml` (pinned 1.97.0), so toolchain upgrades are
  decoupled from container digests. Note that with digests pinned, the runtime layer's apt
  packages are likewise frozen at the image point in time, and security patches enter with digest upgrades.

  Upgrade method (re-query the multi-arch index digest, then change the Dockerfile and the
  CI Docker job validates it immediately):

  ```bash
  # 以 rust:1-bookworm 为例；debian 换 scope 与 tag 即可
  token=$(curl -s 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/rust:pull' | jq -r .token)
  curl -sI -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    https://registry-1.docker.io/v2/library/rust/manifests/1-bookworm |
    grep -i docker-content-digest
  ```
