#!/usr/bin/env bash
# One-shot reproducible build: path remapping + tauri build --bundles deb + normalize-deb.
# Usage: scripts/build-repro.sh [output.deb] (defaults to Persona_0.1.0_amd64.deb at the repo root)
#       scripts/build-repro.sh --docker [output filename]
#         Runs the same flow inside a persona-repro container with a pinned
#         base image (the canonical cross-machine reproducible recipe, see the
#         "Build container" section of docs/REPRODUCIBLE_BUILDS.md): artifacts
#         land in the repo root, and the container engine can be overridden via
#         PERSONA_REPRO_RUNTIME (e.g. podman).
# Design and measurements are in docs/REPRODUCIBLE_BUILDS.md. Note that the
# RUSTFLAGS environment variable takes precedence over .cargo/config.toml's target
# rustflags (the current config has only a Windows section, so Linux builds
# lose nothing).
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)

# Container mode: build/reuse the image, then re-invoke this script inside the
# container (without --docker, the original path below runs). The separate
# CARGO_TARGET_DIR is the key point — the container's glibc differs from the
# host's and cargo's incremental fingerprints do not distinguish toolchain
# environments, so reusing the host's target/ would bake mismatched caches into
# the artifact. The mount point is fixed at /repo (the repo= resolution in this
# script then just works), and HOME=/root is constant inside the container, so
# the RUSTFLAGS remapping target is identical across hosts.
if [ "${1:-}" = "--docker" ]; then
  shift
  out_name=$(basename "${1:-Persona_0.1.0_amd64.deb}")
  runtime=${PERSONA_REPRO_RUNTIME:-docker}
  "$runtime" build -f "$repo/docker/Dockerfile.repro" -t persona-repro:latest "$repo"
  "$runtime" run --rm -v "$repo":/repo -w /repo \
    -e CARGO_TARGET_DIR=/tmp/repro-target \
    -e CI=true \
    persona-repro:latest \
    bash -c 'pnpm -C desktop install --frozen-lockfile --filter "persona-desktop..." && bash scripts/build-repro.sh "/repo/'"$out_name"'"'
  echo "容器内构建完成（宿主可见）: $repo/$out_name"
  exit 0
fi

out=${1:-$repo/Persona_0.1.0_amd64.deb}

# Anchor the timestamp to the current HEAD commit time (falls back to 0 outside git)
export SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)
# Remap the build machine's $HOME uniformly: panic locations etc. no longer
# carry real user paths, so artifacts compiled on different machines (same
# toolchain) converge
export RUSTFLAGS="--remap-path-prefix=$HOME=/repro-home"

mkdir -p "$(dirname "$out")"
(cd "$repo/desktop" && ./node_modules/.bin/tauri build --bundles deb)
deb=$(find "$repo/desktop/src-tauri/target/release/bundle/deb" -name '*.deb' | head -1)
"$repo/scripts/normalize-deb.sh" "$deb" "$out"
echo "可复现产物: $out (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
