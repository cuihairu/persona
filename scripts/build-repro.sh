#!/usr/bin/env bash
# 一键可复现构建：路径重映射 + tauri build --bundles deb + normalize-deb。
# 用法: scripts/build-repro.sh [输出.deb]（缺省仓库根 Persona_0.1.0_amd64.deb）
# 设计与实测见 docs/REPRODUCIBLE_BUILDS.md。注意 RUSTFLAGS 环境变量优先级
# 高于 .cargo/config.toml 的 target rustflags（当前配置仅 Windows 段，
# Linux 构建无损失）。
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$repo/Persona_0.1.0_amd64.deb}

# 时间戳锚定到当前 HEAD 提交时刻（非 git 环境退化为 0）
export SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)
# 构建机 $HOME 统一重映射：panic location 等不再携带真实用户路径，
# 跨机器（同工具链）编译产物趋于一致
export RUSTFLAGS="--remap-path-prefix=$HOME=/repro-home"

mkdir -p "$(dirname "$out")"
(cd "$repo/desktop" && ./node_modules/.bin/tauri build --bundles deb)
deb=$(find "$repo/desktop/src-tauri/target/release/bundle/deb" -name '*.deb' | head -1)
"$repo/scripts/normalize-deb.sh" "$deb" "$out"
echo "可复现产物: $out (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
