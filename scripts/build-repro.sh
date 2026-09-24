#!/usr/bin/env bash
# 一键可复现构建：路径重映射 + tauri build --bundles deb + normalize-deb。
# 用法: scripts/build-repro.sh [输出.deb]（缺省仓库根 Persona_0.1.0_amd64.deb）
#       scripts/build-repro.sh --docker [输出文件名]
#         在钉死基座的 persona-repro 容器内执行同款流程（跨机可复现的
#         正式口径，docs/REPRODUCIBLE_BUILDS.md「构建容器」节）：产物写到
#         仓库根，容器引擎可用 PERSONA_REPRO_RUNTIME 覆盖（如 podman）。
# 设计与实测见 docs/REPRODUCIBLE_BUILDS.md。注意 RUSTFLAGS 环境变量优先级
# 高于 .cargo/config.toml 的 target rustflags（当前配置仅 Windows 段，
# Linux 构建无损失）。
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)

# 容器模式：构建/复用镜像后，在容器内递归调用本脚本（无 --docker 走
# 下方原路径）。独立 CARGO_TARGET_DIR 是关键——容器与宿主的 glibc 不同
# 而 cargo 增量指纹不区分工具链环境，误复用宿主 target/ 会把异构缓存
# 编进产物；挂载点固定 /repo（脚本内 repo= 解析自然成立），容器内
# HOME=/root 恒定 → RUSTFLAGS 重映射目标跨宿主一致。
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
