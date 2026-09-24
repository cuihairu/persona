#!/usr/bin/env bash
# deb 产物规范化：把 tauri bundler 产物里的构建时间痕迹归零，使同一输入
# 两次构建产出逐字节相同的 deb（Reproducible builds 基线，见
# docs/REPRODUCIBLE_BUILDS.md）。处理三层：
#   1. ar 成员头 —— `ar -rD` 显式确定性模式（时间戳/uid/gid 归零）
#   2. control/data 的 tar —— 条目按名排序、mtime 统一为 SOURCE_DATE_EPOCH、
#      属主统一 root
#   3. gzip 头 —— `gzip -n` 不写 mtime/原始文件名
# 用法：scripts/normalize-deb.sh <in.deb> <out.deb>
#   SOURCE_DATE_EPOCH 缺省 0；权限位经 tar -p 原样保留（/usr/bin 的可执行位
# 不能丢），仅归一化时间与属主。
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "用法: $0 <in.deb> <out.deb>" >&2
  exit 2
fi

in=$1
out=$2
epoch=${SOURCE_DATE_EPOCH:-0}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cd "$work"
ar x "$(realpath "$in")"

for member in control data; do
  rm -rf "$member"
  mkdir "$member"
  # -p：非 root 也恢复权限位（默认 --no-same-permissions 会把 755 降成
  # 644，打出来的包 /usr/bin/persona 不可执行）
  tar -xpzf "$member.tar.gz" -C "$member"
  tar --sort=name --mtime="@$epoch" --owner=root:0 --group=root:0 \
      --numeric-owner -C "$member" -cf - . | gzip -n -9 > "$member.tar.gz.new"
  mv "$member.tar.gz.new" "$member.tar.gz"
done

# 输出路径可能恰在 in.deb 同目录：先落到临时名再替换
# （不能用 mktemp 预建空文件——GNU ar 的 r 操作会先校验既有文件是否
# 合法归档，空文件直接报 file format not recognized）
tmpout="$out.tmp$$"
ar -rD "$tmpout" debian-binary control.tar.gz data.tar.gz
mv "$tmpout" "$out"
