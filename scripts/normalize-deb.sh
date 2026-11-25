#!/usr/bin/env bash
# deb artifact normalization: zero out the build-time traces in the tauri
# bundler's output so that the same input produces a byte-for-byte identical
# deb across two builds (Reproducible builds baseline; see
# docs/REPRODUCIBLE_BUILDS.md). Three layers are handled:
#   1. ar member headers — `ar -rD` explicit deterministic mode (timestamps/uid/gid zeroed)
#   2. control/data tar — entries sorted by name, mtime normalized to
#      SOURCE_DATE_EPOCH, ownership normalized to root
#   3. gzip headers — `gzip -n` omits the mtime/original filename
# Usage: scripts/normalize-deb.sh <in.deb> <out.deb>
#   SOURCE_DATE_EPOCH defaults to 0; permission bits are preserved as-is via
#   tar -p (the /usr/bin executable bit must not be lost); only times and
#   ownership are normalized.
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
  # -p: restore permission bits even when not root (the default
  # --no-same-permissions downgrades 755 to 644, leaving /usr/bin/persona in the
  # built package non-executable)
  tar -xpzf "$member.tar.gz" -C "$member"
  tar --sort=name --mtime="@$epoch" --owner=root:0 --group=root:0 \
      --numeric-owner -C "$member" -cf - . | gzip -n -9 > "$member.tar.gz.new"
  mv "$member.tar.gz.new" "$member.tar.gz"
done

# The output path may sit in the same directory as in.deb: write to a temp name
# and then replace (do not pre-create an empty file with mktemp — GNU ar's r
# operation validates that an existing file is a legal archive, and an empty
# file fails immediately with file format not recognized)
tmpout="$out.tmp$$"
ar -rD "$tmpout" debian-binary control.tar.gz data.tar.gz
mv "$tmpout" "$out"
