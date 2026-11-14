#!/bin/sh
# Builds the three OpenWrt .ipk packages for persona (custos/meshlet
# precedent):
#   persona             musl static binary (persona-server) + procd init
#                       + UCI config, arch-specific
#   luci-app-persona    LuCI controller, settings page and status dashboard
#                       (arch all)
#   app-meta-persona    iStore app metadata (icon + app json), arch all
#
# Usage: build-ipk.sh <bin-dir> [out-dir] [--arch x86_64|aarch64] [--rel N]
#
# <bin-dir> must contain the release persona-server binary (e.g.
# target/x86_64-unknown-linux-musl/release). The package architecture is
# derived from the ELF (`file`); --arch overrides it. The .ipk container is
# the tar.gz layout (debian-binary + control.tar.gz + data.tar.gz as a
# single tar), the same form the custos/meshlet packages ship and which
# opkg on iStoreOS 24.10 installs.
#
# Zero-knowledge red line: the package ships NO credential material. The
# UCI config and control scripts only reference the (admin-managed,
# root-only) token file path; no token value is ever embedded.
set -eu

die() { printf 'build-ipk: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SRC="$SCRIPT_DIR"
REPO_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)

BINDIR=""
OUT="."
ARCH_OVERRIDE=""
REL_OVERRIDE=""
while [ $# -gt 0 ]; do
	case "$1" in
		--rel)
			[ $# -ge 2 ] || die "--rel requires a value"
			REL_OVERRIDE="$2"
			shift 2
			;;
		--arch)
			[ $# -ge 2 ] || die "--arch requires a value (x86_64|aarch64)"
			ARCH_OVERRIDE="$2"
			shift 2
			;;
		--*)
			die "unknown option: $1"
			;;
		*)
			if [ -z "$BINDIR" ]; then
				BINDIR="$1"
			else
				OUT="$1"
			fi
			shift
			;;
	esac
done

[ -n "$BINDIR" ] || die "usage: build-ipk.sh <bin-dir> [out-dir] [--arch x86_64|aarch64] [--rel N]"
[ -d "$BINDIR" ] || die "bin dir not found: $BINDIR"
[ -f "$BINDIR/persona-server" ] || die "missing binary in $BINDIR: persona-server"
[ -f "$SRC/app-meta/persona.json" ] || die "app-meta/persona.json missing"
[ -f "$REPO_DIR/desktop/src-tauri/icons/256x256.png" ] || die "desktop/src-tauri/icons/256x256.png missing"

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_DIR/Cargo.toml" | head -1)
[ -n "$VERSION" ] || die "cannot read version from Cargo.toml"
REL="${VERSION}-1"
[ -n "$REL_OVERRIDE" ] && REL="${VERSION}-${REL_OVERRIDE}"

if [ -n "$ARCH_OVERRIDE" ]; then
	case "$ARCH_OVERRIDE" in
		x86_64 | aarch64) ARCH="$ARCH_OVERRIDE" ;;
		*) die "unsupported --arch: $ARCH_OVERRIDE (expected x86_64|aarch64)" ;;
	esac
else
	# `file` reports the ELF machine, mapped to opkg's architecture names.
	ARCH=$(file -b "$BINDIR/persona-server" | sed -n 's/.*[, ]\(x86-64\|aarch64\).*/\1/p' | head -1)
	case "$ARCH" in
		x86-64) ARCH=x86_64 ;;
		aarch64) ARCH=aarch64 ;;
		*) die "unsupported binary architecture: $ARCH (pass --arch)" ;;
	esac
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# ---- persona (arch-specific) -----------------------------------------------
R="$STAGE/persona"
mkdir -p "$R/data/etc/init.d" "$R/data/etc/config" "$R/data/usr/bin" "$R/CONTROL"
cp "$SRC/etc/init.d/persona" "$R/data/etc/init.d/"
cp "$SRC/etc/config/persona" "$R/data/etc/config/"
cp "$BINDIR/persona-server" "$R/data/usr/bin/"
chmod 755 "$R/data/etc/init.d/persona" "$R/data/usr/bin/persona-server"

cat > "$R/CONTROL/conffiles" <<'EOF'
/etc/config/persona
/etc/init.d/persona
EOF
cp "$SRC/CONTROL/postinst" "$R/CONTROL/postinst"
cp "$SRC/CONTROL/prerm" "$R/CONTROL/prerm"
SIZE=$(du -sk "$R/data" | cut -f1)
cat > "$R/CONTROL/control" <<EOF
Package: persona
Version: $REL
Depends: libc
Source: https://github.com/cuihairu/persona
SourceName: persona
License: MIT
Section: net
SourceDateEpoch: 1794931200
Maintainer: cuihairu <chuihairu@gmail.com>
Architecture: $ARCH
Installed-Size: $SIZE
Description: Self-hosted zero-knowledge sync server (Rust + Axum + SQLite): relays encrypted persona data, backups and multi-device accounts. Ships no credentials; device tokens live in a root-only file configured after install.
 自托管 zero-knowledge 同步服务（Rust + Axum + SQLite）：中继分身密文、备份与多设备账号。包内不含任何凭据；设备令牌装好后写入 root-only 文件。
EOF

chmod 755 "$R"/CONTROL/postinst "$R"/CONTROL/prerm
mkdir -p "$OUT"
tar -czf "$R/control.tar.gz" -C "$R/CONTROL" ./control ./postinst ./prerm ./conffiles
# Whole-tree archive with directory entries: opkg's unpacker does not
# create missing parent directories for file-only members (the meshlet
# acceptance-router lesson: view/<app>/ missing -> status.htm "wfopen" fail).
tar -czf "$R/data.tar.gz" -C "$R/data" etc usr
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/persona_${REL}_${ARCH}.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/persona_${REL}_${ARCH}.ipk"

# ---- luci-app-persona (all) --------------------------------------------------
R="$STAGE/luci"
mkdir -p "$R/data/usr/lib/lua/luci/controller" "$R/data/usr/lib/lua/luci/model/cbi" \
	"$R/data/usr/lib/lua/luci/view/persona" "$R/CONTROL"
cp "$SRC/usr/lib/lua/luci/controller/persona.lua" "$R/data/usr/lib/lua/luci/controller/"
cp "$SRC/usr/lib/lua/luci/model/cbi/persona.lua" "$R/data/usr/lib/lua/luci/model/cbi/"
cp "$SRC/usr/lib/lua/luci/view/persona/status.htm" "$R/data/usr/lib/lua/luci/view/persona/"

cat > "$R/CONTROL/postinst" <<'EOF'
#!/bin/sh
# Drop the LuCI menu/index caches so the new controller routes are picked
# up without a reboot (idempotent; nothing to do when the cache is absent).
rm -f /tmp/luci-indexcache* 2>/dev/null || true
exit 0
EOF
cat > "$R/CONTROL/prerm" <<'EOF'
#!/bin/sh
exit 0
EOF
SIZE=$(du -sk "$R/data" | cut -f1)
cat > "$R/CONTROL/control" <<EOF
Package: luci-app-persona
Version: $REL
Depends: persona
Source: https://github.com/cuihairu/persona
SourceName: luci-app-persona
License: MIT
Section: net
SourceDateEpoch: 1794931200
Maintainer: cuihairu <chuihairu@gmail.com>
Architecture: all
Installed-Size: $SIZE
Description: LuCI interface for the persona server: settings page (UCI -> env wiring) and a live status dashboard (service state, port listen, database, recent logs).
 persona 服务的 LuCI 界面：设置页（UCI -> 环境变量映射）与实时状态面板（服务状态、端口监听、数据库、最近日志）。
EOF

chmod 755 "$R"/CONTROL/postinst "$R"/CONTROL/prerm
tar -czf "$R/control.tar.gz" -C "$R/CONTROL" ./control ./postinst ./prerm
# Whole-tree archive with directory entries (see the persona note above).
tar -czf "$R/data.tar.gz" -C "$R/data" usr
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/luci-app-persona_${REL}_all.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/luci-app-persona_${REL}_all.ipk"

# ---- app-meta-persona (all) — the iStore-facing metadata package ------------
R="$STAGE/meta"
mkdir -p "$R/data/usr/lib/opkg/meta" "$R/data/www/luci-static/resources/app-icons" \
	"$R/CONTROL"
# The manifest version tracks the workspace version at build time.
sed "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" \
	"$SRC/app-meta/persona.json" > "$R/data/usr/lib/opkg/meta/persona.json"
cp "$REPO_DIR/desktop/src-tauri/icons/256x256.png" \
	"$R/data/www/luci-static/resources/app-icons/persona.png"

cat > "$R/CONTROL/postinst" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$R/CONTROL/prerm" <<'EOF'
#!/bin/sh
exit 0
EOF
SIZE=$(du -sk "$R/data" | cut -f1)
cat > "$R/CONTROL/control" <<EOF
Package: app-meta-persona
Version: $REL
Depends: luci-app-persona
Source: https://github.com/cuihairu/persona
SourceName: app-meta-persona
License: MIT
Section: net
SourceDateEpoch: 1794931200
Maintainer: cuihairu <chuihairu@gmail.com>
Architecture: all
Installed-Size: $SIZE
Description: iStore app metadata for persona (icon and app manifest).
 persona 的 iStore 应用元数据（图标与应用清单）。
EOF

chmod 755 "$R"/CONTROL/postinst "$R"/CONTROL/prerm
tar -czf "$R/control.tar.gz" -C "$R/CONTROL" ./control ./postinst ./prerm
# Whole-tree archive with directory entries (see the persona note above).
tar -czf "$R/data.tar.gz" -C "$R/data" usr www
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/app-meta-persona_${REL}_all.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/app-meta-persona_${REL}_all.ipk"
