#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BIN="${BEPR_BIN:-$ROOT/target/release/bepr}"
VERSION="$(awk -F\" '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
ARCH="${BEPR_DEB_ARCH:-$(dpkg --print-architecture)}"
OUT="$ROOT/target/package"
WORK="$ROOT/target/package/debroot"

if [ ! -x "$BIN" ]; then
    echo "missing $BIN; run: cargo build --release --locked" >&2
    exit 1
fi

rm -rf "$WORK"
mkdir -p \
    "$WORK/DEBIAN" \
    "$WORK/usr/bin" \
    "$WORK/etc/bepr/keys" \
    "$WORK/lib/systemd/system" \
    "$OUT"

install -m 0755 "$BIN" "$WORK/usr/bin/bepr"
install -m 0644 "$ROOT/packaging/examples/server.conf" "$WORK/etc/bepr/server.conf.example"
install -m 0644 "$ROOT/packaging/examples/client.conf" "$WORK/etc/bepr/client.conf.example"
install -m 0644 "$ROOT/packaging/systemd/bepr.service" "$WORK/lib/systemd/system/bepr.service"

cat > "$WORK/DEBIAN/control" <<EOF
Package: bepr
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: bepr maintainers
Description: Small authenticated reverse shell pipe
EOF

cat > "$WORK/DEBIAN/conffiles" <<EOF
/etc/bepr/server.conf.example
/etc/bepr/client.conf.example
EOF

cat > "$WORK/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
EOF

cat > "$WORK/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
EOF

chmod 0755 "$WORK/DEBIAN/postinst" "$WORK/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$WORK" "$OUT/bepr_${VERSION}_${ARCH}.deb"
