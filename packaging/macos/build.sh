#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BIN="$ROOT/target/release/bepr"
VERSION="$(awk -F\" '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
OUT="$ROOT/target/package"
WORK="$ROOT/target/package/pkgroot"

if [ ! -x "$BIN" ]; then
    echo "missing $BIN; run: cargo build --release --locked" >&2
    exit 1
fi

if ! command -v pkgbuild >/dev/null 2>&1; then
    echo "missing pkgbuild; run this on macOS with Xcode command line tools installed" >&2
    exit 1
fi

rm -rf "$WORK"
mkdir -p \
    "$WORK/usr/local/bin" \
    "$WORK/etc/bepr/keys" \
    "$WORK/etc/bepr/user-keys" \
    "$WORK/var/log/bepr" \
    "$WORK/Library/LaunchDaemons" \
    "$OUT"

install -m 0755 "$BIN" "$WORK/usr/local/bin/bepr"
install -m 0644 "$ROOT/packaging/examples/server.conf" "$WORK/etc/bepr/server.conf.example"
install -m 0644 "$ROOT/packaging/examples/client.conf" "$WORK/etc/bepr/client.conf.example"
install -m 0644 "$ROOT/packaging/examples/user.conf" "$WORK/etc/bepr/user.conf.example"
install -m 0644 "$ROOT/packaging/launchd/com.bepr.plist" "$WORK/Library/LaunchDaemons/com.bepr.plist"

pkgbuild \
    --root "$WORK" \
    --identifier "com.bepr" \
    --version "$VERSION" \
    --install-location "/" \
    --ownership recommended \
    "$OUT/bepr-${VERSION}.pkg"
