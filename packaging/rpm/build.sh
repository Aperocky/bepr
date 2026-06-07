#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BIN="$ROOT/target/release/bepr"
VERSION="$(awk -F\" '/^version = / { print $2; exit }' "$ROOT/Cargo.toml")"
OUT="$ROOT/target/package"
WORK="$ROOT/target/package/rpmroot"
SPEC="$ROOT/target/package/bepr.spec"

if [ ! -x "$BIN" ]; then
    echo "missing $BIN; run: cargo build --release --locked" >&2
    exit 1
fi

rm -rf "$WORK"
mkdir -p \
    "$WORK/usr/bin" \
    "$WORK/etc/bepr/keys" \
    "$WORK/usr/lib/systemd/system" \
    "$OUT"

install -m 0755 "$BIN" "$WORK/usr/bin/bepr"
install -m 0644 "$ROOT/packaging/examples/server.conf" "$WORK/etc/bepr/server.conf.example"
install -m 0644 "$ROOT/packaging/examples/client.conf" "$WORK/etc/bepr/client.conf.example"
install -m 0644 "$ROOT/packaging/systemd/bepr.service" "$WORK/usr/lib/systemd/system/bepr.service"

cat > "$SPEC" <<EOF
Name: bepr
Version: $VERSION
Release: 1%{?dist}
Summary: Small authenticated reverse shell pipe
License: MIT

%description
Small authenticated reverse shell pipe.

%post
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

%files
/usr/bin/bepr
%dir /etc/bepr
%dir /etc/bepr/keys
%config(noreplace) /etc/bepr/server.conf.example
%config(noreplace) /etc/bepr/client.conf.example
/usr/lib/systemd/system/bepr.service
EOF

rpmbuild \
    --define "_topdir $OUT/rpmbuild" \
    --define "_buildrootdir $OUT/rpmbuild/BUILDROOT" \
    --buildroot "$WORK" \
    -bb "$SPEC"

find "$OUT/rpmbuild/RPMS" -name 'bepr-*.rpm' -exec cp {} "$OUT/" \;
