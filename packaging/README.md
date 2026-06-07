# bepr packaging

This directory contains basic packaging files for the single `bepr`
binary.

The packages install:

```txt
/usr/bin/bepr
/etc/bepr/keys/
/etc/bepr/client.conf.example
/etc/bepr/server.conf.example
```

The deb wrapper installs `bepr.service` under `/lib/systemd/system/`. The rpm
wrapper installs it under `/usr/lib/systemd/system/`.

The macOS pkg wrapper installs `com.bepr.plist` under
`/Library/LaunchDaemons/`.

The server uses `/tmp/bepr.sock` for local operator IPC.

## Build the binary

Build the release binary first:

```sh
cargo build --release --locked
```

## Build a deb

```sh
packaging/deb/build.sh
```

The package is written to `target/package/`.

## Build an rpm

```sh
packaging/rpm/build.sh
```

The package is written to `target/package/`.

## Build a macOS pkg

```sh
packaging/macos/build.sh
```

The package is written to `target/package/`. The build script must run on macOS
with `pkgbuild` available.

Install it with:

```sh
sudo installer -pkg target/package/bepr-<version>.pkg -target /
```

## Services

The packages install, but do not enable or start, one service:

```sh
systemctl enable --now bepr
```

Before starting it, create exactly one active config:

```sh
cp /etc/bepr/server.conf.example /etc/bepr/server.conf
# or
cp /etc/bepr/client.conf.example /etc/bepr/client.conf
```

Edit the copied config before enabling the service.

If `/etc/bepr/server.conf` exists, `bepr.service` runs `bepr server`. If
`/etc/bepr/client.conf` exists, it runs `bepr client`. If both exist or neither
exists, the service exits with an error.

On macOS, use launchd after creating exactly one active config:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bepr.plist
sudo launchctl enable system/com.bepr
sudo launchctl kickstart -k system/com.bepr
```

Stop it with:

```sh
sudo launchctl bootout system/com.bepr
```
