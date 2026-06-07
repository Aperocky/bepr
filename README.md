# bepr

A tiny authenticated client/server reverse shell over outbound WebSocket
connections.

The client opens an outbound WebSocket to the server. The server already knows
the client public key. On connect, the server sends a random challenge and
accepts the connection only if the client signs that challenge with the matching
Ed25519 private key. After that, an operator on the server can attach a terminal
and both sides pipe raw bytes.

This is intentionally basic:

- no enrollment
- no discovery
- no PTY
- no persistence
- no per-connection multiplexing
- multiple clients can be connected at once
- one shell/operator attachment per client at a time

## Build

```sh
cargo build --release
```

## Usage

Install or copy the binary to both machines:

```txt
/usr/local/bin/bepr
```

Create an Ed25519 keypair on the client machine:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Copy the client public key to the server. The public key filename is the client
ID:

```txt
/etc/bepr/keys/laptop.pub   -> client ID laptop
/etc/bepr/keys/pi.pub       -> client ID pi
```

Create the server config on the server machine:

```txt
# /etc/bepr/server.conf
bind = 0.0.0.0:8080
key_dir = /etc/bepr/keys
```

Create the client config on the client machine. The path must use the same
client ID as the public key filename on the server:

```txt
# /etc/bepr/client.conf
server = ws://server.example:8080/agent/laptop
private_key_path = /home/alice/.ssh/id_ed25519
shell = /bin/sh
```

The `server` value is the public WebSocket URL reachable from the client, not
the server bind address. The shell line is optional.

Run the server:

```sh
bepr server
```

Run the client:

```sh
bepr client
```

From the server machine, list connected clients:

```sh
bepr list
```

Attach to a client:

```sh
bepr connect laptop
```

Once attached, the `bepr connect` terminal stdin/stdout is piped to the selected
client shell. Multiple clients may be connected to the server at the same time,
but a single client can only have one operator attached at a time.

Config overrides are available for manual testing:

```sh
bepr server --config ./server.conf
bepr client --config ./client.conf
```

## Run as Systemd/Launchd Service

The packaged Linux and macOS services choose the mode from config files:

```txt
/etc/bepr/server.conf exists only -> run bepr server
/etc/bepr/client.conf exists only -> run bepr client
both exist                     -> fail
neither exists                  -> fail
```

Packages install example configs only:

```txt
/etc/bepr/server.conf.example
/etc/bepr/client.conf.example
```

Copy exactly one example to the active config path, edit it, then enable the
service for that platform.

Linux:

```sh
sudo cp /etc/bepr/server.conf.example /etc/bepr/server.conf
sudo vi /etc/bepr/server.conf
sudo systemctl enable --now bepr
```

macOS:

```sh
sudo cp /etc/bepr/server.conf.example /etc/bepr/server.conf
sudo vi /etc/bepr/server.conf
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bepr.plist
sudo launchctl enable system/com.bepr
sudo launchctl kickstart -k system/com.bepr
```

For client mode, create `/etc/bepr/client.conf` instead.

## Packaging

Packaging files live under `packaging/`.

Build packages from an existing release binary:

```sh
cargo build --release --locked
packaging/deb/build.sh
packaging/rpm/build.sh
packaging/macos/build.sh
```

The packages install:

```txt
/usr/bin/bepr                         # deb/rpm
/usr/local/bin/bepr                   # macOS pkg
/etc/bepr/server.conf.example
/etc/bepr/client.conf.example
/etc/bepr/keys/
/lib/systemd/system/bepr.service      # deb
/usr/lib/systemd/system/bepr.service  # rpm
/Library/LaunchDaemons/com.bepr.plist # macOS pkg
```

Packages install service files but do not enable or start them.
