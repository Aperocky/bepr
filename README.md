# bepr

Very small authenticated reverse shell pipe.

The client opens an outbound WebSocket to the server. The server already knows the
client public key. On connect, the server sends a random challenge and accepts the
connection only if the client signs that challenge with the matching Ed25519
private key. After that, both sides pipe raw bytes.

This is intentionally basic:

- no enrollment
- no discovery
- no multiplexing
- no PTY
- no persistence
- one operator terminal attached to one client connection

## Build

```sh
cargo build --release
```

## Install layout

Recommended installed paths:

```txt
/usr/local/bin/bepr-client
/usr/local/bin/bepr-server
/etc/bepr/client.conf
/etc/bepr/server.conf
/etc/bepr/keys/default.pub
```

The client reads `/etc/bepr/client.conf` by default when started without
arguments. The server reads `/etc/bepr/server.conf` by default when started
without arguments.

## Manual key setup

Create an Ed25519 keypair on the client machine:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

The client uses the private key path. Copy the public key file to the server,
for example as `/etc/bepr/keys/default.pub`.

## Config

`/etc/bepr/server.conf`:

```txt
bind = 0.0.0.0:8080
client = default, /etc/bepr/keys/default.pub
```

Each `client` line is:

```txt
client = <client_id>, <path_to_openssh_ed25519_public_key>
```

The client ID must match the URL path in the client config.

`/etc/bepr/client.conf`:

```txt
server = ws://server.example:8080/agent/default
private_key_path = /home/alice/.ssh/id_ed25519
shell = /bin/sh
```

The `server` value is the public WebSocket URL reachable from the client, not
the server bind address. The shell line is optional.

Server:

```sh
bepr-server
```

Client:

```sh
bepr-client
```

Overrides:

```sh
bepr-server --config ./server.conf
bepr-client --config ./client.conf
bepr-client ws://server.example:8080/agent/default <private_key_hex> /bin/sh
```

Once authenticated, the server terminal stdin/stdout is piped to the client shell.
