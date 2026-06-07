# bepr

Very small authenticated reverse shell pipe.

The client opens an outbound WebSocket to the server. The server already knows the
client public key. On connect, the server sends a random challenge and accepts the
connection only if the client signs that challenge with the matching Ed25519
private key. After that, the server can attach a local operator terminal and
both sides pipe raw bytes.

This is intentionally basic:

- no enrollment
- no discovery
- no multiplexing
- no PTY
- no persistence
- one operator terminal attached to one client connection at a time

## Build

```sh
cargo build --release
```

## Install layout

Recommended installed paths:

```txt
/usr/local/bin/bepr
/etc/bepr/client.conf
/etc/bepr/server.conf
/etc/bepr/keys/default.pub
/etc/bepr/keys/laptop.pub
/tmp/bepr.sock
```

`bepr client` reads `/etc/bepr/client.conf` by default. `bepr server` reads
`/etc/bepr/server.conf` by default. `bepr connect` and `bepr list` use
`/tmp/bepr.sock`.

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
key_dir = /etc/bepr/keys
```

Every `*.pub` file in `key_dir` is an allowed client. The client ID is the file
stem:

```txt
/etc/bepr/keys/default.pub  -> /agent/default
/etc/bepr/keys/laptop.pub   -> /agent/laptop
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

Server daemon:

```sh
bepr server
```

Client:

```sh
bepr client
```

Operator attach on the server machine:

```sh
bepr connect default
```

List connected clients from the server machine:

```sh
bepr list
```

Overrides:

```sh
bepr server --config ./server.conf
bepr client --config ./client.conf
```

Once attached, the `bepr connect` terminal stdin/stdout is piped to the selected
client shell.

## Operator IPC

The server listens on `/tmp/bepr.sock`, a local Unix socket. Operator commands
are one line of UTF-8 text terminated by `\n`.

List clients:

```txt
LIST\n
```

Response:

```txt
OK\n
<client_id>\t<idle|attached>\n
...
```

Attach to a client:

```txt
CONNECT <client_id>\n
```

Response:

```txt
OK\n
```

After `OK\n`, the connection switches to raw byte pipe mode. Bytes from the
operator socket go to the client shell stdin, and bytes from the client shell
stdout/stderr come back on the same socket.

Errors are one line:

```txt
ERR <message>\n
```
