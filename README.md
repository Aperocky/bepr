# bepr

A tiny authenticated client/server reverse shell over outbound WebSocket connections.

Single binary cover all 3 mode: server mode, client mode, and operator mode. 1MB in size, 500K - 5M memory usage, virtual PTY so long as your target host has outbound internet access.

Why this came to be: I had to travel, and don't want to expose the computers at home to a dynamic IP or register/paid services. This tiny open source binary packed in all format that I need to consume solves the problem of remote access to home machines and the only requirement is to get one publicly available host in some cloud somewhere. bepr is packaged to covers needed platform support (rpm + dpkg + pkg).

![bepr connection model](assets/bepr-flow.svg)

This is intentionally basic:

- no enrollment
- no discovery
- no per-connection multiplexing
- multiple clients can be connected at once
- one shell/operator attachment per client at a time

This allows the same binary to serve all purpose and remain extremely compact at some setup cost, in the future if this gets more attention, setup can be improved via additional scaffolding.

## Usage

Go to https://github.com/Aperocky/bepr/releases to find the version of the package for your platform. download it and use these command to install

```sh
sudo installer -pkg bepr-<version>.pkg -target /
sudo dpkg -i bepr_<version>_<arch>.deb
sudo rpm -i bepr-<version>-<arch>.rpm
```

And now, depending on what your machine is for, you need to setup client and server at once together, since the binary work together but does not sync automatically (set up before you leave!)

```sh
ssh-keygen -t ed25519 -f /etc/bepr/keys/pi_zero
```

This would generate the private public key on the client host (a pi in this case).

Now on the server host, copy the private key you just created:

```txt
/etc/bepr/keys/mac_m1.pub   -> client ID laptop
/etc/bepr/keys/pi_zero.pub  -> client ID pi
```

Now you must create the config, note, under `/etc/bepr`, the installation already created `client.conf.example` and `server.conf.example`. You only need to create one of them:

Create the server config on the server machine:

```txt
# cat /etc/bepr/server.conf
bind = 0.0.0.0:25223
key_dir = /etc/bepr/keys
tls_cert = /etc/bepr/tls/cert.pem
tls_key  = /etc/bepr/tls/privkey.pem
```

Create the client config on the client machine. The path must use the same client ID as the public key filename on the server:

```txt
# cat /etc/bepr/client.conf
server = wss://server.example:25223/bepr/pi_zero
private_key_path = /etc/bepr/keys/pi_zero.pub
shell = /bin/sh
```

The `server` value is the public WebSocket URL reachable from the client. If the server has keys in $name.pub format in the key dir, url will be available under `domain:port/bepr/$name` path.

Now you are able to start the service, the installation do not start it due to the setup mentioned previously:

linux:
```sh
sudo systemctl enable --now bepr
```

mac:
```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bepr.plist
sudo launchctl enable system/com.bepr
sudo launchctl kickstart -k system/com.bepr
```

From the server machine, you can list registered clients and their state:

```sh
root@server.example:~# bepr list
laptop	disconnected
mac_m1	connected
pi_zero	connected
```

You may go start a PTY directly from this server:

```sh
bepr connect laptop
```

Once attached, the `bepr connect` terminal stdin/stdout is piped to the selected client shell. Client shells run inside a PTY, while the server remains a raw byte router. Multiple clients may be connected to the server at the same time, but a single client can only have one operator attached at a time.

To operate from another machine, forward the server's local operator socket with

```sh
ssh -N -L /tmp/bepr-remote.sock:/tmp/bepr.sock user@server.example
```

Then point operator commands at the forwarded local socket:

```sh
bepr list --socket /tmp/bepr-remote.sock
bepr connect --socket /tmp/bepr-remote.sock laptop
```

This keeps bepr's control socket local to the server. SSH handles remote access and authentication.

## Run Manually or Test

`bepr` binary can be manually ran without service/packaging with direct commands and arguments:

```sh
./bepr server --config $server_config_path
./bepr client --config $client_config_path
./bepr connect --socket $socket_file_path $destination
```

## Packaging

Packaging files live under `packaging/`.

GitHub Actions builds native Linux packages for x86_64 and arm64, plus a macOS
pkg, from `.github/workflows/package.yml`.

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
/var/log/bepr/
/lib/systemd/system/bepr.service      # deb
/usr/lib/systemd/system/bepr.service  # rpm
/Library/LaunchDaemons/com.bepr.plist # macOS pkg
```

Packages install service files but do not enable or start them.
