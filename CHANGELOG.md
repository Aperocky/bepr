# Changelog

### v0.3.3
- ⚙️  Add canonical client endpoint `/bepr/client/<client_id>`; legacy `/bepr/<client_id>` remains accepted for backwards compatibility
- 🔒 Reject reserved or ambiguous client IDs (`client`, `user`, paths containing `/`)
- 🛠️  Consolidate `read_line` and `read_ssh_string` into `util`

### v0.3.2
- 🔒 Restrict operator socket to owner-only permissions (0600) after bind
- 🔒 Add 30-second timeout on client authentication to prevent connection stalling
- 📝 Document persistent shell behavior and `stty sane` recovery

### v0.3.1
- ⚙️  Default server bind changed to `0.0.0.0:443` — `wss://` URLs no longer need a port

### v0.3.0
- 🔒 Add TLS 1.3 support — all client-server traffic is now encrypted over `wss://`
- 🔒 Enforce `wss://` in client config; `ws://` is not permitted except in end-to-end tests via `BEPR_INSECURE_SKIP_TLS_VERIFY`
- ⚙️  Add `tls_cert` and `tls_key` fields to server config
- ⚙️  TLS certificate reloaded every 5 minutes alongside public keys (picks up renewals without restart)

### v0.2.1
- ✨ Buffer pending client output so the initial shell prompt is visible on attach
- 🐛 Translate non-TTY piped input newlines for PTY shell input

### v0.2.0
- ✨ Spawn client shells inside a PTY with `pty-process`
- ✨ Put `bepr connect` terminal input into raw mode for PTY sessions
- 🐛 Remove the fake local `bepr connect` prompt

### v0.1.4
- 🐛 Make `exit` in the remote shell close `bepr connect`
- 🐛 Move the interactive `bepr connect` input prompt to stderr and reduce prompt/output interleaving
- ⚙️  Write packaged service logs to `/var/log/bepr/server.log` and `/var/log/bepr/client.log`
- 🧪 Add e2e coverage for interactive terminal prompt behavior

### v0.1.3
- ✨ Add local `$ ` prompt for interactive `bepr connect`
- ⚙️  Change the default server bind port to `25223`
- 📝 Add changelog

### v0.1.2
- ✨ Add server-side WebSocket heartbeat and stale-session cleanup
- ✨ `bepr list` now shows registered clients as `connected` or `disconnected`
- 🧪 Add e2e coverage for disconnect cleanup and reconnect

### v0.1.1
- 📦 Add GitHub Actions release assets for tag builds
- 📦 Build Linux deb/rpm artifacts for amd64 and arm64
- 📦 Build macOS pkg artifact

### v0.1.0
- 🚀 Initial release of `bepr`
- ✨ Single `bepr` binary with server mode, client mode, and operator commands
- ✨ Authenticated reverse shell over outbound WebSocket connections
- ✨ Multi-client server support with public-key based client registration
- ✨ Local operator IPC through `/tmp/bepr.sock`
- ✨ Optional remote operator access through SSH Unix socket forwarding
- 📦 Add systemd, launchd, deb, rpm, and pkg packaging
- 🧪 Add unit tests and end-to-end shell tunnel coverage
