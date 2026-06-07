# Changelog

### v0.1.4
- ⚙️  Write packaged service logs to `/var/log/bepr/server.log` and `/var/log/bepr/client.log`

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
