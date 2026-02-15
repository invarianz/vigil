# vigil

Accountability screenshot software for elementary OS.

vigil takes screenshots of your screen at random intervals and sends them to your accountability partner via Matrix (with end-to-end encryption). It works on both X11 and Wayland, including elementary OS 7 and 8.

## Features

- Random-interval screenshots that cannot be predicted
- Dual backend: XDG Desktop Portal (Wayland) and Gala D-Bus (X11)
- **Matrix transport**: sends screenshots directly to a private encrypted chat room -- no third-party server sees your data
- Optional HTTP endpoint upload for custom server setups
- Queues screenshots for delivery when offline, retries on startup
- Tamper detection: alerts your partner if the daemon is stopped, autostart is removed, or the binary is modified
- Heartbeat dead man's switch: silence = alert
- Systemd user service with watchdog and restart-on-kill
- Follows elementary OS Human Interface Guidelines
- Built with GTK 4 and Granite 7

## Architecture

vigil runs as two processes:

- **vigil-daemon**: headless systemd service that takes screenshots, sends them via Matrix, and monitors for tampering. Runs even when the GUI is closed.
- **vigil GUI**: thin GTK4 app that connects to the daemon over D-Bus. Shows status and settings.

## How Wayland screenshots work

On Wayland, vigil uses the XDG Desktop Portal Screenshot interface. The first time it takes a screenshot, the system shows a one-time permission dialog. Once the user grants access, all subsequent screenshots are taken silently. If the user revokes permission, vigil detects the failure and reports it to the accountability partner.

## Building

```bash
# Install dependencies (elementary OS 8 / Ubuntu 24.04)
sudo apt install valac meson libgranite-7-dev libgtk-4-dev \
  libjson-glib-dev libsoup-3.0-dev libportal-dev libportal-gtk4-dev

# Build
meson setup build
meson compile -C build

# Run tests
meson test -C build

# Run unit tests only
meson test -C build --suite unit

# Install
sudo meson install -C build

# Enable the daemon
systemctl --user enable --now vigil-daemon.service
```

## Usage: setting up with your accountability partner

### Step 1: Create Matrix accounts

Both you and your partner need a Matrix account. You can use any Matrix homeserver:

- **matrix.org** -- free, public registration at https://app.element.io
- **Self-hosted** -- run your own Conduit or Synapse server for maximum privacy

Your partner installs **Element** (free) on their phone (Android/iOS) or desktop.

### Step 2: Create a private room

1. In Element, create a new room
2. Set it to **Private** (invite only)
3. **Enable encryption** (this is the default in Element for private rooms)
4. Invite your partner to the room
5. Note the **Room ID** (click room name > Settings > Advanced > Internal room ID). It looks like `!abc123xyz:matrix.org`

### Step 3: Get an access token

Your vigil installation needs an access token to send messages as your Matrix user. The simplest way:

```bash
curl -X POST "https://matrix.org/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "m.login.password",
    "identifier": {"type": "m.id.user", "user": "YOUR_USERNAME"},
    "password": "YOUR_PASSWORD",
    "initial_device_display_name": "Vigil"
  }'
```

The response contains `"access_token": "syt_..."` -- copy this value.

### Step 4: Set up end-to-end encryption with pantalaimon

For E2EE, vigil talks to pantalaimon (a local encryption proxy) instead of the homeserver directly. Pantalaimon handles all the Olm/Megolm crypto transparently.

```bash
# Install pantalaimon
pip install pantalaimon

# Create config
mkdir -p ~/.config/pantalaimon
cat > ~/.config/pantalaimon/pantalaimon.conf << 'EOF'
[Default]
Homeserver = https://matrix.org
ListenAddress = localhost
ListenPort = 8009
IgnoreVerification = true
EOF

# Start pantalaimon (or set up as a systemd user service)
pantalaimon --config ~/.config/pantalaimon/pantalaimon.conf &

# Log in through pantalaimon to set up encryption keys
curl -X POST "http://localhost:8009/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "m.login.password",
    "identifier": {"type": "m.id.user", "user": "YOUR_USERNAME"},
    "password": "YOUR_PASSWORD",
    "initial_device_display_name": "Vigil"
  }'
```

Use the access token from this pantalaimon login (not the direct homeserver one).

### Step 5: Configure vigil

Open the vigil GUI, go to Settings, and fill in:

| Field | Value |
|---|---|
| Homeserver URL | `http://localhost:8009` (pantalaimon) or `https://matrix.org` (no E2EE) |
| Access token | The `syt_...` token from step 3 or 4 |
| Room ID | The `!abc123xyz:matrix.org` from step 2 |

Or configure via command line:

```bash
gsettings set io.github.invarianz.vigil matrix-homeserver-url 'http://localhost:8009'
gsettings set io.github.invarianz.vigil matrix-access-token 'syt_YOUR_TOKEN'
gsettings set io.github.invarianz.vigil matrix-room-id '!YOUR_ROOM_ID:matrix.org'
gsettings set io.github.invarianz.vigil monitoring-enabled true
```

### Step 6: Verify it works

Your partner should see messages appearing in the Element room:

- **Screenshots**: appear as images with timestamps
- **Heartbeats**: periodic status messages like `Vigil active | uptime: 2h 30m | screenshots: 15 | pending: 0`
- **Tamper alerts**: `ALERT [autostart_missing]: Autostart desktop entry is missing`

If vigil goes completely silent (killed, uninstalled), the **absence of heartbeats** is itself the alert.

### Step 7: Lock it down

Once everything is working, your accountability partner should verify:

1. The daemon is running: `systemctl --user status vigil-daemon.service`
2. Autostart is enabled: check that the daemon desktop entry exists in `/etc/xdg/autostart/`
3. The systemd service has `RefuseManualStop=true` and `Restart=always`

The daemon monitors its own integrity and alerts via Matrix if:
- The autostart entry is deleted or modified
- The systemd service is disabled
- The daemon binary is replaced
- Screenshot permission is revoked
- Monitoring is disabled via GSettings

## Configuration

All settings are stored via GSettings (`io.github.invarianz.vigil`):

| Setting | Description | Default |
|---|---|---|
| `matrix-homeserver-url` | Matrix homeserver or pantalaimon URL | (empty) |
| `matrix-access-token` | Matrix access token | (empty) |
| `matrix-room-id` | Matrix room ID for screenshots | (empty) |
| `endpoint-url` | Optional HTTP endpoint for uploads | (empty) |
| `api-token` | Optional HTTP Bearer token | (empty) |
| `min-interval-seconds` | Minimum time between screenshots | 120 (2 min) |
| `max-interval-seconds` | Maximum time between screenshots | 600 (10 min) |
| `max-local-screenshots` | Screenshots to keep locally | 100 |
| `monitoring-enabled` | Whether monitoring is active | false |
| `autostart-enabled` | Start at login | false |
| `heartbeat-interval-seconds` | Heartbeat ping interval | 60 (1 min) |
| `tamper-check-interval-seconds` | Tamper check interval | 120 (2 min) |

## Without E2EE (simpler setup)

If you trust your Matrix homeserver (e.g. you self-host it), you can skip pantalaimon entirely. Just point the homeserver URL directly at your server. The room will still be invite-only, but the homeserver operator could technically see the images.

For self-hosting, [Conduit](https://conduit.rs/) is a lightweight Matrix server that runs on a Raspberry Pi.

## Upload API (alternative to Matrix)

vigil can also POST screenshots as `multipart/form-data` to a custom HTTP endpoint:

- `screenshot`: PNG image file
- `timestamp`: ISO 8601 capture timestamp
- `device_id`: Stable UUID for this device

An `Authorization: Bearer <token>` header is sent if an API token is configured. Both Matrix and HTTP transports can be active simultaneously.

## License

GPL-3.0-or-later
