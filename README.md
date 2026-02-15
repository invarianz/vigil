# vigil

Accountability screenshot software for elementary OS.

vigil takes screenshots of your screen at random intervals and sends them to your accountability partner via Matrix with native end-to-end encryption. It works on both X11 and Wayland, including elementary OS 7 and 8.

## Features

- Random-interval screenshots that cannot be predicted
- Dual backend: XDG Desktop Portal (Wayland) and Gala D-Bus (X11)
- **Native E2EE**: built-in Olm/Megolm encryption via libolm -- no external proxy needed
- **One-button setup**: enter homeserver, username, password, partner ID, and E2EE password -- one click does login, room creation, key exchange, and encryption setup
- **Matrix transport**: sends screenshots to a private encrypted chat room -- no third-party server sees your data
- Queues screenshots for delivery when offline, retries on startup
- Tamper detection: alerts your partner if the daemon is stopped, autostart is removed, settings are changed, E2EE is disabled, or the binary is modified
- Heartbeat dead man's switch: silence = alert
- Systemd user service with watchdog and restart-on-kill
- Follows elementary OS Human Interface Guidelines
- Built with GTK 4 and Granite 7

## Architecture

vigil runs as two processes:

- **vigil-daemon**: headless systemd service that takes screenshots, encrypts them with Megolm, sends them via Matrix, and monitors for tampering. Runs even when the GUI is closed.
- **vigil GUI**: thin GTK4 app that connects to the daemon over D-Bus. Shows status and settings. Handles one-time setup (login, room creation, E2EE initialization).

### E2EE flow

1. GUI creates an OlmAccount and uploads device keys to the homeserver
2. A Megolm outbound group session is created for room encryption
3. Partner's device keys are queried and one-time keys claimed
4. The Megolm room key is Olm-encrypted per-device and sent via to-device messages
5. All outgoing messages and screenshots are Megolm-encrypted
6. Crypto state is pickled (encrypted with the E2EE password) and persisted to disk
7. The daemon restores the pickled state on startup and continues encrypting

## How Wayland screenshots work

On Wayland, vigil uses the XDG Desktop Portal Screenshot interface. The first time it takes a screenshot, the system shows a one-time permission dialog. Once the user grants access, all subsequent screenshots are taken silently. If the user revokes permission, vigil detects the failure and reports it to the accountability partner.

## Building

```bash
# Install dependencies (elementary OS 8 / Ubuntu 24.04)
sudo apt install valac meson libgranite-7-dev libgtk-4-dev \
  libjson-glib-dev libsoup-3.0-dev libportal-dev libportal-gtk4-dev libolm-dev

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

### Step 2: Configure vigil

Open the vigil GUI and go to Settings. Fill in:

1. **Homeserver** -- just the server name (e.g. `matrix.org`). vigil auto-discovers the full URL via `.well-known`.
2. **Username** -- your Matrix username (without the `@` prefix)
3. **Password** -- your Matrix password
4. **Partner Matrix ID** -- your accountability partner's full Matrix ID (e.g. `@partner:matrix.org`)
5. **E2EE Password** -- a password that encrypts your encryption keys at rest

Click **Setup**. vigil will:
- Discover and connect to your homeserver
- Log in with your credentials
- Create a private encrypted room and invite your partner
- Initialize end-to-end encryption
- Upload device keys and share room keys with your partner's devices

Once setup completes, enable monitoring from the Status tab.

### Step 3: Partner accepts the invite

Your partner opens Element and accepts the room invite. They will see:

- **Screenshots**: appear as images with timestamps
- **Heartbeats**: periodic status messages like `Vigil active | uptime: 2h 30m | screenshots: 15 | pending: 0`
- **Tamper alerts**: `ALERT [autostart_missing]: Autostart desktop entry is missing`

If vigil goes completely silent (killed, uninstalled), the **absence of heartbeats** is itself the alert.

### Step 4: Lock it down

Once everything is working, your accountability partner should verify:

1. The daemon is running: `systemctl --user status vigil-daemon.service`
2. Autostart is enabled: check that the daemon desktop entry exists in `/etc/xdg/autostart/`
3. The systemd service has `RefuseManualStop=true` and `Restart=always`

The daemon monitors its own integrity and alerts via Matrix if:
- The autostart entry is deleted or modified
- The systemd service is disabled
- The daemon binary is replaced
- Monitoring is disabled via GSettings
- Matrix transport settings are cleared or partially removed
- E2EE encryption keys are cleared

## Configuration

All settings are stored via GSettings (`io.github.invarianz.vigil`):

| Setting | Description | Default |
|---|---|---|
| `matrix-homeserver-url` | Matrix homeserver URL (auto-discovered) | (empty) |
| `matrix-access-token` | Matrix access token (set during login) | (empty) |
| `matrix-room-id` | Matrix room ID (auto-created) | (empty) |
| `matrix-user-id` | Matrix user ID (set during login) | (empty) |
| `partner-matrix-id` | Partner's Matrix user ID | (empty) |
| `device-id` | Matrix device ID (set during login) | (empty) |
| `e2ee-pickle-key` | E2EE password for encrypting crypto state | (empty) |
| `min-interval-seconds` | Minimum time between screenshots | 120 (2 min) |
| `max-interval-seconds` | Maximum time between screenshots | 600 (10 min) |
| `max-local-screenshots` | Screenshots to keep locally | 100 |
| `monitoring-enabled` | Whether monitoring is active | false |
| `autostart-enabled` | Start at login | false |
| `heartbeat-interval-seconds` | Heartbeat ping interval | 60 (1 min) |
| `tamper-check-interval-seconds` | Tamper check interval | 120 (2 min) |

## License

GPL-3.0-or-later
