<p align="center">
  <img src="data/icons/128/io.github.invarianz.vigil.svg" alt="Vigil" width="128" height="128">
</p>

<h1 align="center">Vigil</h1>

<p align="center">
  <strong>Accountability screenshot software for elementary OS</strong>
</p>

<p align="center">
  <a href="https://github.com/invarianz/Vigil/actions/workflows/build-test.yml"><img src="https://github.com/invarianz/Vigil/actions/workflows/build-test.yml/badge.svg" alt="Build & Test"></a>
  <a href="https://github.com/invarianz/Vigil/blob/main/COPYING"><img src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg" alt="License: GPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/platform-elementary%20OS%207%20%7C%208-64BAFF.svg" alt="Platform: elementary OS 7 | 8">
  <img src="https://img.shields.io/badge/GTK-4-4A86CF.svg" alt="GTK 4">
  <img src="https://img.shields.io/badge/encryption-Matrix%20E2EE-brightgreen.svg" alt="Encryption: Matrix E2EE">
</p>

---

Vigil takes screenshots of your screen at random intervals and sends them to your accountability partner via Matrix with native end-to-end encryption. It works on both X11 and Wayland, including elementary OS 7 and 8.

## Features

- Random-interval screenshots (30s--2min by default) that cannot be predicted
- Dual backend: XDG Desktop Portal (Wayland) and Gala D-Bus (X11)
- **Native E2EE**: built-in Olm/Megolm encryption via libolm -- no external proxy needed
- **Encrypted attachments**: screenshots are AES-256-CTR encrypted before upload per the Matrix spec -- the homeserver never sees plaintext images
- **One-button setup**: enter homeserver, username, password, partner ID, and E2EE password -- one click does login, room creation, key exchange, and encryption setup
- **Matrix transport**: sends screenshots to a private encrypted chat room -- no third-party server sees your data
- Queues screenshots for delivery when offline, retries on startup
- Tamper detection: alerts your partner if the daemon is stopped, autostart is removed, settings are changed, E2EE is disabled, or the binary is modified
- Heartbeat dead man's switch with explicit "next check-in by" deadline -- partner sees a concrete time, no technical knowledge needed
- Systemd user service with watchdog and restart-on-kill
- Follows elementary OS Human Interface Guidelines
- Built with GTK 4 and Granite 7

## Architecture

vigil runs as two processes:

- **vigil-daemon**: headless systemd service that takes screenshots, encrypts them, sends them via Matrix, and monitors for tampering. Runs even when the GUI is closed.
- **vigil GUI**: thin GTK4 app that connects to the daemon over D-Bus. Shows status and settings. Handles one-time setup (login, room creation, E2EE initialization).

### Encryption scheme

vigil implements the full Matrix E2EE stack natively, with no dependency on external encryption proxies like pantalaimon.

#### Key hierarchy

```
E2EE Password (user-provided)
  └─ Pickle key: encrypts all libolm state at rest on disk

OlmAccount (per-device, long-lived)
  ├─ Ed25519 identity key: signs device keys and messages
  ├─ Curve25519 identity key: used for Olm key agreement
  └─ One-time keys (Curve25519): consumed during Olm session setup

Megolm outbound group session (per-room, long-lived)
  └─ Session key: shared with partner devices via Olm-encrypted to-device messages
      └─ Ratchets forward after each message (forward secrecy within the session)

AES-256-CTR key (per-attachment, ephemeral)
  └─ Fresh random 256-bit key + 128-bit IV generated for each screenshot
```

#### What happens when a screenshot is taken

1. **Screenshot capture**: vigil captures the screen via XDG Desktop Portal (Wayland) or Gala D-Bus (X11)
2. **File encryption (AES-256-CTR)**: the PNG file is encrypted with a fresh random 256-bit AES key and 128-bit IV using OpenSSL's EVP API. A SHA-256 hash of the ciphertext is computed (also via OpenSSL) for integrity verification. The homeserver only ever receives opaque encrypted bytes.
3. **Upload**: the encrypted blob is uploaded to the Matrix content repository as `application/octet-stream`
4. **Event encryption (Megolm)**: the event JSON (containing the `mxc://` URL, JWK decryption key, IV, and SHA-256 hash) is encrypted with the room's Megolm outbound group session
5. **Send**: the `m.room.encrypted` event is sent to the room. Only devices that received the Megolm session key can decrypt the event, and only then can they decrypt the attachment.

#### E2EE setup flow (one-time)

1. GUI creates an OlmAccount and uploads Ed25519 + Curve25519 device keys to the homeserver
2. 50 signed one-time keys (Curve25519) are uploaded for Olm session bootstrapping
3. A Megolm outbound group session is created for room encryption
4. Partner's device keys are queried via `/keys/query` and one-time keys claimed via `/keys/claim`
5. An Olm session is established with each partner device using Curve25519 key agreement
6. The Megolm room key (`m.room_key`) is Olm-encrypted per-device and sent via `/sendToDevice`
7. All crypto state is pickled (encrypted with the E2EE password) and persisted to `~/.local/share/io.github.invarianz.vigil/crypto/`
8. The daemon restores the pickled state on startup and continues encrypting

#### Security hardening

- **No unencrypted fallback**: if E2EE is configured but encryption fails, messages are dropped rather than sent in plaintext
- **CSPRNG only**: all random material comes from `/dev/urandom` via a cached file descriptor. If the CSPRNG becomes unavailable, the daemon aborts rather than falling back to a weak PRNG
- **Restrictive file permissions**: the crypto directory is `0700`, pickle files are `0600`, and screenshot directories are `0700`
- **Hardware-accelerated crypto**: AES-256-CTR encryption and SHA-256 hashing use OpenSSL's EVP API, which automatically uses hardware acceleration (AES-NI, SHA-NI) when available

## How Wayland screenshots work

On Wayland, vigil uses the XDG Desktop Portal Screenshot interface. The first time it takes a screenshot, the system shows a one-time permission dialog. Once the user grants access, all subsequent screenshots are taken silently. If the user revokes permission, vigil detects the failure and reports it to the accountability partner.

## Building

```bash
# Install dependencies (elementary OS 8 / Ubuntu 24.04)
sudo apt install valac meson libgranite-7-dev libgtk-4-dev \
  libjson-glib-dev libsoup-3.0-dev libportal-dev libportal-gtk4-dev \
  libolm-dev libssl-dev

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

- **Screenshots**: batches of images sent every 10 minutes (captured every 30s--2min, delivered in batches to avoid flooding)
- **Heartbeats**: periodic status messages every 15 minutes: `Vigil active | uptime: 2h 30m | screenshots: 15 | pending: 0 | next check-in by: 14:35`
- **TAMPER ALERT**: bold, formatted alerts that stand out: **TAMPER ALERT [autostart_missing]** -- clearly different from routine messages
- **STATUS messages**: informational notices like `STATUS: Vigil going offline (clean shutdown, this is normal)` or `resumed after 45m gap (device was asleep or offline, this is normal)`

Your partner only needs to understand three things:
1. **Regular messages** = everything is fine
2. **"TAMPER ALERT"** (bold) = something suspicious happened, investigate
3. **"next check-in by" deadline passes** with no new message = something is wrong (covers kill, uninstall, etc.)

### Step 4: Settings are auto-locked

After setup, vigil **automatically locks all settings** and sends a 6-character unlock code to your partner via Matrix:

> Settings are now locked. Unlock code: A7KM3P -- Keep this code. The user will need it from you to change any settings.

To change any settings later, the user must:
1. Ask the partner for the unlock code
2. Enter it in the GUI
3. Make changes
4. Click "Lock Settings" -- a **new** unlock code is generated and sent to the partner

If someone tries to bypass the lock via command-line tools (`gsettings`, `dconf-editor`), a tamper alert fires immediately.

### Step 5: Verify the setup

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
- The settings lock is disabled or bypassed

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
| `settings-locked` | Whether settings are locked (partner holds unlock code) | false |
| `min-interval-seconds` | Minimum time between screenshots | 30 (30 sec) |
| `max-interval-seconds` | Maximum time between screenshots | 120 (2 min) |
| `max-local-screenshots` | Screenshots to keep locally | 100 |
| `monitoring-enabled` | Whether monitoring is active | false |
| `autostart-enabled` | Start at login | false |
| `heartbeat-interval-seconds` | Heartbeat ping interval | 900 (15 min) |
| `upload-batch-interval-seconds` | How often to send screenshots to partner | 600 (10 min) |
| `tamper-check-interval-seconds` | Tamper check interval | 120 (2 min) |

## License

GPL-3.0-or-later
