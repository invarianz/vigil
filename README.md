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

Vigil takes screenshots of your screen at random intervals and sends them to an accountability partner of your choice. Everything is end-to-end encrypted -- not even the server can see your images.

You install Vigil, your partner installs [Element](https://element.io/) (a free chat app), and you're connected. Vigil runs quietly in the background and alerts your partner if someone tries to tamper with it.

## How it works

1. Vigil captures your screen at unpredictable intervals (every 30 seconds to 2 minutes)
2. Each screenshot is encrypted before it ever leaves your device
3. The encrypted image is sent to your partner through a private [Matrix](https://matrix.org/) chat room
4. Your partner views the screenshots in Element on their phone or computer
5. If Vigil is stopped, uninstalled, or tampered with, your partner receives an alert

Your partner doesn't need any technical knowledge. They just watch for screenshots, and if the messages stop or a **TAMPER ALERT** appears, they know something is wrong.

## Features

- **Unpredictable timing** -- screenshots are taken at random intervals so they can't be anticipated
- **End-to-end encrypted** -- screenshots are encrypted on your device before upload; the server never sees them
- **One-click setup** -- enter your account details, click Setup, and Vigil handles login, room creation, and encryption automatically
- **Tamper detection** -- alerts your partner if the daemon is stopped, autostart is removed, settings are changed, or the binary is modified
- **Dead man's switch** -- heartbeat messages include a "next check-in by" deadline so your partner knows exactly when to expect the next update
- **Offline resilience** -- queues screenshots for delivery when offline, retries on reconnect
- **Settings lock** -- after setup, settings are locked behind a code that only your partner knows
- **Works on X11 and Wayland** -- dual screenshot backend for elementary OS 7 and 8
- **Flatpak-ready** -- uses XDG Background portal for autostart; detects if permission is revoked
- **Runs as a system service** -- keeps running even when the GUI is closed, restarts automatically if killed (via systemd on native installs, or XDG Background portal in Flatpak)
- **Local storage** -- screenshots are kept on disk at `~/.local/share/io.github.invarianz.vigil/screenshots/` so you can verify captures even without Matrix configured

## Getting started

### What you'll need

- **You**: elementary OS 7 or 8 with Vigil installed
- **Your partner**: any device with [Element](https://element.io/) installed (phone or computer)
- **Matrix accounts** for both of you -- free accounts at [matrix.org](https://app.element.io) work fine, or you can self-host for maximum privacy

### Step 1: Set up Vigil

Open Vigil and go to Settings. Fill in:

1. **Homeserver** -- your Matrix server (e.g. `matrix.org`)
2. **Username** -- your Matrix username
3. **Password** -- your Matrix password
4. **Partner Matrix ID** -- your partner's Matrix ID (e.g. `@partner:matrix.org`)
5. **E2EE Password** -- a password to protect your encryption keys on disk

Click **Setup**. Vigil will log in, create a private encrypted room, invite your partner, and set up encryption -- all in one step.

### Step 2: Your partner accepts the invite

Your partner opens Element and accepts the room invite from Vigil. From now on, they'll receive:

- **Screenshots** -- batches of images delivered every 10 minutes
- **Heartbeats** -- status messages every 15 minutes with a "next check-in by" deadline
- **Tamper alerts** -- bold warnings if someone tries to interfere with Vigil

Your partner only needs to watch for three things:

| What they see | What it means |
|---|---|
| Regular messages and screenshots | Everything is working normally |
| **TAMPER ALERT** | Something suspicious happened -- investigate |
| "Next check-in by" deadline passes with no message | Something is wrong (device off, Vigil removed, etc.) |

### Step 3: Settings are locked automatically

After setup, Vigil locks all settings and sends a 6-character unlock code to your partner:

> Settings are now locked. Unlock code: A7KM3P -- Keep this code. The user will need it from you to change any settings.

To change settings later, you'll need to ask your partner for the code. If someone tries to bypass the lock through system tools, a tamper alert fires immediately.

### Step 4: Enable monitoring

Switch to the Status tab and enable monitoring. Vigil starts capturing in the background and keeps running as a system service, even after you close the window.

## What your partner sees

Vigil communicates with your partner through different types of messages. Here's what each one looks like and what it means.

### Normal operation

> Vigil active | uptime: 2h 30m | screenshots: 15 | pending: 0 | next check-in by: 14:35

This is a regular heartbeat, sent every 15 minutes. It tells your partner everything is running smoothly. The "next check-in by" time is the deadline -- if no new message arrives by then, something may be wrong.

### Clean shutdown (computer turned off or restarted)

> STATUS: Vigil going offline (clean shutdown, this is normal) | uptime was: 4h 12m | pending: 0

When you shut down or restart your computer, Vigil sends this message before it stops. Your partner knows the silence that follows is expected and not suspicious. When your computer starts up again, the next heartbeat will mention the gap:

> Vigil active | uptime: 0h 1m | screenshots: 0 | pending: 0 | resumed after 8h 15m gap (device was asleep or offline, this is normal) | next check-in by: 08:20

### Sleep and wake

If your computer was asleep (lid closed, suspended), the next heartbeat reports exactly how long the gap was. Your partner can see the gap duration and judge whether it makes sense (e.g. overnight sleep vs. suspicious midday silence).

### Network outage

If Vigil can't reach the server, it keeps trying. Once the connection is restored, the heartbeat reports how many check-ins were missed:

> Vigil active | uptime: 3h 0m | screenshots: 12 | pending: 5 | recovering: 3 heartbeats were missed | next check-in by: 15:45

Screenshots taken while offline are queued and delivered as soon as the connection comes back.

### Tamper alerts

If someone tries to interfere with Vigil, a bold alert is sent immediately -- it doesn't wait for the next heartbeat:

> **TAMPER ALERT [autostart_missing]**
> Autostart desktop entry is missing

These alerts fire when:

| Alert type | What happened |
|---|---|
| `monitoring_disabled` | Screenshot monitoring was turned off |
| `interval_tampered` | Screenshot intervals were set unreasonably high |
| `timer_tampered` | Heartbeat, upload, or tamper-check timers were increased beyond safe limits |
| `matrix_cleared` | All Matrix connection settings were deleted |
| `matrix_incomplete` | Some Matrix settings were deleted (breaks the connection) |
| `partner_changed` | The partner Matrix ID was changed or cleared |
| `e2ee_disabled` | Encryption keys were cleared |
| `autostart_missing` | The autostart entry was deleted |
| `autostart_modified` | The autostart entry was changed to point elsewhere |
| `autostart_unreadable` | The autostart entry exists but cannot be read |
| `systemd_disabled` | The system service was disabled |
| `settings_unlocked` | The settings lock was bypassed |
| `unlock_code_cleared` | The unlock code was erased while settings are locked |
| `binary_missing` | The Vigil daemon binary was deleted |
| `binary_modified` | The Vigil program file was replaced |
| `binary_unreadable` | The Vigil daemon binary cannot be read |
| `capture_stalled` | No screenshot captured within the expected interval (backend may have failed silently) |
| `orphan_screenshots` | Many screenshots have no pending marker (markers may have been deleted to suppress upload) |
| `disk_space_low` | Less than 50 MB disk space remaining; screenshots cannot be stored |
| `screenshot_tampered` | A screenshot file was modified after capture (integrity hash mismatch) |
| `capture_counter_tampered` | The lifetime capture counter file was modified (HMAC mismatch) |
| `e2ee_init_failed` | Encryption failed to start -- screenshots would be sent unencrypted, so monitoring is refused |
| `background_permission_revoked` | Background running/autostart permission was revoked |
| `ld_preload_detected` | LD_PRELOAD environment variable is set (possible library injection) |
| `prctl_failed` | Failed to disable process core dumps/ptrace (process hardening failed) |
| `screenshot_deleted` | A screenshot file was unexpectedly deleted (not by the daemon) |
| `marker_deleted` | A pending upload marker was unexpectedly deleted (not by the daemon) |
| `crypto_file_tampered` | A file in the crypto directory was modified or deleted |

### Forced kill or uninstall

If Vigil is killed with `kill -9`, the power is pulled, or it's uninstalled entirely, there is no opportunity to send a message. This is exactly what the dead man's switch handles: the "next check-in by" deadline passes with no message, and your partner knows something is wrong.

### What your partner needs to remember

1. **Regular messages arriving on time** = everything is fine
2. **"Going offline (clean shutdown)"** = computer was turned off normally, expect silence
3. **"Resumed after Xm gap"** = computer was asleep or offline, now back
4. **"TAMPER ALERT"** = something suspicious, investigate
5. **Deadline passes with no message at all** = most serious; Vigil was forcibly stopped

## Security and encryption

Vigil implements the Matrix end-to-end encryption protocol natively using libolm. No external encryption proxy is needed.

- **Screenshots** are encrypted with a fresh AES-256 key before upload -- the server only stores opaque encrypted data
- **Messages** are encrypted with Megolm (the same protocol used by Element and other Matrix clients)
- **Key exchange** happens automatically via Olm during setup
- **No unencrypted fallback** -- if encryption fails, the message is dropped rather than sent in plaintext
- **All randomness** comes from the system CSPRNG (`/dev/urandom`); if it becomes unavailable, Vigil aborts rather than using weak randomness
- **Encryption keys** are stored on disk encrypted with your E2EE password, with restrictive file permissions

<details>
<summary>Encryption details (click to expand)</summary>

### Architecture

Vigil runs as two processes:

- **vigil-daemon** -- a background system service that captures screenshots, encrypts them, sends them via Matrix, and monitors for tampering. Runs even when the GUI is closed.
- **vigil** -- a GTK 4 app for status and settings. Connects to the daemon over D-Bus. Handles one-time setup.

### What happens when a screenshot is taken

1. The screen is captured via XDG Desktop Portal (Wayland) or Gala D-Bus (X11)
2. The PNG is encrypted with a fresh random AES-256-CTR key and IV, then a SHA-256 hash of the ciphertext is computed for integrity verification
3. The encrypted blob is uploaded to the Matrix content repository
4. The event JSON (containing the download URL, decryption key, IV, and hash) is encrypted with the room's Megolm session
5. The encrypted event is sent to the room -- only your partner's devices can decrypt it

### Key hierarchy

```
E2EE Password (user-provided)
  └─ Pickle key: encrypts all cryptographic state at rest

OlmAccount (per-device, long-lived)
  ├─ Ed25519 identity key: signs device keys and messages
  ├─ Curve25519 identity key: used for key agreement
  └─ One-time keys: consumed during session setup

Megolm outbound group session (per-room)
  └─ Session key: shared with partner via Olm-encrypted messages
      └─ Ratchets forward after each message

AES-256-CTR key (per-screenshot, ephemeral)
  └─ Fresh random 256-bit key + 128-bit IV for each file
```

</details>

## Building from source

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

# Install
sudo meson install -C build

# Enable the daemon (native install)
systemctl --user enable --now vigil-daemon.service
```

When running as a Flatpak, the daemon uses the XDG Background portal instead of systemd. Autostart is requested automatically on first launch -- no manual service setup is needed.

## License

GPL-3.0-or-later
