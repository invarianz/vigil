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
- **Tamper detection** -- alerts your partner if Vigil is stopped, settings are changed via dconf, or files are modified. Distinguishes between **tamper attempts** (bold red) and **warnings** (orange) based on severity
- **Offline resilience** -- queues screenshots for delivery when offline, retries on reconnect
- **Settings lock** -- after setup, settings are locked behind a code that only your partner knows
- **Flatpak sandboxed** -- runs inside a Flatpak sandbox with seccomp, separate PID/mount namespaces, and restricted filesystem access. Detects sandbox escapes
- **Persistent background service** -- keeps running even when the GUI is closed, restarts automatically via XDG Background portal autostart

## Getting started

### What you'll need

- **You**: elementary OS 7 or 8 with Vigil installed (via Flatpak)
- **Your partner**: any device with [Element](https://element.io/) installed (phone or computer)
- **Matrix accounts** for both of you -- free accounts at [matrix.org](https://app.element.io) work fine, or you can self-host for maximum privacy

### Step 1: Set up Vigil

Open Vigil and go to Settings. Fill in:

1. **Matrix Server** -- your Matrix server (e.g. `matrix.org`)
2. **Username** -- your Matrix username
3. **Password** -- your Matrix password
4. **Partner Matrix ID** -- your partner's Matrix ID (e.g. `@partner:matrix.org`)
5. **E2EE Password** -- a password to protect your encryption keys on disk

Click **Setup**. Vigil will log in, create a private encrypted room, invite your partner, and set up encryption -- all in one step.

### Step 2: Your partner accepts the invite

Your partner opens Element and accepts the room invite from Vigil. From now on, they'll receive:

- **Screenshots** -- images sent every 1-2 minutes
- **Tamper alerts** -- bold warnings if someone tries to interfere with Vigil
- **Shutdown notices** -- a message when the computer shuts down or restarts

Your partner only needs to watch for three things:

| What they see | What it means |
|---|---|
| Regular screenshots arriving | Everything is working normally |
| **TAMPER ALERT** | Something suspicious happened -- investigate |
| Screenshots stop arriving with no "Going offline" notice | Something is wrong (device off, Vigil removed, etc.) |

### Step 3: Settings are locked automatically

After setup, Vigil locks all settings behind a 6-character unlock code. The code is shown once in the Vigil GUI -- write it down or tell your partner directly (in person, by phone, or through another chat). Vigil does **not** send the code through Matrix, because that would let the monitored user read it.

To change settings later, you'll need to ask your partner for the code. If someone tries to bypass the lock through system tools, a tamper alert fires immediately.

### Step 4: Enable monitoring

Switch to the Status tab and enable monitoring. Vigil starts capturing in the background and keeps running even after you close the window.

## What your partner sees

Vigil sends messages your partner can understand at a glance -- no technical knowledge needed.

### Clean shutdown (computer turned off or restarted)

> NOTICE: Going offline
>
> The computer is shutting down or restarting. This is normal.
> Vigil will start again automatically when the computer turns back on.
>
> Was running for 4 hours 12 minutes.

When you shut down or restart your computer, Vigil sends this message before it stops. Your partner knows the silence that follows is expected.

### Tamper alerts

Vigil distinguishes two severity levels. **Tamper attempts** (bold red) indicate active circumvention -- someone bypassing the UI to edit settings, weakening the sandbox, or modifying files. **Warnings** (orange) indicate system issues or legitimate changes made while settings are unlocked.

Alerts are sent immediately -- they don't wait for the next heartbeat:

> **TAMPER ATTEMPT:** The settings lock was bypassed. Someone may have unlocked settings via dconf instead of the GUI.

Warnings look different:

> Warning: No screenshot was taken when expected. The screenshot system may have stopped working.

Here are the types of problems Vigil can detect:

**Always a tamper attempt** (active circumvention):

| What your partner sees | What it means |
|---|---|
| The settings lock was bypassed | Someone unlocked settings via dconf instead of the GUI |
| The unlock code was cleared | Someone removed the unlock code via dconf |
| All connection settings were deleted | Matrix transport was wiped (only fires after initial setup) |
| Connection settings are partially cleared | Some Matrix keys were selectively removed |
| Screenshot timing was tampered with | Interval set outside valid range (< 30s, > 120s, or gap < 30s) via dconf |
| A screenshot was modified after it was taken | Someone edited a screenshot before upload |
| A screenshot was unexpectedly deleted | A screenshot was removed before it could be sent |
| A pending upload marker was deleted | Upload tracking was tampered with |
| The capture counter was tampered with | Lifetime screenshot count was modified |
| Encryption state files were tampered with | Crypto files were deleted on disk |
| Vigil is running outside the sandbox | `/.flatpak-info` is missing -- sandbox was bypassed |
| Many screenshots have no upload marker | Markers may have been systematically deleted |

**Tamper if locked, warning if unlocked** (settings changes):

| What your partner sees | What it means |
|---|---|
| Screenshot monitoring was turned off | Monitoring was disabled |
| Your partner ID was changed or removed | Partner Matrix ID was cleared |
| Encryption keys were deleted | E2EE pickle key was cleared |
| Service timer was changed | Upload or tamper-check interval was set very high |
| Vigil was stopped or uninstalled | Vigil was manually stopped (not a system shutdown) |
| Permission to run in the background was revoked | XDG Background portal permission lost |
| Encryption failed to start | E2EE init failed -- no screenshots will be sent |

**Always a warning** (system issues):

| What your partner sees | What it means |
|---|---|
| No screenshot was taken when expected | Capture may have stalled (portal denied, compositor crash) |
| Disk space is critically low | Less than 50 MB free |
| Settings unlocked with correct code | Authorized unlock via GUI (partner should verify they gave the code) |

Failed alerts are persisted to disk and retried after each successful screenshot upload, so nothing is missed even during network outages.

### Manual stop or uninstall

If Vigil is stopped with `flatpak kill`, terminated with SIGTERM, or uninstalled, it detects that this was NOT a system shutdown (no `PrepareForShutdown` signal from logind) and sends a tamper alert (if settings are locked) or warning (if unlocked) before going offline.

If Vigil is killed with `kill -9` or the power is pulled, there is no opportunity to send any message. Your partner will notice that screenshots have stopped arriving without a "Going offline" notice.

### What your partner needs to remember

1. **Screenshots arriving regularly** = everything is fine
2. **"NOTICE: Going offline"** = computer was turned off normally, expect silence
3. **"TAMPER ATTEMPT"** (bold red) = someone is actively trying to circumvent Vigil, investigate immediately
4. **"Warning"** (orange) = a system issue or legitimate unlocked settings change
5. **Screenshots stop with no "Going offline" notice** = most serious; Vigil was forcibly stopped

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

Vigil is a single GTK 4 application (inside the Flatpak sandbox) that runs
the monitoring engine in-process. With `--background`, it starts headless
(no window) for autostart at login. Clicking the icon opens the GUI window;
closing the window hides it while the engine keeps running.

### What happens when a screenshot is taken

1. The screen is captured via the XDG Desktop Portal (inside the Flatpak sandbox)
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
  libolm-dev libssl-dev flatpak-builder

# Build and install as Flatpak (recommended)
flatpak-builder --user --install --force-clean flatpak-build io.github.invarianz.vigil.yml

# Or build locally for development (tests only -- screenshots require Flatpak)
meson setup build
meson compile -C build
meson test -C build
```

Vigil uses the XDG Background portal for autostart with `--background` -- no manual service setup is needed. Autostart is requested automatically on first launch.

## License

GPL-3.0-or-later
