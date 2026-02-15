# Vigil

Accountability screenshot software for elementary OS.

Vigil takes screenshots of your screen at random intervals and uploads them to a server where an accountability partner can review them. It works on both X11 and Wayland, including elementary OS 7 and 8.

## Features

- Random-interval screenshots that cannot be predicted
- Dual backend: XDG Desktop Portal (Wayland) and Gala D-Bus (X11)
- Uploads to a configurable HTTPS endpoint with Bearer token auth
- Queues screenshots for upload when offline, retries on startup
- Detects and reports when monitoring is disabled
- Follows elementary OS Human Interface Guidelines
- Built with GTK 4 and Granite 7

## How Wayland screenshots work

On Wayland, Vigil uses the XDG Desktop Portal Screenshot interface. The first time it takes a screenshot, the system shows a one-time permission dialog. Once the user grants access, all subsequent screenshots are taken silently. If the user revokes permission, Vigil detects the failure and reports it to the accountability partner.

## Building

```bash
# Install dependencies (elementary OS 8)
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
```

## Configuration

All settings are stored via GSettings (`io.github.invarianz.vigil`):

| Setting | Description | Default |
|---|---|---|
| `endpoint-url` | HTTPS endpoint for uploading screenshots | (empty) |
| `api-token` | Bearer token for authentication | (empty) |
| `min-interval-seconds` | Minimum time between screenshots | 120 (2 min) |
| `max-interval-seconds` | Maximum time between screenshots | 600 (10 min) |
| `max-local-screenshots` | Screenshots to keep locally | 100 |
| `monitoring-enabled` | Whether monitoring is active | false |
| `autostart-enabled` | Start at login | false |

## Upload API

Vigil POSTs screenshots as `multipart/form-data` to the configured endpoint:

- `screenshot`: PNG image file
- `timestamp`: ISO 8601 capture timestamp
- `device_id`: Stable UUID for this device

An `Authorization: Bearer <token>` header is sent if an API token is configured.

## License

GPL-3.0-or-later
