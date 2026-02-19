/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Sends regular heartbeat messages to the Matrix room.
 *
 * This is the core tamper-resistance mechanism: the accountability partner
 * EXPECTS regular heartbeats. If they stop arriving, something is wrong.
 * Silence itself is the signal -- this handles kill, uninstall, network
 * block, and every other "make it stop running" attack.
 *
 * Sleep/wake awareness:
 *   Each heartbeat records a monotonic timestamp. On the next tick, if the
 *   wall-clock gap exceeds 2x the expected interval, the device was likely
 *   asleep or the network was down. The heartbeat message reports the gap
 *   so the partner can distinguish sleep from tampering.
 *
 * Clean shutdown:
 *   When the daemon shuts down gracefully (systemd stop, reboot), it sends
 *   a "going offline" message so the partner knows silence is expected.
 *
 * Network failure:
 *   Consecutive send failures are tracked. On recovery, the heartbeat
 *   reports how many were missed so the partner knows there was a gap.
 *
 * Sequence numbering:
 *   Each heartbeat carries a monotonically increasing sequence number.
 *   The partner can detect gaps (suppressed heartbeats) or replays
 *   (duplicated numbers) for defense-in-depth.
 *
 * Alert persistence:
 *   Unsent tamper alerts are persisted to disk so they survive daemon
 *   restarts and network outages. On startup, persisted alerts are
 *   re-queued for delivery in the next heartbeat.
 *
 * Config hash signing:
 *   When an EncryptionService is available, the config hash included in
 *   heartbeats is signed with the Ed25519 device key. The partner can
 *   verify the signature against the published device key.
 */
public class Vigil.Services.HeartbeatService : Object {

    public signal void heartbeat_sent (DateTime timestamp);
    public signal void heartbeat_failed (string error_message);

    /** Heartbeat interval in seconds. */
    public int interval_seconds { get; set; default = 900; }

    /** Whether the heartbeat loop is running. */
    public bool is_running { get; private set; default = false; }

    /** Daemon start time, for uptime calculation. */
    public DateTime start_time { get; private set; }

    /** Count of screenshots taken since last heartbeat. */
    public int screenshots_since_last { get; set; default = 0; }

    /** Current pending upload count. */
    public int pending_upload_count { get; set; default = 0; }

    /** Whether screenshot monitoring is active. */
    public bool monitoring_active { get; set; default = false; }

    /** Whether screenshot permission is granted. */
    public bool screenshot_permission_ok { get; set; default = true; }

    /** Hash of current configuration for tamper detection. */
    public string config_hash { get; set; default = ""; }

    /** Number of consecutive heartbeat send failures. */
    public int consecutive_failures { get; private set; default = 0; }

    /** Optional EncryptionService for signing config hashes. */
    public Vigil.Services.EncryptionService? encryption { get; set; default = null; }

    /** Data directory for persisting unsent alerts. */
    public string data_dir { get; set; default = ""; }

    /** Monotonically increasing heartbeat sequence number. */
    public int64 sequence_number { get; private set; default = 0; }

    /** Lifetime capture counter from StorageService. */
    public int64 lifetime_captures { get; set; default = 0; }

    /** List of tamper events since last heartbeat. */
    private GenericArray<string> _tamper_events;

    private Vigil.Services.MatrixTransportService? _matrix_svc;
    private uint _timeout_source = 0;

    /** Monotonic timestamp (usec) of last successful or attempted heartbeat. */
    private int64 _last_heartbeat_monotonic = 0;

    /**
     * Create a HeartbeatService.
     *
     * @param matrix_svc The Matrix transport to send heartbeats through.
     *                   May be null for testing.
     */
    public HeartbeatService (Vigil.Services.MatrixTransportService? matrix_svc = null) {
        _matrix_svc = matrix_svc;
    }

    construct {
        start_time = new DateTime.now_local ();
        _tamper_events = new GenericArray<string> ();
    }

    /**
     * Add a tamper event to be reported in the next heartbeat.
     * Also persists to disk so events survive daemon restarts.
     */
    public void report_tamper_event (string event_description) {
        _tamper_events.add (event_description);
        persist_unsent_alerts ();
    }

    /**
     * Start the heartbeat loop.
     * Loads any persisted unsent alerts from a previous run.
     */
    public void start () {
        if (is_running) {
            return;
        }

        is_running = true;
        start_time = new DateTime.now_local ();
        _last_heartbeat_monotonic = GLib.get_monotonic_time ();

        // Load persisted alerts from a previous run
        load_persisted_alerts ();

        // Send first heartbeat immediately
        send_heartbeat.begin ();
        schedule_next ();
    }

    /**
     * Stop the heartbeat loop.
     */
    public void stop () {
        if (!is_running) {
            return;
        }

        if (_timeout_source != 0) {
            Source.remove (_timeout_source);
            _timeout_source = 0;
        }

        is_running = false;
    }

    /**
     * Send a "going offline" message before clean shutdown.
     *
     * This tells the accountability partner that upcoming silence is
     * expected (device shutting down or daemon stopping), rather than
     * suspicious. The partner can still be alerted if silence extends
     * beyond a reasonable window.
     */
    public async void send_offline_notice () {
        if (_matrix_svc == null || !_matrix_svc.is_configured) {
            return;
        }

        var uptime = get_uptime_seconds ();
        var hours = uptime / 3600;
        var minutes = (uptime % 3600) / 60;

        var message = (
            "STATUS: Vigil going offline (clean shutdown, this is normal)" +
            " | uptime was: %lldh %lldm | pending: %d | seq: %lld"
        ).printf (hours, minutes, pending_upload_count, sequence_number);

        yield _matrix_svc.send_text_message (message);
    }

    /**
     * Calculate uptime in seconds since daemon start.
     */
    public int64 get_uptime_seconds () {
        var now = new DateTime.now_local ();
        return now.difference (start_time) / TimeSpan.SECOND;
    }

    /**
     * Build a human-readable heartbeat message for the Matrix room.
     *
     * Includes gap detection (sleep/wake), recovery info (consecutive
     * failures), tamper events, sequence number, and optional config
     * hash signature.
     */
    public string build_heartbeat_message () {
        var uptime = get_uptime_seconds ();
        var hours = uptime / 3600;
        var minutes = (uptime % 3600) / 60;

        var sb = new StringBuilder ();
        sb.append ("Vigil active | uptime: %lldh %lldm | screenshots: %d | pending: %d | seq: %lld | lifetime: %lld".printf (
            hours, minutes, screenshots_since_last, pending_upload_count, sequence_number, lifetime_captures
        ));

        // Detect gap (sleep/wake or network outage recovery)
        var now_mono = GLib.get_monotonic_time ();
        if (_last_heartbeat_monotonic > 0) {
            var elapsed_sec = (now_mono - _last_heartbeat_monotonic) / 1000000;
            var expected_sec = (int64) interval_seconds;

            // If elapsed is more than 2x the interval, there was a gap
            if (elapsed_sec > expected_sec * 2) {
                var gap_min = elapsed_sec / 60;
                var gap_msg = " | resumed after %lldm gap".printf (gap_min) +
                    " (device was asleep or offline, this is normal)";
                sb.append (gap_msg);
            }
        }

        // Report recovery from consecutive failures
        if (consecutive_failures > 0) {
            sb.append (" | recovering: %d heartbeats were missed".printf (consecutive_failures));
        }

        // Tell the partner when to expect the next check-in.
        // If this deadline passes without a new message, something is wrong.
        // Use 2x interval to allow for timing jitter and network delays.
        var deadline = new DateTime.now_local ().add_seconds (interval_seconds * 2);
        sb.append (" | next check-in by: %s".printf (deadline.format ("%H:%M")));

        // Include config hash with optional Ed25519 signature
        if (config_hash != "") {
            sb.append ("\nconfig: %s".printf (config_hash));
            if (encryption != null && encryption.is_ready) {
                var signature = encryption.sign_string (config_hash);
                if (signature != "") {
                    sb.append (" | sig: %s".printf (signature));
                }
            }
        }

        // Cap tamper events to last 50 and total message to ~60KB
        // to prevent unbounded growth from event accumulation.
        if (_tamper_events.length > 0) {
            int start = int.max (0, (int) _tamper_events.length - 50);
            if (start > 0) {
                sb.append ("\nTamper events (%d total, showing last 50):".printf (
                    (int) _tamper_events.length));
            } else {
                sb.append ("\nTamper events:");
            }
            for (int i = start; i < _tamper_events.length; i++) {
                if (sb.len > 60000) {
                    sb.append ("\n  \u2026 (truncated)");
                    break;
                }
                sb.append ("\n  - %s".printf (_tamper_events[i]));
            }
        }

        return sb.str;
    }

    /**
     * Send a heartbeat via Matrix.
     */
    public async bool send_heartbeat () {
        if (_matrix_svc == null || !_matrix_svc.is_configured) {
            heartbeat_failed ("Matrix transport not configured");
            return false;
        }

        sequence_number++;
        var message = build_heartbeat_message ();
        var sent = yield _matrix_svc.send_text_message (message);

        if (sent) {
            consecutive_failures = 0;
            screenshots_since_last = 0;
            _tamper_events.remove_range (0, _tamper_events.length);
            _last_heartbeat_monotonic = GLib.get_monotonic_time ();
            heartbeat_sent (new DateTime.now_local ());
            // Clear persisted alerts since they were successfully sent
            clear_persisted_alerts ();
            return true;
        } else {
            consecutive_failures++;
            heartbeat_failed ("Failed to send heartbeat via Matrix");
            return false;
        }
    }

    /**
     * Persist unsent tamper alerts to disk so they survive daemon restarts.
     */
    private void persist_unsent_alerts () {
        if (data_dir == "" || _tamper_events.length == 0) {
            return;
        }

        var path = Path.build_filename (data_dir, "unsent_alerts.txt");
        var sb = new StringBuilder ();
        for (int i = 0; i < _tamper_events.length; i++) {
            sb.append (_tamper_events[i]);
            sb.append_c ('\n');
        }

        try {
            FileUtils.set_contents (path, sb.str);
            FileUtils.chmod (path, 0600);
        } catch (Error e) {
            debug ("Failed to persist unsent alerts: %s", e.message);
        }
    }

    /**
     * Load persisted unsent alerts from a previous daemon run.
     */
    private void load_persisted_alerts () {
        if (data_dir == "") {
            return;
        }

        var path = Path.build_filename (data_dir, "unsent_alerts.txt");
        if (!FileUtils.test (path, FileTest.EXISTS)) {
            return;
        }

        try {
            string contents;
            FileUtils.get_contents (path, out contents);
            var lines = contents.split ("\n");
            foreach (var line in lines) {
                var stripped = line.strip ();
                if (stripped != "") {
                    _tamper_events.add (stripped);
                }
            }
            if (_tamper_events.length > 0) {
                debug ("Loaded %d persisted tamper alerts from previous run",
                    (int) _tamper_events.length);
            }
        } catch (Error e) {
            debug ("Failed to load persisted alerts: %s", e.message);
        }
    }

    /**
     * Clear persisted alerts after successful heartbeat delivery.
     */
    private void clear_persisted_alerts () {
        if (data_dir == "") {
            return;
        }

        var path = Path.build_filename (data_dir, "unsent_alerts.txt");
        if (FileUtils.test (path, FileTest.EXISTS)) {
            FileUtils.remove (path);
        }
    }

    private void schedule_next () {
        if (!is_running) {
            return;
        }

        _timeout_source = Timeout.add_seconds ((uint) interval_seconds, () => {
            _timeout_source = 0;
            send_heartbeat.begin ();

            if (is_running) {
                schedule_next ();
            }

            return Source.REMOVE;
        });
    }
}
