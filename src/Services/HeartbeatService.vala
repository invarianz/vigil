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
    public signal void gap_detected (int64 gap_seconds);

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

    /** Environment attestation string, sent in the first heartbeat only. */
    public string environment_attestation { get; set; default = ""; }

    /** Monotonically increasing heartbeat sequence number. */
    public int64 sequence_number { get; set; default = 0; }

    /** Lifetime capture counter from StorageService. */
    public int64 lifetime_captures { get; set; default = 0; }

    /** SHA-256 hash of the previous heartbeat message, for chain integrity. */
    public string previous_heartbeat_hash { get; private set; default = ""; }

    /** List of tamper events since last heartbeat. */
    private GenericArray<string> _tamper_events;

    /** Capture hashes recorded since last heartbeat for digest inclusion. */
    private GenericArray<string> _capture_hashes;

    private Vigil.Services.MatrixTransportService? _matrix_svc;
    private uint _timeout_source = 0;
    private bool _attestation_sent = false;

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
        _capture_hashes = new GenericArray<string> ();
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
     * Record a capture hash for inclusion in the next heartbeat digest.
     *
     * The concatenated SHA-256 of all capture hashes is included in the
     * Ed25519-signed heartbeat, creating an unforgeable audit trail that
     * binds specific screenshots to specific heartbeat intervals.
     */
    public void record_capture_hash (string sha256_hex) {
        _capture_hashes.add (sha256_hex);
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

        // Restore chain state across restarts
        load_chain_state ();

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
     * suspicious. Explicitly cancels the deadline from the previous heartbeat
     * so the partner doesn't panic when it passes with no new message.
     */
    public async void send_offline_notice () {
        if (_matrix_svc == null || !_matrix_svc.is_configured) {
            return;
        }

        var uptime = get_uptime_seconds ();

        var sb = new StringBuilder ();
        sb.append ("NOTICE: Going offline\n\n");
        sb.append ("The computer is shutting down or restarting. This is normal.\n");
        sb.append ("Vigil will start again automatically when the computer turns back on.\n");
        sb.append ("You can ignore the deadline from the previous message \u2014 ");
        sb.append ("silence is expected until the computer restarts.\n\n");
        sb.append_printf ("Was running for %s. ", format_duration (uptime));
        sb.append_printf ("%d %s waiting to send.",
            pending_upload_count,
            pending_upload_count == 1 ? "screenshot" : "screenshots");

        yield _matrix_svc.send_text_message (sb.str);
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
     * The message has two sections:
     *  1. A plain-language summary a non-technical partner can understand
     *  2. Cryptographic verification data below a separator (for forensics)
     *
     * Includes gap detection (sleep/wake), recovery info (consecutive
     * failures), tamper events, and optional config hash signature.
     */
    public string build_heartbeat_message () {
        var uptime = get_uptime_seconds ();
        var sb = new StringBuilder ();

        // ── Gap detection ──
        bool has_gap = false;
        int64 gap_seconds = 0;
        var now_mono = GLib.get_monotonic_time ();
        if (_last_heartbeat_monotonic > 0) {
            var elapsed_sec = (now_mono - _last_heartbeat_monotonic) / 1000000;
            var expected_sec = (int64) interval_seconds;
            if (elapsed_sec > expected_sec * 2) {
                has_gap = true;
                gap_seconds = elapsed_sec;
                report_tamper_event (
                    "unmonitored_gap: Device was unmonitored for %s"
                    .printf (format_duration (elapsed_sec)));
                gap_detected (elapsed_sec);
            }
        }

        // ── Separate display events (filter out gap — shown in status section) ──
        var display_events = new GenericArray<string> ();
        for (int i = 0; i < _tamper_events.length; i++) {
            if (!_tamper_events[i].has_prefix ("unmonitored_gap:")) {
                display_events.add (_tamper_events[i]);
            }
        }
        bool has_warnings = display_events.length > 0;

        // ═══════════════════════════════════════════════════════════
        //  Section 1: Plain-language summary (partner-facing)
        // ═══════════════════════════════════════════════════════════

        // ── Status header ──
        if (has_warnings) {
            sb.append ("WARNING: Suspicious activity detected!");
        } else if (has_gap) {
            sb.append_printf ("NOTICE: Back online after %s",
                format_duration (gap_seconds));
        } else if (consecutive_failures > 0) {
            sb.append ("NOTICE: Connection restored");
        } else {
            sb.append ("STATUS: All clear");
        }

        // ── Warning details (human-friendly tamper event descriptions) ──
        if (has_warnings) {
            sb.append ("\n\n");
            int count = int.min ((int) display_events.length, 50);
            int start_idx = (int) display_events.length - count;
            if (start_idx > 0) {
                sb.append_printf (
                    "The following problems were found (%d total, showing last 50):\n",
                    (int) display_events.length);
            } else {
                sb.append (display_events.length == 1
                    ? "The following problem was found:\n"
                    : "The following problems were found:\n");
            }
            for (int i = start_idx; i < display_events.length; i++) {
                if (sb.len > 55000) {
                    sb.append ("  \u2026 (truncated)\n");
                    break;
                }
                sb.append_printf ("  * %s\n", describe_tamper_event (display_events[i]));
            }
        }

        // ── Gap context ──
        if (has_gap) {
            sb.append_printf ("\n%s was not monitoring for %s.\n",
                has_warnings ? "Also, Vigil" : "Vigil",
                format_duration (gap_seconds));
            sb.append ("If you received a \"Going offline\" message before this gap, ");
            sb.append ("it was probably a normal shutdown or sleep.\n");
            sb.append ("If you did NOT receive a \"Going offline\" message, ");
            sb.append ("this could be suspicious.");
        }

        // ── Network recovery ──
        if (consecutive_failures > 0 && !has_gap) {
            sb.append_printf ("\n\nVigil was running but could not reach the server. " +
                "%d %s missed.\n",
                consecutive_failures,
                consecutive_failures == 1 ? "update was" : "updates were");
            sb.append ("Screenshots taken during the outage are now being sent.");
        }

        // ── Stats ──
        sb.append_printf ("\n\nRunning for %s.\n", format_duration (uptime));
        sb.append_printf ("Screenshots taken: %d\n", screenshots_since_last);
        sb.append_printf ("Waiting to send: %d", pending_upload_count);

        // ── Deadline ──
        var deadline_minutes = (int64) interval_seconds * 2 / 60;
        sb.append_printf (
            "\n\nIf no new message arrives within %lld minutes, something may be wrong.",
            deadline_minutes);

        // ═══════════════════════════════════════════════════════════
        //  Section 2: Verification data (below separator)
        // ═══════════════════════════════════════════════════════════

        sb.append ("\n\n\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n");
        sb.append ("Verification data (you can ignore this section):");

        var prev_hash = previous_heartbeat_hash != ""
            ? previous_heartbeat_hash : "genesis";
        sb.append_printf ("\nseq: %lld | lifetime: %lld | prev: %s",
            sequence_number, lifetime_captures, prev_hash);

        if (!_attestation_sent && environment_attestation != "") {
            sb.append_printf ("\nenv: %s", environment_attestation);
            _attestation_sent = true;
        }

        if (config_hash != "") {
            sb.append_printf ("\nconfig: %s", config_hash);
            if (encryption != null && encryption.is_ready) {
                var signature = encryption.sign_string (config_hash);
                if (signature != "") {
                    sb.append_printf (" | sig: %s", signature);
                }
            }
        }

        if (_capture_hashes.length > 0) {
            var hash_concat = new StringBuilder ();
            for (int i = 0; i < _capture_hashes.length; i++) {
                hash_concat.append (_capture_hashes[i]);
            }
            var digest = SecurityUtils.compute_sha256_hex_string (hash_concat.str);
            sb.append_printf ("\ncaptures: %d | digest: %s",
                (int) _capture_hashes.length, digest);
        }

        if (encryption != null && encryption.is_ready) {
            var chain_hash = SecurityUtils.compute_sha256_hex_string (sb.str);
            var chain_sig = encryption.sign_string (chain_hash);
            if (chain_sig != "") {
                sb.append_printf ("\nchain: %s | sig: %s", chain_hash, chain_sig);
            }
        }

        return sb.str;
    }

    /**
     * Format a duration in seconds as human-readable text.
     *
     * Examples: "less than a minute", "5 minutes", "2 hours 30 minutes"
     */
    public static string format_duration (int64 total_seconds) {
        var hours = total_seconds / 3600;
        var minutes = (total_seconds % 3600) / 60;

        if (hours == 0 && minutes == 0) {
            return "less than a minute";
        }
        if (hours == 0) {
            return "%lld %s".printf (
                minutes, minutes == 1 ? "minute" : "minutes");
        }
        if (minutes == 0) {
            return "%lld %s".printf (
                hours, hours == 1 ? "hour" : "hours");
        }
        return "%lld %s %lld %s".printf (
            hours, hours == 1 ? "hour" : "hours",
            minutes, minutes == 1 ? "minute" : "minutes");
    }

    /**
     * Translate a raw tamper event string into plain language.
     *
     * Raw events use "event_type: technical details" format. This method
     * replaces them with descriptions a non-technical person can understand.
     */
    public static string describe_tamper_event (string raw_event) {
        var colon_pos = raw_event.index_of (": ");
        if (colon_pos < 0) {
            return raw_event;
        }

        var event_type = raw_event.substring (0, colon_pos);

        switch (event_type) {
            case "monitoring_disabled":
                return "Screenshot monitoring was turned off.";
            case "interval_tampered":
                return "Screenshot timing was changed to take very few screenshots.";
            case "timer_tampered":
                return "Internal timing settings were changed to unsafe values.";
            case "matrix_cleared":
                return "All connection settings were deleted. " +
                    "Vigil can no longer send you messages or screenshots.";
            case "matrix_incomplete":
                return "Some connection settings were deleted. " +
                    "The connection to you may be broken.";
            case "partner_changed":
                return "Your partner ID was changed or removed. " +
                    "Someone may be trying to stop messages from reaching you.";
            case "e2ee_disabled":
                return "Encryption keys were deleted. " +
                    "Screenshots cannot be sent securely.";
            case "autostart_missing":
                return "Vigil\u2019s autostart was removed. " +
                    "Vigil will not start automatically after the next reboot.";
            case "autostart_modified":
                return "Vigil\u2019s autostart was changed to point to " +
                    "a different program.";
            case "autostart_unreadable":
                return "Vigil\u2019s autostart file cannot be read. " +
                    "Its permissions may have been changed.";
            case "systemd_disabled":
                return "Vigil\u2019s background service was disabled. " +
                    "Vigil may not restart automatically if stopped.";
            case "settings_unlocked":
                return "The settings lock was bypassed without the unlock code.";
            case "unlock_code_cleared":
                return "The unlock code was erased while settings " +
                    "are still supposed to be locked.";
            case "binary_missing":
                return "The Vigil program file was deleted. " +
                    "Someone may be trying to uninstall Vigil.";
            case "binary_modified":
                return "The Vigil program file was replaced or modified.";
            case "binary_unreadable":
                return "The Vigil program file cannot be read. " +
                    "Its permissions may have been changed.";
            case "capture_stalled":
                return "No screenshot was taken when expected. " +
                    "The screenshot system may have stopped working.";
            case "orphan_screenshots":
                return "Some screenshots are missing their upload markers. " +
                    "They may have been tampered with to prevent upload.";
            case "disk_space_low":
                return "The device is almost out of storage space. " +
                    "Screenshots may not be saved.";
            case "screenshot_tampered":
                return "A screenshot was modified after it was taken. " +
                    "Someone may have tried to edit it before it was sent.";
            case "capture_counter_tampered":
                return "The screenshot counter was tampered with.";
            case "e2ee_init_failed":
                return "Encryption failed to start. Screenshots are saved " +
                    "locally and will be sent once encryption recovers.";
            case "background_permission_revoked":
                return "Permission for Vigil to run in the background " +
                    "was revoked. Vigil may stop when the window is closed.";
            case "ld_preload_detected":
                return "A suspicious system setting was detected that could " +
                    "be used to intercept Vigil\u2019s operations.";
            case "prctl_failed":
                return "Vigil\u2019s security hardening failed to apply.";
            case "screenshot_deleted":
                return "A screenshot was unexpectedly deleted " +
                    "before it could be sent.";
            case "marker_deleted":
                return "An upload marker was deleted. Someone may be trying " +
                    "to prevent a screenshot from being sent.";
            case "crypto_file_tampered":
                return "An encryption file was deleted or modified. " +
                    "Secure communication may be disrupted.";
            case "unmonitored_gap":
                return "The device was not being monitored for a period " +
                    "of time (see above for details).";
            case "dumpable_reactivated":
                return "A security protection was disabled and had to be " +
                    "re-enabled. Someone may be trying to inspect " +
                    "Vigil\u2019s memory.";
            case "display_service_gone":
                return "The screenshot service has disappeared. " +
                    "Screenshots may fail until it recovers.";
            case "display_service_replaced":
                return "The screenshot service was replaced with " +
                    "a different program. Screenshots may not be genuine.";
            default:
                return raw_event;
        }
    }

    /**
     * Send a heartbeat via Matrix.
     */
    public async bool send_heartbeat () {
        if (_matrix_svc == null || !_matrix_svc.is_configured) {
            return false;
        }

        sequence_number++;
        var message = build_heartbeat_message ();
        var message_hash = SecurityUtils.compute_sha256_hex_string (message);
        var sent = yield _matrix_svc.send_text_message (message);

        if (sent) {
            consecutive_failures = 0;
            screenshots_since_last = 0;
            _tamper_events.remove_range (0, _tamper_events.length);
            _capture_hashes.remove_range (0, _capture_hashes.length);
            _last_heartbeat_monotonic = GLib.get_monotonic_time ();
            previous_heartbeat_hash = message_hash;
            persist_chain_state ();
            heartbeat_sent (new DateTime.now_local ());
            // Clear persisted alerts since they were successfully sent
            clear_persisted_alerts ();
            return true;
        } else {
            consecutive_failures++;
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
     * Persist heartbeat chain state (sequence number + previous hash) to disk.
     */
    private void persist_chain_state () {
        if (data_dir == "") {
            return;
        }

        var path = Path.build_filename (data_dir, "heartbeat_chain");
        var content = "%lld\n%s\n".printf (sequence_number, previous_heartbeat_hash);

        try {
            SecurityUtils.write_secure_file (path, content);
        } catch (Error e) {
            debug ("Failed to persist chain state: %s", e.message);
        }
    }

    /**
     * Load heartbeat chain state from disk to restore chain across restarts.
     */
    private void load_chain_state () {
        if (data_dir == "") {
            return;
        }

        var path = Path.build_filename (data_dir, "heartbeat_chain");
        if (!FileUtils.test (path, FileTest.EXISTS)) {
            return;
        }

        try {
            string contents;
            FileUtils.get_contents (path, out contents);
            var lines = contents.split ("\n");

            if (lines.length >= 1 && lines[0].strip () != "") {
                sequence_number = int64.parse (lines[0].strip ());
            }

            if (lines.length >= 2 && lines[1].strip () != "") {
                previous_heartbeat_hash = lines[1].strip ();
            }

            if (sequence_number > 0 || previous_heartbeat_hash != "") {
                debug ("Restored heartbeat chain: seq=%lld, prev=%s",
                    sequence_number,
                    previous_heartbeat_hash.length >= 16
                        ? previous_heartbeat_hash.substring (0, 16) + "\u2026"
                        : previous_heartbeat_hash);
            }
        } catch (Error e) {
            debug ("Failed to load chain state: %s", e.message);
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
