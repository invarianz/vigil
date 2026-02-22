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
    public string build_heartbeat_message (out string? html_body = null) {
        var uptime = get_uptime_seconds ();
        var sb = new StringBuilder ();
        var html = new StringBuilder ();

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
                    "~unmonitored_gap: Device was unmonitored for %s"
                    .printf (format_duration (elapsed_sec)));
                gap_detected (elapsed_sec);
            }
        }

        // ── Separate display events into tamper attempts and warnings ──
        var tamper_events = new GenericArray<string> ();
        var warning_events = new GenericArray<string> ();
        for (int i = 0; i < _tamper_events.length; i++) {
            var evt = _tamper_events[i];
            // Filter out gap events — shown in status section
            if (evt.has_prefix ("unmonitored_gap:") ||
                evt.has_prefix ("~unmonitored_gap:")) {
                continue;
            }
            if (is_warning_event (evt)) {
                warning_events.add (evt);
            } else {
                tamper_events.add (evt);
            }
        }
        bool has_tampers = tamper_events.length > 0;
        bool has_warnings = warning_events.length > 0;
        bool has_events = has_tampers || has_warnings;

        // ═══════════════════════════════════════════════════════════
        //  Section 1: Plain-language summary (partner-facing)
        // ═══════════════════════════════════════════════════════════

        // ── Status header ──
        if (has_tampers) {
            sb.append ("TAMPER ATTEMPT DETECTED!");
            html.append ("<b><font color=\"#dc3545\">TAMPER ATTEMPT DETECTED!</font></b>");
        } else if (has_warnings) {
            sb.append ("WARNING: Issues detected");
            html.append ("<font color=\"#fd7e14\">WARNING: Issues detected</font>");
        } else if (has_gap) {
            var gap_text = "NOTICE: Back online after %s".printf (
                format_duration (gap_seconds));
            sb.append (gap_text);
            html.append (Markup.escape_text (gap_text));
        } else if (consecutive_failures > 0) {
            sb.append ("NOTICE: Connection restored");
            html.append ("NOTICE: Connection restored");
        } else {
            sb.append ("STATUS: All clear");
            html.append ("STATUS: All clear");
        }

        // ── Tamper event details (bold red) ──
        if (has_tampers) {
            sb.append ("\n\n");
            html.append ("<br><br>");
            int count = int.min ((int) tamper_events.length, 50);
            int start_idx = (int) tamper_events.length - count;
            if (start_idx > 0) {
                var intro = "Tamper attempts detected (%d total, showing last 50):\n".printf (
                    (int) tamper_events.length);
                sb.append (intro);
                html.append (Markup.escape_text (intro.strip ()));
                html.append ("<br>");
            } else {
                var intro = tamper_events.length == 1
                    ? "Tamper attempt detected:\n"
                    : "Tamper attempts detected:\n";
                sb.append (intro);
                html.append (Markup.escape_text (intro.strip ()));
                html.append ("<br>");
            }
            for (int i = start_idx; i < tamper_events.length; i++) {
                if (sb.len > 50000) {
                    sb.append ("  \u2026 (truncated)\n");
                    html.append ("\u2026 (truncated)<br>");
                    break;
                }
                var desc = describe_tamper_event (tamper_events[i]);
                sb.append_printf ("  * %s\n", desc);
                html.append_printf ("<b><font color=\"#dc3545\">  \u2022 %s</font></b><br>",
                    Markup.escape_text (desc));
            }
        }

        // ── Warning event details (orange) ──
        if (has_warnings) {
            sb.append ("\n");
            html.append ("<br>");
            int count = int.min ((int) warning_events.length, 50);
            int start_idx = (int) warning_events.length - count;
            if (has_tampers) {
                var intro = "Also, the following issues were found:\n";
                sb.append (intro);
                html.append (Markup.escape_text (intro.strip ()));
                html.append ("<br>");
            } else if (start_idx > 0) {
                var intro = "The following issues were found (%d total, showing last 50):\n".printf (
                    (int) warning_events.length);
                sb.append (intro);
                html.append (Markup.escape_text (intro.strip ()));
                html.append ("<br>");
            } else {
                var intro = warning_events.length == 1
                    ? "The following issue was found:\n"
                    : "The following issues were found:\n";
                sb.append (intro);
                html.append (Markup.escape_text (intro.strip ()));
                html.append ("<br>");
            }
            for (int i = start_idx; i < warning_events.length; i++) {
                if (sb.len > 55000) {
                    sb.append ("  \u2026 (truncated)\n");
                    html.append ("\u2026 (truncated)<br>");
                    break;
                }
                var desc = describe_tamper_event (warning_events[i]);
                sb.append_printf ("  * %s\n", desc);
                html.append_printf ("<font color=\"#fd7e14\">  \u2022 %s</font><br>",
                    Markup.escape_text (desc));
            }
        }

        // ── Gap context ──
        if (has_gap) {
            var gap_line = "\n%s was not monitoring for %s.\n".printf (
                has_events ? "Also, Vigil" : "Vigil",
                format_duration (gap_seconds));
            sb.append (gap_line);
            html.append ("<br>");
            html.append (Markup.escape_text (gap_line.strip ()));
            html.append ("<br>");

            var offline_line = "If you received a \"Going offline\" message before this gap, " +
                "it was probably a normal shutdown or sleep.\n" +
                "If you did NOT receive a \"Going offline\" message, " +
                "this could be suspicious.";
            sb.append (offline_line);
            html.append (Markup.escape_text (offline_line));
        }

        // ── Network recovery ──
        if (consecutive_failures > 0 && !has_gap) {
            var recovery = "\n\nVigil was running but could not reach the server. " +
                "%d %s missed.\n".printf (
                    consecutive_failures,
                    consecutive_failures == 1 ? "update was" : "updates were") +
                "Screenshots taken during the outage are now being sent.";
            sb.append (recovery);
            html.append ("<br><br>");
            html.append (Markup.escape_text (recovery.strip ()));
        }

        // ── Stats ──
        var stats = "\n\nRunning for %s.\nScreenshots taken: %d\nWaiting to send: %d".printf (
            format_duration (uptime), screenshots_since_last, pending_upload_count);
        sb.append (stats);
        html.append ("<br><br>");
        html.append (Markup.escape_text (stats.strip ()).replace ("\n", "<br>"));

        // ── Deadline ──
        var deadline_minutes = (int64) interval_seconds * 2 / 60;
        var deadline = "\n\nIf no new message arrives within %lld minutes, something may be wrong.".printf (
            deadline_minutes);
        sb.append (deadline);
        html.append ("<br><br>");
        html.append (Markup.escape_text (deadline.strip ()));

        // ═══════════════════════════════════════════════════════════
        //  Section 2: Verification data (below separator)
        // ═══════════════════════════════════════════════════════════

        sb.append ("\n\n\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n");
        sb.append ("Verification data (you can ignore this section):");
        html.append ("<br><br>\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500<br>");
        html.append ("Verification data (you can ignore this section):<br><pre>");

        var prev_hash = previous_heartbeat_hash != ""
            ? previous_heartbeat_hash : "genesis";
        var seq_line = "seq: %lld | lifetime: %lld | prev: %s".printf (
            sequence_number, lifetime_captures, prev_hash);
        sb.append_printf ("\n%s", seq_line);
        html.append (Markup.escape_text (seq_line));

        if (!_attestation_sent && environment_attestation != "") {
            var env_line = "env: %s".printf (environment_attestation);
            sb.append_printf ("\n%s", env_line);
            html.append_printf ("\n%s", Markup.escape_text (env_line));
            _attestation_sent = true;
        }

        if (config_hash != "") {
            sb.append_printf ("\nconfig: %s", config_hash);
            html.append_printf ("\nconfig: %s", Markup.escape_text (config_hash));
            if (encryption != null && encryption.is_ready) {
                var signature = encryption.sign_string (config_hash);
                if (signature != "") {
                    sb.append_printf (" | sig: %s", signature);
                    html.append_printf (" | sig: %s", Markup.escape_text (signature));
                }
            }
        }

        if (_capture_hashes.length > 0) {
            var hash_concat = new StringBuilder ();
            for (int i = 0; i < _capture_hashes.length; i++) {
                hash_concat.append (_capture_hashes[i]);
            }
            var digest = SecurityUtils.compute_sha256_hex_string (hash_concat.str);
            var cap_line = "captures: %d | digest: %s".printf (
                (int) _capture_hashes.length, digest);
            sb.append_printf ("\n%s", cap_line);
            html.append_printf ("\n%s", Markup.escape_text (cap_line));
        }

        if (encryption != null && encryption.is_ready) {
            var chain_hash = SecurityUtils.compute_sha256_hex_string (sb.str);
            var chain_sig = encryption.sign_string (chain_hash);
            if (chain_sig != "") {
                var chain_line = "chain: %s | sig: %s".printf (chain_hash, chain_sig);
                sb.append_printf ("\n%s", chain_line);
                html.append_printf ("\n%s", Markup.escape_text (chain_line));
            }
        }

        html.append ("</pre>");
        html_body = html.str;

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
    /**
     * Check whether a raw event string represents a warning (not a tamper attempt).
     *
     * Warning events are prefixed with "~" by TamperDetectionService to
     * indicate they are system issues or legitimate setting changes, not
     * active tampering.
     */
    public static bool is_warning_event (string raw_event) {
        return raw_event.has_prefix ("~");
    }

    public static string describe_tamper_event (string raw_event) {
        var colon_pos = raw_event.index_of (": ");
        if (colon_pos < 0) {
            return raw_event;
        }

        var event_type = raw_event.substring (0, colon_pos);
        // Strip warning prefix before lookup
        if (event_type.has_prefix ("~")) {
            event_type = event_type.substring (1);
        }

        switch (event_type) {
            case "monitoring_disabled":
                return "Screenshot monitoring was turned off. " +
                    "No screenshots are being taken.";
            case "interval_tampered":
                return "Screenshot timing was changed to take very " +
                    "few screenshots. Long gaps between screenshots " +
                    "mean activity is going unmonitored.";
            case "timer_tampered":
                return "Vigil\u2019s check-in timing was changed to very " +
                    "long intervals. You will receive fewer updates " +
                    "and problems will be detected much slower.";
            case "matrix_cleared":
                return "All connection settings were deleted. " +
                    "Vigil can no longer send you messages or screenshots.";
            case "matrix_incomplete":
                return "Some connection settings were deleted. " +
                    "Vigil\u2019s connection to you is broken \u2014 " +
                    "you will NOT receive screenshots or updates " +
                    "until this is fixed.";
            case "partner_changed":
                return "Your partner ID was removed from the settings. " +
                    "Messages and screenshots will no longer be sent to you.";
            case "e2ee_disabled":
                return "Encryption keys were deleted. " +
                    "Screenshots cannot be sent securely.";
            case "settings_unlocked":
                return "The settings lock was bypassed without " +
                    "the unlock code.";
            case "unlock_code_cleared":
                return "The unlock code was erased while settings " +
                    "are locked. Someone is trying to bypass " +
                    "the settings lock.";
            case "capture_stalled":
                return "No screenshot has been taken when expected. " +
                    "The screenshot system has stopped working \u2014 " +
                    "activity is NOT being monitored.";
            case "orphan_screenshots":
                return "Upload markers were deleted to prevent " +
                    "screenshots from being sent to you.";
            case "disk_space_low":
                return "The device is almost out of storage space. " +
                    "New screenshots cannot be saved.";
            case "screenshot_tampered":
                return "A screenshot was modified after it was taken. " +
                    "Someone edited it before it was sent to you.";
            case "capture_counter_tampered":
                return "The screenshot counter was tampered with. " +
                    "Someone is trying to hide how many screenshots " +
                    "were taken.";
            case "e2ee_init_failed":
                return "Encryption failed to start. Screenshots are saved " +
                    "locally and will be sent once encryption recovers.";
            case "background_permission_revoked":
                return "Permission for Vigil to run in the background " +
                    "was revoked. Vigil will stop running when the " +
                    "window is closed and will NOT restart automatically.";
            case "screenshot_deleted":
                return "A screenshot was deleted before it could be " +
                    "sent to you. Someone is destroying evidence.";
            case "marker_deleted":
                return "An upload marker was deleted to prevent " +
                    "a screenshot from being sent to you.";
            case "crypto_file_tampered":
                return "An encryption file was deleted. Encrypted " +
                    "communication with you is broken.";
            case "unmonitored_gap":
                return "The device was not being monitored for a period " +
                    "of time (see above for details).";
            case "sandbox_escaped":
                return "Vigil is running outside its Flatpak sandbox. " +
                    "All security protections are bypassed \u2014 " +
                    "screenshots and encryption cannot be trusted.";
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
        string? html_body;
        var message = build_heartbeat_message (out html_body);
        var message_hash = SecurityUtils.compute_sha256_hex_string (message);
        bool sent;
        if (html_body != null) {
            sent = yield _matrix_svc.send_html_message (message, html_body);
        } else {
            sent = yield _matrix_svc.send_text_message (message);
        }

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

            if (lines.length >= 1) {
                var seq_str = lines[0].strip ();
                if (seq_str != "") {
                    sequence_number = int64.parse (seq_str);
                }
            }

            if (lines.length >= 2) {
                var prev_hash = lines[1].strip ();
                if (prev_hash != "") {
                    previous_heartbeat_hash = prev_hash;
                }
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
