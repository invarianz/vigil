/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Periodically checks system integrity and reports anomalies.
 *
 * Detected events are reported via the tamper_detected signal. The daemon
 * forwards these to the Matrix room so the accountability partner is
 * informed immediately, even when the user is actively tampering.
 *
 * In addition to periodic checks, this service monitors GSettings
 * reactively -- any change to a critical key triggers an immediate check.
 *
 * The check interval includes random jitter (75%-125% of base interval)
 * so an attacker cannot time modifications between predictable checks.
 */
public class Vigil.Services.TamperDetectionService : Object {

    public signal void tamper_detected (string event_type, string details);

    /** How often to run checks, in seconds (base interval before jitter). */
    public int check_interval_seconds { get; set; default = 120; }

    /** Whether the detection loop is running. */
    public bool is_running { get; private set; default = false; }

    /** Path to the autostart desktop file. */
    public string autostart_desktop_path { get; set; }

    /** Path to the daemon binary. */
    public string daemon_binary_path { get; set; default = ""; }

    /** Expected SHA256 hash of the daemon binary (set at install time). */
    public string expected_binary_hash { get; set; default = ""; }

    /** Path to the screenshots directory (for orphan detection). */
    public string screenshots_dir { get; set; default = ""; }

    /** Path to the pending markers directory (for orphan detection). */
    public string pending_dir { get; set; default = ""; }

    /** Maximum capture interval in seconds (for liveness monitoring). */
    public int max_capture_interval_seconds { get; set; default = 120; }

    /** Monotonic timestamp (usec) of the last successful screenshot capture. */
    private int64 _last_capture_monotonic = 0;

    /** Whether monitoring has started (to avoid false liveness alerts at startup). */
    private bool _monitoring_started = false;

    private GLib.Settings? _settings = null;
    private uint _timeout_source = 0;

    /** Tracks whether the background portal flag was ever seen as true. */
    private bool _background_portal_was_granted = false;

    /**
     * Create a TamperDetectionService.
     *
     * @param settings Optional GLib.Settings instance. When null,
     *                 settings-based checks are skipped (useful in tests).
     */
    public TamperDetectionService (GLib.Settings? settings = null) {
        _settings = settings;

        if (_settings != null) {
            connect_settings_signals ();
        }
    }

    construct {
        autostart_desktop_path = Path.build_filename (
            Environment.get_user_config_dir (),
            "autostart",
            "io.github.invarianz.vigil.daemon.desktop"
        );
    }

    /**
     * Start periodic tamper detection checks.
     */
    public void start () {
        if (is_running) {
            return;
        }

        is_running = true;

        // Run first check immediately
        run_all_checks ();
        schedule_next ();
    }

    /**
     * Stop the detection loop.
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
     * Run all tamper detection checks. Can be called on-demand.
     */
    public void run_all_checks () {
        check_autostart_entry ();
        check_systemd_service ();
        check_settings_sanity ();
        check_binary_integrity ();
        check_capture_liveness ();
        check_orphan_screenshots ();
    }

    /**
     * Record a successful screenshot capture for liveness monitoring.
     */
    public void report_capture_success () {
        _last_capture_monotonic = GLib.get_monotonic_time ();
        _monitoring_started = true;
    }

    /**
     * Check that screenshots are actually being captured.
     *
     * If monitoring is active but no screenshot has been taken within
     * 2x the maximum capture interval, the screenshot backend may have
     * failed silently (portal denied, compositor crash, etc.).
     */
    public void check_capture_liveness () {
        if (!_monitoring_started || _last_capture_monotonic == 0) {
            return;
        }

        if (_settings != null && !_settings.get_boolean ("monitoring-enabled")) {
            return;
        }

        var now = GLib.get_monotonic_time ();
        var elapsed_sec = (now - _last_capture_monotonic) / 1000000;
        var threshold = (int64) max_capture_interval_seconds * 2;

        if (elapsed_sec > threshold) {
            emit_tamper ("capture_stalled",
                "No screenshot captured in %lld seconds (expected every %d seconds)".printf (
                    elapsed_sec, max_capture_interval_seconds));
        }
    }

    /**
     * Detect orphan screenshots: files in the screenshots directory
     * that have no corresponding pending marker and haven't been uploaded.
     *
     * If an attacker deletes pending marker files to suppress evidence
     * upload, these orphaned screenshots will be detected.
     */
    public void check_orphan_screenshots () {
        if (screenshots_dir == "" || pending_dir == "") {
            return;
        }

        if (!FileUtils.test (screenshots_dir, FileTest.IS_DIR)) {
            return;
        }

        try {
            var dir = File.new_for_path (screenshots_dir);
            var enumerator = dir.enumerate_children (
                "standard::name",
                FileQueryInfoFlags.NONE,
                null
            );

            int orphan_count = 0;
            FileInfo? info;
            while ((info = enumerator.next_file (null)) != null) {
                var name = info.get_name ();
                if (!name.has_suffix (".png")) {
                    continue;
                }

                // Check if a pending marker exists for this file
                var marker_path = Path.build_filename (pending_dir, name + ".pending");
                if (!FileUtils.test (marker_path, FileTest.EXISTS)) {
                    orphan_count++;
                }
            }

            // A few orphans are normal (recently uploaded, cleanup pending).
            // Only alert if there are many, suggesting systematic marker deletion.
            if (orphan_count > 5) {
                emit_tamper ("orphan_screenshots",
                    "%d screenshots have no pending marker (markers may have been deleted)".printf (
                        orphan_count));
            }
        } catch (Error e) {
            debug ("Could not check for orphan screenshots: %s", e.message);
        }
    }

    /**
     * Compute a SHA256 hash of current GSettings values that matter.
     * Used to detect config changes between heartbeats.
     */
    public string compute_config_hash () {
        if (_settings == null) {
            return "no-settings";
        }

        // Hash a "is-set" sentinel for the pickle key rather than the raw
        // secret, to avoid passing the key through unnecessary code paths.
        var pickle_key_set = _settings.get_string ("e2ee-pickle-key") != "";

        var data = "%s|%s|%s|%d|%d|%d|%b|%s|%b|%s|%d|%d|%d".printf (
            _settings.get_string ("matrix-homeserver-url"),
            _settings.get_string ("matrix-access-token"),
            _settings.get_string ("matrix-room-id"),
            _settings.get_int ("min-interval-seconds"),
            _settings.get_int ("max-interval-seconds"),
            _settings.get_int ("max-local-screenshots"),
            _settings.get_boolean ("monitoring-enabled"),
            _settings.get_string ("device-id"),
            pickle_key_set,
            _settings.get_string ("partner-matrix-id"),
            _settings.get_int ("heartbeat-interval-seconds"),
            _settings.get_int ("upload-batch-interval-seconds"),
            _settings.get_int ("tamper-check-interval-seconds")
        );

        return SecurityUtils.compute_sha256_hex_string (data);
    }

    /**
     * Check that the autostart desktop file exists and hasn't been tampered with.
     */
    public void check_autostart_entry () {
        if (!FileUtils.test (autostart_desktop_path, FileTest.EXISTS)) {
            emit_tamper ("autostart_missing",
                "Autostart desktop entry is missing: %s".printf (autostart_desktop_path));
            return;
        }

        // Check that the Exec line points to the right binary
        try {
            string contents;
            FileUtils.get_contents (autostart_desktop_path, out contents);
            if (!contents.contains ("io.github.invarianz.vigil.daemon")) {
                emit_tamper ("autostart_modified",
                    "Autostart entry does not reference the daemon binary");
            }
        } catch (Error e) {
            emit_tamper ("autostart_unreadable",
                "Cannot read autostart entry: %s".printf (e.message));
        }
    }

    /**
     * Check that the systemd user service is enabled and active.
     */
    public void check_systemd_service () {
        try {
            var enabled_proc = new Subprocess.newv (
                { "systemctl", "--user", "is-enabled", "vigil-daemon.service" },
                SubprocessFlags.STDOUT_PIPE | SubprocessFlags.STDERR_MERGE
            );
            string stdout_buf;
            enabled_proc.communicate_utf8 (null, null, out stdout_buf, null);

            if (!enabled_proc.get_successful ()) {
                emit_tamper ("systemd_disabled",
                    "vigil-daemon.service is not enabled (status: %s)".printf (
                        stdout_buf.strip ()));
            }
        } catch (Error e) {
            // systemctl may not be available (e.g., in containers)
            debug ("Could not check systemd service: %s", e.message);
        }
    }

    /**
     * Check that GSettings values are sane (not tampered to disable monitoring).
     */
    public void check_settings_sanity () {
        if (_settings == null) {
            return;
        }

        // Check if monitoring was disabled
        if (!_settings.get_boolean ("monitoring-enabled")) {
            emit_tamper ("monitoring_disabled",
                "Monitoring has been disabled via settings");
        }

        // Check if intervals have been set too high (> 5 minutes)
        // The absolute maximum gap between screenshots should be 2 minutes,
        // so anything above 5 minutes is clearly tampered.
        int min_interval = _settings.get_int ("min-interval-seconds");
        int max_interval = _settings.get_int ("max-interval-seconds");

        if (min_interval > 300) {
            emit_tamper ("interval_tampered",
                "Minimum interval set to %d seconds (> 5 minutes)".printf (min_interval));
        }

        if (max_interval > 300) {
            emit_tamper ("interval_tampered",
                "Maximum interval set to %d seconds (> 5 minutes)".printf (max_interval));
        }

        // Check if Matrix transport was cleared
        string hs_url = _settings.get_string ("matrix-homeserver-url");
        string token = _settings.get_string ("matrix-access-token");
        string room_id = _settings.get_string ("matrix-room-id");

        if (hs_url == "" && token == "" && room_id == "") {
            emit_tamper ("matrix_cleared",
                "All Matrix transport settings have been cleared");
        } else if (hs_url == "" || token == "" || room_id == "") {
            emit_tamper ("matrix_incomplete",
                "Matrix transport settings are partially cleared (transport broken)");
        }

        // Check if service timers have been set dangerously high.
        // Heartbeat > 1 hour, upload batch > 1 hour, tamper check > 30 min
        // are all far beyond the defaults and indicate intentional tampering.
        int heartbeat_interval = _settings.get_int ("heartbeat-interval-seconds");
        if (heartbeat_interval > 3600) {
            emit_tamper ("timer_tampered",
                "Heartbeat interval set to %d seconds (> 1 hour)".printf (heartbeat_interval));
        }

        int upload_batch_interval = _settings.get_int ("upload-batch-interval-seconds");
        if (upload_batch_interval > 3600) {
            emit_tamper ("timer_tampered",
                "Upload batch interval set to %d seconds (> 1 hour)".printf (upload_batch_interval));
        }

        int tamper_check_interval = _settings.get_int ("tamper-check-interval-seconds");
        if (tamper_check_interval > 1800) {
            emit_tamper ("timer_tampered",
                "Tamper check interval set to %d seconds (> 30 min)".printf (tamper_check_interval));
        }

        // Check if partner Matrix ID was changed or cleared
        string partner_id = _settings.get_string ("partner-matrix-id");
        if (hs_url != "" && token != "" && room_id != "" && partner_id == "") {
            emit_tamper ("partner_changed",
                "Partner Matrix ID was cleared while transport is configured");
        }

        // Check if E2EE settings were cleared
        string device_id = _settings.get_string ("device-id");
        string pickle_key = _settings.get_string ("e2ee-pickle-key");

        if (device_id != "" && pickle_key == "") {
            emit_tamper ("e2ee_disabled",
                "E2EE pickle key was cleared (encryption will not work)");
        }

        // Check if background portal permission was revoked via dconf
        bool bg_granted = _settings.get_boolean ("background-portal-granted");
        if (bg_granted) {
            _background_portal_was_granted = true;
        } else if (_background_portal_was_granted) {
            emit_background_permission_revoked ();
        }

        // Check if settings lock was bypassed
        check_settings_lock ();
    }

    /**
     * Check that the settings lock hasn't been bypassed via CLI.
     *
     * If `settings-locked` was changed to false, or the unlock code hash
     * was cleared while locked, this is a tamper event. The GUI sends a
     * "Settings unlocked (authorized by partner)" message BEFORE toggling
     * the lock, so the partner can distinguish legitimate vs. bypassed
     * unlocks by checking whether that message preceded the alert.
     */
    public void check_settings_lock () {
        if (_settings == null) {
            return;
        }

        // If settings were previously locked (hash exists) but lock flag cleared
        var hash = _settings.get_string ("unlock-code-hash");
        var locked = _settings.get_boolean ("settings-locked");

        if (hash != "" && !locked) {
            emit_tamper ("settings_unlocked",
                "Settings lock was disabled (unlock code may have been bypassed)");
        }

        // If lock is set but hash was cleared (attempt to make unlock trivial)
        if (locked && hash == "") {
            emit_tamper ("unlock_code_cleared",
                "Unlock code hash was cleared while settings are locked");
        }
    }

    /**
     * Verify the daemon binary hasn't been replaced.
     */
    public void check_binary_integrity () {
        if (daemon_binary_path == "" || expected_binary_hash == "") {
            return; // No baseline to compare against
        }

        if (!FileUtils.test (daemon_binary_path, FileTest.EXISTS)) {
            emit_tamper ("binary_missing",
                "Daemon binary not found at %s".printf (daemon_binary_path));
            return;
        }

        try {
            uint8[] contents;
            FileUtils.get_data (daemon_binary_path, out contents);
            var actual_hash = SecurityUtils.compute_sha256_hex (contents);

            if (actual_hash != expected_binary_hash) {
                emit_tamper ("binary_modified",
                    "Daemon binary hash mismatch (expected %s, got %s)".printf (
                        expected_binary_hash.substring (0, 16) + "\u2026",
                        actual_hash.substring (0, 16) + "\u2026"));
            }
        } catch (Error e) {
            emit_tamper ("binary_unreadable",
                "Cannot read daemon binary: %s".printf (e.message));
        }
    }

    /**
     * Connect to GSettings changed signals for reactive tamper detection.
     * Any change to a critical key triggers an immediate settings check.
     */
    private void connect_settings_signals () {
        string[] critical_keys = {
            "monitoring-enabled",
            "min-interval-seconds",
            "max-interval-seconds",
            "matrix-homeserver-url",
            "matrix-access-token",
            "matrix-room-id",
            "device-id",
            "e2ee-pickle-key",
            "settings-locked",
            "unlock-code-hash",
            "heartbeat-interval-seconds",
            "upload-batch-interval-seconds",
            "tamper-check-interval-seconds",
            "partner-matrix-id",
            "background-portal-granted"
        };

        foreach (var key in critical_keys) {
            _settings.changed[key].connect (() => {
                if (is_running) {
                    debug ("Critical setting changed, running tamper check");
                    check_settings_sanity ();
                }
            });
        }
    }

    /**
     * Report a tamper event from an external source.
     *
     * Used by other services (e.g. DBusServer) to funnel tamper events
     * through the same signal pipeline for immediate partner notification.
     */
    public void report_tamper (string event_type, string details) {
        emit_tamper (event_type, details);
    }

    /**
     * Emit a tamper event for E2EE initialization failure.
     * Called by the daemon when E2EE was configured but failed to start.
     */
    public void emit_e2ee_init_failure () {
        emit_tamper ("e2ee_init_failed",
            "E2EE initialization failed at startup -- " +
            "monitoring will not send screenshots until encryption is restored");
    }

    /**
     * Emit a tamper event for background portal permission revocation.
     * Called by the daemon when the XDG Background portal denies autostart.
     */
    public void emit_background_permission_revoked () {
        emit_tamper ("background_permission_revoked",
            "Background portal autostart permission was revoked -- " +
            "daemon will not auto-start at next login");
    }

    private void emit_tamper (string event_type, string details) {
        debug ("Tamper detected [%s]: %s", event_type, details);
        tamper_detected (event_type, details);
    }

    /**
     * Compute a jittered interval for the next tamper check.
     *
     * Adds random jitter of 75%-125% of the base interval using CSPRNG,
     * so an attacker cannot predict when the next check will run and
     * time modifications to fall between checks.
     */
    private int get_jittered_interval () {
        int base_interval = check_interval_seconds;
        int min_val = base_interval * 3 / 4;
        int max_val = base_interval * 5 / 4;

        if (min_val >= max_val) {
            return base_interval;
        }

        int range = max_val - min_val;
        uint32 rand_val = SecurityUtils.csprng_uint32 ();

        return min_val + (int) (rand_val % (range + 1));
    }

    private void schedule_next () {
        if (!is_running) {
            return;
        }

        var interval = get_jittered_interval ();
        _timeout_source = Timeout.add_seconds ((uint) interval, () => {
            _timeout_source = 0;
            run_all_checks ();

            if (is_running) {
                schedule_next ();
            }

            return Source.REMOVE;
        });
    }
}
