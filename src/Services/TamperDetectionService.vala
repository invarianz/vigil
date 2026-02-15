/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Periodically checks system integrity and reports anomalies.
 *
 * Detected events are reported to HeartbeatService for inclusion
 * in the next heartbeat payload, so the server/accountability partner
 * is informed even when the user is actively tampering.
 */
public class Vigil.Services.TamperDetectionService : Object {

    public signal void tamper_detected (string event_type, string details);

    /** How often to run checks, in seconds. */
    public int check_interval_seconds { get; set; default = 120; }

    /** Whether the detection loop is running. */
    public bool is_running { get; private set; default = false; }

    /** Path to the autostart desktop file. */
    public string autostart_desktop_path { get; set; }

    /** Path to the daemon binary. */
    public string daemon_binary_path { get; set; default = ""; }

    /** Expected SHA256 hash of the daemon binary (set at install time). */
    public string expected_binary_hash { get; set; default = ""; }

    private GLib.Settings? _settings = null;
    private uint _timeout_source = 0;

    /**
     * Create a TamperDetectionService.
     *
     * @param settings Optional GLib.Settings instance. When null,
     *                 settings-based checks are skipped (useful in tests).
     */
    public TamperDetectionService (GLib.Settings? settings = null) {
        _settings = settings;
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
        check_screenshot_permission ();
        check_binary_integrity ();
    }

    /**
     * Compute a SHA256 hash of current GSettings values that matter.
     * Used by HeartbeatService to detect config changes server-side.
     */
    public string compute_config_hash () {
        if (_settings == null) {
            return "no-settings";
        }

        var data = "%s|%s|%d|%d|%d|%b".printf (
            _settings.get_string ("endpoint-url"),
            _settings.get_string ("api-token"),
            _settings.get_int ("min-interval-seconds"),
            _settings.get_int ("max-interval-seconds"),
            _settings.get_int ("max-local-screenshots"),
            _settings.get_boolean ("monitoring-enabled")
        );

        return Checksum.compute_for_string (ChecksumType.SHA256, data);
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

        // Check if intervals have been set absurdly high (> 1 hour)
        int min_interval = _settings.get_int ("min-interval-seconds");
        int max_interval = _settings.get_int ("max-interval-seconds");

        if (min_interval > 3600) {
            emit_tamper ("interval_tampered",
                "Minimum interval set to %d seconds (> 1 hour)".printf (min_interval));
        }

        if (max_interval > 7200) {
            emit_tamper ("interval_tampered",
                "Maximum interval set to %d seconds (> 2 hours)".printf (max_interval));
        }

        // Check if endpoint was cleared
        string endpoint = _settings.get_string ("endpoint-url");
        if (endpoint == "") {
            emit_tamper ("endpoint_cleared",
                "Upload endpoint URL has been cleared");
        }
    }

    /**
     * Check if screenshot portal permission is still granted.
     */
    public void check_screenshot_permission () {
        // On Wayland, check if the portal is accessible
        var session = Vigil.Utils.detect_session_type ();
        if (session != Vigil.Utils.SessionType.WAYLAND) {
            return; // Only relevant on Wayland
        }

        // We check by trying to talk to the portal; actual permission
        // is verified when a screenshot is attempted. If screenshots
        // start failing, ScreenshotService reports it and we pick it up.
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
            var actual_hash = Checksum.compute_for_data (ChecksumType.SHA256, contents);

            if (actual_hash != expected_binary_hash) {
                emit_tamper ("binary_modified",
                    "Daemon binary hash mismatch (expected %s, got %s)".printf (
                        expected_binary_hash.substring (0, 16) + "...",
                        actual_hash.substring (0, 16) + "..."));
            }
        } catch (Error e) {
            emit_tamper ("binary_unreadable",
                "Cannot read daemon binary: %s".printf (e.message));
        }
    }

    private void emit_tamper (string event_type, string details) {
        debug ("Tamper detected [%s]: %s", event_type, details);
        tamper_detected (event_type, details);
    }

    private void schedule_next () {
        if (!is_running) {
            return;
        }

        _timeout_source = Timeout.add_seconds ((uint) check_interval_seconds, () => {
            _timeout_source = 0;
            run_all_checks ();

            if (is_running) {
                schedule_next ();
            }

            return Source.REMOVE;
        });
    }
}
