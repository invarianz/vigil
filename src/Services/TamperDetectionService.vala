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

    /** Path to the screenshots directory (for orphan detection). */
    public string screenshots_dir { get; set; default = ""; }

    /** Path to the pending markers directory (for orphan detection). */
    public string pending_dir { get; set; default = ""; }

    /** Path to the crypto directory (for file monitoring). Empty = auto-detect. */
    public string crypto_dir { get; set; default = ""; }

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

    /** Tracks whether monitoring was ever active (to avoid false alerts on first setup). */
    private bool _monitoring_was_active = false;

    /** Tracks whether settings were ever observed as locked. */
    private bool _settings_were_locked = false;

    /** Paths that the daemon itself is about to delete (expected, not tamper). */
    private GenericSet<string> _expected_deletions;

    /** Active GIO file monitors for inotify watches. */
    private GenericArray<FileMonitor> _monitors;

    /** Whether file monitoring is active. */
    private bool _file_monitoring_active = false;

    /** Cached config hash (invalidated on settings change). */
    private string? _cached_config_hash = null;

    /**
     * Create a TamperDetectionService.
     *
     * @param settings Optional GLib.Settings instance. When null,
     *                 settings-based checks are skipped (useful in tests).
     */
    public TamperDetectionService (GLib.Settings? settings = null) {
        _settings = settings;
        _expected_deletions = new GenericSet<string> (str_hash, str_equal);
        _monitors = new GenericArray<FileMonitor> ();

        if (_settings != null) {
            connect_settings_signals ();
        }
    }

    construct {
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
     * Stop the detection loop and file monitoring.
     */
    public void stop () {
        if (!is_running) {
            return;
        }

        stop_file_monitoring ();

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
        check_settings_sanity ();
        check_dumpable ();
        check_tracer_pid ();
        SecurityUtils.check_ld_so_preload (null, this);
        check_display_service ();
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
            emit_warning ("capture_stalled",
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
     *
     * The result is cached and invalidated when any watched setting
     * changes (via connect_settings_signals). This eliminates 12
     * GSettings reads + string formatting + SHA-256 on cache hits.
     */
    public string compute_config_hash () {
        if (_settings == null) {
            return "no-settings";
        }

        if (_cached_config_hash != null) {
            return _cached_config_hash;
        }

        // Hash a "is-set" sentinel for the pickle key rather than the raw
        // secret, to avoid passing the key through unnecessary code paths.
        var pickle_key_set = _settings.get_string ("e2ee-pickle-key") != "";

        var data = "%s|%s|%s|%d|%d|%b|%s|%b|%s|%d|%d|%d".printf (
            _settings.get_string ("matrix-homeserver-url"),
            _settings.get_string ("matrix-access-token"),
            _settings.get_string ("matrix-room-id"),
            _settings.get_int ("min-interval-seconds"),
            _settings.get_int ("max-interval-seconds"),
            _settings.get_boolean ("monitoring-enabled"),
            _settings.get_string ("device-id"),
            pickle_key_set,
            _settings.get_string ("partner-matrix-id"),
            _settings.get_int ("heartbeat-interval-seconds"),
            _settings.get_int ("upload-batch-interval-seconds"),
            _settings.get_int ("tamper-check-interval-seconds")
        );

        _cached_config_hash = SecurityUtils.compute_sha256_hex_string (data);
        return _cached_config_hash;
    }

    /**
     * Check that GSettings values are sane (not tampered to disable monitoring).
     */
    public void check_settings_sanity () {
        if (_settings == null) {
            return;
        }

        bool locked = _settings.get_boolean ("settings-locked");

        // Track whether monitoring was ever active
        if (_settings.get_boolean ("monitoring-enabled")) {
            _monitoring_was_active = true;
        }

        // Only alert if monitoring was previously active and then disabled.
        // Severity depends on lock state: changing settings while unlocked
        // is legitimate (warning), while locked is a tamper attempt.
        if (_monitoring_was_active &&
            !_settings.get_boolean ("monitoring-enabled")) {
            emit_lock_dependent (locked, "monitoring_disabled",
                "Monitoring has been disabled via settings");
        }

        // Check screenshot interval bounds.
        // Valid range: 30-120 seconds with >= 30s gap between min and max.
        // Any values outside these bounds indicate direct dconf tampering.
        int min_interval = _settings.get_int ("min-interval-seconds");
        int max_interval = _settings.get_int ("max-interval-seconds");

        if (min_interval < 30) {
            emit_tamper ("interval_tampered",
                "Minimum interval set to %d seconds (below 30s floor)".printf (min_interval));
        }

        if (max_interval > 120) {
            emit_tamper ("interval_tampered",
                "Maximum interval set to %d seconds (above 2 minute ceiling)".printf (max_interval));
        }

        if (max_interval - min_interval < 30 && min_interval >= 30 && max_interval <= 120) {
            emit_tamper ("interval_tampered",
                "Interval gap is %d seconds (below 30s minimum gap)".printf (max_interval - min_interval));
        }

        // Check if Matrix transport was cleared (only after setup is complete,
        // since settings are written one-by-one during initial setup and the
        // intermediate state would cause false positives).
        string hs_url = _settings.get_string ("matrix-homeserver-url");
        string token = _settings.get_string ("matrix-access-token");
        string room_id = _settings.get_string ("matrix-room-id");

        if (_settings_were_locked) {
            if (hs_url == "" && token == "" && room_id == "") {
                emit_tamper ("matrix_cleared",
                    "All Matrix transport settings have been cleared");
            } else if (hs_url == "" || token == "" || room_id == "") {
                emit_tamper ("matrix_incomplete",
                    "Matrix transport settings are partially cleared (transport broken)");
            }
        }

        // Check if service timers have been set dangerously high.
        // Heartbeat > 1 hour, upload batch > 1 hour, tamper check > 30 min
        // are all far beyond the defaults and indicate intentional tampering.
        int heartbeat_interval = _settings.get_int ("heartbeat-interval-seconds");
        if (heartbeat_interval >= 3600) {
            emit_lock_dependent (locked, "timer_tampered",
                "Heartbeat interval set to %d seconds (>= 1 hour)".printf (heartbeat_interval));
        }

        int upload_batch_interval = _settings.get_int ("upload-batch-interval-seconds");
        if (upload_batch_interval >= 3600) {
            emit_lock_dependent (locked, "timer_tampered",
                "Upload batch interval set to %d seconds (>= 1 hour)".printf (upload_batch_interval));
        }

        int tamper_check_interval = _settings.get_int ("tamper-check-interval-seconds");
        if (tamper_check_interval >= 1800) {
            emit_lock_dependent (locked, "timer_tampered",
                "Tamper check interval set to %d seconds (>= 30 min)".printf (tamper_check_interval));
        }

        // Check if partner Matrix ID was changed or cleared
        string partner_id = _settings.get_string ("partner-matrix-id");
        if (hs_url != "" && token != "" && room_id != "" && partner_id == "") {
            emit_lock_dependent (locked, "partner_changed",
                "Partner Matrix ID was cleared while transport is configured");
        }

        // Check if E2EE settings were cleared
        string device_id = _settings.get_string ("device-id");
        string pickle_key = _settings.get_string ("e2ee-pickle-key");

        if (device_id != "" && pickle_key == "") {
            emit_lock_dependent (locked, "e2ee_disabled",
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
     * The GUI writes an `authorized_unlock` marker file before toggling
     * `settings-locked` to false. If the marker is present, this is a
     * legitimate unlock (WARNING). If absent, it was a dconf bypass (TAMPER).
     */
    public void check_settings_lock () {
        if (_settings == null) {
            return;
        }

        var hash = _settings.get_string ("unlock-code-hash");
        var locked = _settings.get_boolean ("settings-locked");

        // Track lock state to avoid false positives during initial setup
        if (locked) {
            _settings_were_locked = true;
        }

        // Only alert if we previously observed settings as locked and they got unlocked
        if (_settings_were_locked && hash != "" && !locked) {
            var marker = Path.build_filename (
                SecurityUtils.get_app_data_dir (), "authorized_unlock"
            );
            if (FileUtils.test (marker, FileTest.EXISTS)) {
                FileUtils.unlink (marker);
                emit_warning ("settings_unlocked",
                    "Settings unlocked with correct code (authorized)");
            } else {
                emit_tamper ("settings_unlocked",
                    "Settings lock was disabled (unlock code may have been bypassed)");
            }
        }

        // If lock is set but hash was cleared (attempt to make unlock trivial)
        if (locked && hash == "") {
            emit_tamper ("unlock_code_cleared",
                "Unlock code hash was cleared while settings are locked");
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
                // Invalidate cached config hash on any settings change
                _cached_config_hash = null;
                if (is_running) {
                    debug ("Critical setting changed, running tamper check");
                    check_settings_sanity ();
                }
            });
        }
    }

    /**
     * Register a path as an expected deletion (called before the daemon's own deletes).
     *
     * The file monitor will ignore DELETE events for registered paths.
     */
    public void expect_deletion (string path) {
        _expected_deletions.add (path.dup ());
    }

    /**
     * Start inotify watches on critical directories.
     *
     * Monitors screenshots_dir and pending_dir for unexpected deletions,
     * and the crypto directory for any modifications.
     */
    public void start_file_monitoring () {
        if (_file_monitoring_active) {
            return;
        }

        _file_monitoring_active = true;

        // Watch screenshots directory
        if (screenshots_dir != "") {
            watch_directory (screenshots_dir, "screenshot");
        }

        // Watch pending markers directory
        if (pending_dir != "") {
            watch_directory (pending_dir, "marker");
        }

        // Note: the crypto directory is NOT monitored via inotify because
        // GLib's atomic file writes (used by write_secure_file) create
        // temp files that trigger spurious DELETE events on every pickle
        // save. Crypto integrity is verified via periodic checks instead.
    }

    /**
     * Stop all file monitors.
     */
    public void stop_file_monitoring () {
        if (!_file_monitoring_active) {
            return;
        }

        for (int i = 0; i < _monitors.length; i++) {
            _monitors[i].cancel ();
        }
        _monitors.remove_range (0, _monitors.length);
        _file_monitoring_active = false;
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

    /** PID of the display service (Portal/compositor). 0 = unconfigured. */
    public uint32 display_service_pid { get; set; default = 0; }

    /** Executable path of the display service at registration time. */
    public string display_service_exe { get; set; default = ""; }

    /** D-Bus name of the display service (for diagnostics). */
    public string display_service_name { get; set; default = ""; }

    /**
     * Check that the process dumpable flag hasn't been re-enabled.
     *
     * If an attacker re-enables PR_SET_DUMPABLE after startup hardening,
     * this detects it, re-hardens, and fires a tamper event.
     */
    public void check_dumpable () {
        var warning_msg = SecurityUtils.check_and_reharden_dumpable ();
        if (warning_msg != null) {
            emit_tamper ("dumpable_reactivated", warning_msg);
        }
    }

    /**
     * Check whether another process is tracing this process via ptrace.
     *
     * Root can ptrace despite PR_SET_DUMPABLE=0 via CAP_SYS_PTRACE.
     * TracerPid in /proc/self/status is non-zero when actively traced.
     */
    public void check_tracer_pid () {
        try {
            string contents;
            FileUtils.get_contents ("/proc/self/status", out contents);
            foreach (var line in contents.split ("\n")) {
                if (line.has_prefix ("TracerPid:")) {
                    var pid_str = line.substring (10).strip ();
                    if (pid_str != "0" && pid_str != "") {
                        emit_tamper ("ptrace_detected",
                            "Process is being traced by PID %s".printf (pid_str));
                    }
                    break;
                }
            }
        } catch (Error e) {
            // Not actionable
        }
    }

    /**
     * Check that the display service (Portal/compositor) is still running
     * and hasn't been replaced by a different executable.
     *
     * If the PID is gone, the compositor may have crashed or been killed.
     * If the exe changed, a fake display service may have been substituted.
     */
    public void check_display_service () {
        if (display_service_pid == 0) {
            return;
        }

        var proc_dir = "/proc/%u".printf (display_service_pid);
        if (!FileUtils.test (proc_dir, FileTest.IS_DIR)) {
            emit_warning ("display_service_gone",
                "Display service %s (PID %u) is no longer running".printf (
                    display_service_name, display_service_pid));
            display_service_pid = 0;
            return;
        }

        var exe_link = "%s/exe".printf (proc_dir);
        try {
            var current_exe = FileUtils.read_link (exe_link);
            if (display_service_exe != "" && current_exe != display_service_exe) {
                emit_tamper ("display_service_replaced",
                    "Display service %s (PID %u) exe changed from %s to %s".printf (
                        display_service_name, display_service_pid,
                        display_service_exe, current_exe));
            }
        } catch (Error e) {
            // Cannot read exe link -- process may have exited between checks
            debug ("Could not read exe for display service PID %u: %s",
                display_service_pid, e.message);
        }
    }

    /**
     * Emit a tamper event for E2EE initialization failure.
     * Called by the daemon when E2EE was configured but failed to start.
     */
    public void emit_e2ee_init_failure () {
        emit_warning ("e2ee_init_failed",
            "E2EE initialization failed at startup -- " +
            "monitoring will not send screenshots until encryption is restored");
    }

    /**
     * Emit a tamper event for background portal permission revocation.
     * Called by the daemon when the XDG Background portal denies autostart.
     */
    public void emit_background_permission_revoked () {
        emit_warning ("background_permission_revoked",
            "Background portal autostart permission was revoked -- " +
            "daemon will not auto-start at next login");
    }

    /**
     * Set up a GIO FileMonitor on a directory with the given category tag.
     */
    private void watch_directory (string dir_path, string category) {
        try {
            var dir = File.new_for_path (dir_path);
            if (!dir.query_exists ()) {
                return;
            }

            var monitor = dir.monitor_directory (FileMonitorFlags.NONE, null);
            monitor.changed.connect ((file, other, event) => {
                handle_monitor_event (file, event, category);
            });
            _monitors.add (monitor);
            debug ("File monitor started on %s (%s)", dir_path, category);
        } catch (Error e) {
            debug ("Could not watch %s: %s", dir_path, e.message);
        }
    }

    /**
     * Handle a file monitor event. Fires tamper events for unexpected changes.
     */
    private void handle_monitor_event (File file, FileMonitorEvent event, string category) {
        if (event != FileMonitorEvent.DELETED &&
            event != FileMonitorEvent.CHANGED) {
            return;
        }

        var path = file.get_path ();
        if (path == null) {
            return;
        }

        // Crypto directory: only alert on deletion of KNOWN crypto files.
        // GLib's atomic writes create temp files (e.g. "account.pickle.Q5OUK3")
        // that get renamed -- the temp file deletion triggers inotify. Ignore
        // these by only matching exact known filenames.
        if (category == "crypto") {
            if (event == FileMonitorEvent.DELETED) {
                var basename = Path.get_basename (path);
                if (basename == "account.pickle" ||
                    basename == "megolm_outbound.pickle" ||
                    basename == "pickle_key" ||
                    basename == "access_token") {
                    emit_tamper ("crypto_file_tampered",
                        "Crypto file %s was deleted".printf (basename));
                }
            }
            return;
        }

        // For screenshots and markers, only care about deletions
        if (event != FileMonitorEvent.DELETED) {
            return;
        }

        // Check if this was an expected deletion (O(1) hash lookup)
        if (_expected_deletions.contains (path)) {
            _expected_deletions.remove (path);
            return;
        }

        // Unexpected deletion -- fire tamper event
        if (category == "screenshot") {
            emit_tamper ("screenshot_deleted",
                "Screenshot file unexpectedly deleted: %s".printf (
                    Path.get_basename (path)));
        } else if (category == "marker") {
            emit_tamper ("marker_deleted",
                "Pending marker unexpectedly deleted: %s".printf (
                    Path.get_basename (path)));
        }
    }

    private void emit_tamper (string event_type, string details) {
        debug ("Tamper detected [%s]: %s", event_type, details);
        tamper_detected (event_type, details);
    }

    private void emit_warning (string event_type, string details) {
        debug ("Warning [%s]: %s", event_type, details);
        tamper_detected ("~" + event_type, details);
    }

    /** Emit tamper when locked, warning when unlocked. */
    private void emit_lock_dependent (bool locked, string event_type, string details) {
        if (locked) {
            emit_tamper (event_type, details);
        } else {
            emit_warning (event_type, details);
        }
    }

    /**
     * Report a warning event from an external source.
     *
     * Used by other services (e.g. DBusServer) to funnel warning events
     * through the same signal pipeline with the ~ severity prefix.
     */
    public void report_warning (string event_type, string details) {
        emit_warning (event_type, details);
    }

    private int get_jittered_interval () {
        return SecurityUtils.jittered_interval (check_interval_seconds);
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
