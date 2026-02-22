/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Periodically checks system integrity and reports anomalies.
 *
 * Detected events are reported via the tamper_detected signal and
 * immediately forwarded to the Matrix room so the accountability partner
 * is informed, even when the user is actively tampering.
 *
 * Also owns alert persistence: unsent tamper alerts are saved to disk
 * so they survive daemon restarts and network outages.
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

    /** Path to the crypto directory (for periodic existence checking). */
    public string crypto_dir { get; set; default = ""; }

    /** Maximum capture interval in seconds (for liveness monitoring). */
    public int max_capture_interval_seconds { get; set; default = 120; }

    /** Data directory for persisting unsent alerts. */
    public string data_dir { get; set; default = ""; }

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

    /** Crypto files seen on disk (for periodic existence checking). */
    private GenericSet<string> _crypto_files_seen;

    /** List of tamper events pending delivery. */
    private GenericArray<string> _unsent_alerts;

    /** Matrix transport for sending alerts. May be null in tests. */
    private Vigil.Services.MatrixTransportService? _matrix_svc;

    /**
     * Create a TamperDetectionService.
     *
     * @param settings Optional GLib.Settings instance. When null,
     *                 settings-based checks are skipped (useful in tests).
     * @param matrix_svc Optional Matrix transport for sending alerts.
     *                   When null, alerts are persisted but not sent.
     */
    public TamperDetectionService (GLib.Settings? settings = null,
                                   Vigil.Services.MatrixTransportService? matrix_svc = null) {
        _settings = settings;
        _matrix_svc = matrix_svc;
        _expected_deletions = new GenericSet<string> (str_hash, str_equal);
        _crypto_files_seen = new GenericSet<string> (str_hash, str_equal);
        _monitors = new GenericArray<FileMonitor> ();
        _unsent_alerts = new GenericArray<string> ();

        if (_settings != null) {
            connect_settings_signals ();
        }
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
        check_flatpak_sandbox ();
        check_crypto_files ();
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
                "No screenshot captured in %s seconds (expected every %d seconds)".printf (
                    elapsed_sec.to_string (), max_capture_interval_seconds));
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
            // Preload all marker names into a HashSet (one directory scan)
            // instead of N stat() calls — O(1) lookup per screenshot.
            var marker_names = new GenericSet<string> (str_hash, str_equal);
            if (FileUtils.test (pending_dir, FileTest.IS_DIR)) {
                var pdir = File.new_for_path (pending_dir);
                var penum = pdir.enumerate_children (
                    "standard::name", FileQueryInfoFlags.NONE, null);
                FileInfo? pinfo;
                while ((pinfo = penum.next_file (null)) != null) {
                    marker_names.add (pinfo.get_name ());
                }
            }

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

                if (!marker_names.contains (name + ".pending")) {
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
        // Upload batch > 1 hour, tamper check > 30 min are far beyond the
        // defaults and indicate intentional tampering.
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
            emit_lock_dependent (locked, "background_permission_revoked",
                "Background portal autostart permission was revoked -- " +
                "daemon will not auto-start at next login");
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

        // Note: crypto directory is NOT monitored via inotify because
        // GLib's atomic writes cause spurious DELETE events. Crypto file
        // existence is checked periodically by check_crypto_files() instead.
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

    /**
     * Check that the Flatpak sandbox is intact.
     *
     * /.flatpak-info must exist inside the sandbox. If it's missing,
     * the daemon is running outside Flatpak (bypassing sandboxing).
     */
    public void check_flatpak_sandbox () {
        if (!FileUtils.test ("/.flatpak-info", FileTest.EXISTS)) {
            emit_tamper ("sandbox_escaped",
                "/.flatpak-info not found -- daemon is running outside Flatpak sandbox");
        }
    }

    /**
     * Check that critical crypto files still exist on disk.
     *
     * These files are essential for E2EE operation. If they are deleted
     * while the daemon is running, encryption will break on next restart.
     * Inotify is not used because GLib's atomic writes (create temp, rename)
     * cause spurious DELETE events on every pickle save.
     */
    public void check_crypto_files () {
        var crypto_path = crypto_dir != ""
            ? crypto_dir
            : Path.build_filename (SecurityUtils.get_app_data_dir (), "crypto");

        if (!FileUtils.test (crypto_path, FileTest.IS_DIR)) {
            return;
        }

        string[] critical_files = {
            "account.pickle", "megolm_outbound.pickle",
            "pickle_key", "access_token"
        };

        foreach (var filename in critical_files) {
            var path = Path.build_filename (crypto_path, filename);
            if (_crypto_files_seen.contains (filename) &&
                !FileUtils.test (path, FileTest.EXISTS)) {
                emit_tamper ("crypto_file_tampered",
                    "Crypto file %s was deleted".printf (filename));
                _crypto_files_seen.remove (filename);
            } else if (FileUtils.test (path, FileTest.EXISTS)) {
                _crypto_files_seen.add (filename);
            }
        }
    }

    /**
     * Emit a tamper event for E2EE initialization failure.
     * Called by the daemon when E2EE was configured but failed to start.
     * Severity depends on settings lock state: if locked, the user has
     * no reason to be touching encryption files, so failure is suspicious.
     */
    public void emit_e2ee_init_failure () {
        bool locked = _settings != null &&
            _settings.get_boolean ("settings-locked");
        emit_lock_dependent (locked, "e2ee_init_failed",
            "E2EE initialization failed at startup -- " +
            "monitoring will not send screenshots until encryption is restored");
    }

    /**
     * Emit a tamper event for background portal permission revocation.
     * Called by the daemon when the XDG Background portal denies autostart.
     * Severity depends on settings lock state.
     */
    public void emit_background_permission_revoked () {
        bool locked = _settings != null &&
            _settings.get_boolean ("settings-locked");
        emit_lock_dependent (locked, "background_permission_revoked",
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
        if (event != FileMonitorEvent.DELETED) {
            return;
        }

        var path = file.get_path ();
        if (path == null) {
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
        var event_str = "%s: %s".printf (event_type, details);
        if (has_unsent_alert (event_str)) {
            return;
        }
        debug ("Tamper detected [%s]: %s", event_type, details);
        _unsent_alerts.add (event_str);
        persist_unsent_alerts ();
        tamper_detected (event_type, details);

        if (_matrix_svc != null && _matrix_svc.is_configured) {
            _matrix_svc.send_alert.begin (event_type, details, (obj, res) => {
                if (_matrix_svc.send_alert.end (res)) {
                    remove_unsent_alert (event_str);
                }
            });
        }
    }

    private void emit_warning (string event_type, string details) {
        var event_str = "~%s: %s".printf (event_type, details);
        if (has_unsent_alert (event_str)) {
            return;
        }
        debug ("Warning [%s]: %s", event_type, details);
        _unsent_alerts.add (event_str);
        persist_unsent_alerts ();
        tamper_detected ("~" + event_type, details);

        if (_matrix_svc != null && _matrix_svc.is_configured) {
            _matrix_svc.send_alert.begin ("~" + event_type, details, (obj, res) => {
                if (_matrix_svc.send_alert.end (res)) {
                    remove_unsent_alert (event_str);
                }
            });
        }
    }

    private bool has_unsent_alert (string event_str) {
        for (uint i = 0; i < _unsent_alerts.length; i++) {
            if (_unsent_alerts[i] == event_str) {
                return true;
            }
        }
        return false;
    }

    private void remove_unsent_alert (string event_str) {
        for (uint i = 0; i < _unsent_alerts.length; i++) {
            if (_unsent_alerts[i] == event_str) {
                _unsent_alerts.remove_index (i);
                persist_unsent_alerts ();
                return;
            }
        }
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

    // ──────────────────────────────────────────────────────────
    //  Alert persistence
    // ──────────────────────────────────────────────────────────

    /**
     * Retry delivery of persisted unsent alerts.
     *
     * Called after successful screenshot uploads. Sends each alert via
     * the Matrix transport and clears the file on success.
     */
    public async void flush_unsent_alerts () {
        if (_matrix_svc == null || !_matrix_svc.is_configured) {
            return;
        }

        if (_unsent_alerts.length == 0) {
            return;
        }

        bool all_sent = true;
        for (int i = 0; i < _unsent_alerts.length; i++) {
            var raw = _unsent_alerts[i];
            var colon_pos = raw.index_of (": ");
            string event_type;
            string details;
            if (colon_pos >= 0) {
                event_type = raw.substring (0, colon_pos);
                details = raw.substring (colon_pos + 2);
            } else {
                event_type = raw;
                details = raw;
            }

            bool sent = yield _matrix_svc.send_alert (event_type, details);
            if (!sent) {
                all_sent = false;
                break;
            }
        }

        if (all_sent) {
            _unsent_alerts.remove_range (0, _unsent_alerts.length);
            clear_persisted_alerts ();
        }
    }

    /**
     * Load persisted alerts from a previous run.
     * Called on startup to restore unsent alerts.
     */
    public void load_persisted_alerts () {
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
                    _unsent_alerts.add (stripped);
                }
            }
            if (_unsent_alerts.length > 0) {
                debug ("Loaded %d persisted tamper alerts from previous run",
                    (int) _unsent_alerts.length);
            }
        } catch (Error e) {
            debug ("Failed to load persisted alerts: %s", e.message);
        }
    }

    /**
     * Persist unsent tamper alerts to disk so they survive daemon restarts.
     */
    private void persist_unsent_alerts () {
        if (data_dir == "" || _unsent_alerts.length == 0) {
            return;
        }

        var path = Path.build_filename (data_dir, "unsent_alerts.txt");
        var sb = new StringBuilder ();
        for (int i = 0; i < _unsent_alerts.length; i++) {
            sb.append (_unsent_alerts[i]);
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
     * Clear persisted alerts after successful delivery.
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

    // ──────────────────────────────────────────────────────────
    //  Static event description helpers
    // ──────────────────────────────────────────────────────────

    /**
     * Check whether a raw event string represents a warning (not a tamper attempt).
     *
     * Warning events are prefixed with "~" to indicate they are system issues
     * or legitimate setting changes, not active tampering.
     */
    public static bool is_warning_event (string raw_event) {
        return raw_event.has_prefix ("~");
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
                return "A service timer was changed to a very " +
                    "long interval. Problems will be detected much slower.";
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
            case "connection_lost":
                return "Multiple screenshot uploads failed in a row. " +
                    "The device may have lost its internet connection.";
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
            case "sandbox_escaped":
                return "Vigil is running outside its Flatpak sandbox. " +
                    "All security protections are bypassed \u2014 " +
                    "screenshots and encryption cannot be trusted.";
            case "process_stopped":
                return "Vigil was stopped or uninstalled. " +
                    "This was NOT a system shutdown \u2014 " +
                    "someone manually stopped Vigil.";
            default:
                return raw_event;
        }
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
            return "%s %s".printf (
                minutes.to_string (), minutes == 1 ? "minute" : "minutes");
        }
        if (minutes == 0) {
            return "%s %s".printf (
                hours.to_string (), hours == 1 ? "hour" : "hours");
        }
        return "%s %s %s %s".printf (
            hours.to_string (), hours == 1 ? "hour" : "hours",
            minutes.to_string (), minutes == 1 ? "minute" : "minutes");
    }

    private void schedule_next () {
        if (!is_running) {
            return;
        }

        var interval = SecurityUtils.jittered_interval (check_interval_seconds);
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
