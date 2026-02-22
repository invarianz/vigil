/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Central monitoring engine.
 *
 * Owns all monitoring services and exposes status/control to the GUI.
 * Runs in-process — no D-Bus IPC needed.
 */
public class Vigil.MonitoringEngine : Object {

    private Vigil.Services.ScreenshotService _screenshot_svc;
    private Vigil.Services.SchedulerService _scheduler_svc;
    private Vigil.Services.StorageService _storage_svc;
    private Vigil.Services.TamperDetectionService _tamper_svc;
    private Vigil.Services.MatrixTransportService _matrix_svc;
    private GLib.Settings _settings;

    private Queue<string> _recent_tamper_events;
    private uint _pending_retry_source = 0;
    private uint _background_portal_source = 0;
    private uint _key_sharing_source = 0;
    private bool _room_keys_shared = false;

    /* Properties */

    public bool monitoring_active { get; private set; default = false; }
    public bool system_shutdown_pending { get; private set; default = false; }

    public string active_backend_name {
        owned get {
            return _screenshot_svc.active_backend_name ?? "none";
        }
    }

    public string next_capture_time_iso {
        owned get {
            if (_scheduler_svc.next_capture_time == null) {
                return "";
            }
            return _scheduler_svc.next_capture_time.format_iso8601 ();
        }
    }

    public string last_capture_time_iso {
        owned get {
            if (_scheduler_svc.last_capture_time == null) {
                return "";
            }
            return _scheduler_svc.last_capture_time.format_iso8601 ();
        }
    }

    public string[] recent_tamper_events {
        owned get {
            var len = _recent_tamper_events.get_length ();
            string[] result = new string[len];
            unowned List<string> node = _recent_tamper_events.head;
            for (uint i = 0; i < len; i++) {
                result[i] = node.data;
                node = node.next;
            }
            return result;
        }
    }

    /* Signals */
    public signal void status_changed ();
    public signal void screenshot_captured (string path);
    public signal void screenshot_capture_failed (string message);
    public signal void tamper_event (string event_type, string details);

    public MonitoringEngine (
        Vigil.Services.ScreenshotService screenshot_svc,
        Vigil.Services.SchedulerService scheduler_svc,
        Vigil.Services.StorageService storage_svc,
        Vigil.Services.TamperDetectionService tamper_svc,
        Vigil.Services.MatrixTransportService matrix_svc,
        GLib.Settings settings
    ) {
        _screenshot_svc = screenshot_svc;
        _scheduler_svc = scheduler_svc;
        _storage_svc = storage_svc;
        _tamper_svc = tamper_svc;
        _matrix_svc = matrix_svc;
        _settings = settings;
        _recent_tamper_events = new Queue<string> ();

        connect_signals ();
    }

    /**
     * Request an immediate screenshot capture.
     */
    public async void request_capture () {
        yield handle_capture ();
    }

    /**
     * Get a JSON blob with the full engine status.
     */
    public string get_status_json () {
        var builder = new Json.Builder ();
        builder.begin_object ();

        builder.set_member_name ("monitoring_active");
        builder.add_boolean_value (monitoring_active);

        builder.set_member_name ("backend");
        builder.add_string_value (active_backend_name);

        builder.set_member_name ("next_capture");
        builder.add_string_value (next_capture_time_iso);

        builder.set_member_name ("last_capture");
        builder.add_string_value (last_capture_time_iso);

        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        return gen.to_data (null);
    }

    /**
     * Initialize all services and start monitoring if configured.
     */
    public async void initialize () {
        try {
            _storage_svc.initialize ();
        } catch (Error e) {
            warning ("Failed to initialize storage: %s", e.message);
        }

        if (_storage_svc.capture_counter_tampered) {
            _tamper_svc.report_tamper ("capture_counter_tampered",
                "Capture counter file HMAC is invalid (file was modified)");
        }

        // Subscribe to login1 PrepareForShutdown to distinguish system
        // shutdown from manual kill/uninstall
        try {
            var system_bus = yield Bus.get (BusType.SYSTEM);
            system_bus.signal_subscribe (
                "org.freedesktop.login1",
                "org.freedesktop.login1.Manager",
                "PrepareForShutdown",
                "/org/freedesktop/login1",
                null,
                DBusSignalFlags.NONE,
                on_prepare_for_shutdown
            );
        } catch (Error e) {
            debug ("Could not subscribe to login1 signals: %s", e.message);
        }

        yield _screenshot_svc.initialize ();

        apply_settings ();
        bind_settings ();

        // Initialize E2EE from stored credentials (before file monitoring
        // starts, so pickle writes don't trigger crypto_file_tampered)
        initialize_encryption ();

        // Share room keys with partner (retries until successful)
        schedule_key_sharing ();

        // Start tamper detection
        _tamper_svc.start ();

        // Start inotify watches on screenshots, pending, and crypto directories
        _tamper_svc.start_file_monitoring ();

        // Start monitoring if previously enabled
        if (_settings.get_boolean ("monitoring-enabled")) {
            start_monitoring ();
        }

        // Load persisted alerts from previous run
        _tamper_svc.load_persisted_alerts ();

        // Upload any pending screenshots from previous sessions

        yield flush_pending_uploads ();

        // Flush any persisted alerts after pending uploads
        yield _tamper_svc.flush_unsent_alerts ();

        // Request background/autostart permission via XDG portal (Flatpak)
        yield request_background_portal ();
        schedule_background_portal_check ();

        // Notify UI that initialization is complete (backend name, etc.)
        status_changed ();
    }

    private void start_monitoring () {
        monitoring_active = true;
        _scheduler_svc.start ();
        status_changed ();
    }

    private void stop_monitoring () {
        monitoring_active = false;
        _scheduler_svc.stop ();
        status_changed ();
    }

    private void on_prepare_for_shutdown (DBusConnection conn, string? sender,
        string object_path, string interface_name, string signal_name,
        Variant parameters) {
        bool active;
        parameters.get ("(b)", out active);
        if (active) {
            system_shutdown_pending = true;
        }
    }

    private void connect_signals () {
        _scheduler_svc.capture_requested.connect (() => {
            handle_capture.begin ();
        });

        _screenshot_svc.screenshot_taken.connect ((path) => {
            _tamper_svc.report_capture_success ();
            screenshot_captured (path);
            status_changed ();
        });

        _screenshot_svc.screenshot_failed.connect ((msg) => {
            screenshot_capture_failed (msg);
        });

        _tamper_svc.tamper_detected.connect ((event_type, details) => {
            var event_str = "%s: %s".printf (event_type, details);
            _recent_tamper_events.push_tail (event_str);
            // Keep only last 50 — O(1) pop from head vs O(n) array shift
            if (_recent_tamper_events.get_length () > 50) {
                _recent_tamper_events.pop_head ();
            }
            tamper_event (event_type, details);
        });

        _storage_svc.will_delete_file.connect ((path) => {
            _tamper_svc.expect_deletion (path);
        });

        // Listen for monitoring toggle from settings
        _settings.changed["monitoring-enabled"].connect (() => {
            bool enabled = _settings.get_boolean ("monitoring-enabled");
            if (enabled && !monitoring_active) {
                start_monitoring ();
            } else if (!enabled && monitoring_active) {
                stop_monitoring ();
            }
        });
    }

    private void apply_settings () {
        _scheduler_svc.min_interval_seconds = _settings.get_int ("min-interval-seconds");
        _scheduler_svc.max_interval_seconds = _settings.get_int ("max-interval-seconds");

        // Matrix transport settings
        _matrix_svc.homeserver_url = _settings.get_string ("matrix-homeserver-url");
        _matrix_svc.access_token = _settings.get_string ("matrix-access-token");
        _matrix_svc.room_id = _settings.get_string ("matrix-room-id");

        // Wire up tamper detection: orphan check dirs & capture liveness threshold
        _tamper_svc.screenshots_dir = _storage_svc.screenshots_dir;
        _tamper_svc.pending_dir = _storage_svc.pending_dir;
        _tamper_svc.crypto_dir = Vigil.Services.SecurityUtils.get_crypto_dir ();
        _tamper_svc.max_capture_interval_seconds = _settings.get_int ("max-interval-seconds");
        _tamper_svc.check_interval_seconds = _settings.get_int ("tamper-check-interval-seconds");

        // Wire up tamper detection data dir for alert persistence
        var data_dir = Path.build_filename (
            Environment.get_user_data_dir (),
            "io.github.invarianz.vigil"
        );
        _tamper_svc.data_dir = data_dir;

        // Derive HMAC key from pickle key for marker integrity
        var pickle_key = _settings.get_string ("e2ee-pickle-key");
        if (pickle_key != "") {
            _storage_svc.hmac_key = Vigil.Services.EncryptionService.derive_hmac_key (pickle_key);
        }
    }

    private void bind_settings () {
        _settings.changed["min-interval-seconds"].connect (() => {
            _scheduler_svc.min_interval_seconds = _settings.get_int ("min-interval-seconds");
        });
        _settings.changed["max-interval-seconds"].connect (() => {
            _scheduler_svc.max_interval_seconds = _settings.get_int ("max-interval-seconds");
        });
        _settings.changed["matrix-homeserver-url"].connect (() => {
            _matrix_svc.homeserver_url = _settings.get_string ("matrix-homeserver-url");
        });
        _settings.changed["matrix-access-token"].connect (() => {
            _matrix_svc.access_token = _settings.get_string ("matrix-access-token");
        });
        _settings.changed["matrix-room-id"].connect (() => {
            _matrix_svc.room_id = _settings.get_string ("matrix-room-id");
        });

        // Re-initialize E2EE when setup completes while engine is running.
        // Watch both pickle-key and device-id: if the user re-runs setup
        // with the same pickle password, only device-id changes (new login),
        // and vice versa.
        _settings.changed["e2ee-pickle-key"].connect (() => {
            initialize_encryption ();
        });
        _settings.changed["device-id"].connect (() => {
            initialize_encryption ();
        });
    }

    private void initialize_encryption () {
        var pickle_key = _settings.get_string ("e2ee-pickle-key");
        var user_id = _settings.get_string ("matrix-user-id");
        var device_id = _settings.get_string ("device-id");

        if (pickle_key == "" || user_id == "" || device_id == "") {
            return;
        }

        var enc = _matrix_svc.encryption;
        if (enc == null) {
            enc = new Vigil.Services.EncryptionService ();
            _matrix_svc.encryption = enc;
        }

        // Skip if already initialized with the same credentials
        if (enc.is_ready && enc.device_id == device_id && enc.user_id == user_id) {
            return;
        }

        enc.cleanup ();
        enc.device_id = device_id;
        enc.user_id = user_id;

        // restore_only: must not create new Olm accounts — the GUI
        // does that during setup. If the pickle isn't written yet (race with
        // GUI), we retry shortly.
        if (enc.initialize (pickle_key, true)) {
            // Restore or create Megolm outbound session — without this,
            // share_room_keys() cannot build room key content and will
            // fail indefinitely on first launch.
            if (!enc.restore_group_session ()) {
                enc.create_outbound_group_session ();
            }
            debug ("E2EE (re)initialized from settings (session: %s)", enc.megolm_session_id);

            // Share room keys with partner (new session or first init)
            _room_keys_shared = false;
            schedule_key_sharing ();
        } else {
            debug ("E2EE pickle not ready, will retry in 5s");
            Timeout.add_seconds (5, () => {
                initialize_encryption ();
                return Source.REMOVE;
            });
        }
    }

    /**
     * Schedule room key sharing with the partner.
     *
     * Attempts to share the Megolm session key immediately, then retries
     * every 60 seconds until successful. This handles the case where
     * the partner hasn't set up their Element client yet when Vigil
     * first runs, or when the engine restarts with a new session.
     */
    private void schedule_key_sharing () {
        if (_room_keys_shared || _key_sharing_source != 0) {
            return;
        }

        var partner_id = _settings.get_string ("partner-matrix-id");
        if (partner_id == "") {
            return;
        }

        if (_matrix_svc.encryption == null ||
            !_matrix_svc.encryption.is_ready ||
            !_matrix_svc.is_configured) {
            return;
        }

        attempt_key_sharing.begin (partner_id);
    }

    private async void attempt_key_sharing (string partner_id) {
        bool success = yield _matrix_svc.share_room_keys_with_partner (partner_id);
        if (success) {
            _room_keys_shared = true;
            debug ("Room keys shared with partner successfully");
            return;
        }

        // Retry after 60 seconds
        debug ("Key sharing failed, will retry in 60s");
        _key_sharing_source = Timeout.add_seconds (60, () => {
            _key_sharing_source = 0;
            var current_partner = _settings.get_string ("partner-matrix-id");
            if (current_partner != "" && !_room_keys_shared) {
                attempt_key_sharing.begin (current_partner);
            }
            return Source.REMOVE;
        });
    }

    private async void handle_capture () {
        // Check disk space before capture (minimum 50 MB)
        try {
            var dir = File.new_for_path (_storage_svc.screenshots_dir);
            var fs_info = dir.query_filesystem_info ("filesystem::free", null);
            var free_bytes = fs_info.get_attribute_uint64 ("filesystem::free");

            if (free_bytes < 50 * 1024 * 1024) {
                var free_mb = (int64) (free_bytes / (1024 * 1024));
                _tamper_svc.report_warning ("disk_space_low",
                    "Less than 50 MB disk space remaining (%lld MB free), ".printf (free_mb) +
                    "screenshots cannot be stored");
                return;
            }
        } catch (Error e) {
            debug ("Could not check disk space: %s", e.message);
        }

        var path = _storage_svc.generate_screenshot_path ();
        bool success = yield _screenshot_svc.take_screenshot (path);

        if (success) {
            // Read file ONCE — reuse for both pending marking and immediate upload.
            // Eliminates a redundant 2MB read + SHA-256 recomputation.
            uint8[] file_data;
            try {
                FileUtils.get_data (path, out file_data);
            } catch (Error e) {
                warning ("Failed to read screenshot %s: %s", path, e.message);
                return;
            }

            try {
                _storage_svc.mark_pending (path, file_data);
            } catch (Error e) {
                warning ("Failed to mark screenshot as pending: %s", e.message);
            }

    
            status_changed ();
            _storage_svc.cleanup_old_screenshots ();

            // Upload using pre-loaded data (avoids redundant 2MB read)
            yield upload_screenshot (path, file_data);
        }
    }

    /**
     * Upload a single screenshot immediately after capture.
     *
     * @param file_path Path to the screenshot file.
     * @param preloaded_data If non-null, uses this pre-loaded file data
     *                       instead of reading from disk. Avoids a redundant
     *                       2MB read when called from handle_capture().
     */
    private async void upload_screenshot (string file_path, uint8[]? preloaded_data = null) {
        uint8[] file_data;
        if (preloaded_data != null) {
            file_data = preloaded_data;
        } else {
            try {
                FileUtils.get_data (file_path, out file_data);
            } catch (Error e) {
                debug ("Could not read screenshot %s: %s", file_path, e.message);
                return;
            }
        }

        if (!_storage_svc.verify_screenshot_integrity_from_data (file_path, file_data)) {
            _tamper_svc.report_tamper ("screenshot_tampered",
                "Screenshot file was modified after capture: %s".printf (
                    Path.get_basename (file_path)));
            _storage_svc.mark_uploaded (file_path);
            return;
        }

        if (_matrix_svc.is_configured) {
            var now = new DateTime.now_local ();
            bool delivered = yield _matrix_svc.send_screenshot_data (
                (owned) file_data, file_path, now);
            if (delivered) {
                _storage_svc.mark_uploaded (file_path);
        

                // Flush any persisted unsent alerts after successful upload
                yield _tamper_svc.flush_unsent_alerts ();
            } else {
                // Upload failed — schedule a retry for all pending
                schedule_pending_retry ();
            }
        }
    }

    /**
     * Schedule a retry for pending uploads (e.g., after a failed immediate upload).
     * Retries once after 60 seconds; no recurring timer.
     */
    private void schedule_pending_retry () {
        if (_pending_retry_source != 0) {
            return;
        }
        _pending_retry_source = Timeout.add_seconds (60, () => {
            _pending_retry_source = 0;
            flush_pending_uploads.begin ();
            return Source.REMOVE;
        });
    }

    private async void flush_pending_uploads () {
        var pending = _storage_svc.get_pending_screenshots ();
        if (pending.length == 0) {
            return;
        }

        debug ("Retrying %d pending uploads", (int) pending.length);
        for (int i = 0; i < pending.length; i++) {
            var item = pending[i];
            var now = item.capture_time ?? new DateTime.now_local ();

            // Read file ONCE -- reuse buffer for both integrity verify and upload.
            // This eliminates 2 redundant 2MB file reads per screenshot.
            uint8[] file_data;
            try {
                FileUtils.get_data (item.file_path, out file_data);
            } catch (Error e) {
                debug ("Could not read pending screenshot %s: %s",
                    item.file_path, e.message);
                // File is gone; clean up the orphan marker
                _storage_svc.mark_uploaded (item.file_path);
                continue;
            }

            // Verify integrity using pre-loaded data (no re-read)
            if (!_storage_svc.verify_screenshot_integrity_from_data (
                    item.file_path, file_data)) {
                _tamper_svc.report_tamper ("screenshot_tampered",
                    "Screenshot file was modified after capture: %s".printf (
                        Path.get_basename (item.file_path)));
                // Discard tampered file -- do not upload compromised evidence
                _storage_svc.mark_uploaded (item.file_path);
                continue;
            }

            if (_matrix_svc.is_configured) {
                // Pass pre-loaded data to avoid a third file read
                bool delivered = yield _matrix_svc.send_screenshot_data (
                    (owned) file_data, item.file_path, now);
                if (delivered) {
                    _storage_svc.mark_uploaded (item.file_path);
                }
            }
        }
        // If any uploads failed, schedule another retry.
        // Use cached pending_count (maintained by mark_uploaded) instead of
        // re-scanning the directory -- saves one full directory enumeration.
        if (_storage_svc.pending_count > 0) {
            schedule_pending_retry ();
        }
    }

    /**
     * Request background/autostart permission via the XDG Background portal.
     *
     * On success, sets the GSettings flag so tamper detection can detect
     * if it's later revoked. On denial (when previously granted), fires
     * a tamper event. On error (portal unavailable, e.g. non-Flatpak),
     * logs a debug message without triggering tamper.
     */
    private async void request_background_portal () {
        try {
            var portal = new Xdp.Portal ();

            var commandline = new GenericArray<unowned string> ();
            commandline.add ("io.github.invarianz.vigil");
            commandline.add ("--background");

            bool granted = yield portal.request_background (
                null,
                "Vigil needs to run in the background to capture screenshots " +
                "and send them to your accountability partner.",
                commandline,
                Xdp.BackgroundFlags.AUTOSTART,
                null
            );

            if (granted) {
                _settings.set_boolean ("background-portal-granted", true);
                debug ("Background portal: autostart permission granted");
            } else {
                debug ("Background portal: permission denied");
                if (_settings.get_boolean ("background-portal-granted")) {
                    _settings.set_boolean ("background-portal-granted", false);
                    _tamper_svc.emit_background_permission_revoked ();
                }
            }
        } catch (Error e) {
            // Portal unavailable (non-Flatpak environment) -- not a tamper event
            debug ("Background portal unavailable: %s", e.message);
        }
    }

    /**
     * Schedule periodic re-checks of background portal permission.
     * Uses the same jittered interval approach as tamper detection.
     */
    private void schedule_background_portal_check () {
        int base_interval = _settings.get_int ("tamper-check-interval-seconds");
        int interval = Vigil.Services.SecurityUtils.jittered_interval (base_interval);

        _background_portal_source = Timeout.add_seconds ((uint) interval, () => {
            _background_portal_source = 0;
            request_background_portal.begin (() => {
                schedule_background_portal_check ();
            });
            return Source.REMOVE;
        });
    }
}
