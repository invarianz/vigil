/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * D-Bus interface definition for the Vigil daemon.
 *
 * The daemon owns all monitoring services and exposes status/control
 * over the session bus. The GUI app is a thin D-Bus client.
 *
 * Bus name: io.github.invarianz.vigil.Daemon
 * Object path: /io/github/invarianz/vigil/Daemon
 */

/**
 * The D-Bus interface that the GUI connects to as a proxy.
 */
[DBus (name = "io.github.invarianz.vigil.Daemon")]
public interface Vigil.Daemon.IDaemonBus : Object {

    /* Read-only properties exposed on D-Bus */
    public abstract bool monitoring_active { get; }
    public abstract string active_backend_name { owned get; }
    public abstract string next_capture_time_iso { owned get; }
    public abstract string last_capture_time_iso { owned get; }
    public abstract int pending_upload_count { get; }
    public abstract bool screenshot_permission_ok { get; }
    public abstract int64 uptime_seconds { get; }
    public abstract string[] recent_tamper_events { owned get; }

    /* Methods callable over D-Bus */
    public abstract async void request_capture () throws Error;
    public abstract string get_status_json () throws Error;

    /* Signals relayed over D-Bus */
    public signal void status_changed ();
    public signal void screenshot_captured (string path);
    public signal void screenshot_capture_failed (string message);
    public signal void tamper_event (string event_type, string details);
}

/**
 * Server-side implementation of the D-Bus interface.
 *
 * Wraps all the service objects and exposes a clean bus API.
 */
[DBus (name = "io.github.invarianz.vigil.Daemon")]
public class Vigil.Daemon.DBusServer : Object {

    private Vigil.Services.ScreenshotService _screenshot_svc;
    private Vigil.Services.SchedulerService _scheduler_svc;
    private Vigil.Services.StorageService _storage_svc;
    private Vigil.Services.HeartbeatService _heartbeat_svc;
    private Vigil.Services.TamperDetectionService _tamper_svc;
    private Vigil.Services.MatrixTransportService _matrix_svc;
    private GLib.Settings _settings;

    private Queue<string> _recent_tamper_events;
    private int _cached_pending_count = 0;
    private uint _pending_retry_source = 0;
    private uint _background_portal_source = 0;
    private uint _key_sharing_source = 0;
    private bool _room_keys_shared = false;

    /* D-Bus properties */

    public bool monitoring_active { get; private set; default = false; }

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

    public int pending_upload_count {
        get {
            return _cached_pending_count;
        }
    }

    public bool screenshot_permission_ok {
        get {
            return _heartbeat_svc.screenshot_permission_ok;
        }
    }

    public int64 uptime_seconds {
        get {
            return _heartbeat_svc.get_uptime_seconds ();
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

    /* D-Bus signals */
    public signal void status_changed ();
    public signal void screenshot_captured (string path);
    public signal void screenshot_capture_failed (string message);
    public signal void tamper_event (string event_type, string details);

    public DBusServer (
        Vigil.Services.ScreenshotService screenshot_svc,
        Vigil.Services.SchedulerService scheduler_svc,
        Vigil.Services.StorageService storage_svc,
        Vigil.Services.HeartbeatService heartbeat_svc,
        Vigil.Services.TamperDetectionService tamper_svc,
        Vigil.Services.MatrixTransportService matrix_svc,
        GLib.Settings settings
    ) {
        _screenshot_svc = screenshot_svc;
        _scheduler_svc = scheduler_svc;
        _storage_svc = storage_svc;
        _heartbeat_svc = heartbeat_svc;
        _tamper_svc = tamper_svc;
        _matrix_svc = matrix_svc;
        _settings = settings;
        _recent_tamper_events = new Queue<string> ();

        connect_signals ();
    }

    /**
     * Request an immediate screenshot capture.
     */
    public async void request_capture () throws Error {
        yield handle_capture ();
    }

    /**
     * Get a JSON blob with the full daemon status.
     */
    public string get_status_json () throws Error {
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

        builder.set_member_name ("pending_uploads");
        builder.add_int_value (pending_upload_count);

        builder.set_member_name ("uptime_seconds");
        builder.add_int_value (uptime_seconds);

        builder.set_member_name ("screenshot_permission_ok");
        builder.add_boolean_value (screenshot_permission_ok);

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

        _heartbeat_svc.lifetime_captures = _storage_svc.lifetime_captures;

        // Collect environment attestation for the first heartbeat
        try {
            var binary_path = FileUtils.read_link ("/proc/self/exe");
            _heartbeat_svc.environment_attestation =
                Vigil.Services.SecurityUtils.collect_environment_attestation (binary_path);
        } catch (Error e) {
            debug ("Could not collect environment attestation: %s", e.message);
        }

        yield _screenshot_svc.initialize ();

        // Record display service PID for tamper detection
        yield record_display_service_pid ();

        apply_settings ();
        bind_settings ();

        // Initialize E2EE from stored credentials (before file monitoring
        // starts, so pickle writes don't trigger crypto_file_tampered)
        initialize_encryption ();

        // Share room keys with partner (retries until successful)
        schedule_key_sharing ();

        // Start heartbeat
        _heartbeat_svc.start ();

        // Start tamper detection
        _tamper_svc.start ();

        // Start inotify watches on screenshots, pending, and crypto directories
        _tamper_svc.start_file_monitoring ();

        // Start monitoring if previously enabled
        if (_settings.get_boolean ("monitoring-enabled")) {
            start_monitoring ();
        }

        // Upload any pending screenshots from previous sessions
        refresh_pending_count ();
        yield flush_pending_uploads ();

        // Request background/autostart permission via XDG portal (Flatpak)
        yield request_background_portal ();
        schedule_background_portal_check ();
    }

    private void start_monitoring () {
        monitoring_active = true;
        _scheduler_svc.start ();
        _heartbeat_svc.monitoring_active = true;
        status_changed ();
    }

    private void stop_monitoring () {
        monitoring_active = false;
        _scheduler_svc.stop ();
        _heartbeat_svc.monitoring_active = false;
        status_changed ();
    }

    private void connect_signals () {
        _scheduler_svc.capture_requested.connect (() => {
            handle_capture.begin ();
        });

        _screenshot_svc.screenshot_taken.connect ((path) => {
            _heartbeat_svc.screenshots_since_last++;
            _heartbeat_svc.lifetime_captures = _storage_svc.lifetime_captures;
            _tamper_svc.report_capture_success ();
            screenshot_captured (path);
            status_changed ();
        });

        _screenshot_svc.screenshot_failed.connect ((msg) => {
            screenshot_capture_failed (msg);
        });

        _tamper_svc.tamper_detected.connect ((event_type, details) => {
            var event_str = "%s: %s".printf (event_type, details);
            _heartbeat_svc.report_tamper_event (event_str);
            _recent_tamper_events.push_tail (event_str);
            // Keep only last 50 — O(1) pop from head vs O(n) array shift
            if (_recent_tamper_events.get_length () > 50) {
                _recent_tamper_events.pop_head ();
            }
            tamper_event (event_type, details);

            // Send tamper alerts via Matrix immediately
            if (_matrix_svc.is_configured) {
                _matrix_svc.send_alert.begin (event_type, details);
            }
        });

        _storage_svc.will_delete_file.connect ((path) => {
            _tamper_svc.expect_deletion (path);
        });

        _storage_svc.capture_hashed.connect ((hash) => {
            _heartbeat_svc.record_capture_hash (hash);
        });

        _heartbeat_svc.gap_detected.connect ((gap_seconds) => {
            _tamper_svc.report_warning ("unmonitored_gap",
                "Device was unmonitored for %lld minutes".printf (gap_seconds / 60));
        });

        _heartbeat_svc.heartbeat_sent.connect (() => {
            _heartbeat_svc.config_hash = _tamper_svc.compute_config_hash ();
            refresh_pending_count ();
            _heartbeat_svc.pending_upload_count = _cached_pending_count;
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
        _heartbeat_svc.interval_seconds = _settings.get_int ("heartbeat-interval-seconds");

        // Matrix transport settings
        _matrix_svc.homeserver_url = _settings.get_string ("matrix-homeserver-url");
        _matrix_svc.access_token = _settings.get_string ("matrix-access-token");
        _matrix_svc.room_id = _settings.get_string ("matrix-room-id");

        // Wire up tamper detection: orphan check dirs & capture liveness threshold
        _tamper_svc.screenshots_dir = _storage_svc.screenshots_dir;
        _tamper_svc.pending_dir = _storage_svc.pending_dir;
        _tamper_svc.max_capture_interval_seconds = _settings.get_int ("max-interval-seconds");
        _tamper_svc.check_interval_seconds = _settings.get_int ("tamper-check-interval-seconds");

        // Wire up heartbeat data dir for alert persistence
        var data_dir = Path.build_filename (
            Environment.get_user_data_dir (),
            "io.github.invarianz.vigil"
        );
        _heartbeat_svc.data_dir = data_dir;

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

        // Re-initialize E2EE when setup completes while daemon is running.
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

        // restore_only: daemon must not create new Olm accounts — the GUI
        // does that during setup. If the pickle isn't written yet (race with
        // GUI), we retry shortly.
        if (enc.initialize (pickle_key, true)) {
            // Restore or create Megolm outbound session — without this,
            // share_room_keys() cannot build room key content and will
            // fail indefinitely on first launch.
            if (!enc.restore_group_session ()) {
                enc.create_outbound_group_session ();
            }
            // Wire up encryption for config hash signing in heartbeats
            _heartbeat_svc.encryption = enc;
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
     * Get the UNIX process ID of a D-Bus name owner.
     *
     * Calls org.freedesktop.DBus.GetConnectionUnixProcessID.
     * Returns 0 if the name is not owned or the call fails.
     */
    private async uint32 get_dbus_name_pid (string bus_name) {
        try {
            var conn = GLib.Bus.get_sync (BusType.SESSION);
            var result = yield conn.call (
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixProcessID",
                new Variant ("(s)", bus_name),
                new VariantType ("(u)"),
                DBusCallFlags.NONE,
                5000,
                null
            );
            uint32 pid;
            result.get ("(u)", out pid);
            return pid;
        } catch (Error e) {
            debug ("Could not get PID for %s: %s", bus_name, e.message);
            return 0;
        }
    }

    /**
     * Record the display service PID for tamper detection.
     *
     * Looks up the D-Bus service backing the screenshot backend and
     * records its PID and exe path so periodic checks can detect if
     * it disappears or gets replaced.
     */
    private async void record_display_service_pid () {
        var backend = _screenshot_svc.active_backend_name;
        if (backend == null) {
            return;
        }

        // Portal is the only backend (Flatpak-only app)
        string bus_name = "org.freedesktop.portal.Desktop";

        var pid = yield get_dbus_name_pid (bus_name);
        if (pid == 0) {
            return;
        }

        _tamper_svc.display_service_pid = pid;
        _tamper_svc.display_service_name = bus_name;
        debug ("Display service: %s PID=%u", bus_name, pid);
    }

    /**
     * Schedule room key sharing with the partner.
     *
     * Attempts to share the Megolm session key immediately, then retries
     * every 60 seconds until successful. This handles the case where
     * the partner hasn't set up their Element client yet when Vigil
     * first runs, or when the daemon restarts with a new session.
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

            refresh_pending_count ();
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
                refresh_pending_count ();
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

        refresh_pending_count ();

        // If any uploads failed, schedule another retry
        var remaining = _storage_svc.get_pending_screenshots ();
        if (remaining.length > 0) {
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
            commandline.add ("io.github.invarianz.vigil.daemon");

            bool granted = yield portal.request_background (
                null,
                "Vigil needs to run in the background to capture screenshots " +
                "and send heartbeats to your accountability partner.",
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

    private void refresh_pending_count () {
        _cached_pending_count = _storage_svc.pending_count;
    }
}
