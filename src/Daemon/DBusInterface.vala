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

    private GenericArray<string> _recent_tamper_events;
    private int _cached_pending_count = 0;

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
            string[] result = new string[_recent_tamper_events.length];
            for (int i = 0; i < _recent_tamper_events.length; i++) {
                result[i] = _recent_tamper_events[i];
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
        _recent_tamper_events = new GenericArray<string> ();

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

        yield _screenshot_svc.initialize ();

        apply_settings ();
        bind_settings ();

        // Start heartbeat
        _heartbeat_svc.start ();

        // Start tamper detection
        _tamper_svc.start ();

        // Start monitoring if previously enabled
        if (_settings.get_boolean ("monitoring-enabled")) {
            start_monitoring ();
        }

        // Update cached pending count
        refresh_pending_count ();

        // Retry pending uploads
        yield retry_pending_uploads ();
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
            screenshot_captured (path);
            status_changed ();
        });

        _screenshot_svc.screenshot_failed.connect ((msg, time) => {
            screenshot_capture_failed (msg);
        });

        _tamper_svc.tamper_detected.connect ((event_type, details) => {
            _heartbeat_svc.report_tamper_event ("%s: %s".printf (event_type, details));
            _recent_tamper_events.add ("%s: %s".printf (event_type, details));
            // Keep only last 50
            if (_recent_tamper_events.length > 50) {
                _recent_tamper_events.remove_index (0);
            }
            tamper_event (event_type, details);

            // Send tamper alerts via Matrix immediately
            if (_matrix_svc.is_configured) {
                _matrix_svc.send_alert.begin (event_type, details);
            }
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
        _storage_svc.max_local_screenshots = _settings.get_int ("max-local-screenshots");

        // Matrix transport settings
        _matrix_svc.homeserver_url = _settings.get_string ("matrix-homeserver-url");
        _matrix_svc.access_token = _settings.get_string ("matrix-access-token");
        _matrix_svc.room_id = _settings.get_string ("matrix-room-id");
    }

    private void bind_settings () {
        _settings.changed["min-interval-seconds"].connect (() => {
            _scheduler_svc.min_interval_seconds = _settings.get_int ("min-interval-seconds");
        });
        _settings.changed["max-interval-seconds"].connect (() => {
            _scheduler_svc.max_interval_seconds = _settings.get_int ("max-interval-seconds");
        });
        _settings.changed["max-local-screenshots"].connect (() => {
            _storage_svc.max_local_screenshots = _settings.get_int ("max-local-screenshots");
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

        // Re-initialize E2EE when setup completes while daemon is running
        _settings.changed["e2ee-pickle-key"].connect (() => {
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

        if (enc.initialize (pickle_key)) {
            enc.restore_group_session ();
            debug ("E2EE (re)initialized from settings (session: %s)", enc.megolm_session_id);
        } else {
            warning ("E2EE initialization failed");
        }
    }

    private async void handle_capture () {
        var path = _storage_svc.generate_screenshot_path ();
        bool success = yield _screenshot_svc.take_screenshot (path);

        if (success) {
            try {
                _storage_svc.mark_pending (path);
            } catch (Error e) {
                warning ("Failed to mark screenshot as pending: %s", e.message);
            }

            var now = new DateTime.now_local ();

            if (_matrix_svc.is_configured) {
                bool delivered = yield _matrix_svc.send_screenshot (path, now);
                if (delivered) {
                    _storage_svc.mark_uploaded (path);
                    refresh_pending_count ();
                    status_changed ();
                }
            }

            _storage_svc.cleanup_old_screenshots ();
        }
    }

    private async void retry_pending_uploads () {
        var pending = _storage_svc.get_pending_screenshots ();
        if (pending.length == 0) {
            return;
        }

        debug ("Retrying %d pending uploads", (int) pending.length);
        for (int i = 0; i < pending.length; i++) {
            var item = pending[i];
            var now = item.capture_time ?? new DateTime.now_local ();

            if (_matrix_svc.is_configured) {
                bool delivered = yield _matrix_svc.send_screenshot (item.file_path, now);
                if (delivered) {
                    _storage_svc.mark_uploaded (item.file_path);
                }
            }
        }

        refresh_pending_count ();
    }

    private void refresh_pending_count () {
        _cached_pending_count = (int) _storage_svc.get_pending_screenshots ().length;
    }
}
