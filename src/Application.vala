/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Single-binary GTK4 application.
 *
 * Runs the monitoring engine in-process. With --background, starts
 * headless (no window). User clicking the icon triggers activate()
 * which shows the window.
 */
public class Vigil.Application : Gtk.Application {

    private Vigil.MonitoringEngine _engine;
    private Vigil.Services.ScreenshotService _screenshot_svc;
    private Vigil.Services.SchedulerService _scheduler_svc;
    private Vigil.Services.StorageService _storage_svc;
    private Vigil.Services.TamperDetectionService _tamper_svc;
    private Vigil.Services.MatrixTransportService _matrix_svc;
    private GLib.Settings _settings;

    private DateTime _start_time;
    private bool _background_mode = false;

    public Application () {
        Object (
            application_id: "io.github.invarianz.vigil",
            flags: ApplicationFlags.DEFAULT_FLAGS
        );
    }

    construct {
        Intl.setlocale (LocaleCategory.ALL, "");
        Intl.bindtextdomain (Vigil.Config.APP_ID, Vigil.Config.LOCALEDIR);
        Intl.bind_textdomain_codeset (Vigil.Config.APP_ID, "UTF-8");
        Intl.textdomain (Vigil.Config.APP_ID);

        add_main_option (
            "background", 'b',
            OptionFlags.NONE, OptionArg.NONE,
            "Start in background mode (no window)", null
        );
    }

    protected override int handle_local_options (VariantDict options) {
        if (options.contains ("background")) {
            _background_mode = true;
        }
        return -1; // continue to startup/activate
    }

    protected override void startup () {
        base.startup ();

        _start_time = new DateTime.now_local ();

        Granite.init ();

        // Color scheme tracking
        var granite_settings = Granite.Settings.get_default ();
        var gtk_settings = Gtk.Settings.get_default ();

        gtk_settings.gtk_application_prefer_dark_theme =
            granite_settings.prefers_color_scheme == Granite.Settings.ColorScheme.DARK;

        granite_settings.notify["prefers-color-scheme"].connect (() => {
            gtk_settings.gtk_application_prefer_dark_theme =
                granite_settings.prefers_color_scheme == Granite.Settings.ColorScheme.DARK;
        });

        // Quit action
        var quit_action = new SimpleAction ("quit", null);
        quit_action.activate.connect (quit);
        add_action (quit_action);
        string[] quit_accels = { "<Control>q" };
        set_accels_for_action ("app.quit", quit_accels);

        // Handle SIGTERM/SIGINT gracefully so shutdown() runs
        Unix.signal_add (ProcessSignal.TERM, () => { quit (); return Source.REMOVE; });
        Unix.signal_add (ProcessSignal.INT, () => { quit (); return Source.REMOVE; });

        // Keep process alive when window is closed
        hold ();

        // Create service instances
        _screenshot_svc = new Vigil.Services.ScreenshotService ();
        _scheduler_svc = new Vigil.Services.SchedulerService ();
        _storage_svc = new Vigil.Services.StorageService ();
        _settings = new GLib.Settings ("io.github.invarianz.vigil");
        var settings = _settings;

        // Set up Matrix transport with optional E2EE
        _matrix_svc = new Vigil.Services.MatrixTransportService ();
        var matrix_svc = _matrix_svc;
        var enc_svc = new Vigil.Services.EncryptionService ();

        // Prefer access token from secure file, fall back to GSettings
        var file_token = Vigil.Services.MatrixTransportService.load_access_token_from_file ();
        if (file_token != null) {
            settings.set_string ("matrix-access-token", file_token);
            debug ("Loaded access token from secure file");
        }

        // Restore E2EE state if setup was completed.
        // Prefer pickle key from secure file, fall back to GSettings.
        var device_id = settings.get_string ("device-id");
        var user_id = settings.get_string ("matrix-user-id");
        var pickle_key = Vigil.Services.EncryptionService.load_pickle_key_from_file ();
        if (pickle_key == null) {
            pickle_key = settings.get_string ("e2ee-pickle-key");
            // Migrate: save to file and clear from GSettings
            if (pickle_key != "") {
                Vigil.Services.EncryptionService.save_pickle_key_to_file (pickle_key);
                debug ("Migrated pickle key from GSettings to secure file");
            }
        } else {
            debug ("Loaded pickle key from secure file");
            // Ensure GSettings still has the key for tamper detection checks
            // (the tamper service checks if pickle_key setting is empty)
            if (settings.get_string ("e2ee-pickle-key") == "") {
                settings.set_string ("e2ee-pickle-key", pickle_key);
            }
        }

        bool e2ee_expected = device_id != "" && user_id != "" && pickle_key != "";
        bool e2ee_ok = false;

        if (e2ee_expected) {
            enc_svc.device_id = device_id;
            enc_svc.user_id = user_id;
            if (enc_svc.initialize (pickle_key)) {
                enc_svc.restore_group_session ();
                debug ("E2EE initialized (session: %s)", enc_svc.megolm_session_id);
                e2ee_ok = true;
            } else {
                warning ("E2EE initialization failed -- refusing to send unencrypted");
            }
        }

        // Only attach encryption service if it initialized successfully.
        // If E2EE was expected but failed, leave encryption null so
        // MatrixTransportService refuses to send (no silent plaintext fallback).
        if (e2ee_ok) {
            matrix_svc.encryption = enc_svc;
        }

        _tamper_svc = new Vigil.Services.TamperDetectionService (settings, matrix_svc);

        // If E2EE was configured but failed to initialize, fire a tamper
        // alert so the partner knows encryption is broken.
        if (e2ee_expected && !e2ee_ok) {
            _tamper_svc.emit_e2ee_init_failure ();
        }

        _engine = new Vigil.MonitoringEngine (
            _screenshot_svc,
            _scheduler_svc,
            _storage_svc,
            _tamper_svc,
            matrix_svc,
            settings
        );

        // Initialize asynchronously
        _engine.initialize.begin ((obj, res) => {
            _engine.initialize.end (res);
            debug ("Monitoring engine initialized, backend: %s",
                _screenshot_svc.active_backend_name ?? "none");
        });
    }

    protected override void activate () {
        // First activation with --background: skip window
        if (_background_mode) {
            _background_mode = false;
            debug ("Started in background mode");
            return;
        }

        var window = active_window;
        if (window == null) {
            window = new Vigil.MainWindow (this, _engine);
        }
        window.present ();
    }

    protected override void shutdown () {
        bool system_shutdown = _engine != null && _engine.system_shutdown_pending;

        // If this is NOT a system shutdown, send alert directly (synchronous,
        // no fire-and-forget to avoid duplicate delivery)
        if (!system_shutdown && _matrix_svc != null && _matrix_svc.is_configured) {
            bool locked = _settings != null &&
                _settings.get_boolean ("settings-locked");
            string event_type = locked ? "process_stopped" : "~process_stopped";

            var alert_loop = new MainLoop (null, false);
            _matrix_svc.send_alert.begin (event_type,
                "Vigil was stopped without a system shutdown",
                (obj, res) => {
                    _matrix_svc.send_alert.end (res);
                    alert_loop.quit ();
                });
            Timeout.add_seconds (3, () => {
                alert_loop.quit ();
                return Source.REMOVE;
            });
            alert_loop.run ();
        }

        // Send "going offline" notice in orange (system shutdowns already
        // sent theirs in on_prepare_for_shutdown while network was still up)
        if (!system_shutdown && _matrix_svc != null && _matrix_svc.is_configured) {
            var now = new DateTime.now_local ();
            var uptime = now.difference (_start_time) / TimeSpan.SECOND;
            var text = "Going offline — Vigil was stopped manually.\n" +
                "Was running for %s.".printf (
                    Vigil.Services.TamperDetectionService.format_duration (uptime));

            var loop = new MainLoop (null, false);
            _matrix_svc.send_notice.begin (text, "#fd7e14", (obj, res) => {
                _matrix_svc.send_notice.end (res);
                loop.quit ();
            });
            Timeout.add_seconds (5, () => { loop.quit (); return Source.REMOVE; });
            loop.run ();
        }
        if (_tamper_svc != null) {
            _tamper_svc.stop ();
        }
        if (_scheduler_svc != null) {
            _scheduler_svc.stop ();
        }

        base.shutdown ();
    }

    public static int main (string[] args) {
        return new Vigil.Application ().run (args);
    }
}
