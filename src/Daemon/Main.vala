/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Headless daemon entry point.
 *
 * This is a GApplication (not Gtk.Application) that:
 *   1. Owns the session bus name io.github.invarianz.vigil.Daemon
 *   2. Exports the DBusServer object on the bus
 *   3. Runs the monitoring engine (scheduler, screenshot, Matrix, E2EE, heartbeat, tamper)
 *
 * The daemon runs independently of the GUI. It is started via the
 * XDG Background portal (Flatpak autostart) and keeps running even
 * when the GUI is closed.
 */
public class Vigil.Daemon.DaemonApp : GLib.Application {

    private Vigil.Daemon.DBusServer _dbus_server;
    private Vigil.Services.ScreenshotService _screenshot_svc;
    private Vigil.Services.SchedulerService _scheduler_svc;
    private Vigil.Services.StorageService _storage_svc;
    private Vigil.Services.HeartbeatService _heartbeat_svc;
    private Vigil.Services.TamperDetectionService _tamper_svc;
    private GenericArray<string> _deferred_tamper_events;

    public DaemonApp () {
        Object (
            application_id: "io.github.invarianz.vigil.Daemon",
            flags: ApplicationFlags.IS_SERVICE
        );
    }

    construct {
        Intl.setlocale (LocaleCategory.ALL, "");
        Intl.bindtextdomain (Vigil.Config.APP_ID, Vigil.Config.LOCALEDIR);
        Intl.bind_textdomain_codeset (Vigil.Config.APP_ID, "UTF-8");
        Intl.textdomain (Vigil.Config.APP_ID);
    }

    protected override void startup () {
        base.startup ();

        // Harden process before anything else: disable ptrace, detect LD_PRELOAD
        _deferred_tamper_events = Vigil.Services.SecurityUtils.harden_process ();

        // Hold the application so it doesn't exit (it's a service)
        hold ();

        // Create service instances
        _screenshot_svc = new Vigil.Services.ScreenshotService ();
        _scheduler_svc = new Vigil.Services.SchedulerService ();
        _storage_svc = new Vigil.Services.StorageService ();
        var settings = new GLib.Settings ("io.github.invarianz.vigil");

        // Set up Matrix transport with optional E2EE
        var matrix_svc = new Vigil.Services.MatrixTransportService ();
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

        _heartbeat_svc = new Vigil.Services.HeartbeatService (matrix_svc);
        _tamper_svc = new Vigil.Services.TamperDetectionService (settings);

        // Drain deferred tamper events collected before services existed.
        // prctl_failed is a warning (system issue), everything else is tamper.
        for (int i = 0; i < _deferred_tamper_events.length; i++) {
            var parts = _deferred_tamper_events[i].split (":", 2);
            if (parts.length == 2) {
                if (parts[0] == "prctl_failed") {
                    _tamper_svc.report_warning (parts[0], parts[1]);
                } else {
                    _tamper_svc.report_tamper (parts[0], parts[1]);
                }
            }
        }

        // If E2EE was configured but failed to initialize, fire a tamper
        // alert so the partner knows encryption is broken. This is more
        // visible than a log warning that nobody reads.
        if (e2ee_expected && !e2ee_ok) {
            _heartbeat_svc.report_tamper_event (
                "E2EE initialization failed -- screenshots will NOT be sent " +
                "until encryption is restored (pickle file may be corrupt " +
                "or E2EE password may have changed)"
            );
            // Also emit as a tamper signal for immediate alert delivery
            _tamper_svc.emit_e2ee_init_failure ();
        }

        _dbus_server = new Vigil.Daemon.DBusServer (
            _screenshot_svc,
            _scheduler_svc,
            _storage_svc,
            _heartbeat_svc,
            _tamper_svc,
            matrix_svc,
            settings
        );

        // Initialize asynchronously
        _dbus_server.initialize.begin ((obj, res) => {
            _dbus_server.initialize.end (res);
            debug ("Daemon services initialized, backend: %s",
                _screenshot_svc.active_backend_name ?? "none");
        });

    }

    protected override void activate () {
        // Service mode: nothing to activate visually
        debug ("Vigil daemon activated");
    }

    /**
     * Called when the app acquires its bus name.
     * Export the D-Bus interface object.
     */
    private void on_bus_acquired (DBusConnection connection) {
        try {
            connection.register_object (
                "/io/github/invarianz/vigil/Daemon",
                _dbus_server
            );
            debug ("D-Bus object exported");
        } catch (IOError e) {
            warning ("Could not export D-Bus object: %s", e.message);
        }
    }

    protected override void shutdown () {
        // Send "going offline" notice so the partner knows silence is expected
        if (_heartbeat_svc != null) {
            // Run the async send synchronously within a brief main loop spin.
            // systemd gives us a generous shutdown timeout (DefaultTimeoutStopSec).
            var loop = new MainLoop (null, false);
            _heartbeat_svc.send_offline_notice.begin ((obj, res) => {
                _heartbeat_svc.send_offline_notice.end (res);
                loop.quit ();
            });
            // Spin for at most 5 seconds, then give up
            Timeout.add_seconds (5, () => { loop.quit (); return Source.REMOVE; });
            loop.run ();

            _heartbeat_svc.stop ();
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
        var app = new Vigil.Daemon.DaemonApp ();

        app.startup.connect (() => {
            var connection = app.get_dbus_connection ();
            if (connection != null) {
                app.on_bus_acquired (connection);
            }
        });

        return app.run (args);
    }
}
