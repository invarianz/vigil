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
 *   4. Notifies systemd watchdog periodically
 *
 * The daemon runs independently of the GUI. It is started via
 * systemd user service or XDG autostart and keeps running even
 * when the GUI is closed.
 */
public class Vigil.Daemon.DaemonApp : GLib.Application {

    private Vigil.Daemon.DBusServer _dbus_server;
    private Vigil.Services.ScreenshotService _screenshot_svc;
    private Vigil.Services.SchedulerService _scheduler_svc;
    private Vigil.Services.StorageService _storage_svc;
    private Vigil.Services.HeartbeatService _heartbeat_svc;
    private Vigil.Services.TamperDetectionService _tamper_svc;
    private uint _watchdog_source = 0;

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

        // Restore E2EE state if device_id is set (setup was completed)
        var device_id = settings.get_string ("device-id");
        if (device_id != "") {
            enc_svc.device_id = device_id;
            enc_svc.user_id = ""; // Will be set from access token
        }
        matrix_svc.encryption = enc_svc;

        _heartbeat_svc = new Vigil.Services.HeartbeatService (matrix_svc);
        _tamper_svc = new Vigil.Services.TamperDetectionService (settings);

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

        // Start systemd watchdog notifications
        start_watchdog ();
    }

    protected override bool dbus_register (DBusConnection connection, string object_path) throws Error {
        base.dbus_register (connection, object_path);
        return true;
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

    /**
     * Periodically notify the systemd watchdog that we're alive.
     */
    private void start_watchdog () {
        // Check if WatchdogSec is configured
        var watchdog_usec = Environment.get_variable ("WATCHDOG_USEC");
        if (watchdog_usec == null) {
            debug ("No WATCHDOG_USEC set, watchdog disabled");
            return;
        }

        int64 usec = int64.parse (watchdog_usec);
        if (usec <= 0) {
            return;
        }

        // Notify at half the watchdog interval
        uint interval_sec = (uint) (usec / 2000000);
        if (interval_sec < 1) {
            interval_sec = 1;
        }

        debug ("Watchdog: notifying every %u seconds", interval_sec);

        // Send initial ready notification
        try {
            var proc = new Subprocess.newv (
                { "systemd-notify", "--ready" },
                SubprocessFlags.NONE
            );
            proc.wait (null);
        } catch (Error e) {
            debug ("systemd-notify --ready failed: %s", e.message);
        }

        _watchdog_source = Timeout.add_seconds (interval_sec, () => {
            try {
                var proc = new Subprocess.newv (
                    { "systemd-notify", "WATCHDOG=1" },
                    SubprocessFlags.NONE
                );
                proc.wait (null);
            } catch (Error e) {
                debug ("Watchdog notify failed: %s", e.message);
            }
            return Source.CONTINUE;
        });
    }

    protected override void shutdown () {
        if (_watchdog_source != 0) {
            Source.remove (_watchdog_source);
            _watchdog_source = 0;
        }

        if (_heartbeat_svc != null) {
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
