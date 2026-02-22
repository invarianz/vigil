/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * GTK4 GUI application.
 *
 * This is a thin D-Bus client that connects to the Vigil daemon
 * (io.github.invarianz.vigil.Daemon) and displays status / settings.
 * All monitoring logic runs in the daemon process.
 */
public class Vigil.Application : Gtk.Application {

    private Vigil.Daemon.IDaemonBus? daemon_proxy = null;

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
    }

    protected override void startup () {
        base.startup ();

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
        set_accels_for_action ("app.quit", { "<Control>q" });

        // Connect to the daemon over D-Bus
        connect_to_daemon.begin ();
    }

    protected override void activate () {
        var window = active_window;
        if (window == null) {
            window = new Vigil.MainWindow (this, daemon_proxy);
        }
        window.present ();
    }

    private async void connect_to_daemon () {
        // Try connecting to an already-running daemon
        daemon_proxy = yield try_dbus_connect ();
        if (daemon_proxy != null) {
            debug ("Connected to Vigil daemon over D-Bus");
            update_window_proxy ();
            return;
        }

        // Daemon not running — spawn it
        if (!try_spawn_daemon ()) {
            warning ("Could not connect to or spawn Vigil daemon");
            return;
        }

        // Retry connection while daemon starts up and registers on D-Bus
        for (int i = 0; i < 4; i++) {
            yield async_delay (500 + i * 500);
            daemon_proxy = yield try_dbus_connect ();
            if (daemon_proxy != null) {
                debug ("Connected to Vigil daemon over D-Bus (after spawn)");
                update_window_proxy ();
                return;
            }
        }

        warning ("Daemon spawned but D-Bus registration timed out");
    }

    private async Vigil.Daemon.IDaemonBus? try_dbus_connect () {
        try {
            return yield Bus.get_proxy<Vigil.Daemon.IDaemonBus> (
                BusType.SESSION,
                "io.github.invarianz.vigil.Daemon",
                "/io/github/invarianz/vigil/Daemon"
            );
        } catch (Error e) {
            debug ("D-Bus connect attempt: %s", e.message);
            return null;
        }
    }

    /**
     * Spawn the daemon binary from the same directory as the GUI binary.
     * Works for both Flatpak (/app/bin/) and development (builddir/).
     */
    private bool try_spawn_daemon () {
        try {
            var gui_path = FileUtils.read_link ("/proc/self/exe");
            var daemon_path = Path.build_filename (
                Path.get_dirname (gui_path),
                Vigil.Config.APP_ID + ".daemon"
            );

            if (!FileUtils.test (daemon_path, FileTest.IS_EXECUTABLE)) {
                warning ("Daemon binary not found at %s", daemon_path);
                return false;
            }

            debug ("Spawning daemon: %s", daemon_path);
            Process.spawn_async (
                null,
                { daemon_path },
                null,
                SpawnFlags.DO_NOT_REAP_CHILD,
                null,
                null
            );
            return true;
        } catch (Error e) {
            warning ("Failed to spawn daemon: %s", e.message);
            return false;
        }
    }

    private void update_window_proxy () {
        if (active_window != null) {
            ((Vigil.MainWindow) active_window).set_daemon_proxy (daemon_proxy);
        }
    }

    private async void async_delay (uint ms) {
        Timeout.add (ms, () => {
            async_delay.callback ();
            return Source.REMOVE;
        });
        yield;
    }

    public static int main (string[] args) {
        return new Vigil.Application ().run (args);
    }
}
