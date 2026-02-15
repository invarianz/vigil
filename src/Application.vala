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
            flags: ApplicationFlags.FLAGS_NONE
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
        try {
            daemon_proxy = yield Bus.get_proxy<Vigil.Daemon.IDaemonBus> (
                BusType.SESSION,
                "io.github.invarianz.vigil.Daemon",
                "/io/github/invarianz/vigil/Daemon"
            );
            debug ("Connected to Vigil daemon over D-Bus");

            // If a window is already showing, update it
            if (active_window != null) {
                ((Vigil.MainWindow) active_window).set_daemon_proxy (daemon_proxy);
            }
        } catch (Error e) {
            warning ("Could not connect to Vigil daemon: %s. Is the daemon running?", e.message);
        }
    }

    public static int main (string[] args) {
        return new Vigil.Application ().run (args);
    }
}
