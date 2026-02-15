/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Main window -- now a D-Bus client of the daemon.
 *
 * Reads status from the daemon proxy and displays it.
 * Settings are changed via GSettings (which the daemon also watches).
 */
public class Vigil.MainWindow : Gtk.ApplicationWindow {

    private GLib.Settings settings;
    private Vigil.Widgets.StatusView status_view;
    private Vigil.Widgets.SettingsView settings_view;
    private Granite.Toast toast;
    private Vigil.Daemon.IDaemonBus? _daemon;
    private Gtk.Label daemon_status_label;
    private uint _poll_source = 0;

    public MainWindow (Gtk.Application application, Vigil.Daemon.IDaemonBus? daemon_proxy) {
        Object (
            application: application,
            default_height: 600,
            default_width: 500,
            title: "Vigil"
        );

        _daemon = daemon_proxy;

        if (_daemon != null) {
            connect_daemon_signals ();
            refresh_status ();
        } else {
            show_daemon_disconnected ();
        }
    }

    construct {
        settings = new GLib.Settings ("io.github.invarianz.vigil");

        // Header bar with view switcher
        var view_stack = new Gtk.Stack () {
            transition_type = Gtk.StackTransitionType.SLIDE_LEFT_RIGHT
        };

        status_view = new Vigil.Widgets.StatusView ();
        settings_view = new Vigil.Widgets.SettingsView ();

        var status_scroll = new Gtk.ScrolledWindow () {
            child = status_view,
            hscrollbar_policy = Gtk.PolicyType.NEVER
        };

        var settings_scroll = new Gtk.ScrolledWindow () {
            child = settings_view,
            hscrollbar_policy = Gtk.PolicyType.NEVER
        };

        view_stack.add_titled (status_scroll, "status", "Status");
        view_stack.add_titled (settings_scroll, "settings", "Settings");

        var stack_switcher = new Gtk.StackSwitcher () {
            stack = view_stack
        };

        var headerbar = new Gtk.HeaderBar () {
            title_widget = stack_switcher
        };

        set_titlebar (headerbar);

        // Toast overlay for notifications
        toast = new Granite.Toast ("");
        var overlay = new Gtk.Overlay () {
            child = view_stack
        };
        overlay.add_overlay (toast);

        // Daemon connection status bar
        daemon_status_label = new Gtk.Label ("") {
            visible = false
        };
        daemon_status_label.add_css_class ("error");

        var main_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 0);
        main_box.append (daemon_status_label);
        main_box.append (overlay);

        child = main_box;

        // Window state persistence
        settings.bind ("window-width", this, "default-width", SettingsBindFlags.DEFAULT);
        settings.bind ("window-height", this, "default-height", SettingsBindFlags.DEFAULT);

        if (settings.get_boolean ("window-maximized")) {
            maximize ();
        }

        close_request.connect (() => {
            settings.set_boolean ("window-maximized", maximized);
            if (_poll_source != 0) {
                Source.remove (_poll_source);
                _poll_source = 0;
            }
            return false;
        });

        // Monitoring toggle changes GSettings, which the daemon watches
        status_view.monitoring_toggled.connect ((active) => {
            settings.set_boolean ("monitoring-enabled", active);
        });

        // Poll daemon status periodically (D-Bus signals may be missed in some scenarios)
        _poll_source = Timeout.add_seconds (5, () => {
            refresh_status ();
            return Source.CONTINUE;
        });
    }

    /**
     * Update the daemon proxy (e.g. after reconnecting).
     */
    public void set_daemon_proxy (Vigil.Daemon.IDaemonBus? proxy) {
        _daemon = proxy;
        if (_daemon != null) {
            daemon_status_label.visible = false;
            connect_daemon_signals ();
            refresh_status ();
        } else {
            show_daemon_disconnected ();
        }
    }

    private void connect_daemon_signals () {
        _daemon.status_changed.connect (() => {
            refresh_status ();
        });

        _daemon.screenshot_captured.connect ((path) => {
            toast.title = "Screenshot captured";
            toast.send_notification ();
            refresh_status ();
        });

        _daemon.screenshot_capture_failed.connect ((msg) => {
            toast.title = "Screenshot failed: %s".printf (msg);
            toast.send_notification ();
        });

        _daemon.tamper_event.connect ((event_type, details) => {
            toast.title = "Integrity check: %s".printf (event_type);
            toast.send_notification ();
        });
    }

    private void refresh_status () {
        if (_daemon == null) {
            return;
        }

        try {
            status_view.set_monitoring_active (_daemon.monitoring_active);
            status_view.set_backend_name (_daemon.active_backend_name);
            status_view.set_pending_count (_daemon.pending_upload_count);

            var next_iso = _daemon.next_capture_time_iso;
            if (next_iso != "") {
                var next = new DateTime.from_iso8601 (next_iso, new TimeZone.local ());
                status_view.set_next_capture_time (next);
            } else {
                status_view.set_next_capture_time (null);
            }

            var last_iso = _daemon.last_capture_time_iso;
            if (last_iso != "") {
                var last = new DateTime.from_iso8601 (last_iso, new TimeZone.local ());
                status_view.set_last_capture_time (last);
            } else {
                status_view.set_last_capture_time (null);
            }
        } catch (Error e) {
            debug ("Failed to refresh status from daemon: %s", e.message);
            show_daemon_disconnected ();
        }
    }

    private void show_daemon_disconnected () {
        daemon_status_label.label = "  Daemon not connected. Is vigil-daemon running?  ";
        daemon_status_label.visible = true;
        status_view.set_monitoring_active (false);
        status_view.set_backend_name ("Daemon offline");
    }
}
