/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Main window — connected to the in-process MonitoringEngine.
 *
 * Settings are changed via GSettings (which the engine also watches).
 */
public class Vigil.MainWindow : Gtk.ApplicationWindow {

    private GLib.Settings settings;
    private Vigil.Widgets.StatusView status_view;
    private Vigil.Widgets.SettingsView settings_view;
    private Granite.Toast toast;
    private Vigil.MonitoringEngine _engine;

    public MainWindow (Gtk.Application application, Vigil.MonitoringEngine engine) {
        Object (
            application: application,
            default_height: 600,
            default_width: 500,
            title: "Vigil"
        );

        _engine = engine;
        connect_engine_signals ();
        refresh_status ();
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
            child = view_stack,
            vexpand = true
        };
        overlay.add_overlay (toast);

        child = overlay;

        // Window state persistence
        settings.bind ("window-width", this, "default-width", SettingsBindFlags.DEFAULT);
        settings.bind ("window-height", this, "default-height", SettingsBindFlags.DEFAULT);

        if (settings.get_boolean ("window-maximized")) {
            maximize ();
        }

        close_request.connect (() => {
            settings.set_boolean ("window-maximized", maximized);
            visible = false;
            return true; // prevent destruction — process stays alive via hold()
        });

        // Monitoring toggle changes GSettings, which the engine watches
        status_view.monitoring_toggled.connect ((active) => {
            settings.set_boolean ("monitoring-enabled", active);
        });
    }

    private void connect_engine_signals () {
        _engine.status_changed.connect (() => {
            refresh_status ();
        });

        _engine.screenshot_captured.connect ((path) => {
            toast.title = "Screenshot captured";
            toast.send_notification ();
            refresh_status ();
        });

        _engine.screenshot_capture_failed.connect ((msg) => {
            toast.title = "Screenshot failed: %s".printf (msg);
            toast.send_notification ();
        });

        _engine.tamper_event.connect ((event_type, details) => {
            toast.title = "Integrity check: %s".printf (event_type);
            toast.send_notification ();
        });
    }

    private void refresh_status () {
        // Read monitoring state from GSettings (source of truth)
        status_view.set_monitoring_active (settings.get_boolean ("monitoring-enabled"));
        status_view.set_backend_name (_engine.active_backend_name);

        var status_json = _engine.get_status_json ();
        var parser = new Json.Parser ();
        try {
            parser.load_from_data (status_json);
            var obj = parser.get_root ().get_object ();

            var last_iso = obj.get_string_member ("last_capture");
            if (last_iso != "") {
                var last = new DateTime.from_iso8601 (last_iso, new TimeZone.local ());
                status_view.set_last_capture_time (last);
            } else {
                status_view.set_last_capture_time (null);
            }
        } catch (Error e) {
            debug ("Failed to parse status JSON: %s", e.message);
        }
    }
}
