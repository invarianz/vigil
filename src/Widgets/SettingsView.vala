/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Settings view for configuring Vigil.
 *
 * Covers: Matrix login, homeserver, room ID, screenshot intervals,
 * local retention, and autostart toggle.
 *
 * The login flow lets users enter username + password directly
 * instead of having to manually obtain an access token via curl.
 */
public class Vigil.Widgets.SettingsView : Gtk.Box {

    private Gtk.Entry matrix_homeserver_entry;
    private Gtk.Entry matrix_username_entry;
    private Gtk.PasswordEntry matrix_password_entry;
    private Gtk.Button matrix_login_button;
    private Gtk.Button matrix_test_button;
    private Gtk.Label matrix_status_label;
    private Gtk.Entry matrix_room_entry;
    private Gtk.SpinButton min_interval_spin;
    private Gtk.SpinButton max_interval_spin;
    private Gtk.SpinButton retention_spin;
    private Gtk.Switch autostart_switch;

    private GLib.Settings settings;
    private Vigil.Services.MatrixTransportService _matrix_svc;

    public SettingsView () {
        Object (
            orientation: Gtk.Orientation.VERTICAL,
            spacing: 24,
            margin_top: 24,
            margin_bottom: 24,
            margin_start: 24,
            margin_end: 24
        );
    }

    construct {
        settings = new GLib.Settings ("io.github.invarianz.vigil");
        _matrix_svc = new Vigil.Services.MatrixTransportService ();

        // --- Matrix section ---
        var matrix_header = new Granite.HeaderLabel ("Matrix");

        var matrix_hs_label = new Gtk.Label ("Homeserver URL") {
            halign = Gtk.Align.START
        };
        matrix_homeserver_entry = new Gtk.Entry () {
            placeholder_text = "https://matrix.org or http://localhost:8009 (pantalaimon)",
            hexpand = true
        };
        settings.bind ("matrix-homeserver-url", matrix_homeserver_entry, "text", SettingsBindFlags.DEFAULT);

        // Login fields (username + password + button)
        var login_label = new Gtk.Label ("Username") {
            halign = Gtk.Align.START
        };
        matrix_username_entry = new Gtk.Entry () {
            placeholder_text = "your_username",
            hexpand = true
        };

        var password_label = new Gtk.Label ("Password") {
            halign = Gtk.Align.START
        };
        matrix_password_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };

        matrix_login_button = new Gtk.Button.with_label ("Login") {
            halign = Gtk.Align.END
        };
        matrix_login_button.add_css_class (Granite.STYLE_CLASS_SUGGESTED_ACTION);
        matrix_login_button.clicked.connect (on_login_clicked);

        matrix_test_button = new Gtk.Button.with_label ("Test Connection") {
            halign = Gtk.Align.END
        };
        matrix_test_button.clicked.connect (on_test_clicked);

        matrix_status_label = new Gtk.Label ("") {
            halign = Gtk.Align.START,
            hexpand = true,
            wrap = true
        };

        // Show existing token status
        var existing_token = settings.get_string ("matrix-access-token");
        if (existing_token != "") {
            matrix_status_label.label = "Logged in (token stored)";
            matrix_status_label.add_css_class ("success");
        }

        var matrix_room_label = new Gtk.Label ("Room ID") {
            halign = Gtk.Align.START
        };
        matrix_room_entry = new Gtk.Entry () {
            placeholder_text = "!roomid:matrix.org",
            hexpand = true
        };
        settings.bind ("matrix-room-id", matrix_room_entry, "text", SettingsBindFlags.DEFAULT);

        var button_box = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 8) {
            halign = Gtk.Align.END
        };
        button_box.append (matrix_test_button);
        button_box.append (matrix_login_button);

        var matrix_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        matrix_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        matrix_grid.attach (matrix_hs_label, 0, 0);
        matrix_grid.attach (matrix_homeserver_entry, 1, 0);
        matrix_grid.attach (login_label, 0, 1);
        matrix_grid.attach (matrix_username_entry, 1, 1);
        matrix_grid.attach (password_label, 0, 2);
        matrix_grid.attach (matrix_password_entry, 1, 2);
        matrix_grid.attach (button_box, 1, 3);
        matrix_grid.attach (matrix_status_label, 0, 4, 2);
        matrix_grid.attach (matrix_room_label, 0, 5);
        matrix_grid.attach (matrix_room_entry, 1, 5);

        // --- Schedule section ---
        var schedule_header = new Granite.HeaderLabel ("Schedule");

        var min_label = new Gtk.Label ("Minimum interval (minutes)") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        min_interval_spin = new Gtk.SpinButton.with_range (1, 60, 1);
        // Bind as seconds in GSettings, display as minutes in UI
        var min_seconds = settings.get_int ("min-interval-seconds");
        min_interval_spin.value = min_seconds / 60.0;
        min_interval_spin.value_changed.connect (() => {
            settings.set_int ("min-interval-seconds", (int) (min_interval_spin.value * 60));
        });

        var max_label = new Gtk.Label ("Maximum interval (minutes)") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        max_interval_spin = new Gtk.SpinButton.with_range (1, 120, 1);
        var max_seconds = settings.get_int ("max-interval-seconds");
        max_interval_spin.value = max_seconds / 60.0;
        max_interval_spin.value_changed.connect (() => {
            settings.set_int ("max-interval-seconds", (int) (max_interval_spin.value * 60));
        });

        var schedule_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        schedule_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        schedule_grid.attach (min_label, 0, 0);
        schedule_grid.attach (min_interval_spin, 1, 0);
        schedule_grid.attach (max_label, 0, 1);
        schedule_grid.attach (max_interval_spin, 1, 1);

        // --- Storage section ---
        var storage_header = new Granite.HeaderLabel ("Storage");

        var retention_label = new Gtk.Label ("Maximum local screenshots") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        retention_spin = new Gtk.SpinButton.with_range (10, 1000, 10);
        settings.bind ("max-local-screenshots", retention_spin, "value", SettingsBindFlags.DEFAULT);

        var storage_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        storage_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        storage_grid.attach (retention_label, 0, 0);
        storage_grid.attach (retention_spin, 1, 0);

        // --- Autostart section ---
        var system_header = new Granite.HeaderLabel ("System");

        var autostart_label = new Gtk.Label ("Start at login") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        autostart_switch = new Gtk.Switch () {
            valign = Gtk.Align.CENTER
        };
        settings.bind ("autostart-enabled", autostart_switch, "active", SettingsBindFlags.DEFAULT);

        var system_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        system_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        system_grid.attach (autostart_label, 0, 0);
        system_grid.attach (autostart_switch, 1, 0);

        // Assemble the view
        append (matrix_header);
        append (matrix_grid);
        append (schedule_header);
        append (schedule_grid);
        append (storage_header);
        append (storage_grid);
        append (system_header);
        append (system_grid);
    }

    private void on_login_clicked () {
        var hs_url = matrix_homeserver_entry.text.strip ();
        var username = matrix_username_entry.text.strip ();
        var password = matrix_password_entry.text;

        if (hs_url == "" || username == "" || password == "") {
            set_status ("Please fill in homeserver URL, username, and password", false);
            return;
        }

        matrix_login_button.sensitive = false;
        set_status ("Logging in...", false);

        _matrix_svc.login.begin (hs_url, username, password, (obj, res) => {
            var token = _matrix_svc.login.end (res);
            matrix_login_button.sensitive = true;

            if (token != null) {
                // Store the token and homeserver URL
                settings.set_string ("matrix-access-token", token);
                settings.set_string ("matrix-homeserver-url", hs_url);

                // Clear password from the field
                matrix_password_entry.text = "";

                set_status ("Login successful", true);
            } else {
                set_status ("Login failed -- check credentials and homeserver URL", false);
            }
        });
    }

    private void on_test_clicked () {
        // Use stored token for verification
        _matrix_svc.homeserver_url = settings.get_string ("matrix-homeserver-url");
        _matrix_svc.access_token = settings.get_string ("matrix-access-token");

        if (_matrix_svc.homeserver_url == "" || _matrix_svc.access_token == "") {
            set_status ("Log in first or configure a homeserver and token", false);
            return;
        }

        matrix_test_button.sensitive = false;
        set_status ("Testing connection...", false);

        _matrix_svc.verify_connection.begin ((obj, res) => {
            var user_id = _matrix_svc.verify_connection.end (res);
            matrix_test_button.sensitive = true;

            if (user_id != null) {
                set_status ("Connected as %s".printf (user_id), true);
            } else {
                set_status ("Connection failed -- check homeserver and token", false);
            }
        });
    }

    private void set_status (string message, bool success) {
        matrix_status_label.label = message;
        matrix_status_label.remove_css_class ("success");
        matrix_status_label.remove_css_class ("error");
        if (success) {
            matrix_status_label.add_css_class ("success");
        } else if (message != "") {
            matrix_status_label.add_css_class ("error");
        }
    }
}
