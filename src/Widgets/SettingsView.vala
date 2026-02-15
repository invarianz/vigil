/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Radically simplified settings view.
 *
 * The user only needs to provide:
 *   1. Homeserver (auto-discovered from server name)
 *   2. Username
 *   3. Password
 *   4. Partner's Matrix ID
 *   5. E2EE password (for encrypting crypto state at rest)
 *
 * One "Setup" button does everything: login, create encrypted room,
 * initialize E2EE, upload device keys, share room keys.
 *
 * Schedule/storage/system settings are in a collapsible "Advanced" section.
 */
public class Vigil.Widgets.SettingsView : Gtk.Box {

    private Gtk.Entry homeserver_entry;
    private Gtk.Entry username_entry;
    private Gtk.PasswordEntry password_entry;
    private Gtk.Entry partner_entry;
    private Gtk.PasswordEntry e2ee_password_entry;
    private Gtk.Button setup_button;
    private Gtk.Label status_label;
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

        // --- Account setup section ---
        var setup_header = new Granite.HeaderLabel ("Account Setup");

        homeserver_entry = new Gtk.Entry () {
            placeholder_text = "matrix.org",
            hexpand = true
        };
        var existing_hs = settings.get_string ("matrix-homeserver-url");
        if (existing_hs != "") {
            homeserver_entry.text = existing_hs;
        }

        username_entry = new Gtk.Entry () {
            placeholder_text = "your_username",
            hexpand = true
        };

        password_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };

        partner_entry = new Gtk.Entry () {
            placeholder_text = "@partner:matrix.org",
            hexpand = true
        };
        var existing_partner = settings.get_string ("partner-matrix-id");
        if (existing_partner != "") {
            partner_entry.text = existing_partner;
        }

        e2ee_password_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };

        setup_button = new Gtk.Button.with_label ("Setup") {
            halign = Gtk.Align.END
        };
        setup_button.add_css_class (Granite.STYLE_CLASS_SUGGESTED_ACTION);
        setup_button.clicked.connect (on_setup_clicked);

        status_label = new Gtk.Label ("") {
            halign = Gtk.Align.START,
            hexpand = true,
            wrap = true
        };

        // Show existing status
        var existing_token = settings.get_string ("matrix-access-token");
        var existing_room = settings.get_string ("matrix-room-id");
        if (existing_token != "" && existing_room != "") {
            set_status ("Connected and ready", true);
        } else if (existing_token != "") {
            set_status ("Logged in (room not yet created)", false);
        }

        var setup_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        setup_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        var hs_label = new Gtk.Label ("Homeserver") { halign = Gtk.Align.START };
        var user_label = new Gtk.Label ("Username") { halign = Gtk.Align.START };
        var pw_label = new Gtk.Label ("Password") { halign = Gtk.Align.START };
        var partner_label = new Gtk.Label ("Partner Matrix ID") { halign = Gtk.Align.START };
        var e2ee_label = new Gtk.Label ("E2EE Password") { halign = Gtk.Align.START };

        setup_grid.attach (hs_label, 0, 0);
        setup_grid.attach (homeserver_entry, 1, 0);
        setup_grid.attach (user_label, 0, 1);
        setup_grid.attach (username_entry, 1, 1);
        setup_grid.attach (pw_label, 0, 2);
        setup_grid.attach (password_entry, 1, 2);
        setup_grid.attach (partner_label, 0, 3);
        setup_grid.attach (partner_entry, 1, 3);
        setup_grid.attach (e2ee_label, 0, 4);
        setup_grid.attach (e2ee_password_entry, 1, 4);
        setup_grid.attach (setup_button, 1, 5);
        setup_grid.attach (status_label, 0, 6, 2);

        // --- Advanced section (collapsed) ---
        var advanced_header = new Granite.HeaderLabel ("Advanced");

        var min_label = new Gtk.Label ("Minimum interval (minutes)") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        min_interval_spin = new Gtk.SpinButton.with_range (1, 60, 1);
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

        var retention_label = new Gtk.Label ("Maximum local screenshots") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        retention_spin = new Gtk.SpinButton.with_range (10, 1000, 10);
        settings.bind ("max-local-screenshots", retention_spin, "value", SettingsBindFlags.DEFAULT);

        var autostart_label = new Gtk.Label ("Start at login") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        autostart_switch = new Gtk.Switch () {
            valign = Gtk.Align.CENTER
        };
        settings.bind ("autostart-enabled", autostart_switch, "active", SettingsBindFlags.DEFAULT);

        var advanced_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        advanced_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        advanced_grid.attach (min_label, 0, 0);
        advanced_grid.attach (min_interval_spin, 1, 0);
        advanced_grid.attach (max_label, 0, 1);
        advanced_grid.attach (max_interval_spin, 1, 1);
        advanced_grid.attach (retention_label, 0, 2);
        advanced_grid.attach (retention_spin, 1, 2);
        advanced_grid.attach (autostart_label, 0, 3);
        advanced_grid.attach (autostart_switch, 1, 3);

        // Assemble the view
        append (setup_header);
        append (setup_grid);
        append (advanced_header);
        append (advanced_grid);
    }

    /**
     * One-button setup: login, create room, initialize E2EE.
     */
    private void on_setup_clicked () {
        var hs_input = homeserver_entry.text.strip ();
        var username = username_entry.text.strip ();
        var password = password_entry.text;
        var partner_id = partner_entry.text.strip ();
        var e2ee_password = e2ee_password_entry.text;

        if (hs_input == "" || username == "" || password == "") {
            set_status ("Please fill in homeserver, username, and password", false);
            return;
        }

        if (partner_id == "" || !partner_id.has_prefix ("@")) {
            set_status ("Please enter the partner's Matrix ID (e.g. @partner:matrix.org)", false);
            return;
        }

        if (e2ee_password == "") {
            set_status ("Please set an E2EE password to protect your encryption keys", false);
            return;
        }

        setup_button.sensitive = false;
        set_status ("Discovering homeserver...", false);

        run_setup.begin (hs_input, username, password, partner_id, e2ee_password);
    }

    private async void run_setup (string hs_input, string username, string password,
                                   string partner_id, string e2ee_password) {
        // Step 1: Discover homeserver
        var hs_url = yield _matrix_svc.discover_homeserver (hs_input);
        if (hs_url == null) {
            set_status ("Failed to discover homeserver", false);
            setup_button.sensitive = true;
            return;
        }
        set_status ("Logging in to %s...".printf (hs_url), false);

        // Step 2: Login
        var token = yield _matrix_svc.login (hs_url, username, password);
        if (token == null) {
            set_status ("Login failed -- check credentials", false);
            setup_button.sensitive = true;
            return;
        }

        // Save credentials
        settings.set_string ("matrix-homeserver-url", hs_url);
        settings.set_string ("matrix-access-token", token);
        settings.set_string ("partner-matrix-id", partner_id);
        set_status ("Creating encrypted room...", false);

        // Step 3: Create encrypted room with partner
        var new_room_id = yield _matrix_svc.create_encrypted_room (partner_id);
        if (new_room_id == null) {
            set_status ("Room creation failed -- is the partner ID correct?", false);
            setup_button.sensitive = true;
            return;
        }
        settings.set_string ("matrix-room-id", new_room_id);
        set_status ("Setting up E2EE...", false);

        // Step 4: Initialize E2EE
        var enc_svc = new Vigil.Services.EncryptionService ();
        enc_svc.user_id = _matrix_svc.last_user_id;
        enc_svc.device_id = _matrix_svc.last_device_id;
        settings.set_string ("device-id", _matrix_svc.last_device_id);

        if (!enc_svc.initialize (e2ee_password)) {
            set_status ("E2EE initialization failed", false);
            setup_button.sensitive = true;
            return;
        }

        // Step 5: Full E2EE setup (upload keys, create Megolm session, share)
        bool e2ee_ok = yield _matrix_svc.setup_e2ee (enc_svc, partner_id);

        // Clear password fields
        password_entry.text = "";
        e2ee_password_entry.text = "";

        setup_button.sensitive = true;

        if (e2ee_ok) {
            set_status ("Setup complete -- monitoring ready", true);
        } else {
            // Partial success - login and room created but E2EE had issues
            set_status ("Setup mostly complete -- E2EE key sharing deferred until partner is online", true);
        }
    }

    private void set_status (string message, bool success) {
        status_label.label = message;
        status_label.remove_css_class ("success");
        status_label.remove_css_class ("error");
        if (success) {
            status_label.add_css_class ("success");
        } else if (message != "") {
            status_label.add_css_class ("error");
        }
    }
}
