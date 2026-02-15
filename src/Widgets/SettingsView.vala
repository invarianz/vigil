/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Settings view for configuring Vigil.
 *
 * Covers: upload endpoint, API token, screenshot intervals,
 * local retention, and autostart toggle.
 */
public class Vigil.Widgets.SettingsView : Gtk.Box {

    private Gtk.Entry endpoint_entry;
    private Gtk.PasswordEntry token_entry;
    private Gtk.Entry matrix_homeserver_entry;
    private Gtk.PasswordEntry matrix_token_entry;
    private Gtk.Entry matrix_room_entry;
    private Gtk.SpinButton min_interval_spin;
    private Gtk.SpinButton max_interval_spin;
    private Gtk.SpinButton retention_spin;
    private Gtk.Switch autostart_switch;

    private GLib.Settings settings;

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

        // --- Upload section ---
        var upload_header = new Granite.HeaderLabel ("Upload");

        var endpoint_label = new Gtk.Label ("Server endpoint URL") {
            halign = Gtk.Align.START
        };
        endpoint_entry = new Gtk.Entry () {
            placeholder_text = "https://your-server.example.com/api/screenshots",
            hexpand = true
        };
        settings.bind ("endpoint-url", endpoint_entry, "text", SettingsBindFlags.DEFAULT);

        var token_label = new Gtk.Label ("API token") {
            halign = Gtk.Align.START
        };
        token_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };
        settings.bind ("api-token", token_entry, "text", SettingsBindFlags.DEFAULT);

        var upload_grid = new Gtk.Grid () {
            row_spacing = 8,
            column_spacing = 16,
            margin_top = 8,
            margin_bottom = 8,
            margin_start = 16,
            margin_end = 16
        };
        upload_grid.add_css_class (Granite.STYLE_CLASS_CARD);

        upload_grid.attach (endpoint_label, 0, 0);
        upload_grid.attach (endpoint_entry, 1, 0);
        upload_grid.attach (token_label, 0, 1);
        upload_grid.attach (token_entry, 1, 1);

        // --- Matrix section ---
        var matrix_header = new Granite.HeaderLabel ("Matrix (recommended)");

        var matrix_hs_label = new Gtk.Label ("Homeserver URL") {
            halign = Gtk.Align.START
        };
        matrix_homeserver_entry = new Gtk.Entry () {
            placeholder_text = "http://localhost:8009 (pantalaimon) or https://matrix.org",
            hexpand = true
        };
        settings.bind ("matrix-homeserver-url", matrix_homeserver_entry, "text", SettingsBindFlags.DEFAULT);

        var matrix_token_label = new Gtk.Label ("Access token") {
            halign = Gtk.Align.START
        };
        matrix_token_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };
        settings.bind ("matrix-access-token", matrix_token_entry, "text", SettingsBindFlags.DEFAULT);

        var matrix_room_label = new Gtk.Label ("Room ID") {
            halign = Gtk.Align.START
        };
        matrix_room_entry = new Gtk.Entry () {
            placeholder_text = "!roomid:matrix.org",
            hexpand = true
        };
        settings.bind ("matrix-room-id", matrix_room_entry, "text", SettingsBindFlags.DEFAULT);

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
        matrix_grid.attach (matrix_token_label, 0, 1);
        matrix_grid.attach (matrix_token_entry, 1, 1);
        matrix_grid.attach (matrix_room_label, 0, 2);
        matrix_grid.attach (matrix_room_entry, 1, 2);

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
        append (upload_header);
        append (upload_grid);
        append (schedule_header);
        append (schedule_grid);
        append (storage_header);
        append (storage_grid);
        append (system_header);
        append (system_grid);
    }
}
