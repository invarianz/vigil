/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Shows the current monitoring status: active/inactive, next capture time,
 * recent capture history, and any errors.
 */
public class Vigil.Widgets.StatusView : Gtk.Box {

    private Gtk.Label status_label;
    private Gtk.Label next_capture_label;
    private Gtk.Label last_capture_label;
    private Gtk.Label backend_label;
    private Gtk.Label pending_uploads_label;
    private Gtk.Switch monitoring_switch;

    public signal void monitoring_toggled (bool active);

    public StatusView () {
        Object ();
    }

    construct {
        orientation = Gtk.Orientation.VERTICAL;
        spacing = 24;
        margin_top = 24;
        margin_bottom = 24;
        margin_start = 24;
        margin_end = 24;

        // Header area with monitoring toggle
        var header_box = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 12);

        var title_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 4);

        var title = new Gtk.Label ("Monitoring") {
            halign = Gtk.Align.START,
            hexpand = true
        };
        title.add_css_class ("h2");

        var subtitle = new Gtk.Label ("Vigil takes screenshots at random intervals for accountability") {
            halign = Gtk.Align.START,
            wrap = true
        };
        subtitle.add_css_class ("dim-label");

        title_box.append (title);
        title_box.append (subtitle);

        monitoring_switch = new Gtk.Switch () {
            valign = Gtk.Align.CENTER
        };
        monitoring_switch.notify["active"].connect (() => {
            monitoring_toggled (monitoring_switch.active);
            update_status_display ();
        });

        header_box.append (title_box);
        header_box.append (monitoring_switch);

        // Status info card
        var info_card = new Gtk.Box (Gtk.Orientation.VERTICAL, 16) {
            margin_top = 16,
            margin_bottom = 16,
            margin_start = 20,
            margin_end = 20
        };

        // Status row
        status_label = new Gtk.Label ("Inactive") {
            halign = Gtk.Align.END,
            hexpand = true
        };
        info_card.append (create_info_row ("Status", status_label));

        // Backend row
        backend_label = new Gtk.Label ("Detecting\u2026") {
            halign = Gtk.Align.END,
            hexpand = true
        };
        info_card.append (create_info_row ("Screenshot method", backend_label));

        // Next capture row
        next_capture_label = new Gtk.Label ("\u2014") {
            halign = Gtk.Align.END,
            hexpand = true
        };
        info_card.append (create_info_row ("Next capture", next_capture_label));

        // Last capture row
        last_capture_label = new Gtk.Label ("\u2014") {
            halign = Gtk.Align.END,
            hexpand = true
        };
        info_card.append (create_info_row ("Last capture", last_capture_label));

        // Pending uploads row
        pending_uploads_label = new Gtk.Label ("0") {
            halign = Gtk.Align.END,
            hexpand = true
        };
        info_card.append (create_info_row ("Pending uploads", pending_uploads_label));

        var icon = new Gtk.Image.from_icon_name ("io.github.invarianz.vigil") {
            pixel_size = 128,
            opacity = 0.15,
            vexpand = true,
            valign = Gtk.Align.END,
            halign = Gtk.Align.CENTER,
            margin_bottom = 24
        };

        append (header_box);
        append (info_card);
        append (icon);
    }

    public void set_monitoring_active (bool active) {
        monitoring_switch.active = active;
        update_status_display ();
    }

    public void set_backend_name (string? name) {
        backend_label.label = name ?? "Not available";
    }

    public void set_next_capture_time (DateTime? time) {
        if (time == null) {
            next_capture_label.label = "\u2014";
        } else {
            next_capture_label.label = time.format ("%H:%M:%S");
        }
    }

    public void set_last_capture_time (DateTime? time) {
        if (time == null) {
            last_capture_label.label = "\u2014";
        } else {
            last_capture_label.label = time.format ("%H:%M:%S");
        }
    }

    public void set_pending_count (int count) {
        pending_uploads_label.label = count.to_string ();
        if (count > 10) {
            pending_uploads_label.add_css_class (Granite.CssClass.WARNING);
        } else {
            pending_uploads_label.remove_css_class (Granite.CssClass.WARNING);
        }
    }

    private static Gtk.Box create_info_row (string title_text, Gtk.Label value_label) {
        var row = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 12) {
            margin_top = 2,
            margin_bottom = 2
        };
        var label = new Gtk.Label (title_text) {
            halign = Gtk.Align.START,
            hexpand = true
        };
        label.add_css_class ("h4");
        row.append (label);
        row.append (value_label);
        return row;
    }

    private void update_status_display () {
        if (monitoring_switch.active) {
            status_label.label = "Active";
            status_label.remove_css_class ("error");
            status_label.add_css_class ("success");
        } else {
            status_label.label = "Inactive";
            status_label.remove_css_class ("success");
            status_label.add_css_class ("error");
        }
    }
}
