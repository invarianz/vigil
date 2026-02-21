/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Dual-thumb range slider for selecting a min/max interval.
 *
 * Draws a track with two draggable thumbs. The highlighted region
 * between the thumbs shows the selected range. Values snap to the
 * configured step size. A minimum gap between thumbs is enforced.
 *
 * Styled to match elementary OS Gtk.Scale conventions:
 * light thumb with border/shadow, foreground-based track fill.
 */
public class Vigil.Widgets.RangeScale : Gtk.Widget {

    /** Emitted when either value changes. */
    public signal void values_changed ();

    public double range_min { get; construct; }
    public double range_max { get; construct; }
    public double step { get; construct; default = 5; }
    public double min_gap { get; construct; default = 30; }

    private double _lower_value;
    public double lower_value {
        get { return _lower_value; }
        set {
            _lower_value = value.clamp (range_min, _upper_value - min_gap);
            queue_draw ();
        }
    }

    private double _upper_value;
    public double upper_value {
        get { return _upper_value; }
        set {
            _upper_value = value.clamp (_lower_value + min_gap, range_max);
            queue_draw ();
        }
    }

    private const int THUMB_SIZE = 14;
    private const int THUMB_RADIUS = 7;
    private const int TRACK_HEIGHT = 3;
    private const int H_PADDING = THUMB_RADIUS + 2;
    private const int TRACK_Y = 16;
    private const int WIDGET_HEIGHT = 48;

    private bool _dragging_lower = false;
    private bool _dragging_upper = false;
    private double _drag_start_x = 0;

    public RangeScale (double range_min, double range_max, double step,
                       double min_gap, double initial_lower, double initial_upper) {
        Object (
            range_min: range_min,
            range_max: range_max,
            step: step,
            min_gap: min_gap
        );
        _lower_value = initial_lower.clamp (range_min, range_max - min_gap);
        _upper_value = initial_upper.clamp (_lower_value + min_gap, range_max);
    }

    static construct {
        set_css_name ("range-scale");
    }

    construct {
        hexpand = true;
        set_size_request (-1, WIDGET_HEIGHT);

        var drag = new Gtk.GestureDrag ();
        drag.drag_begin.connect (on_drag_begin);
        drag.drag_update.connect (on_drag_update);
        drag.drag_end.connect (on_drag_end);
        add_controller (drag);
    }

    private double value_to_x (double val) {
        var width = get_width () - 2 * H_PADDING;
        return H_PADDING + (val - range_min) / (range_max - range_min) * width;
    }

    private double x_to_value (double x) {
        var width = get_width () - 2 * H_PADDING;
        var raw = range_min + (x - H_PADDING) / width * (range_max - range_min);
        raw = Math.round (raw / step) * step;
        return raw.clamp (range_min, range_max);
    }

    private string format_value (double val) {
        var secs = (int) val;
        if (secs >= 60 && secs % 60 == 0) {
            return "%dmin".printf (secs / 60);
        } else if (secs >= 60) {
            return "%d:%02d".printf (secs / 60, secs % 60);
        }
        return "%ds".printf (secs);
    }

    protected override void snapshot (Gtk.Snapshot snapshot) {
        var width = get_width ();
        var height = get_height ();

        var cr = snapshot.append_cairo (
            Graphene.Rect ().init (0, 0, width, height)
        );

        var fg = get_color ();

        // Track background — elementary: rgba(black, 0.05) with border
        cr.set_source_rgba (0, 0, 0, 0.05);
        rounded_rect (cr, H_PADDING, TRACK_Y - TRACK_HEIGHT / 2.0,
                      width - 2 * H_PADDING, TRACK_HEIGHT, TRACK_HEIGHT / 2.0);
        cr.fill ();

        // Track border
        cr.set_source_rgba (0, 0, 0, 0.15);
        cr.set_line_width (1);
        rounded_rect (cr, H_PADDING, TRACK_Y - TRACK_HEIGHT / 2.0,
                      width - 2 * H_PADDING, TRACK_HEIGHT, TRACK_HEIGHT / 2.0);
        cr.stroke ();

        // Highlighted range — elementary: rgba($fg-color, 0.7)
        var x_lo = value_to_x (_lower_value);
        var x_hi = value_to_x (_upper_value);
        cr.set_source_rgba (fg.red, fg.green, fg.blue, 0.7);
        rounded_rect (cr, x_lo, TRACK_Y - TRACK_HEIGHT / 2.0,
                      x_hi - x_lo, TRACK_HEIGHT, TRACK_HEIGHT / 2.0);
        cr.fill ();

        // Thumbs
        draw_thumb (cr, x_lo, TRACK_Y);
        draw_thumb (cr, x_hi, TRACK_Y);

        // Value labels below thumbs
        cr.set_source_rgba (fg.red, fg.green, fg.blue, 0.7);
        cr.set_font_size (11);

        Cairo.TextExtents ext;
        var lo_text = format_value (_lower_value);
        cr.text_extents (lo_text, out ext);
        var lo_label_x = (x_lo - ext.width / 2).clamp (0, width - ext.width);
        cr.move_to (lo_label_x, TRACK_Y + THUMB_RADIUS + 16);
        cr.show_text (lo_text);

        var hi_text = format_value (_upper_value);
        cr.text_extents (hi_text, out ext);
        var hi_label_x = (x_hi - ext.width / 2).clamp (0, width - ext.width);
        if (hi_label_x < lo_label_x + 30) {
            hi_label_x = lo_label_x + 30;
        }
        cr.move_to (hi_label_x, TRACK_Y + THUMB_RADIUS + 16);
        cr.show_text (hi_text);
    }

    private void draw_thumb (Cairo.Context cr, double x, double y) {
        // Shadow — elementary: 0 1px 1px 1px rgba(black, 0.1)
        cr.set_source_rgba (0, 0, 0, 0.1);
        cr.arc (x, y + 1, THUMB_RADIUS, 0, 2 * Math.PI);
        cr.fill ();

        // Fill — elementary: bg-color (light/white)
        cr.set_source_rgba (1, 1, 1, 1);
        cr.arc (x, y, THUMB_RADIUS, 0, 2 * Math.PI);
        cr.fill ();

        // Border — elementary: 1px $border-color
        cr.set_source_rgba (0, 0, 0, 0.2);
        cr.set_line_width (1);
        cr.arc (x, y, THUMB_RADIUS, 0, 2 * Math.PI);
        cr.stroke ();
    }

    private static void rounded_rect (Cairo.Context cr, double x, double y,
                                       double w, double h, double r) {
        cr.new_sub_path ();
        cr.arc (x + w - r, y + r, r, -Math.PI / 2, 0);
        cr.arc (x + w - r, y + h - r, r, 0, Math.PI / 2);
        cr.arc (x + r, y + h - r, r, Math.PI / 2, Math.PI);
        cr.arc (x + r, y + r, r, Math.PI, 3 * Math.PI / 2);
        cr.close_path ();
    }

    private void on_drag_begin (double x, double y) {
        var x_lo = value_to_x (_lower_value);
        var x_hi = value_to_x (_upper_value);

        var dist_lo = (x - x_lo).abs ();
        var dist_hi = (x - x_hi).abs ();
        var grab_dist = THUMB_RADIUS * 2.5;

        if (dist_lo <= dist_hi && dist_lo < grab_dist) {
            _dragging_lower = true;
            _drag_start_x = x;
        } else if (dist_hi < grab_dist) {
            _dragging_upper = true;
            _drag_start_x = x;
        }
    }

    private void on_drag_update (double offset_x, double offset_y) {
        var x = _drag_start_x + offset_x;
        var val = x_to_value (x);

        if (_dragging_lower) {
            var max_lower = _upper_value - min_gap;
            if (val > max_lower) val = max_lower;
            if (val < range_min) val = range_min;
            if (val != _lower_value) {
                _lower_value = val;
                queue_draw ();
                values_changed ();
            }
        } else if (_dragging_upper) {
            var min_upper = _lower_value + min_gap;
            if (val < min_upper) val = min_upper;
            if (val > range_max) val = range_max;
            if (val != _upper_value) {
                _upper_value = val;
                queue_draw ();
                values_changed ();
            }
        }
    }

    private void on_drag_end (double offset_x, double offset_y) {
        _dragging_lower = false;
        _dragging_upper = false;
    }
}
