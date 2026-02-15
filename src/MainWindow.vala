/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

public class Vigil.MainWindow : Gtk.ApplicationWindow {

    private GLib.Settings settings;
    private Vigil.Widgets.StatusView status_view;
    private Vigil.Widgets.SettingsView settings_view;
    private Granite.Toast toast;

    /* Services are owned by the Application and passed in */
    private Vigil.Services.ScreenshotService screenshot_service;
    private Vigil.Services.SchedulerService scheduler_service;
    private Vigil.Services.UploadService upload_service;
    private Vigil.Services.StorageService storage_service;

    public MainWindow (
        Gtk.Application application,
        Vigil.Services.ScreenshotService screenshot_service,
        Vigil.Services.SchedulerService scheduler_service,
        Vigil.Services.UploadService upload_service,
        Vigil.Services.StorageService storage_service
    ) {
        Object (
            application: application,
            default_height: 600,
            default_width: 500,
            title: "Vigil"
        );

        this.screenshot_service = screenshot_service;
        this.scheduler_service = scheduler_service;
        this.upload_service = upload_service;
        this.storage_service = storage_service;

        connect_services ();
        load_state ();
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

        child = overlay;

        // Window state persistence
        settings.bind ("window-width", this, "default-width", SettingsBindFlags.DEFAULT);
        settings.bind ("window-height", this, "default-height", SettingsBindFlags.DEFAULT);

        if (settings.get_boolean ("window-maximized")) {
            maximize ();
        }

        close_request.connect (() => {
            settings.set_boolean ("window-maximized", maximized);
            return false;
        });
    }

    private void connect_services () {
        // Monitoring toggle
        status_view.monitoring_toggled.connect ((active) => {
            if (active) {
                scheduler_service.start ();
            } else {
                scheduler_service.stop ();
            }
            settings.set_boolean ("monitoring-enabled", active);
        });

        // Update UI when scheduler changes
        scheduler_service.scheduler_started.connect (() => {
            update_next_capture_display ();
        });

        scheduler_service.scheduler_stopped.connect (() => {
            status_view.set_next_capture_time (null);
        });

        // When a capture is requested by the scheduler
        scheduler_service.capture_requested.connect (() => {
            handle_capture_request.begin ();
        });

        // Screenshot events
        screenshot_service.screenshot_taken.connect ((path) => {
            status_view.set_last_capture_time (new DateTime.now_local ());
            update_next_capture_display ();
        });

        screenshot_service.screenshot_failed.connect ((msg, time) => {
            toast.title = "Screenshot failed: %s".printf (msg);
            toast.send_notification ();
        });

        // Upload events
        upload_service.upload_succeeded.connect ((path) => {
            storage_service.mark_uploaded (path);
            update_pending_count ();
        });

        upload_service.upload_failed.connect ((path, msg) => {
            debug ("Upload failed for %s: %s (will retry later)", path, msg);
        });

        // Refresh pending count every 30 seconds
        Timeout.add_seconds (30, () => {
            update_pending_count ();
            return Source.CONTINUE;
        });
    }

    private void load_state () {
        status_view.set_backend_name (screenshot_service.active_backend_name);

        // Restore monitoring state
        bool monitoring_enabled = settings.get_boolean ("monitoring-enabled");
        status_view.set_monitoring_active (monitoring_enabled);

        // Bind scheduler intervals from settings
        scheduler_service.min_interval_seconds = settings.get_int ("min-interval-seconds");
        scheduler_service.max_interval_seconds = settings.get_int ("max-interval-seconds");

        // Listen for interval setting changes
        settings.changed["min-interval-seconds"].connect (() => {
            scheduler_service.min_interval_seconds = settings.get_int ("min-interval-seconds");
        });
        settings.changed["max-interval-seconds"].connect (() => {
            scheduler_service.max_interval_seconds = settings.get_int ("max-interval-seconds");
        });

        // Bind upload settings
        upload_service.endpoint_url = settings.get_string ("endpoint-url");
        upload_service.api_token = settings.get_string ("api-token");
        upload_service.device_id = get_or_create_device_id ();

        settings.changed["endpoint-url"].connect (() => {
            upload_service.endpoint_url = settings.get_string ("endpoint-url");
        });
        settings.changed["api-token"].connect (() => {
            upload_service.api_token = settings.get_string ("api-token");
        });

        // Bind storage settings
        storage_service.max_local_screenshots = settings.get_int ("max-local-screenshots");
        settings.changed["max-local-screenshots"].connect (() => {
            storage_service.max_local_screenshots = settings.get_int ("max-local-screenshots");
        });

        update_pending_count ();
    }

    private async void handle_capture_request () {
        var path = storage_service.generate_screenshot_path ();
        bool success = yield screenshot_service.take_screenshot (path);

        if (success) {
            try {
                storage_service.mark_pending (path);
            } catch (Error e) {
                warning ("Failed to mark screenshot as pending: %s", e.message);
            }

            // Attempt immediate upload
            var now = new DateTime.now_local ();
            yield upload_service.upload (path, now);

            // Clean up old screenshots
            storage_service.cleanup_old_screenshots ();
        }
    }

    private void update_next_capture_display () {
        status_view.set_next_capture_time (scheduler_service.next_capture_time);
    }

    private void update_pending_count () {
        var pending = storage_service.get_pending_screenshots ();
        status_view.set_pending_count ((int) pending.length);
    }

    private string get_or_create_device_id () {
        var device_id = settings.get_string ("device-id");
        if (device_id == "") {
            device_id = GLib.Uuid.string_random ();
            settings.set_string ("device-id", device_id);
        }
        return device_id;
    }
}
