/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

public class Vigil.Application : Gtk.Application {

    private Vigil.Services.ScreenshotService screenshot_service;
    private Vigil.Services.SchedulerService scheduler_service;
    private Vigil.Services.UploadService upload_service;
    private Vigil.Services.StorageService storage_service;

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

        // Initialize services
        screenshot_service = new Vigil.Services.ScreenshotService ();
        scheduler_service = new Vigil.Services.SchedulerService ();
        upload_service = new Vigil.Services.UploadService ();
        storage_service = new Vigil.Services.StorageService ();

        try {
            storage_service.initialize ();
        } catch (Error e) {
            warning ("Failed to initialize storage: %s", e.message);
        }

        // Initialize screenshot backend asynchronously
        screenshot_service.initialize.begin ((obj, res) => {
            screenshot_service.initialize.end (res);
            debug ("Screenshot service ready, backend: %s",
                screenshot_service.active_backend_name ?? "none");
        });

        // Retry pending uploads on startup
        retry_pending_uploads.begin ();
    }

    protected override void activate () {
        var window = active_window;
        if (window == null) {
            window = new Vigil.MainWindow (
                this,
                screenshot_service,
                scheduler_service,
                upload_service,
                storage_service
            );
        }
        window.present ();
    }

    /**
     * On startup, try to upload any screenshots that failed to upload previously.
     */
    private async void retry_pending_uploads () {
        var pending = storage_service.get_pending_screenshots ();
        if (pending.length == 0) {
            return;
        }

        debug ("Retrying %d pending uploads", (int) pending.length);
        for (int i = 0; i < pending.length; i++) {
            var item = pending[i];
            yield upload_service.upload (item.file_path, item.capture_time ?? new DateTime.now_local ());
        }
    }

    public static int main (string[] args) {
        return new Vigil.Application ().run (args);
    }
}
