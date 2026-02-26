/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Screenshot service using the XDG Desktop Portal (libportal).
 *
 * Takes non-interactive screenshots via Xdp.ScreenshotFlags.NONE.
 */
public class Vigil.Services.ScreenshotService : Object {

    public signal void screenshot_taken (string file_path);
    public signal void screenshot_failed (string error_message);

    private bool _portal_available = false;

    private static void ensure_parent_dir (string path) throws Error {
        var dir = File.new_for_path (path).get_parent ();
        if (dir != null && !dir.query_exists ()) {
            dir.make_directory_with_parents (null);
        }
    }

    public string? active_backend_name {
        get {
            if (_portal_available) return "XDG Desktop Portal";
            return null;
        }
    }

    /**
     * Initialize the service by probing the Portal backend.
     */
    public async void initialize () {
        _portal_available = yield check_portal_available ();
        if (_portal_available) {
            debug ("Using Portal screenshot backend");
            return;
        }

        warning ("No screenshot backend available!");
    }

    /**
     * Take a screenshot and save it to the given path.
     *
     * @param destination_path Where to save the screenshot PNG.
     * @return true on success.
     */
    public async bool take_screenshot (string destination_path) {
        if (_portal_available) {
            return yield take_screenshot_portal (destination_path);
        }

        var msg = "No screenshot backend is available";
        warning (msg);
        screenshot_failed (msg);
        return false;
    }

    /**
     * Take a screenshot via the XDG Desktop Portal (libportal).
     */
    private async bool take_screenshot_portal (string destination_path) {
        try {
            var portal = new Xdp.Portal ();

            string uri = yield portal.take_screenshot (
                null,
                Xdp.ScreenshotFlags.NONE,
                null
            );

            if (uri == null || uri == "") {
                throw new IOError.FAILED ("Portal returned empty screenshot URI");
            }

            var source_file = File.new_for_uri (uri);
            var dest_file = File.new_for_path (destination_path);

            // Verify source is a regular file (not a symlink) before copying
            var source_info = yield source_file.query_info_async (
                "standard::type",
                FileQueryInfoFlags.NOFOLLOW_SYMLINKS,
                Priority.DEFAULT, null);
            if (source_info.get_file_type () != FileType.REGULAR) {
                throw new IOError.FAILED (
                    "Portal screenshot source is not a regular file");
            }

            ensure_parent_dir (destination_path);

            yield source_file.copy_async (
                dest_file,
                FileCopyFlags.OVERWRITE | FileCopyFlags.TARGET_DEFAULT_PERMS,
                Priority.DEFAULT, null, null
            );

            // Clean up portal temp file
            try {
                var del_info = yield source_file.query_info_async (
                    "standard::type",
                    FileQueryInfoFlags.NOFOLLOW_SYMLINKS,
                    Priority.DEFAULT, null);
                if (del_info.get_file_type () == FileType.REGULAR) {
                    yield source_file.delete_async (Priority.DEFAULT, null);
                }
            } catch (Error e) {
                debug ("Could not delete portal temp file: %s", e.message);
            }

            screenshot_taken (destination_path);
            return true;
        } catch (Error e) {
            var msg = "Screenshot failed (XDG Desktop Portal): %s".printf (e.message);
            warning (msg);
            screenshot_failed (msg);
        }

        return false;
    }

    /**
     * Check if the XDG Desktop Portal screenshot interface is available.
     */
    private async bool check_portal_available () {
        try {
            var connection = yield Bus.get (BusType.SESSION);
            var result = yield connection.call (
                "org.freedesktop.portal.Desktop",
                "/org/freedesktop/portal/desktop",
                "org.freedesktop.DBus.Properties",
                "Get",
                new Variant ("(ss)", "org.freedesktop.portal.Screenshot", "version"),
                new VariantType ("(v)"),
                DBusCallFlags.NONE,
                5000,
                null
            );

            Variant version_variant;
            result.get ("(v)", out version_variant);
            uint32 version = version_variant.get_uint32 ();
            debug ("Portal Screenshot version: %u", version);
            return version >= 1;
        } catch (Error e) {
            debug ("Portal Screenshot not available: %s", e.message);
            return false;
        }
    }
}
