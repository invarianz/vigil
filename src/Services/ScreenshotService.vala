/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Screenshot service using the XDG Desktop Portal.
 *
 * This app is Flatpak-only; Portal is the sole screenshot mechanism.
 * Uses libportal for a clean async GObject API.
 */
public class Vigil.Services.ScreenshotService : Object {

    public signal void screenshot_taken (string file_path);
    public signal void screenshot_failed (string error_message);

    private bool _portal_available = false;

    public string? active_backend_name {
        get {
            return _portal_available ? "XDG Desktop Portal" : null;
        }
    }

    /**
     * Initialize the service by checking Portal availability.
     */
    public async void initialize () {
        _portal_available = yield check_portal_available ();
        if (_portal_available) {
            debug ("Using Portal screenshot backend");
            return;
        }

        warning ("Portal screenshot backend not available!");
    }

    /**
     * Take a screenshot and save it to the given path.
     *
     * @param destination_path Where to save the screenshot PNG.
     * @return true on success.
     */
    public async bool take_screenshot (string destination_path) {
        if (!_portal_available) {
            var msg = "No screenshot backend is available";
            warning (msg);
            screenshot_failed (msg);
            return false;
        }

        try {
            var portal = new Xdp.Portal ();

            // Take a non-interactive screenshot (NONE = no interactive dialog)
            // On first call the portal may show a one-time "Allow" dialog.
            // After the user grants permission, subsequent calls are silent.
            string uri = yield portal.take_screenshot (
                null,
                Xdp.ScreenshotFlags.NONE,
                null
            );

            if (uri == null || uri == "") {
                throw new IOError.FAILED ("Portal returned empty screenshot URI");
            }

            // The portal returns a file:// URI; copy to our destination
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

            // Ensure the destination directory exists
            var dest_dir = dest_file.get_parent ();
            if (dest_dir != null && !dest_dir.query_exists ()) {
                dest_dir.make_directory_with_parents (null);
            }

            // TARGET_DEFAULT_PERMS ensures destination gets correct ownership
            yield source_file.copy_async (
                dest_file,
                FileCopyFlags.OVERWRITE | FileCopyFlags.TARGET_DEFAULT_PERMS,
                Priority.DEFAULT,
                null,
                null
            );

            // Clean up the temporary file created by the portal.
            // Re-verify it's still a regular file before deleting to prevent
            // symlink-based deletion attacks.
            try {
                var del_info = yield source_file.query_info_async (
                    "standard::type",
                    FileQueryInfoFlags.NOFOLLOW_SYMLINKS,
                    Priority.DEFAULT, null);
                if (del_info.get_file_type () == FileType.REGULAR) {
                    yield source_file.delete_async (Priority.DEFAULT, null);
                }
            } catch (Error e) {
                // Not critical if cleanup fails
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
