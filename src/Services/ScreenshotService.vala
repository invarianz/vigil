/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Screenshot service with two backends:
 *
 *  1. Gala D-Bus (org.gnome.Shell.Screenshot) — preferred inside Flatpak.
 *     Calls Screenshot(include_cursor=false, flash=false, filename) so
 *     screenshots are completely silent (no animation).
 *
 *  2. XDG Desktop Portal (libportal) — fallback if Gala D-Bus is not
 *     accessible (e.g. non-Gala compositors).
 *
 * Both are accessible from the Flatpak sandbox via talk-name permissions.
 */
public class Vigil.Services.ScreenshotService : Object {

    public signal void screenshot_taken (string file_path);
    public signal void screenshot_failed (string error_message);

    private bool _gala_available = false;
    private bool _portal_available = false;

    public string? active_backend_name {
        get {
            if (_gala_available) return "Gala D-Bus";
            if (_portal_available) return "XDG Desktop Portal";
            return null;
        }
    }

    /**
     * Initialize the service by probing available backends.
     * Prefers Gala D-Bus (silent) over Portal (shows animation).
     */
    public async void initialize () {
        _gala_available = yield check_gala_available ();
        if (_gala_available) {
            debug ("Using Gala D-Bus screenshot backend (silent)");
            return;
        }

        _portal_available = yield check_portal_available ();
        if (_portal_available) {
            debug ("Using Portal screenshot backend (Gala D-Bus not available)");
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
        if (_gala_available) {
            return yield take_screenshot_gala (destination_path);
        }

        if (_portal_available) {
            return yield take_screenshot_portal (destination_path);
        }

        var msg = "No screenshot backend is available";
        warning (msg);
        screenshot_failed (msg);
        return false;
    }

    /**
     * Take a screenshot via Gala's org.gnome.Shell.Screenshot D-Bus interface.
     * Silent — no screen flash or animation.
     *
     * Gala runs on the host and cannot write directly into Flatpak's
     * remapped data directory, so we ask it to write to /tmp and then
     * copy the result to the final destination ourselves.
     */
    private async bool take_screenshot_gala (string destination_path) {
        try {
            // Gala runs on the host and can't write into Flatpak's private
            // XDG_DATA_HOME (~/.var/app/...). Use the shared filesystem
            // grant (--filesystem=xdg-data/io.github.invarianz.vigil) at
            // ~/.local/share/io.github.invarianz.vigil — accessible to both.
            var shared_dir = Path.build_filename (
                Environment.get_home_dir (),
                ".local", "share", "io.github.invarianz.vigil"
            );
            var tmp_path = Path.build_filename (
                shared_dir, ".gala-capture-%s.png".printf (
                    GLib.get_monotonic_time ().to_string ()));

            var connection = yield Bus.get (BusType.SESSION);

            var result = yield connection.call (
                "org.gnome.Shell.Screenshot",
                "/org/gnome/Shell/Screenshot",
                "org.gnome.Shell.Screenshot",
                "Screenshot",
                new Variant ("(bbs)", false, false, tmp_path),
                new VariantType ("(bs)"),
                DBusCallFlags.NONE,
                10000,
                null
            );

            bool success;
            string filename_used;
            result.get ("(bs)", out success, out filename_used);

            if (!success) {
                throw new IOError.FAILED ("Gala Screenshot returned failure");
            }

            // Copy from host-accessible /tmp to app data directory
            var source = File.new_for_path (
                filename_used != "" ? filename_used : tmp_path);
            var dest = File.new_for_path (destination_path);

            var dest_dir = dest.get_parent ();
            if (dest_dir != null && !dest_dir.query_exists ()) {
                dest_dir.make_directory_with_parents (null);
            }

            yield source.copy_async (
                dest,
                FileCopyFlags.OVERWRITE | FileCopyFlags.TARGET_DEFAULT_PERMS,
                Priority.DEFAULT, null, null
            );

            // Clean up temp file
            try {
                yield source.delete_async (Priority.DEFAULT, null);
            } catch (Error e) {
                debug ("Could not delete Gala temp file: %s", e.message);
            }

            screenshot_taken (destination_path);
            return true;
        } catch (Error e) {
            // If Gala D-Bus fails at runtime, fall back to portal
            if (_portal_available) {
                debug ("Gala D-Bus failed (%s), falling back to portal", e.message);
                return yield take_screenshot_portal (destination_path);
            }

            var msg = "Screenshot failed (Gala D-Bus): %s".printf (e.message);
            warning (msg);
            screenshot_failed (msg);
            return false;
        }
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

            var dest_dir = dest_file.get_parent ();
            if (dest_dir != null && !dest_dir.query_exists ()) {
                dest_dir.make_directory_with_parents (null);
            }

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
     * Check if Gala's org.gnome.Shell.Screenshot D-Bus interface is reachable.
     */
    private async bool check_gala_available () {
        try {
            var connection = yield Bus.get (BusType.SESSION);
            yield connection.call (
                "org.gnome.Shell.Screenshot",
                "/org/gnome/Shell/Screenshot",
                "org.freedesktop.DBus.Peer",
                "Ping",
                null,
                null,
                DBusCallFlags.NONE,
                3000,
                null
            );
            return true;
        } catch (Error e) {
            debug ("Gala D-Bus not available: %s", e.message);
            return false;
        }
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
