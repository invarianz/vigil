/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Screenshot backend using the XDG Desktop Portal.
 *
 * This works on Wayland (and X11) via org.freedesktop.portal.Screenshot.
 * On portal v3+, the first non-interactive call triggers a one-time permission
 * dialog. Once the user grants permission, all subsequent calls are silent.
 *
 * Uses libportal for a clean async GObject API.
 */
public class Vigil.Services.PortalScreenshotBackend : Object, Vigil.Services.IScreenshotBackend {

    public string backend_name {
        get { return "XDG Desktop Portal"; }
    }

    public async bool is_available () {
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

    public async bool capture (string destination_path) throws Error {
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

        return true;
    }
}
