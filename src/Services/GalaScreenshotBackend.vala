/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Screenshot backend using Gala's org.gnome.Shell.Screenshot D-Bus interface.
 *
 * This works on elementary OS 7 (X11) where Gala exposes this interface
 * without access restrictions. No user confirmation is needed.
 */

[DBus (name = "org.gnome.Shell.Screenshot")]
interface GalaScreenshotProxy : Object {
    public abstract async void screenshot (
        bool include_cursor,
        bool flash,
        string filename,
        out bool success,
        out string filename_used
    ) throws DBusError, IOError;
}

public class Vigil.Services.GalaScreenshotBackend : Object, Vigil.Services.IScreenshotBackend {

    public string backend_name {
        get { return "Gala (org.gnome.Shell.Screenshot)"; }
    }

    public async bool is_available () {
        try {
            var connection = yield Bus.get (BusType.SESSION);
            var result = yield connection.call (
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                new Variant ("(s)", "org.gnome.Shell.Screenshot"),
                new VariantType ("(b)"),
                DBusCallFlags.NONE,
                5000,
                null
            );

            bool has_owner;
            result.get ("(b)", out has_owner);
            return has_owner;
        } catch (Error e) {
            debug ("Gala Screenshot not available: %s", e.message);
            return false;
        }
    }

    public async bool capture (string destination_path) throws Error {
        // Ensure the destination directory exists
        var dest_file = File.new_for_path (destination_path);
        var dest_dir = dest_file.get_parent ();
        if (dest_dir != null && !dest_dir.query_exists ()) {
            dest_dir.make_directory_with_parents (null);
        }

        var proxy = yield Bus.get_proxy<GalaScreenshotProxy> (
            BusType.SESSION,
            "org.gnome.Shell.Screenshot",
            "/org/gnome/Shell/Screenshot"
        );

        bool success;
        string filename_used;
        yield proxy.screenshot (
            false,  // don't include cursor
            false,  // don't flash (silent capture)
            destination_path,
            out success,
            out filename_used
        );

        if (!success) {
            throw new IOError.FAILED ("Gala screenshot call returned failure");
        }

        return true;
    }
}
