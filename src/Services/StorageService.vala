/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Manages local screenshot storage.
 *
 * Screenshots are stored in XDG data directory:
 *   ~/.local/share/io.github.invarianz.vigil/screenshots/
 *
 * This service handles:
 *   - Generating unique file paths for new screenshots
 *   - Tracking which screenshots have been uploaded
 *   - Cleaning up old screenshots after successful upload
 *   - Querying pending (not yet uploaded) screenshots
 */
public class Vigil.Services.StorageService : Object {

    /** Maximum number of screenshots to retain locally. */
    public int max_local_screenshots { get; set; default = 100; }

    /** Directory where screenshots are stored. */
    public string screenshots_dir { get; private set; }

    /** Directory where upload-pending metadata is stored. */
    public string pending_dir { get; private set; }

    private string _base_dir;

    /**
     * Create a StorageService.
     *
     * @param base_dir Optional base directory override. If null, uses
     *                 the XDG data directory. Pass explicitly for testing.
     */
    public StorageService (string? base_dir = null) {
        if (base_dir != null) {
            _base_dir = base_dir;
        } else {
            _base_dir = Path.build_filename (
                Environment.get_user_data_dir (),
                "io.github.invarianz.vigil"
            );
        }
        screenshots_dir = Path.build_filename (_base_dir, "screenshots");
        pending_dir = Path.build_filename (_base_dir, "pending");
    }

    /**
     * Ensure storage directories exist.
     */
    public void initialize () throws Error {
        var dirs = new string[] { _base_dir, screenshots_dir, pending_dir };
        foreach (var dir_path in dirs) {
            var dir = File.new_for_path (dir_path);
            if (!dir.query_exists ()) {
                dir.make_directory_with_parents (null);
            }
        }
    }

    /**
     * Generate a unique file path for a new screenshot.
     *
     * Format: screenshots/vigil_20250615_143052_a3f2.png
     */
    public string generate_screenshot_path () {
        var now = new DateTime.now_local ();
        var timestamp = now.format ("%Y%m%d_%H%M%S");
        var random_suffix = "%04x".printf (Random.next_int () % 0xFFFF);
        var filename = "vigil_%s_%s.png".printf (timestamp, random_suffix);
        return Path.build_filename (screenshots_dir, filename);
    }

    /**
     * Mark a screenshot as pending upload by creating a marker file.
     */
    public void mark_pending (string screenshot_path) throws Error {
        var basename = Path.get_basename (screenshot_path);
        var marker_path = Path.build_filename (pending_dir, basename + ".pending");
        var marker = File.new_for_path (marker_path);

        // Write the full path and timestamp to the marker
        var now = new DateTime.now_local ();
        var content = "%s\n%s\n".printf (screenshot_path, now.format_iso8601 ());
        marker.replace_contents (
            content.data,
            null,
            false,
            FileCreateFlags.REPLACE_DESTINATION,
            null,
            null
        );
    }

    /**
     * Mark a screenshot as successfully uploaded (remove pending marker).
     */
    public void mark_uploaded (string screenshot_path) {
        var basename = Path.get_basename (screenshot_path);
        var marker_path = Path.build_filename (pending_dir, basename + ".pending");
        var marker = File.new_for_path (marker_path);

        try {
            if (marker.query_exists ()) {
                marker.delete ();
            }
        } catch (Error e) {
            warning ("Failed to remove pending marker: %s", e.message);
        }
    }

    /**
     * Get all screenshots that are pending upload.
     *
     * @return Array of pending screenshot entries.
     */
    public GenericArray<PendingScreenshot?> get_pending_screenshots () {
        var pending = new GenericArray<PendingScreenshot?> ();

        try {
            var dir = File.new_for_path (pending_dir);
            if (!dir.query_exists ()) {
                return pending;
            }

            var enumerator = dir.enumerate_children (
                "standard::name",
                FileQueryInfoFlags.NONE,
                null
            );

            FileInfo? info;
            while ((info = enumerator.next_file (null)) != null) {
                var name = info.get_name ();
                if (!name.has_suffix (".pending")) {
                    continue;
                }

                var marker_path = Path.build_filename (pending_dir, name);
                var marker = File.new_for_path (marker_path);

                uint8[] contents;
                marker.load_contents (null, out contents, null);
                var lines = ((string) contents).split ("\n");

                if (lines.length >= 2) {
                    var screenshot_file = File.new_for_path (lines[0]);
                    if (screenshot_file.query_exists ()) {
                        var item = PendingScreenshot ();
                        item.file_path = lines[0];
                        item.capture_time = new DateTime.from_iso8601 (lines[1], null);
                        pending.add (item);
                    } else {
                        // Screenshot file was deleted; clean up marker
                        try {
                            marker.delete ();
                        } catch (Error del_err) {
                            warning ("Failed to delete orphan marker: %s", del_err.message);
                        }
                    }
                }
            }
        } catch (Error e) {
            warning ("Error reading pending screenshots: %s", e.message);
        }

        return pending;
    }

    /**
     * Delete old screenshots, keeping at most max_local_screenshots.
     *
     * Only deletes screenshots that have been uploaded (no pending marker).
     *
     * @return Number of screenshots deleted.
     */
    public int cleanup_old_screenshots () {
        int deleted = 0;

        try {
            var dir = File.new_for_path (screenshots_dir);
            if (!dir.query_exists ()) {
                return 0;
            }

            var enumerator = dir.enumerate_children (
                "standard::name,time::modified",
                FileQueryInfoFlags.NONE,
                null
            );

            // Collect all screenshot files with their modification time
            var screenshot_files = new GenericArray<ScreenshotFile?> ();
            FileInfo? info;
            while ((info = enumerator.next_file (null)) != null) {
                var name = info.get_name ();
                if (!name.has_suffix (".png")) {
                    continue;
                }

                var file_path = Path.build_filename (screenshots_dir, name);
                var item = ScreenshotFile ();
                item.path = file_path;
                item.modified = info.get_modification_date_time ();
                screenshot_files.add (item);
            }

            // Sort by modification time, oldest first
            screenshot_files.sort ((a, b) => {
                return a.modified.compare (b.modified);
            });

            // Delete excess uploaded screenshots (oldest first)
            int excess = (int) screenshot_files.length - max_local_screenshots;
            for (int i = 0; i < excess && i < screenshot_files.length; i++) {
                var file_path = screenshot_files[i].path;
                var marker_path = Path.build_filename (
                    pending_dir,
                    Path.get_basename (file_path) + ".pending"
                );

                // Only delete if already uploaded (no pending marker)
                if (!File.new_for_path (marker_path).query_exists ()) {
                    try {
                        File.new_for_path (file_path).delete ();
                        deleted++;
                    } catch (Error e) {
                        warning ("Failed to delete %s: %s", file_path, e.message);
                    }
                }
            }
        } catch (Error e) {
            warning ("Cleanup error: %s", e.message);
        }

        return deleted;
    }
}

public struct Vigil.Services.PendingScreenshot {
    public string file_path;
    public DateTime? capture_time;
}

public struct Vigil.Services.ScreenshotFile {
    public string path;
    public DateTime modified;
}
