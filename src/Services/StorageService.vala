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

    /** Cached count of pending screenshots. Use instead of scanning the directory. */
    public int pending_count { get; private set; default = -1; }

    /** Lifetime capture counter (monotonically increasing, persisted to disk). */
    public int64 lifetime_captures { get; private set; default = 0; }

    /** Whether the capture counter file failed HMAC verification on load. */
    public bool capture_counter_tampered { get; private set; default = false; }

    /**
     * HMAC key for marker file integrity.
     *
     * When set, pending markers include an HMAC-SHA256 tag computed over
     * the marker content (path, timestamp, hash). This prevents an
     * attacker from modifying the stored hash in a marker to match a
     * tampered screenshot without knowing the HMAC key.
     *
     * Derived from the E2EE pickle key at daemon startup.
     */
    public string hmac_key { get; set; default = ""; }

    private string _base_dir;
    private int _screenshot_file_count = -1;

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
            // Screenshots may contain sensitive content -- restrict access
            SecurityUtils.ensure_secure_directory (dir_path);
        }

        load_capture_counter ();
    }

    /**
     * Generate a unique file path for a new screenshot.
     *
     * Format: screenshots/vigil_20250615_143052_a3f2.png
     */
    public string generate_screenshot_path () {
        var now = new DateTime.now_local ();
        var timestamp = now.format ("%Y%m%d_%H%M%S");
        var random_suffix = GLib.Uuid.string_random ().substring (0, 4);
        var filename = "vigil_%s_%s.png".printf (timestamp, random_suffix);
        return Path.build_filename (screenshots_dir, filename);
    }

    /**
     * Mark a screenshot as pending upload by creating a marker file.
     *
     * Computes a SHA-256 hash of the file at capture time so integrity
     * can be verified before upload (detects post-capture tampering).
     */
    public void mark_pending (string screenshot_path) throws Error {
        // Validate that the path is within our screenshots directory
        // to prevent directory traversal attacks.
        var abs_path = File.new_for_path (screenshot_path).get_path ();
        var abs_screenshots_dir = File.new_for_path (screenshots_dir).get_path ();
        if (abs_path == null || abs_screenshots_dir == null ||
            !abs_path.has_prefix (abs_screenshots_dir + "/")) {
            throw new IOError.INVALID_ARGUMENT (
                "Screenshot path is outside the screenshots directory");
        }

        var basename = Path.get_basename (screenshot_path);
        var marker_path = Path.build_filename (pending_dir, basename + ".pending");
        var marker = File.new_for_path (marker_path);

        // Compute SHA-256 hash of the screenshot for integrity verification
        string file_hash = "";
        try {
            // Validate file size to prevent DoS from maliciously large files
            var file_info = File.new_for_path (screenshot_path).query_info (
                "standard::size,standard::type",
                FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
            if (file_info.get_file_type () != FileType.REGULAR) {
                throw new IOError.INVALID_ARGUMENT (
                    "Screenshot is not a regular file");
            }
            if (file_info.get_size () > SecurityUtils.MAX_SCREENSHOT_SIZE) {
                throw new IOError.INVALID_ARGUMENT (
                    "Screenshot exceeds maximum size (%lld bytes)".printf (
                        SecurityUtils.MAX_SCREENSHOT_SIZE));
            }

            uint8[] file_data;
            FileUtils.get_data (screenshot_path, out file_data);
            file_hash = SecurityUtils.compute_sha256_hex (file_data);
        } catch (Error e) {
            // File may not exist yet in tests; not fatal -- integrity
            // check will treat empty hash as "no baseline" and accept.
            debug ("Could not hash screenshot for integrity: %s", e.message);
        }

        // Write the full path, timestamp, and hash to the marker.
        // If an HMAC key is set, append an HMAC-SHA256 tag as a 4th line
        // to authenticate the marker content (prevents hash substitution).
        var now = new DateTime.now_local ();
        var core_content = "%s\n%s\n%s".printf (screenshot_path, now.format_iso8601 (), file_hash);
        var content = build_hmac_content (core_content);
        marker.replace_contents (
            content.data,
            null,
            false,
            FileCreateFlags.REPLACE_DESTINATION,
            null,
            null
        );

        if (pending_count >= 0) {
            pending_count++;
        }

        lifetime_captures++;
        persist_capture_counter ();
    }

    /**
     * Verify integrity using pre-loaded file data (avoids redundant re-read).
     *
     * Use this in the upload pipeline where the file is already in memory
     * for encryption, saving a 2MB file read + SHA-256 recomputation.
     *
     * @param screenshot_path Path used to locate the marker file.
     * @param file_data Pre-loaded file bytes.
     * @return true if the data matches the capture-time hash.
     */
    public bool verify_screenshot_integrity_from_data (string screenshot_path, uint8[] file_data) {
        var basename = Path.get_basename (screenshot_path);
        var marker_path = Path.build_filename (pending_dir, basename + ".pending");

        try {
            string marker_contents;
            FileUtils.get_contents (marker_path, out marker_contents);
            var lines = marker_contents.split ("\n");

            // Need at least 3 lines: path, timestamp, hash
            if (lines.length < 3 || lines[2].strip () == "") {
                return true; // Legacy marker without hash -- accept
            }

            var stored_hash = lines[2].strip ();

            // Verify HMAC if key is set and marker has a 4th line
            if (hmac_key != "" && lines.length >= 4 && lines[3].strip () != "") {
                var core_content = "%s\n%s\n%s".printf (lines[0], lines[1], stored_hash);
                var expected_hmac = compute_hmac (core_content);
                var stored_hmac = lines[3].strip ();
                if (expected_hmac != stored_hmac) {
                    debug ("Marker HMAC mismatch for %s (marker was tampered)", screenshot_path);
                    return false;
                }
            }

            var current_hash = SecurityUtils.compute_sha256_hex (file_data);

            return current_hash == stored_hash;
        } catch (Error e) {
            warning ("Failed to verify screenshot integrity: %s", e.message);
            return false;
        }
    }

    /**
     * Mark a screenshot as successfully uploaded (remove pending marker).
     */
    public void mark_uploaded (string screenshot_path) {
        var basename = Path.get_basename (screenshot_path);
        var marker_path = Path.build_filename (pending_dir, basename + ".pending");

        // Delete marker directly -- skip query_exists to avoid redundant stat()
        try {
            File.new_for_path (marker_path).delete ();
        } catch (Error e) {
            // Marker may already be gone; not an error
        }

        // Delete the screenshot file -- it's been delivered, no need to keep it
        try {
            File.new_for_path (screenshot_path).delete ();
            // Keep _screenshot_file_count in sync to avoid unnecessary dir scans
            if (_screenshot_file_count > 0) {
                _screenshot_file_count--;
            }
        } catch (Error e) {
            // File may already be gone; not an error
        }

        if (pending_count > 0) {
            pending_count--;
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
                    if (FileUtils.test (lines[0], FileTest.EXISTS)) {
                        var item = PendingScreenshot ();
                        item.file_path = lines[0];
                        item.capture_time = new DateTime.from_iso8601 (lines[1], null);
                        pending.add (item);
                    } else {
                        // Screenshot file was deleted; clean up orphan marker
                        try {
                            marker.delete ();
                        } catch (Error del_err) {
                            // Ignore cleanup failures
                        }
                    }
                }
            }
        } catch (Error e) {
            warning ("Error reading pending screenshots: %s", e.message);
        }

        // Sync the cached count whenever a full scan is performed
        pending_count = (int) pending.length;
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

        // Fast path: if we know the count is below the limit, skip the expensive scan
        if (_screenshot_file_count >= 0 && _screenshot_file_count <= max_local_screenshots) {
            return 0;
        }

        try {
            var dir = File.new_for_path (screenshots_dir);
            if (!dir.query_exists ()) {
                return 0;
            }

            var enumerator = dir.enumerate_children (
                "standard::name,standard::type,time::modified",
                FileQueryInfoFlags.NOFOLLOW_SYMLINKS,
                null
            );

            // Collect all regular screenshot files with their modification time.
            // Use NOFOLLOW_SYMLINKS to prevent symlink attacks during cleanup.
            var screenshot_files = new GenericArray<ScreenshotFile?> ();
            FileInfo? info;
            while ((info = enumerator.next_file (null)) != null) {
                var name = info.get_name ();
                if (!name.has_suffix (".png")) {
                    continue;
                }

                // Skip non-regular files (symlinks, directories)
                if (info.get_file_type () != FileType.REGULAR) {
                    continue;
                }

                var file_path = Path.build_filename (screenshots_dir, name);
                var item = ScreenshotFile ();
                item.path = file_path;
                item.modified = info.get_modification_date_time ();
                screenshot_files.add (item);
            }

            _screenshot_file_count = (int) screenshot_files.length;

            // If we're within the limit, no work to do
            if (_screenshot_file_count <= max_local_screenshots) {
                return 0;
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
                if (!FileUtils.test (marker_path, FileTest.EXISTS)) {
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

        if (_screenshot_file_count >= 0) {
            _screenshot_file_count -= deleted;
        }
        return deleted;
    }
    /**
     * Load the lifetime capture counter from disk.
     *
     * File format: two lines -- "{count}\n{hmac}\n".
     * If the file doesn't exist (fresh install), starts at 0 with no tamper.
     * If the HMAC is invalid, sets capture_counter_tampered but still loads
     * the count so the counter continues from where it was.
     */
    private void load_capture_counter () {
        var path = Path.build_filename (_base_dir, "capture_counter");

        if (!FileUtils.test (path, FileTest.EXISTS)) {
            return;
        }

        try {
            string contents;
            FileUtils.get_contents (path, out contents);
            var lines = contents.split ("\n");

            if (lines.length >= 1 && lines[0].strip () != "") {
                lifetime_captures = int64.parse (lines[0].strip ());
            }

            // Verify HMAC if key is set and file has an HMAC line
            if (hmac_key != "" && lines.length >= 2 && lines[1].strip () != "") {
                var expected_hmac = compute_hmac (lines[0].strip ());
                var stored_hmac = lines[1].strip ();
                if (expected_hmac != stored_hmac) {
                    capture_counter_tampered = true;
                }
            }
        } catch (Error e) {
            warning ("Failed to load capture counter: %s", e.message);
        }
    }

    /**
     * Persist the lifetime capture counter to disk.
     *
     * Writes "{count}\n{hmac}\n" if an HMAC key is set, or just
     * "{count}\n" otherwise. Uses FileUtils.set_contents() which
     * does atomic write-to-temp-then-rename.
     */
    private void persist_capture_counter () {
        var path = Path.build_filename (_base_dir, "capture_counter");
        var count_str = lifetime_captures.to_string ();
        var content = build_hmac_content (count_str);

        try {
            FileUtils.set_contents (path, content);
            FileUtils.chmod (path, 0600);
        } catch (Error e) {
            warning ("Failed to persist capture counter: %s", e.message);
        }
    }

    /**
     * Build content string with optional HMAC line appended.
     *
     * Returns "{data}\n{hmac}\n" if HMAC key is set, or "{data}\n" otherwise.
     */
    private string build_hmac_content (string data) {
        if (hmac_key != "") {
            return "%s\n%s\n".printf (data, compute_hmac (data));
        }
        return "%s\n".printf (data);
    }

    /**
     * Compute HMAC-SHA256 of the given data using the stored HMAC key.
     *
     * Returns a hex-encoded HMAC digest.
     */
    private string compute_hmac (string data) {
        var hmac = new Hmac (ChecksumType.SHA256, hmac_key.data);
        hmac.update (data.data);
        return hmac.get_string ();
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
