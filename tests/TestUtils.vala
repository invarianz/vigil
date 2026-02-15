/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Shared test utilities used across multiple test suites.
 */
namespace TestUtils {

    /**
     * Recursively delete a directory and all its contents.
     */
    public void delete_directory_recursive (string path) {
        try {
            var dir = Dir.open (path);
            string? name;
            while ((name = dir.read_name ()) != null) {
                var child_path = Path.build_filename (path, name);
                if (FileUtils.test (child_path, FileTest.IS_DIR)) {
                    delete_directory_recursive (child_path);
                } else {
                    FileUtils.remove (child_path);
                }
            }
            DirUtils.remove (path);
        } catch (Error e) {
            // Ignore cleanup errors in tests
        }
    }

    /**
     * Create a unique temporary directory for test isolation.
     */
    public string make_test_dir () {
        return Path.build_filename (
            Environment.get_tmp_dir (),
            "vigil-test-%s".printf (
                GLib.Uuid.string_random ().substring (0, 8)
            )
        );
    }
}
