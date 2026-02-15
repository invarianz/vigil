/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for the StorageService.
 *
 * Uses a temporary directory to isolate test file operations
 * from any real user data.
 */

string test_dir;

void setup_test_dir () {
    test_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-test-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
    // Override XDG_DATA_HOME so StorageService uses our temp dir
    Environment.set_variable ("XDG_DATA_HOME", test_dir, true);
}

void teardown_test_dir () {
    // Clean up test directory recursively
    delete_directory_recursive (test_dir);
}

void delete_directory_recursive (string path) {
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

void test_storage_initialize_creates_dirs () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    assert_true (FileUtils.test (service.screenshots_dir, FileTest.IS_DIR));
    assert_true (FileUtils.test (service.pending_dir, FileTest.IS_DIR));

    teardown_test_dir ();
}

void test_storage_generate_screenshot_path () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();

    var path = service.generate_screenshot_path ();

    // Should be in the screenshots directory
    assert_true (path.has_prefix (service.screenshots_dir));
    // Should end with .png
    assert_true (path.has_suffix (".png"));
    // Should contain "vigil_"
    assert_true (Path.get_basename (path).has_prefix ("vigil_"));

    teardown_test_dir ();
}

void test_storage_generate_unique_paths () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();

    var path1 = service.generate_screenshot_path ();
    var path2 = service.generate_screenshot_path ();

    // Paths should be different (random suffix)
    assert_true (path1 != path2);

    teardown_test_dir ();
}

void test_storage_mark_pending_creates_marker () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    var screenshot_path = Path.build_filename (service.screenshots_dir, "test.png");

    try {
        service.mark_pending (screenshot_path);
    } catch (Error e) {
        assert_not_reached ();
    }

    var marker_path = Path.build_filename (service.pending_dir, "test.png.pending");
    assert_true (FileUtils.test (marker_path, FileTest.EXISTS));

    // Marker should contain the screenshot path
    try {
        uint8[] contents;
        File.new_for_path (marker_path).load_contents (null, out contents, null);
        var text = (string) contents;
        assert_true (text.contains (screenshot_path));
    } catch (Error e) {
        assert_not_reached ();
    }

    teardown_test_dir ();
}

void test_storage_mark_uploaded_removes_marker () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    var screenshot_path = Path.build_filename (service.screenshots_dir, "test.png");

    try {
        service.mark_pending (screenshot_path);
    } catch (Error e) {
        assert_not_reached ();
    }

    service.mark_uploaded (screenshot_path);

    var marker_path = Path.build_filename (service.pending_dir, "test.png.pending");
    assert_true (!FileUtils.test (marker_path, FileTest.EXISTS));

    teardown_test_dir ();
}

void test_storage_get_pending_screenshots () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    // Create some fake screenshot files
    var path1 = Path.build_filename (service.screenshots_dir, "shot1.png");
    var path2 = Path.build_filename (service.screenshots_dir, "shot2.png");

    try {
        FileUtils.set_contents (path1, "fake png 1");
        FileUtils.set_contents (path2, "fake png 2");
        service.mark_pending (path1);
        service.mark_pending (path2);
    } catch (Error e) {
        assert_not_reached ();
    }

    var pending = service.get_pending_screenshots ();
    assert_true (pending.length == 2);

    teardown_test_dir ();
}

void test_storage_get_pending_ignores_missing_files () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    // Create a pending marker for a file that doesn't exist
    var ghost_path = Path.build_filename (service.screenshots_dir, "ghost.png");
    try {
        service.mark_pending (ghost_path);
    } catch (Error e) {
        assert_not_reached ();
    }

    // Should return empty because the screenshot file doesn't exist
    var pending = service.get_pending_screenshots ();
    assert_true (pending.length == 0);

    teardown_test_dir ();
}

void test_storage_cleanup_respects_max () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    service.max_local_screenshots = 3;
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    // Create 5 screenshot files (all uploaded, no pending markers)
    for (int i = 0; i < 5; i++) {
        var path = Path.build_filename (service.screenshots_dir, "shot_%d.png".printf (i));
        try {
            FileUtils.set_contents (path, "fake png %d".printf (i));
        } catch (Error e) {
            assert_not_reached ();
        }
    }

    int deleted = service.cleanup_old_screenshots ();
    assert_true (deleted == 2); // 5 - 3 = 2

    teardown_test_dir ();
}

void test_storage_cleanup_preserves_pending () {
    setup_test_dir ();

    var service = new Vigil.Services.StorageService ();
    service.max_local_screenshots = 1;
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    // Create 3 files, all pending upload
    for (int i = 0; i < 3; i++) {
        var path = Path.build_filename (service.screenshots_dir, "pending_%d.png".printf (i));
        try {
            FileUtils.set_contents (path, "fake png %d".printf (i));
            service.mark_pending (path);
        } catch (Error e) {
            assert_not_reached ();
        }
    }

    int deleted = service.cleanup_old_screenshots ();
    // Should not delete any because all are pending
    assert_true (deleted == 0);

    teardown_test_dir ();
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/storage/initialize", test_storage_initialize_creates_dirs);
    Test.add_func ("/storage/generate_path", test_storage_generate_screenshot_path);
    Test.add_func ("/storage/unique_paths", test_storage_generate_unique_paths);
    Test.add_func ("/storage/mark_pending", test_storage_mark_pending_creates_marker);
    Test.add_func ("/storage/mark_uploaded", test_storage_mark_uploaded_removes_marker);
    Test.add_func ("/storage/get_pending", test_storage_get_pending_screenshots);
    Test.add_func ("/storage/get_pending_ignores_missing", test_storage_get_pending_ignores_missing_files);
    Test.add_func ("/storage/cleanup_max", test_storage_cleanup_respects_max);
    Test.add_func ("/storage/cleanup_preserves_pending", test_storage_cleanup_preserves_pending);

    return Test.run ();
}
