/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for the StorageService.
 *
 * Uses a temporary directory to isolate test file operations
 * from any real user data. Passes the base_dir explicitly to
 * StorageService to avoid GLib's cached XDG_DATA_HOME.
 */

string test_base_dir;

void setup_test_dir () {
    test_base_dir = TestUtils.make_test_dir ();
}

void teardown_test_dir () {
    TestUtils.delete_directory_recursive (test_base_dir);
}

Vigil.Services.StorageService create_test_service () {
    return new Vigil.Services.StorageService (test_base_dir);
}

void test_storage_initialize_creates_dirs () {
    setup_test_dir ();

    var service = create_test_service ();
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

    var service = create_test_service ();

    var path = service.generate_screenshot_path ();

    assert_true (path.has_prefix (service.screenshots_dir));
    assert_true (path.has_suffix (".png"));
    assert_true (Path.get_basename (path).has_prefix ("vigil_"));

    teardown_test_dir ();
}

void test_storage_generate_unique_paths () {
    setup_test_dir ();

    var service = create_test_service ();

    var path1 = service.generate_screenshot_path ();
    var path2 = service.generate_screenshot_path ();

    assert_true (path1 != path2);

    teardown_test_dir ();
}

void test_storage_mark_pending_creates_marker () {
    setup_test_dir ();

    var service = create_test_service ();
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

    var service = create_test_service ();
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

    var service = create_test_service ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

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

    var service = create_test_service ();
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

    var pending = service.get_pending_screenshots ();
    assert_true (pending.length == 0);

    teardown_test_dir ();
}

void test_storage_cleanup_respects_max () {
    setup_test_dir ();

    var service = create_test_service ();
    service.max_local_screenshots = 3;
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    for (int i = 0; i < 5; i++) {
        var path = Path.build_filename (service.screenshots_dir, "shot_%d.png".printf (i));
        try {
            FileUtils.set_contents (path, "fake png %d".printf (i));
        } catch (Error e) {
            assert_not_reached ();
        }
    }

    int deleted = service.cleanup_old_screenshots ();
    assert_true (deleted == 2);

    teardown_test_dir ();
}

void test_storage_cleanup_preserves_pending () {
    setup_test_dir ();

    var service = create_test_service ();
    service.max_local_screenshots = 1;
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

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
    assert_true (deleted == 0);

    teardown_test_dir ();
}

void test_storage_directory_permissions () {
    setup_test_dir ();
    var svc = new Vigil.Services.StorageService (test_base_dir);
    try { svc.initialize (); } catch (Error e) { assert_not_reached (); }

    // All storage directories should be 0700 (owner-only)
    var dirs = new string[] {
        svc.screenshots_dir,
        svc.pending_dir
    };
    foreach (var dir_path in dirs) {
        try {
            var file = File.new_for_path (dir_path);
            var info = file.query_info ("unix::mode", FileQueryInfoFlags.NONE, null);
            var mode = info.get_attribute_uint32 ("unix::mode") & 0777;
            assert_true (mode == 0700);
        } catch (Error e) {
            assert_not_reached ();
        }
    }

    teardown_test_dir ();
}

void test_storage_hmac_marker_integrity () {
    setup_test_dir ();

    var service = create_test_service ();
    service.hmac_key = "test-hmac-key-1234";
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    var screenshot_path = Path.build_filename (service.screenshots_dir, "hmac_test.png");
    var fake_data = "fake png content for hmac test";
    try {
        FileUtils.set_contents (screenshot_path, fake_data);
        service.mark_pending (screenshot_path);
    } catch (Error e) {
        assert_not_reached ();
    }

    // Read the marker and verify it has 4 lines (path, timestamp, hash, hmac)
    var marker_path = Path.build_filename (service.pending_dir, "hmac_test.png.pending");
    try {
        string contents;
        FileUtils.get_contents (marker_path, out contents);
        var lines = contents.split ("\n");
        // Should have at least 4 non-empty lines: path, timestamp, hash, hmac
        int non_empty = 0;
        foreach (var line in lines) {
            if (line.strip () != "") non_empty++;
        }
        assert_true (non_empty >= 4);
    } catch (Error e) {
        assert_not_reached ();
    }

    // Verify integrity passes with correct data
    uint8[] file_data;
    try {
        FileUtils.get_data (screenshot_path, out file_data);
    } catch (Error e) {
        assert_not_reached ();
    }
    assert_true (service.verify_screenshot_integrity_from_data (screenshot_path, file_data));

    teardown_test_dir ();
}

void test_storage_hmac_detects_marker_tamper () {
    setup_test_dir ();

    var service = create_test_service ();
    service.hmac_key = "test-hmac-key-5678";
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    var screenshot_path = Path.build_filename (service.screenshots_dir, "tamper_test.png");
    try {
        FileUtils.set_contents (screenshot_path, "original content");
        service.mark_pending (screenshot_path);
    } catch (Error e) {
        assert_not_reached ();
    }

    // Now tamper with the marker: change the stored hash
    var marker_path = Path.build_filename (service.pending_dir, "tamper_test.png.pending");
    try {
        string contents;
        FileUtils.get_contents (marker_path, out contents);
        var lines = contents.split ("\n");
        // Replace hash line with a fake hash
        lines[2] = "0000000000000000000000000000000000000000000000000000000000000000";
        FileUtils.set_contents (marker_path, string.joinv ("\n", lines));
    } catch (Error e) {
        assert_not_reached ();
    }

    // Verification should fail because HMAC won't match
    uint8[] file_data;
    try {
        FileUtils.get_data (screenshot_path, out file_data);
    } catch (Error e) {
        assert_not_reached ();
    }
    assert_false (service.verify_screenshot_integrity_from_data (screenshot_path, file_data));

    teardown_test_dir ();
}

void test_storage_path_validation_rejects_outside () {
    setup_test_dir ();

    var service = create_test_service ();
    try {
        service.initialize ();
    } catch (Error e) {
        assert_not_reached ();
    }

    // Try to mark a file outside the screenshots directory
    bool threw = false;
    try {
        service.mark_pending ("/tmp/evil_screenshot.png");
    } catch (Error e) {
        threw = true;
    }
    assert_true (threw);

    teardown_test_dir ();
}

void test_storage_pickle_key_file_roundtrip () {
    // Test save/load pickle key static methods
    var test_key = "test-pickle-key-12345";
    Vigil.Services.EncryptionService.save_pickle_key_to_file (test_key);

    var loaded = Vigil.Services.EncryptionService.load_pickle_key_from_file ();
    assert_true (loaded == test_key);

    // Clean up
    var path = Path.build_filename (
        Environment.get_user_data_dir (),
        "io.github.invarianz.vigil", "crypto", "pickle_key");
    FileUtils.remove (path);
}

void test_storage_hmac_key_derivation () {
    var key1 = Vigil.Services.EncryptionService.derive_hmac_key ("password1");
    var key2 = Vigil.Services.EncryptionService.derive_hmac_key ("password2");
    var key3 = Vigil.Services.EncryptionService.derive_hmac_key ("password1");

    // Different passwords produce different keys
    assert_true (key1 != key2);
    // Same password produces same key
    assert_true (key1 == key3);
    // Key is a SHA-256 hex string (64 chars)
    assert_true (key1.length == 64);
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
    Test.add_func ("/storage/directory_permissions", test_storage_directory_permissions);
    Test.add_func ("/storage/hmac_marker_integrity", test_storage_hmac_marker_integrity);
    Test.add_func ("/storage/hmac_detects_marker_tamper", test_storage_hmac_detects_marker_tamper);
    Test.add_func ("/storage/path_validation_rejects_outside", test_storage_path_validation_rejects_outside);
    Test.add_func ("/storage/pickle_key_roundtrip", test_storage_pickle_key_file_roundtrip);
    Test.add_func ("/storage/hmac_key_derivation", test_storage_hmac_key_derivation);

    return Test.run ();
}
