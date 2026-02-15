/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Tests for TamperDetectionService.
 *
 * Uses temp directories and files to simulate autostart entries.
 * GSettings and systemd checks are tested for non-crash behavior
 * since we can't set up real schemas in unit tests.
 */

static string test_dir;

void setup_test_dir () {
    test_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-tamper-test-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
    DirUtils.create_with_parents (test_dir, 0755);
}

void cleanup_test_dir () {
    delete_directory_recursive (test_dir);
}

void delete_directory_recursive (string path) {
    try {
        var dir = Dir.open (path);
        string? name;
        while ((name = dir.read_name ()) != null) {
            var child = Path.build_filename (path, name);
            if (FileUtils.test (child, FileTest.IS_DIR)) {
                delete_directory_recursive (child);
            } else {
                FileUtils.unlink (child);
            }
        }
        DirUtils.remove (path);
    } catch (Error e) {
        // best-effort cleanup
    }
}

void test_start_stop_lifecycle () {
    var svc = new Vigil.Services.TamperDetectionService ();
    // Point to non-existent paths so checks run but don't crash
    svc.autostart_desktop_path = "/tmp/nonexistent-vigil-test.desktop";
    svc.daemon_binary_path = "";
    svc.expected_binary_hash = "";

    assert_false (svc.is_running);
    svc.start ();
    assert_true (svc.is_running);
    svc.stop ();
    assert_false (svc.is_running);
}

void test_double_start_idempotent () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = "/tmp/nonexistent-vigil-test.desktop";
    svc.start ();
    svc.start ();
    assert_true (svc.is_running);
    svc.stop ();
}

void test_double_stop_idempotent () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = "/tmp/nonexistent-vigil-test.desktop";
    svc.start ();
    svc.stop ();
    svc.stop ();
    assert_false (svc.is_running);
}

void test_detects_missing_autostart () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = "/tmp/definitely-does-not-exist.desktop";

    string? detected_type = null;
    svc.tamper_detected.connect ((event_type, details) => {
        detected_type = event_type;
    });

    svc.check_autostart_entry ();
    assert_true (detected_type == "autostart_missing");
}

void test_detects_modified_autostart () {
    setup_test_dir ();

    var desktop_path = Path.build_filename (test_dir, "autostart.desktop");
    try {
        FileUtils.set_contents (desktop_path,
            "[Desktop Entry]\nExec=some-other-binary\n");
    } catch (Error e) {
        Test.fail_printf ("Could not write test file: %s", e.message);
        cleanup_test_dir ();
        return;
    }

    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = desktop_path;

    string? detected_type = null;
    svc.tamper_detected.connect ((event_type, details) => {
        detected_type = event_type;
    });

    svc.check_autostart_entry ();
    assert_true (detected_type == "autostart_modified");

    cleanup_test_dir ();
}

void test_valid_autostart_no_tamper () {
    setup_test_dir ();

    var desktop_path = Path.build_filename (test_dir, "autostart.desktop");
    try {
        FileUtils.set_contents (desktop_path,
            "[Desktop Entry]\nExec=io.github.invarianz.vigil.daemon\n");
    } catch (Error e) {
        Test.fail_printf ("Could not write test file: %s", e.message);
        cleanup_test_dir ();
        return;
    }

    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = desktop_path;

    bool tamper_found = false;
    svc.tamper_detected.connect ((event_type, details) => {
        if (event_type.has_prefix ("autostart")) {
            tamper_found = true;
        }
    });

    svc.check_autostart_entry ();
    assert_false (tamper_found);

    cleanup_test_dir ();
}

void test_binary_integrity_skip_when_no_config () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.daemon_binary_path = "";
    svc.expected_binary_hash = "";

    bool tamper_found = false;
    svc.tamper_detected.connect ((event_type, details) => {
        tamper_found = true;
    });

    svc.check_binary_integrity ();
    // Should not emit anything when paths are empty
    assert_false (tamper_found);
}

void test_binary_integrity_missing_binary () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.daemon_binary_path = "/tmp/nonexistent-binary-file";
    svc.expected_binary_hash = "somehash";

    string? detected_type = null;
    svc.tamper_detected.connect ((event_type, details) => {
        detected_type = event_type;
    });

    svc.check_binary_integrity ();
    assert_true (detected_type == "binary_missing");
}

void test_binary_integrity_hash_mismatch () {
    setup_test_dir ();

    var binary_path = Path.build_filename (test_dir, "fake-binary");
    try {
        FileUtils.set_contents (binary_path, "some binary content");
    } catch (Error e) {
        Test.fail_printf ("Could not write test file: %s", e.message);
        cleanup_test_dir ();
        return;
    }

    var svc = new Vigil.Services.TamperDetectionService ();
    svc.daemon_binary_path = binary_path;
    svc.expected_binary_hash = "0000000000000000000000000000000000000000";

    string? detected_type = null;
    svc.tamper_detected.connect ((event_type, details) => {
        detected_type = event_type;
    });

    svc.check_binary_integrity ();
    assert_true (detected_type == "binary_modified");

    cleanup_test_dir ();
}

void test_binary_integrity_correct_hash () {
    setup_test_dir ();

    var binary_path = Path.build_filename (test_dir, "valid-binary");
    string content = "valid binary content";
    try {
        FileUtils.set_contents (binary_path, content);
    } catch (Error e) {
        Test.fail_printf ("Could not write test file: %s", e.message);
        cleanup_test_dir ();
        return;
    }

    // Compute expected hash
    var expected_hash = Checksum.compute_for_string (ChecksumType.SHA256, content);

    var svc = new Vigil.Services.TamperDetectionService ();
    svc.daemon_binary_path = binary_path;
    svc.expected_binary_hash = expected_hash;

    bool tamper_found = false;
    svc.tamper_detected.connect ((event_type, details) => {
        tamper_found = true;
    });

    svc.check_binary_integrity ();
    assert_false (tamper_found);

    cleanup_test_dir ();
}

void test_config_hash_without_settings () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = "/tmp/nonexistent.desktop";
    // Don't start (which would try to load GSettings)
    var hash = svc.compute_config_hash ();
    assert_true (hash == "no-settings");
}

void test_run_all_checks_no_crash () {
    var svc = new Vigil.Services.TamperDetectionService ();
    svc.autostart_desktop_path = "/tmp/nonexistent.desktop";
    svc.daemon_binary_path = "";
    svc.expected_binary_hash = "";
    // Should not crash even without GSettings or valid paths
    svc.run_all_checks ();
}

void test_default_check_interval () {
    var svc = new Vigil.Services.TamperDetectionService ();
    assert_true (svc.check_interval_seconds == 120);
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/tamper/start_stop_lifecycle", test_start_stop_lifecycle);
    Test.add_func ("/tamper/double_start_idempotent", test_double_start_idempotent);
    Test.add_func ("/tamper/double_stop_idempotent", test_double_stop_idempotent);
    Test.add_func ("/tamper/detects_missing_autostart", test_detects_missing_autostart);
    Test.add_func ("/tamper/detects_modified_autostart", test_detects_modified_autostart);
    Test.add_func ("/tamper/valid_autostart_no_tamper", test_valid_autostart_no_tamper);
    Test.add_func ("/tamper/binary_skip_no_config", test_binary_integrity_skip_when_no_config);
    Test.add_func ("/tamper/binary_missing", test_binary_integrity_missing_binary);
    Test.add_func ("/tamper/binary_hash_mismatch", test_binary_integrity_hash_mismatch);
    Test.add_func ("/tamper/binary_correct_hash", test_binary_integrity_correct_hash);
    Test.add_func ("/tamper/config_hash_without_settings", test_config_hash_without_settings);
    Test.add_func ("/tamper/run_all_checks_no_crash", test_run_all_checks_no_crash);
    Test.add_func ("/tamper/default_check_interval", test_default_check_interval);

    return Test.run ();
}
