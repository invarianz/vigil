/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for TamperDetectionService.
 *
 * Uses a temp directory for autostart desktop path to avoid
 * interfering with the real system.
 */

string test_base_dir;

void setup_test_dir () {
    test_base_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-tamper-test-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
    DirUtils.create_with_parents (test_base_dir, 0755);
}

void teardown_test_dir () {
    delete_directory_recursive (test_base_dir);
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

void test_autostart_missing_detected () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.autostart_desktop_path = "/tmp/definitely-does-not-exist.desktop";

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_autostart_entry ();

    assert_true (event_type == "autostart_missing");
}

void test_autostart_present_no_tamper () {
    setup_test_dir ();

    // Create a fake desktop file
    var desktop_path = Path.build_filename (test_base_dir, "vigil.desktop");
    try {
        FileUtils.set_contents (desktop_path,
            "[Desktop Entry]\nExec=io.github.invarianz.vigil.daemon\n");
    } catch (Error e) {
        assert_not_reached ();
    }

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.autostart_desktop_path = desktop_path;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_autostart_entry ();

    assert_true (event_type == null);

    teardown_test_dir ();
}

void test_autostart_modified_detected () {
    setup_test_dir ();

    var desktop_path = Path.build_filename (test_base_dir, "vigil.desktop");
    try {
        // Write a desktop file that references a different binary
        FileUtils.set_contents (desktop_path,
            "[Desktop Entry]\nExec=some-other-program\n");
    } catch (Error e) {
        assert_not_reached ();
    }

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.autostart_desktop_path = desktop_path;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_autostart_entry ();

    assert_true (event_type == "autostart_modified");

    teardown_test_dir ();
}

void test_config_hash_without_settings () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    var hash = svc.compute_config_hash ();
    assert_true (hash == "no-settings");
}

void test_config_hash_with_settings () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    var svc = new Vigil.Services.TamperDetectionService (settings);

    var hash1 = svc.compute_config_hash ();
    assert_true (hash1 != "");
    assert_true (hash1 != "no-settings");

    // Hash should be deterministic
    var hash2 = svc.compute_config_hash ();
    assert_true (hash1 == hash2);
}

void test_config_hash_changes_on_setting_change () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    var svc = new Vigil.Services.TamperDetectionService (settings);

    var hash_before = svc.compute_config_hash ();

    settings.set_int ("min-interval-seconds", 999);
    var hash_after = svc.compute_config_hash ();

    assert_true (hash_before != hash_after);

    // Reset
    settings.set_int ("min-interval-seconds", 120);
}

void test_settings_sanity_monitoring_disabled () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", false);
    // Set Matrix settings so matrix_cleared doesn't also fire
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? first_event = null;
    svc.tamper_detected.connect ((t, d) => {
        if (first_event == null) {
            first_event = t;
        }
    });

    svc.check_settings_sanity ();
    assert_true (first_event == "monitoring_disabled");
}

void test_settings_sanity_interval_tampered () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 7200);
    // Set Matrix settings so matrix_cleared doesn't also fire
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? first_event = null;
    svc.tamper_detected.connect ((t, d) => {
        if (first_event == null) {
            first_event = t;
        }
    });

    svc.check_settings_sanity ();
    assert_true (first_event == "interval_tampered");

    // Reset
    settings.set_int ("min-interval-seconds", 120);
}

void test_settings_sanity_matrix_cleared () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 120);
    settings.set_int ("max-interval-seconds", 600);
    settings.set_string ("matrix-homeserver-url", "");
    settings.set_string ("matrix-access-token", "");
    settings.set_string ("matrix-room-id", "");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_settings_sanity ();
    assert_true (event_type == "matrix_cleared");
}

void test_settings_sanity_matrix_incomplete () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 120);
    settings.set_int ("max-interval-seconds", 600);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "");
    settings.set_string ("matrix-room-id", "!room:test");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_settings_sanity ();
    assert_true (event_type == "matrix_incomplete");
}

void test_start_stop_lifecycle () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.autostart_desktop_path = "/tmp/nonexistent.desktop";

    assert_false (svc.is_running);

    svc.start ();
    assert_true (svc.is_running);

    svc.stop ();
    assert_false (svc.is_running);
}

void test_binary_integrity_no_baseline () {
    // With empty paths, binary integrity check should be a no-op
    var svc = new Vigil.Services.TamperDetectionService (null);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_binary_integrity ();
    assert_true (event_type == null);
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/tamper/autostart_missing", test_autostart_missing_detected);
    Test.add_func ("/tamper/autostart_present", test_autostart_present_no_tamper);
    Test.add_func ("/tamper/autostart_modified", test_autostart_modified_detected);
    Test.add_func ("/tamper/config_hash_no_settings", test_config_hash_without_settings);
    Test.add_func ("/tamper/config_hash_with_settings", test_config_hash_with_settings);
    Test.add_func ("/tamper/config_hash_changes", test_config_hash_changes_on_setting_change);
    Test.add_func ("/tamper/settings_monitoring_disabled", test_settings_sanity_monitoring_disabled);
    Test.add_func ("/tamper/settings_interval_tampered", test_settings_sanity_interval_tampered);
    Test.add_func ("/tamper/settings_matrix_cleared", test_settings_sanity_matrix_cleared);
    Test.add_func ("/tamper/settings_matrix_incomplete", test_settings_sanity_matrix_incomplete);
    Test.add_func ("/tamper/start_stop_lifecycle", test_start_stop_lifecycle);
    Test.add_func ("/tamper/binary_no_baseline", test_binary_integrity_no_baseline);

    return Test.run ();
}
