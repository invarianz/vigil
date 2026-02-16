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
    test_base_dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (test_base_dir, 0755);
}

void teardown_test_dir () {
    TestUtils.delete_directory_recursive (test_base_dir);
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
    settings.set_int ("min-interval-seconds", 30);
}

void test_settings_sanity_monitoring_disabled () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", false);
    // Set Matrix settings so matrix_cleared / partner_changed don't also fire
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");

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
    settings.set_int ("min-interval-seconds", 600);
    // Set Matrix settings so matrix_cleared / partner_changed don't also fire
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");

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
    settings.set_int ("min-interval-seconds", 30);
}

void test_settings_sanity_matrix_cleared () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
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
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
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

void test_settings_lock_bypass_detected () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    // Simulate: lock was active (hash exists) but lock flag was cleared via CLI
    settings.set_string ("unlock-code-hash", "somehash");
    settings.set_boolean ("settings-locked", false);
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        if (event_type == null) {
            event_type = t;
        }
    });

    svc.check_settings_lock ();
    assert_true (event_type == "settings_unlocked");

    // Cleanup
    settings.set_string ("unlock-code-hash", "");
}

void test_settings_lock_hash_cleared_detected () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    // Simulate: lock is set but hash cleared (attempt to make unlock trivial)
    settings.set_boolean ("settings-locked", true);
    settings.set_string ("unlock-code-hash", "");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        if (event_type == null) {
            event_type = t;
        }
    });

    svc.check_settings_lock ();
    assert_true (event_type == "unlock_code_cleared");

    // Cleanup
    settings.set_boolean ("settings-locked", false);
}

void test_settings_lock_no_tamper_when_properly_locked () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("settings-locked", true);
    settings.set_string ("unlock-code-hash", "a_valid_hash");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_settings_lock ();
    assert_true (event_type == null);

    // Cleanup
    settings.set_boolean ("settings-locked", false);
    settings.set_string ("unlock-code-hash", "");
}

void test_heartbeat_interval_tampered () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");
    settings.set_int ("heartbeat-interval-seconds", 7200);

    var svc = new Vigil.Services.TamperDetectionService (settings);

    GenericArray<string> events = new GenericArray<string> ();
    svc.tamper_detected.connect ((t, d) => {
        events.add (t);
    });

    svc.check_settings_sanity ();

    bool found = false;
    for (int i = 0; i < events.length; i++) {
        if (events[i] == "timer_tampered") found = true;
    }
    assert_true (found);

    // Reset
    settings.set_int ("heartbeat-interval-seconds", 900);
}

void test_upload_batch_interval_tampered () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");
    settings.set_int ("upload-batch-interval-seconds", 5000);

    var svc = new Vigil.Services.TamperDetectionService (settings);

    GenericArray<string> events = new GenericArray<string> ();
    svc.tamper_detected.connect ((t, d) => {
        events.add (t);
    });

    svc.check_settings_sanity ();

    bool found = false;
    for (int i = 0; i < events.length; i++) {
        if (events[i] == "timer_tampered") found = true;
    }
    assert_true (found);

    // Reset
    settings.set_int ("upload-batch-interval-seconds", 600);
}

void test_tamper_check_interval_tampered () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");
    settings.set_int ("tamper-check-interval-seconds", 3600);

    var svc = new Vigil.Services.TamperDetectionService (settings);

    GenericArray<string> events = new GenericArray<string> ();
    svc.tamper_detected.connect ((t, d) => {
        events.add (t);
    });

    svc.check_settings_sanity ();

    bool found = false;
    for (int i = 0; i < events.length; i++) {
        if (events[i] == "timer_tampered") found = true;
    }
    assert_true (found);

    // Reset
    settings.set_int ("tamper-check-interval-seconds", 120);
}

void test_partner_id_cleared () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    GenericArray<string> events = new GenericArray<string> ();
    svc.tamper_detected.connect ((t, d) => {
        events.add (t);
    });

    svc.check_settings_sanity ();

    bool found = false;
    for (int i = 0; i < events.length; i++) {
        if (events[i] == "partner_changed") found = true;
    }
    assert_true (found);

    // Reset
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");
}

void test_timers_within_limits_no_tamper () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");
    settings.set_int ("heartbeat-interval-seconds", 900);
    settings.set_int ("upload-batch-interval-seconds", 600);
    settings.set_int ("tamper-check-interval-seconds", 120);

    var svc = new Vigil.Services.TamperDetectionService (settings);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.check_settings_sanity ();
    assert_true (event_type == null);
}

void test_e2ee_init_failure_event () {
    var svc = new Vigil.Services.TamperDetectionService (null);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
    });

    svc.emit_e2ee_init_failure ();
    assert_true (event_type == "e2ee_init_failed");
}

void test_capture_liveness_no_alarm_before_monitoring () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.max_capture_interval_seconds = 1;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    // Should not fire before report_capture_success() is ever called
    svc.check_capture_liveness ();
    assert_true (event_type == null);
}

void test_capture_liveness_no_alarm_when_recent () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.max_capture_interval_seconds = 3600;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.report_capture_success ();
    svc.check_capture_liveness ();
    assert_true (event_type == null);
}

void test_orphan_detection_no_dirs () {
    var svc = new Vigil.Services.TamperDetectionService (null);

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    // No dirs configured -- should not fire
    svc.check_orphan_screenshots ();
    assert_true (event_type == null);
}

void test_orphan_detection_with_many_orphans () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);
    var screenshots = Path.build_filename (dir, "screenshots");
    var pending = Path.build_filename (dir, "pending");
    DirUtils.create_with_parents (screenshots, 0755);
    DirUtils.create_with_parents (pending, 0755);

    // Create 10 orphan screenshots (no markers)
    for (int i = 0; i < 10; i++) {
        var path = Path.build_filename (screenshots, "orphan_%d.png".printf (i));
        try { FileUtils.set_contents (path, "fake"); } catch (Error e) {}
    }

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.screenshots_dir = screenshots;
    svc.pending_dir = pending;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.check_orphan_screenshots ();
    assert_true (event_type == "orphan_screenshots");

    TestUtils.delete_directory_recursive (dir);
}

void test_orphan_detection_no_alarm_when_few () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);
    var screenshots = Path.build_filename (dir, "screenshots");
    var pending = Path.build_filename (dir, "pending");
    DirUtils.create_with_parents (screenshots, 0755);
    DirUtils.create_with_parents (pending, 0755);

    // Only 3 orphans -- below threshold of 5
    for (int i = 0; i < 3; i++) {
        var path = Path.build_filename (screenshots, "orphan_%d.png".printf (i));
        try { FileUtils.set_contents (path, "fake"); } catch (Error e) {}
    }

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.screenshots_dir = screenshots;
    svc.pending_dir = pending;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.check_orphan_screenshots ();
    assert_true (event_type == null);

    TestUtils.delete_directory_recursive (dir);
}

void test_stop_cleans_up_urandom () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.autostart_desktop_path = "/tmp/nonexistent.desktop";

    svc.start ();
    assert_true (svc.is_running);
    svc.stop ();
    assert_false (svc.is_running);
    // Ensure double-stop is safe
    svc.stop ();
    assert_false (svc.is_running);
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
    Test.add_func ("/tamper/lock_bypass_detected", test_settings_lock_bypass_detected);
    Test.add_func ("/tamper/lock_hash_cleared", test_settings_lock_hash_cleared_detected);
    Test.add_func ("/tamper/lock_properly_locked", test_settings_lock_no_tamper_when_properly_locked);
    Test.add_func ("/tamper/heartbeat_interval_tampered", test_heartbeat_interval_tampered);
    Test.add_func ("/tamper/upload_batch_interval_tampered", test_upload_batch_interval_tampered);
    Test.add_func ("/tamper/tamper_check_interval_tampered", test_tamper_check_interval_tampered);
    Test.add_func ("/tamper/partner_id_cleared", test_partner_id_cleared);
    Test.add_func ("/tamper/timers_within_limits", test_timers_within_limits_no_tamper);
    Test.add_func ("/tamper/e2ee_init_failure", test_e2ee_init_failure_event);
    Test.add_func ("/tamper/capture_liveness_no_alarm_before_monitoring",
        test_capture_liveness_no_alarm_before_monitoring);
    Test.add_func ("/tamper/capture_liveness_no_alarm_when_recent",
        test_capture_liveness_no_alarm_when_recent);
    Test.add_func ("/tamper/orphan_detection_no_dirs", test_orphan_detection_no_dirs);
    Test.add_func ("/tamper/orphan_detection_many_orphans",
        test_orphan_detection_with_many_orphans);
    Test.add_func ("/tamper/orphan_detection_few_no_alarm",
        test_orphan_detection_no_alarm_when_few);
    Test.add_func ("/tamper/stop_cleans_up_urandom", test_stop_cleans_up_urandom);

    return Test.run ();
}
