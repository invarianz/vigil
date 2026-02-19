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

void test_background_portal_flag_cleared_detected () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    // Simulate: portal previously granted permission
    settings.set_boolean ("background-portal-granted", true);
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    // First check: establishes that the flag was true
    svc.check_settings_sanity ();

    // Now clear the flag (simulating revocation via dconf)
    settings.set_boolean ("background-portal-granted", false);

    GenericArray<string> events = new GenericArray<string> ();
    svc.tamper_detected.connect ((t, d) => {
        events.add (t);
    });

    svc.check_settings_sanity ();

    bool found = false;
    for (int i = 0; i < events.length; i++) {
        if (events[i] == "background_permission_revoked") found = true;
    }
    assert_true (found);

    // Cleanup
    settings.set_boolean ("background-portal-granted", false);
}

void test_background_portal_flag_not_set_no_tamper () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    // Default: background-portal-granted is false (never granted)
    settings.set_boolean ("background-portal-granted", false);
    settings.set_boolean ("monitoring-enabled", true);
    settings.set_int ("min-interval-seconds", 30);
    settings.set_int ("max-interval-seconds", 120);
    settings.set_string ("matrix-homeserver-url", "https://matrix.org");
    settings.set_string ("matrix-access-token", "test-token");
    settings.set_string ("matrix-room-id", "!room:test");
    settings.set_string ("partner-matrix-id", "@partner:matrix.org");

    var svc = new Vigil.Services.TamperDetectionService (settings);

    GenericArray<string> events = new GenericArray<string> ();
    svc.tamper_detected.connect ((t, d) => {
        events.add (t);
    });

    svc.check_settings_sanity ();

    bool found = false;
    for (int i = 0; i < events.length; i++) {
        if (events[i] == "background_permission_revoked") found = true;
    }
    assert_false (found);
}

void test_emit_background_permission_revoked () {
    var svc = new Vigil.Services.TamperDetectionService (null);

    string? event_type = null;
    string? event_details = null;
    svc.tamper_detected.connect ((t, d) => {
        event_type = t;
        event_details = d;
    });

    svc.emit_background_permission_revoked ();
    assert_true (event_type == "background_permission_revoked");
    assert_true (event_details.contains ("auto-start"));
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

void test_binary_integrity_valid_binary () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);

    var binary_path = Path.build_filename (dir, "fake_binary");
    var content = "this is a fake binary for testing";
    try { FileUtils.set_contents (binary_path, content); } catch (Error e) { assert_not_reached (); }

    var hash = Vigil.Services.SecurityUtils.compute_sha256_hex (content.data);

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.daemon_binary_path = binary_path;
    svc.expected_binary_hash = hash;

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.check_binary_integrity ();
    assert_true (event_type == null);

    TestUtils.delete_directory_recursive (dir);
}

void test_binary_integrity_modified () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);

    var binary_path = Path.build_filename (dir, "fake_binary");
    try { FileUtils.set_contents (binary_path, "original content"); } catch (Error e) { assert_not_reached (); }

    // Use a wrong hash to simulate modification
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.daemon_binary_path = binary_path;
    svc.expected_binary_hash = "0000000000000000000000000000000000000000000000000000000000000000";

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.check_binary_integrity ();
    assert_true (event_type == "binary_modified");

    TestUtils.delete_directory_recursive (dir);
}

void test_binary_integrity_missing () {
    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.daemon_binary_path = "/tmp/definitely_does_not_exist_binary";
    svc.expected_binary_hash = "somehash";

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.check_binary_integrity ();
    assert_true (event_type == "binary_missing");
}

void test_file_monitoring_expected_deletion () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);
    // Isolate crypto dir so inotify doesn't watch the real user dir
    // (avoids race conditions when parallel test binaries modify crypto files)
    Environment.set_variable ("XDG_DATA_HOME", dir, true);
    Vigil.Services.SecurityUtils.reset_cached_paths ();
    var screenshots = Path.build_filename (dir, "screenshots");
    DirUtils.create_with_parents (screenshots, 0755);

    // Create a file to delete
    var file_path = Path.build_filename (screenshots, "test.png");
    try { FileUtils.set_contents (file_path, "fake"); } catch (Error e) { assert_not_reached (); }

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.screenshots_dir = screenshots;
    svc.pending_dir = Path.build_filename (dir, "pending");

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    // Register expected deletion, then start monitoring
    svc.expect_deletion (file_path);
    svc.start_file_monitoring ();

    // Delete the file
    FileUtils.remove (file_path);

    // Process pending events
    var ctx = MainContext.default ();
    for (int i = 0; i < 50; i++) {
        ctx.iteration (false);
    }

    assert_true (event_type == null);

    svc.stop_file_monitoring ();
    TestUtils.delete_directory_recursive (dir);
}

void test_file_monitoring_unexpected_deletion () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);
    Environment.set_variable ("XDG_DATA_HOME", dir, true);
    Vigil.Services.SecurityUtils.reset_cached_paths ();
    var screenshots = Path.build_filename (dir, "screenshots");
    DirUtils.create_with_parents (screenshots, 0755);

    // Create a file to delete unexpectedly
    var file_path = Path.build_filename (screenshots, "unexpected.png");
    try { FileUtils.set_contents (file_path, "fake"); } catch (Error e) { assert_not_reached (); }

    var svc = new Vigil.Services.TamperDetectionService (null);
    svc.screenshots_dir = screenshots;
    svc.pending_dir = Path.build_filename (dir, "pending");

    string? event_type = null;
    svc.tamper_detected.connect ((t, d) => { event_type = t; });

    svc.start_file_monitoring ();

    // Delete without registering
    FileUtils.remove (file_path);

    // Process pending events (inotify is async)
    var loop = new MainLoop ();
    Timeout.add (200, () => { loop.quit (); return Source.REMOVE; });
    loop.run ();

    assert_true (event_type == "screenshot_deleted");

    svc.stop_file_monitoring ();
    TestUtils.delete_directory_recursive (dir);
}

void test_file_monitoring_stop_is_safe () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);
    Environment.set_variable ("XDG_DATA_HOME", dir, true);
    Vigil.Services.SecurityUtils.reset_cached_paths ();

    var svc = new Vigil.Services.TamperDetectionService (null);

    // Double start/stop should not crash
    svc.start_file_monitoring ();
    svc.start_file_monitoring ();
    svc.stop_file_monitoring ();
    svc.stop_file_monitoring ();

    TestUtils.delete_directory_recursive (dir);
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
    Test.add_func ("/tamper/background_portal_flag_cleared",
        test_background_portal_flag_cleared_detected);
    Test.add_func ("/tamper/background_portal_flag_not_set",
        test_background_portal_flag_not_set_no_tamper);
    Test.add_func ("/tamper/background_permission_revoked_event",
        test_emit_background_permission_revoked);
    Test.add_func ("/tamper/stop_cleans_up_urandom", test_stop_cleans_up_urandom);
    Test.add_func ("/tamper/binary_integrity_valid", test_binary_integrity_valid_binary);
    Test.add_func ("/tamper/binary_integrity_modified", test_binary_integrity_modified);
    Test.add_func ("/tamper/binary_integrity_missing", test_binary_integrity_missing);
    Test.add_func ("/tamper/file_monitoring_expected_deletion",
        test_file_monitoring_expected_deletion);
    Test.add_func ("/tamper/file_monitoring_unexpected_deletion",
        test_file_monitoring_unexpected_deletion);
    Test.add_func ("/tamper/file_monitoring_stop_is_safe",
        test_file_monitoring_stop_is_safe);

    return Test.run ();
}
