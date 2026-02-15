/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Tests for the Daemon DBusServer.
 *
 * These tests verify the DBusServer wiring without an actual D-Bus
 * connection. We test:
 *   - Initial state
 *   - Status JSON generation
 *   - Signal propagation (tamper events)
 *   - Property accessors
 *
 * We can't test actual D-Bus export in unit tests (needs a bus),
 * but we CAN test all the logic inside the server object by
 * constructing it directly with mock/real service instances.
 */

static string test_storage_dir;

void setup_storage () {
    test_storage_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-dbus-test-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
}

void cleanup_storage () {
    delete_directory_recursive (test_storage_dir);
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
        // best-effort
    }
}

/**
 * Create a DBusServer with real service objects (but no D-Bus export).
 * We pass a test GSettings backend so no real schema is needed.
 */
Vigil.Daemon.DBusServer create_test_server () {
    setup_storage ();

    var screenshot_svc = new Vigil.Services.ScreenshotService ();
    var scheduler_svc = new Vigil.Services.SchedulerService ();
    var upload_svc = new Vigil.Services.UploadService ();
    var storage_svc = new Vigil.Services.StorageService (test_storage_dir);
    var heartbeat_svc = new Vigil.Services.HeartbeatService ();
    var tamper_svc = new Vigil.Services.TamperDetectionService (null);
    tamper_svc.autostart_desktop_path = "/tmp/nonexistent.desktop";

    // meson test sets GSETTINGS_SCHEMA_DIR and GSETTINGS_BACKEND=memory
    var settings = new GLib.Settings ("io.github.invarianz.vigil");

    var matrix_svc = new Vigil.Services.MatrixTransportService ();

    return new Vigil.Daemon.DBusServer (
        screenshot_svc,
        scheduler_svc,
        upload_svc,
        storage_svc,
        heartbeat_svc,
        tamper_svc,
        matrix_svc,
        settings
    );
}

void test_initial_state () {
    var server = create_test_server ();

    assert_false (server.monitoring_active);
    assert_true (server.active_backend_name == "none");
    assert_true (server.next_capture_time_iso == "");
    assert_true (server.last_capture_time_iso == "");
    assert_true (server.screenshot_permission_ok == true);
    assert_true (server.uptime_seconds >= 0);

    cleanup_storage ();
}

void test_get_status_json () {
    var server = create_test_server ();

    try {
        var json_str = server.get_status_json ();
        var parser = new Json.Parser ();
        parser.load_from_data (json_str);

        var root = parser.get_root ().get_object ();
        assert_true (root.has_member ("monitoring_active"));
        assert_true (root.has_member ("backend"));
        assert_true (root.has_member ("next_capture"));
        assert_true (root.has_member ("last_capture"));
        assert_true (root.has_member ("pending_uploads"));
        assert_true (root.has_member ("uptime_seconds"));
        assert_true (root.has_member ("screenshot_permission_ok"));
    } catch (Error e) {
        Test.fail_printf ("get_status_json failed: %s", e.message);
    }

    cleanup_storage ();
}

void test_tamper_events_propagated () {
    var screenshot_svc = new Vigil.Services.ScreenshotService ();
    var scheduler_svc = new Vigil.Services.SchedulerService ();
    var upload_svc = new Vigil.Services.UploadService ();

    setup_storage ();
    var storage_svc = new Vigil.Services.StorageService (test_storage_dir);
    var heartbeat_svc = new Vigil.Services.HeartbeatService ();
    var tamper_svc = new Vigil.Services.TamperDetectionService (null);
    tamper_svc.autostart_desktop_path = "/tmp/nonexistent.desktop";
    var settings = new GLib.Settings ("io.github.invarianz.vigil");

    var matrix_svc = new Vigil.Services.MatrixTransportService ();

    var server = new Vigil.Daemon.DBusServer (
        screenshot_svc, scheduler_svc, upload_svc,
        storage_svc, heartbeat_svc, tamper_svc, matrix_svc, settings
    );

    string? received_type = null;
    server.tamper_event.connect ((event_type, details) => {
        received_type = event_type;
    });

    // Simulate a tamper detection event
    tamper_svc.tamper_detected ("test_event", "test details");

    assert_true (received_type == "test_event");

    // Check it appears in recent_tamper_events
    var events = server.recent_tamper_events;
    assert_true (events.length == 1);
    assert_true (events[0] == "test_event: test details");

    cleanup_storage ();
}

void test_pending_upload_count_reflects_storage () {
    var server = create_test_server ();

    // No pending uploads initially
    assert_true (server.pending_upload_count == 0);

    cleanup_storage ();
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/dbus_server/initial_state", test_initial_state);
    Test.add_func ("/dbus_server/get_status_json", test_get_status_json);
    Test.add_func ("/dbus_server/tamper_events_propagated", test_tamper_events_propagated);
    Test.add_func ("/dbus_server/pending_count_reflects_storage",
        test_pending_upload_count_reflects_storage);

    return Test.run ();
}
