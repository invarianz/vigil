/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Tests for the MonitoringEngine.
 *
 * These tests verify the engine wiring without a running application.
 * We test:
 *   - Initial state
 *   - Status JSON generation
 *   - Signal propagation (tamper events)
 *   - Property accessors
 */

static string test_storage_dir;

void setup_storage () {
    test_storage_dir = TestUtils.make_test_dir ();
}

void cleanup_storage () {
    TestUtils.delete_directory_recursive (test_storage_dir);
}

/**
 * Create a MonitoringEngine with real service objects.
 */
Vigil.MonitoringEngine create_test_engine () {
    setup_storage ();

    var screenshot_svc = new Vigil.Services.ScreenshotService ();
    var scheduler_svc = new Vigil.Services.SchedulerService ();
    var storage_svc = new Vigil.Services.StorageService (test_storage_dir);
    var matrix_svc = new Vigil.Services.MatrixTransportService ();
    var tamper_svc = new Vigil.Services.TamperDetectionService (null);

    // meson test sets GSETTINGS_SCHEMA_DIR and GSETTINGS_BACKEND=memory
    var settings = new GLib.Settings ("io.github.invarianz.vigil");

    return new Vigil.MonitoringEngine (
        screenshot_svc,
        scheduler_svc,
        storage_svc,
        tamper_svc,
        matrix_svc,
        settings
    );
}

void test_initial_state () {
    var engine = create_test_engine ();

    assert_false (engine.monitoring_active);
    assert_true (engine.active_backend_name == "none");
    assert_true (engine.next_capture_time_iso == "");
    assert_true (engine.last_capture_time_iso == "");

    cleanup_storage ();
}

void test_get_status_json () {
    var engine = create_test_engine ();

    var json_str = engine.get_status_json ();
    var parser = new Json.Parser ();
    try {
        parser.load_from_data (json_str);

        var root = parser.get_root ().get_object ();
        assert_true (root.has_member ("monitoring_active"));
        assert_true (root.has_member ("backend"));
        assert_true (root.has_member ("next_capture"));
        assert_true (root.has_member ("last_capture"));
    } catch (Error e) {
        Test.fail_printf ("get_status_json failed: %s", e.message);
    }

    cleanup_storage ();
}

void test_tamper_events_propagated () {
    var screenshot_svc = new Vigil.Services.ScreenshotService ();
    var scheduler_svc = new Vigil.Services.SchedulerService ();

    setup_storage ();
    var storage_svc = new Vigil.Services.StorageService (test_storage_dir);
    var matrix_svc = new Vigil.Services.MatrixTransportService ();
    var tamper_svc = new Vigil.Services.TamperDetectionService (null);
    var settings = new GLib.Settings ("io.github.invarianz.vigil");

    var engine = new Vigil.MonitoringEngine (
        screenshot_svc, scheduler_svc,
        storage_svc, tamper_svc, matrix_svc, settings
    );

    string? received_type = null;
    engine.tamper_event.connect ((event_type, details) => {
        received_type = event_type;
    });

    // Simulate a tamper detection event
    tamper_svc.tamper_detected ("test_event", "test details");

    assert_true (received_type == "test_event");

    // Check it appears in recent_tamper_events
    var events = engine.recent_tamper_events;
    assert_true (events.length == 1);
    assert_true (events[0] == "test_event: test details");

    cleanup_storage ();
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/monitoring_engine/initial_state", test_initial_state);
    Test.add_func ("/monitoring_engine/get_status_json", test_get_status_json);
    Test.add_func ("/monitoring_engine/tamper_events_propagated", test_tamper_events_propagated);

    return Test.run ();
}
