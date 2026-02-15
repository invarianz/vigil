/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Tests for HeartbeatService.
 *
 * These test payload building, URL derivation, start/stop lifecycle,
 * tamper event reporting, and counter resets. Network calls are not
 * tested here (no server to talk to).
 */

void test_build_payload_contains_required_fields () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.device_id = "test-device-123";
    svc.monitoring_active = true;
    svc.screenshot_permission_ok = true;
    svc.config_hash = "abc123";
    svc.screenshots_since_last = 5;
    svc.pending_upload_count = 2;

    var payload = svc.build_payload ();

    // Parse and verify JSON
    var parser = new Json.Parser ();
    try {
        parser.load_from_data (payload);
    } catch (Error e) {
        Test.fail_printf ("Invalid JSON: %s", e.message);
        return;
    }

    var root = parser.get_root ().get_object ();

    assert_true (root.has_member ("type"));
    assert_true (root.get_string_member ("type") == "heartbeat");
    assert_true (root.has_member ("timestamp"));
    assert_true (root.has_member ("device_id"));
    assert_true (root.get_string_member ("device_id") == "test-device-123");
    assert_true (root.has_member ("uptime_seconds"));
    assert_true (root.has_member ("monitoring_active"));
    assert_true (root.get_boolean_member ("monitoring_active") == true);
    assert_true (root.has_member ("screenshot_permission_ok"));
    assert_true (root.get_boolean_member ("screenshot_permission_ok") == true);
    assert_true (root.has_member ("config_hash"));
    assert_true (root.get_string_member ("config_hash") == "abc123");
    assert_true (root.has_member ("screenshots_since_last"));
    assert_true (root.get_int_member ("screenshots_since_last") == 5);
    assert_true (root.has_member ("pending_uploads"));
    assert_true (root.get_int_member ("pending_uploads") == 2);
    assert_true (root.has_member ("tamper_events"));
    assert_true (root.get_array_member ("tamper_events").get_length () == 0);
}

void test_build_payload_includes_tamper_events () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.device_id = "dev1";

    svc.report_tamper_event ("autostart_missing: file deleted");
    svc.report_tamper_event ("systemd_disabled: service stopped");

    var payload = svc.build_payload ();
    var parser = new Json.Parser ();
    try {
        parser.load_from_data (payload);
    } catch (Error e) {
        Test.fail_printf ("Invalid JSON: %s", e.message);
        return;
    }

    var root = parser.get_root ().get_object ();
    var events = root.get_array_member ("tamper_events");
    assert_true (events.get_length () == 2);
    assert_true (events.get_string_element (0) == "autostart_missing: file deleted");
    assert_true (events.get_string_element (1) == "systemd_disabled: service stopped");
}

void test_derive_heartbeat_url_replaces_last_path () {
    var result = Vigil.Services.HeartbeatService.derive_heartbeat_url (
        "https://example.com/api/screenshots"
    );
    assert_true (result == "https://example.com/api/heartbeat");
}

void test_derive_heartbeat_url_short_path () {
    var result = Vigil.Services.HeartbeatService.derive_heartbeat_url (
        "https://example.com/upload"
    );
    assert_true (result == "https://example.com/heartbeat");
}

void test_derive_heartbeat_url_appends_when_no_path () {
    var result = Vigil.Services.HeartbeatService.derive_heartbeat_url (
        "https://ex.com"
    );
    // last slash is at position 7 which is <= 8, so it appends
    assert_true (result == "https://ex.com/heartbeat");
}

void test_start_stop_lifecycle () {
    var svc = new Vigil.Services.HeartbeatService ();
    assert_false (svc.is_running);

    svc.endpoint_url = ""; // No endpoint, so send won't actually fire HTTP
    svc.start ();
    assert_true (svc.is_running);

    svc.stop ();
    assert_false (svc.is_running);
}

void test_double_start_is_idempotent () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.start ();
    svc.start (); // Should not crash or double-schedule
    assert_true (svc.is_running);
    svc.stop ();
}

void test_double_stop_is_idempotent () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.start ();
    svc.stop ();
    svc.stop (); // Should not crash
    assert_false (svc.is_running);
}

void test_uptime_is_non_negative () {
    var svc = new Vigil.Services.HeartbeatService ();
    var uptime = svc.get_uptime_seconds ();
    assert_true (uptime >= 0);
}

void test_send_heartbeat_returns_false_without_endpoint () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.endpoint_url = "";

    var loop = new MainLoop ();
    bool result = true;

    svc.send_heartbeat.begin ((obj, res) => {
        result = svc.send_heartbeat.end (res);
        loop.quit ();
    });

    // Run the loop briefly
    Timeout.add (100, () => {
        loop.quit ();
        return Source.REMOVE;
    });
    loop.run ();

    assert_false (result);
}

void test_default_interval () {
    var svc = new Vigil.Services.HeartbeatService ();
    assert_true (svc.interval_seconds == 60);
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/heartbeat/build_payload_required_fields",
        test_build_payload_contains_required_fields);
    Test.add_func ("/heartbeat/build_payload_tamper_events",
        test_build_payload_includes_tamper_events);
    Test.add_func ("/heartbeat/derive_url_replaces_last_path",
        test_derive_heartbeat_url_replaces_last_path);
    Test.add_func ("/heartbeat/derive_url_short_path",
        test_derive_heartbeat_url_short_path);
    Test.add_func ("/heartbeat/derive_url_appends_no_path",
        test_derive_heartbeat_url_appends_when_no_path);
    Test.add_func ("/heartbeat/start_stop_lifecycle",
        test_start_stop_lifecycle);
    Test.add_func ("/heartbeat/double_start_idempotent",
        test_double_start_is_idempotent);
    Test.add_func ("/heartbeat/double_stop_idempotent",
        test_double_stop_is_idempotent);
    Test.add_func ("/heartbeat/uptime_non_negative",
        test_uptime_is_non_negative);
    Test.add_func ("/heartbeat/send_no_endpoint_returns_false",
        test_send_heartbeat_returns_false_without_endpoint);
    Test.add_func ("/heartbeat/default_interval",
        test_default_interval);

    return Test.run ();
}
