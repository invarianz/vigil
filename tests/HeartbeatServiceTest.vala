/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Tests for HeartbeatService.
 *
 * These test heartbeat message building, start/stop lifecycle,
 * tamper event reporting, and counter resets.
 */

void test_build_heartbeat_message_basic () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.screenshots_since_last = 5;
    svc.pending_upload_count = 2;

    var msg = svc.build_heartbeat_message ();

    assert_true (msg.contains ("Vigil active"));
    assert_true (msg.contains ("screenshots: 5"));
    assert_true (msg.contains ("pending: 2"));
}

void test_build_heartbeat_message_with_tamper_events () {
    var svc = new Vigil.Services.HeartbeatService ();

    svc.report_tamper_event ("autostart_missing: file deleted");
    svc.report_tamper_event ("systemd_disabled: service stopped");

    var msg = svc.build_heartbeat_message ();

    assert_true (msg.contains ("Tamper events:"));
    assert_true (msg.contains ("autostart_missing: file deleted"));
    assert_true (msg.contains ("systemd_disabled: service stopped"));
}

void test_start_stop_lifecycle () {
    var svc = new Vigil.Services.HeartbeatService ();
    assert_false (svc.is_running);

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

void test_send_heartbeat_returns_false_without_matrix () {
    var svc = new Vigil.Services.HeartbeatService ();

    var loop = new MainLoop ();
    bool result = true;

    svc.send_heartbeat.begin ((obj, res) => {
        result = svc.send_heartbeat.end (res);
        loop.quit ();
    });

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

void test_report_tamper_event () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.report_tamper_event ("test event 1");
    svc.report_tamper_event ("test event 2");

    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("test event 1"));
    assert_true (msg.contains ("test event 2"));
}

void test_consecutive_failures_tracked () {
    var svc = new Vigil.Services.HeartbeatService ();
    assert_true (svc.consecutive_failures == 0);

    // Without a Matrix service, send will fail
    var loop = new MainLoop ();
    svc.send_heartbeat.begin ((obj, res) => {
        svc.send_heartbeat.end (res);
        loop.quit ();
    });
    Timeout.add (100, () => { loop.quit (); return Source.REMOVE; });
    loop.run ();

    // After a failure, consecutive_failures should not increment
    // because the "not configured" path doesn't count as a network failure
    // (it returns before attempting send)
    assert_true (svc.consecutive_failures == 0);
}

void test_gap_detection_in_message () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.interval_seconds = 1;

    // Start the service to initialize _last_heartbeat_monotonic
    svc.start ();
    svc.stop ();

    // Normal message (no gap) should not contain "resumed"
    var msg = svc.build_heartbeat_message ();
    assert_false (msg.contains ("resumed"));
}

void test_offline_notice_without_matrix () {
    var svc = new Vigil.Services.HeartbeatService ();

    // Should not crash when Matrix is null
    var loop = new MainLoop ();
    svc.send_offline_notice.begin ((obj, res) => {
        svc.send_offline_notice.end (res);
        loop.quit ();
    });
    Timeout.add (100, () => { loop.quit (); return Source.REMOVE; });
    loop.run ();
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/heartbeat/build_message_basic",
        test_build_heartbeat_message_basic);
    Test.add_func ("/heartbeat/build_message_tamper_events",
        test_build_heartbeat_message_with_tamper_events);
    Test.add_func ("/heartbeat/start_stop_lifecycle",
        test_start_stop_lifecycle);
    Test.add_func ("/heartbeat/double_start_idempotent",
        test_double_start_is_idempotent);
    Test.add_func ("/heartbeat/double_stop_idempotent",
        test_double_stop_is_idempotent);
    Test.add_func ("/heartbeat/uptime_non_negative",
        test_uptime_is_non_negative);
    Test.add_func ("/heartbeat/send_no_matrix_returns_false",
        test_send_heartbeat_returns_false_without_matrix);
    Test.add_func ("/heartbeat/default_interval",
        test_default_interval);
    Test.add_func ("/heartbeat/report_tamper_event",
        test_report_tamper_event);
    Test.add_func ("/heartbeat/consecutive_failures",
        test_consecutive_failures_tracked);
    Test.add_func ("/heartbeat/gap_detection",
        test_gap_detection_in_message);
    Test.add_func ("/heartbeat/offline_notice_no_matrix",
        test_offline_notice_without_matrix);

    return Test.run ();
}
