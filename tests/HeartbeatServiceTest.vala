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

    var msg = svc.build_heartbeat_message ();

    assert_true (msg.contains ("STATUS: All clear"));
    assert_true (msg.contains ("Screenshots taken: 5"));
    assert_true (msg.contains ("arrives within"));
    assert_true (msg.contains ("something may be wrong"));
}

void test_build_heartbeat_message_with_tamper_events () {
    var svc = new Vigil.Services.HeartbeatService ();

    svc.report_tamper_event ("settings_unlocked: lock was disabled");
    svc.report_tamper_event ("screenshot_tampered: file was modified");

    var msg = svc.build_heartbeat_message ();

    assert_true (msg.contains ("TAMPER ATTEMPT DETECTED!"));
    assert_true (msg.contains ("Tamper attempt"));
    // Human-friendly descriptions
    assert_true (msg.contains ("settings lock was bypassed"));
    assert_true (msg.contains ("screenshot was modified"));
}

void test_build_heartbeat_message_with_warnings () {
    var svc = new Vigil.Services.HeartbeatService ();

    svc.report_tamper_event ("~capture_stalled: No screenshot in 300s");
    svc.report_tamper_event ("~e2ee_init_failed: encryption failed");

    var msg = svc.build_heartbeat_message ();

    assert_true (msg.contains ("WARNING: Issues detected"));
    assert_true (msg.contains ("issues were found"));
    // Human-friendly descriptions
    assert_true (msg.contains ("screenshot system has stopped working"));
    assert_true (msg.contains ("Encryption failed to start"));
}

void test_build_heartbeat_message_mixed_events () {
    var svc = new Vigil.Services.HeartbeatService ();

    // Mix of tamper and warning events
    svc.report_tamper_event ("settings_unlocked: lock was disabled");
    svc.report_tamper_event ("~capture_stalled: No screenshot in 300s");

    var msg = svc.build_heartbeat_message ();

    // Should use tamper header (takes priority)
    assert_true (msg.contains ("TAMPER ATTEMPT DETECTED!"));
    // Both sections present
    assert_true (msg.contains ("settings lock was bypassed"));
    assert_true (msg.contains ("screenshot system has stopped working"));
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
    assert_true (svc.interval_seconds == 900);
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

    // Normal message (no gap) should not contain gap notice
    var msg = svc.build_heartbeat_message ();
    assert_false (msg.contains ("Back online"));
}

void test_shutdown_notice_without_matrix () {
    var svc = new Vigil.Services.HeartbeatService ();

    // Should not crash when Matrix is null (system shutdown)
    var loop = new MainLoop ();
    svc.send_shutdown_notice.begin (true, (obj, res) => {
        svc.send_shutdown_notice.end (res);
        loop.quit ();
    });
    Timeout.add (100, () => { loop.quit (); return Source.REMOVE; });
    loop.run ();

    // Should not crash when Matrix is null (manual stop)
    var loop2 = new MainLoop ();
    svc.send_shutdown_notice.begin (false, (obj, res) => {
        svc.send_shutdown_notice.end (res);
        loop2.quit ();
    });
    Timeout.add (100, () => { loop2.quit (); return Source.REMOVE; });
    loop2.run ();
}

void test_sequence_number_in_message () {
    var svc = new Vigil.Services.HeartbeatService ();

    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("seq: 0"));
}

void test_alert_persistence () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);

    var svc = new Vigil.Services.HeartbeatService ();
    svc.data_dir = dir;

    // Report events -- should be persisted to file
    svc.report_tamper_event ("test_event_1");
    svc.report_tamper_event ("test_event_2");

    var alerts_path = Path.build_filename (dir, "unsent_alerts.txt");
    assert_true (FileUtils.test (alerts_path, FileTest.EXISTS));

    // Load in a new service instance to verify persistence
    var svc2 = new Vigil.Services.HeartbeatService ();
    svc2.data_dir = dir;
    svc2.start ();
    svc2.stop ();

    var msg = svc2.build_heartbeat_message ();
    assert_true (msg.contains ("test_event_1"));
    assert_true (msg.contains ("test_event_2"));

    TestUtils.delete_directory_recursive (dir);
}

void test_message_size_capped () {
    var svc = new Vigil.Services.HeartbeatService ();

    // Add a large number of tamper events
    for (int i = 0; i < 200; i++) {
        svc.report_tamper_event (
            "long_event_%d: a very detailed description of what happened".printf (i));
    }

    var msg = svc.build_heartbeat_message ();
    // Message should be capped at ~65KB
    assert_true (msg.length <= 65000);
    // Should mention total count
    assert_true (msg.contains ("200 total"));
}

void test_offline_notice_includes_seq () {
    var svc = new Vigil.Services.HeartbeatService ();

    // Build offline message (can't send without Matrix, but check format)
    // The send_offline_notice will return early without Matrix, so test message build
    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("seq:"));
}

void test_heartbeat_chain_prev_genesis () {
    var svc = new Vigil.Services.HeartbeatService ();

    // First message should contain "prev: genesis"
    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("prev: genesis"));
}

void test_heartbeat_chain_persistence () {
    var dir = TestUtils.make_test_dir ();
    DirUtils.create_with_parents (dir, 0755);

    // Write a chain state file
    var chain_path = Path.build_filename (dir, "heartbeat_chain");
    try {
        FileUtils.set_contents (chain_path, "42\nabcdef1234567890\n");
    } catch (Error e) { assert_not_reached (); }

    // New instance should load chain state
    var svc = new Vigil.Services.HeartbeatService ();
    svc.data_dir = dir;
    svc.start ();
    svc.stop ();

    assert_true (svc.sequence_number == 42);
    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("prev: abcdef1234567890"));

    TestUtils.delete_directory_recursive (dir);
}

void test_heartbeat_chain_no_signature_without_encryption () {
    var svc = new Vigil.Services.HeartbeatService ();
    // encryption is null by default

    var msg = svc.build_heartbeat_message ();
    assert_false (msg.contains ("chain:"));
}

void test_environment_attestation_in_first_heartbeat () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.environment_attestation = "host: testbox | session: X11";

    var msg1 = svc.build_heartbeat_message ();
    assert_true (msg1.contains ("env: host: testbox"));

    // Second message should NOT contain attestation
    var msg2 = svc.build_heartbeat_message ();
    assert_false (msg2.contains ("env:"));
}

void test_environment_attestation_empty_omitted () {
    var svc = new Vigil.Services.HeartbeatService ();
    // environment_attestation is empty by default

    var msg = svc.build_heartbeat_message ();
    assert_false (msg.contains ("env:"));
}

void test_gap_fires_tamper_event () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.interval_seconds = 1;

    svc.start ();
    svc.stop ();

    // Wait >2x the interval to trigger gap detection
    Thread.usleep (3000000);

    bool signal_fired = false;
    int64 reported_gap = 0;
    svc.gap_detected.connect ((gap) => {
        signal_fired = true;
        reported_gap = gap;
    });

    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("NOTICE: Back online"));
    assert_true (msg.contains ("not monitoring for"));
    assert_true (msg.contains ("Going offline"));
    assert_true (signal_fired);
    assert_true (reported_gap >= 2);
}

void test_gap_no_downplay_language () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.interval_seconds = 1;

    svc.start ();
    svc.stop ();

    // Wait >2x the interval
    Thread.usleep (3000000);

    var msg = svc.build_heartbeat_message ();
    assert_false (msg.contains ("this is normal"));
}

void test_capture_digest_in_message () {
    var svc = new Vigil.Services.HeartbeatService ();

    svc.record_capture_hash ("aaaa");
    svc.record_capture_hash ("bbbb");

    var msg = svc.build_heartbeat_message ();
    assert_true (msg.contains ("captures: 2"));
    assert_true (msg.contains ("digest:"));
}

void test_capture_digest_absent_when_no_captures () {
    var svc = new Vigil.Services.HeartbeatService ();

    var msg = svc.build_heartbeat_message ();
    assert_false (msg.contains ("captures:"));
    assert_false (msg.contains ("digest:"));
}

void test_verification_section_below_separator () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.sequence_number = 5;

    var msg = svc.build_heartbeat_message ();

    // Verification data should be below the separator
    var sep_pos = msg.index_of ("\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500");
    assert_true (sep_pos >= 0);
    assert_true (msg.contains ("Verification data"));
    assert_true (msg.contains ("seq: 5"));

    // Seq line should appear AFTER the separator
    var seq_pos = msg.index_of ("seq: 5");
    assert_true (seq_pos > sep_pos);
}

void test_describe_tamper_event_known () {
    var result = Vigil.Services.HeartbeatService.describe_tamper_event (
        "settings_unlocked: lock was disabled");
    assert_true (result.contains ("settings lock was bypassed"));

    result = Vigil.Services.HeartbeatService.describe_tamper_event (
        "crypto_file_tampered: Crypto file account.pickle was deleted");
    assert_true (result.contains ("encryption file was deleted"));
}

void test_describe_tamper_event_unknown () {
    var raw = "unknown_event: some details";
    var result = Vigil.Services.HeartbeatService.describe_tamper_event (raw);
    // Unknown events returned as-is
    assert_true (result == raw);
}

void test_describe_tamper_event_no_colon () {
    var raw = "bare event without colon separator";
    var result = Vigil.Services.HeartbeatService.describe_tamper_event (raw);
    assert_true (result == raw);
}

void test_format_duration () {
    assert_true (Vigil.Services.HeartbeatService.format_duration (0) ==
        "less than a minute");
    assert_true (Vigil.Services.HeartbeatService.format_duration (30) ==
        "less than a minute");
    assert_true (Vigil.Services.HeartbeatService.format_duration (60) ==
        "1 minute");
    assert_true (Vigil.Services.HeartbeatService.format_duration (300) ==
        "5 minutes");
    assert_true (Vigil.Services.HeartbeatService.format_duration (3600) ==
        "1 hour");
    assert_true (Vigil.Services.HeartbeatService.format_duration (7200) ==
        "2 hours");
    assert_true (Vigil.Services.HeartbeatService.format_duration (5400) ==
        "1 hour 30 minutes");
    assert_true (Vigil.Services.HeartbeatService.format_duration (3660) ==
        "1 hour 1 minute");
}

void test_gap_with_tamper_shows_tamper_header () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.interval_seconds = 1;

    // Add a real tamper event
    svc.report_tamper_event ("settings_unlocked: lock was disabled");

    svc.start ();
    svc.stop ();

    Thread.usleep (3000000);

    var msg = svc.build_heartbeat_message ();
    // Should show TAMPER (not NOTICE) because of the real tamper event
    assert_true (msg.contains ("TAMPER ATTEMPT DETECTED!"));
    // Gap info should still be present
    assert_true (msg.contains ("Also, Vigil was not monitoring"));
}

void test_is_warning_event () {
    assert_true (Vigil.Services.HeartbeatService.is_warning_event (
        "~monitoring_disabled: Monitoring has been disabled"));
    assert_true (Vigil.Services.HeartbeatService.is_warning_event (
        "~capture_stalled: No screenshot"));
    assert_false (Vigil.Services.HeartbeatService.is_warning_event (
        "settings_unlocked: lock bypassed"));
    assert_false (Vigil.Services.HeartbeatService.is_warning_event (
        "settings_unlocked: bypassed"));
}

void test_describe_strips_warning_prefix () {
    // Warning-prefixed events should still resolve to the correct description
    var result = Vigil.Services.HeartbeatService.describe_tamper_event (
        "~monitoring_disabled: Monitoring has been disabled via settings");
    assert_true (result.contains ("Screenshot monitoring was turned off"));

    result = Vigil.Services.HeartbeatService.describe_tamper_event (
        "~capture_stalled: No screenshot captured in 300 seconds");
    assert_true (result.contains ("screenshot system has stopped working"));
}

void test_heartbeat_html_output () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.report_tamper_event ("settings_unlocked: lock was disabled");

    string? html;
    svc.build_heartbeat_message (out html);

    assert_true (html != null);
    assert_true (html.contains ("#dc3545")); // red for tamper
    assert_true (html.contains ("TAMPER ATTEMPT DETECTED!"));
}

void test_heartbeat_html_warning_color () {
    var svc = new Vigil.Services.HeartbeatService ();
    svc.report_tamper_event ("~capture_stalled: No screenshot in 300s");

    string? html;
    svc.build_heartbeat_message (out html);

    assert_true (html != null);
    assert_true (html.contains ("#fd7e14")); // orange for warning
    assert_true (html.contains ("WARNING: Issues detected"));
}

void test_network_recovery_message () {
    // Check the message format when consecutive_failures is 0 (no recovery message)
    var svc2 = new Vigil.Services.HeartbeatService ();
    // consecutive_failures is read-only from outside, but we can check
    // the message format when it's 0 (no recovery message)
    var msg = svc2.build_heartbeat_message ();
    assert_false (msg.contains ("could not reach the server"));
}

void test_describe_process_stopped () {
    var result = Vigil.Services.HeartbeatService.describe_tamper_event (
        "process_stopped: Vigil was stopped without a system shutdown");
    assert_true (result.contains ("stopped or uninstalled"));
    assert_true (result.contains ("NOT a system shutdown"));

    // Also works with warning prefix
    var result2 = Vigil.Services.HeartbeatService.describe_tamper_event (
        "~process_stopped: Vigil was stopped without a system shutdown");
    assert_true (result2.contains ("stopped or uninstalled"));
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/heartbeat/build_message_basic",
        test_build_heartbeat_message_basic);
    Test.add_func ("/heartbeat/build_message_tamper_events",
        test_build_heartbeat_message_with_tamper_events);
    Test.add_func ("/heartbeat/build_message_warnings",
        test_build_heartbeat_message_with_warnings);
    Test.add_func ("/heartbeat/build_message_mixed",
        test_build_heartbeat_message_mixed_events);
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
    Test.add_func ("/heartbeat/shutdown_notice_no_matrix",
        test_shutdown_notice_without_matrix);
    Test.add_func ("/heartbeat/sequence_number",
        test_sequence_number_in_message);
    Test.add_func ("/heartbeat/alert_persistence",
        test_alert_persistence);
    Test.add_func ("/heartbeat/message_size_capped",
        test_message_size_capped);
    Test.add_func ("/heartbeat/offline_notice_seq",
        test_offline_notice_includes_seq);
    Test.add_func ("/heartbeat/chain_prev_genesis",
        test_heartbeat_chain_prev_genesis);
    Test.add_func ("/heartbeat/chain_persistence",
        test_heartbeat_chain_persistence);
    Test.add_func ("/heartbeat/chain_no_sig_without_encryption",
        test_heartbeat_chain_no_signature_without_encryption);
    Test.add_func ("/heartbeat/attestation_first_heartbeat",
        test_environment_attestation_in_first_heartbeat);
    Test.add_func ("/heartbeat/attestation_empty_omitted",
        test_environment_attestation_empty_omitted);
    Test.add_func ("/heartbeat/gap_fires_tamper_event",
        test_gap_fires_tamper_event);
    Test.add_func ("/heartbeat/gap_no_downplay_language",
        test_gap_no_downplay_language);
    Test.add_func ("/heartbeat/capture_digest_in_message",
        test_capture_digest_in_message);
    Test.add_func ("/heartbeat/capture_digest_absent_no_captures",
        test_capture_digest_absent_when_no_captures);
    Test.add_func ("/heartbeat/verification_below_separator",
        test_verification_section_below_separator);
    Test.add_func ("/heartbeat/describe_tamper_known",
        test_describe_tamper_event_known);
    Test.add_func ("/heartbeat/describe_tamper_unknown",
        test_describe_tamper_event_unknown);
    Test.add_func ("/heartbeat/describe_tamper_no_colon",
        test_describe_tamper_event_no_colon);
    Test.add_func ("/heartbeat/format_duration",
        test_format_duration);
    Test.add_func ("/heartbeat/gap_with_tamper_shows_tamper",
        test_gap_with_tamper_shows_tamper_header);
    Test.add_func ("/heartbeat/network_recovery",
        test_network_recovery_message);
    Test.add_func ("/heartbeat/is_warning_event",
        test_is_warning_event);
    Test.add_func ("/heartbeat/describe_strips_warning_prefix",
        test_describe_strips_warning_prefix);
    Test.add_func ("/heartbeat/html_output",
        test_heartbeat_html_output);
    Test.add_func ("/heartbeat/html_warning_color",
        test_heartbeat_html_warning_color);
    Test.add_func ("/heartbeat/describe_process_stopped",
        test_describe_process_stopped);

    return Test.run ();
}
