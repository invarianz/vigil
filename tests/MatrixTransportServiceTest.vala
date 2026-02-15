/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Tests for MatrixTransportService.
 *
 * These test configuration checking, transaction ID generation,
 * and error paths. Actual HTTP calls to a Matrix server are not
 * tested here.
 */

void test_not_configured_by_default () {
    var svc = new Vigil.Services.MatrixTransportService ();
    assert_false (svc.is_configured);
}

void test_configured_when_all_set () {
    var svc = new Vigil.Services.MatrixTransportService ();
    svc.homeserver_url = "https://matrix.example.com";
    svc.access_token = "syt_test_token";
    svc.room_id = "!test:matrix.example.com";
    assert_true (svc.is_configured);
}

void test_not_configured_missing_room () {
    var svc = new Vigil.Services.MatrixTransportService ();
    svc.homeserver_url = "https://matrix.example.com";
    svc.access_token = "syt_test_token";
    svc.room_id = "";
    assert_false (svc.is_configured);
}

void test_not_configured_missing_token () {
    var svc = new Vigil.Services.MatrixTransportService ();
    svc.homeserver_url = "https://matrix.example.com";
    svc.access_token = "";
    svc.room_id = "!test:matrix.example.com";
    assert_false (svc.is_configured);
}

void test_txn_id_unique () {
    var svc = new Vigil.Services.MatrixTransportService ();
    var id1 = svc.generate_txn_id ();
    var id2 = svc.generate_txn_id ();
    assert_true (id1 != id2);
}

void test_txn_id_has_prefix () {
    var svc = new Vigil.Services.MatrixTransportService ();
    var id = svc.generate_txn_id ();
    assert_true (id.has_prefix ("vigil_"));
}

void test_send_screenshot_fails_unconfigured () {
    var svc = new Vigil.Services.MatrixTransportService ();

    var loop = new MainLoop ();
    bool result = true;
    string? failed_path = null;

    Test.expect_message (null, LogLevelFlags.LEVEL_WARNING, "*not configured*");

    svc.screenshot_send_failed.connect ((path, msg) => {
        failed_path = path;
    });

    svc.send_screenshot.begin ("/tmp/test.png", new DateTime.now_local (), (obj, res) => {
        result = svc.send_screenshot.end (res);
        loop.quit ();
    });

    Timeout.add (100, () => {
        loop.quit ();
        return Source.REMOVE;
    });
    loop.run ();

    Test.assert_expected_messages ();
    assert_false (result);
    assert_true (failed_path == "/tmp/test.png");
}

void test_send_text_fails_unconfigured () {
    var svc = new Vigil.Services.MatrixTransportService ();

    var loop = new MainLoop ();
    bool result = true;

    svc.send_text_message.begin ("test", (obj, res) => {
        result = svc.send_text_message.end (res);
        loop.quit ();
    });

    Timeout.add (100, () => {
        loop.quit ();
        return Source.REMOVE;
    });
    loop.run ();

    assert_false (result);
}

void test_verify_connection_fails_unconfigured () {
    var svc = new Vigil.Services.MatrixTransportService ();

    var loop = new MainLoop ();
    string? user_id = "something";

    svc.verify_connection.begin ((obj, res) => {
        user_id = svc.verify_connection.end (res);
        loop.quit ();
    });

    Timeout.add (100, () => {
        loop.quit ();
        return Source.REMOVE;
    });
    loop.run ();

    assert_true (user_id == null);
}

void test_properties_settable () {
    var svc = new Vigil.Services.MatrixTransportService ();
    svc.homeserver_url = "https://hs.test";
    svc.access_token = "tok123";
    svc.room_id = "!room:test";

    assert_true (svc.homeserver_url == "https://hs.test");
    assert_true (svc.access_token == "tok123");
    assert_true (svc.room_id == "!room:test");
}

void test_encryption_property () {
    var svc = new Vigil.Services.MatrixTransportService ();
    assert_true (svc.encryption == null);

    var enc = new Vigil.Services.EncryptionService ();
    svc.encryption = enc;
    assert_true (svc.encryption == enc);
}

void test_last_user_id_default () {
    var svc = new Vigil.Services.MatrixTransportService ();
    assert_true (svc.last_user_id == "");
    assert_true (svc.last_device_id == "");
}

void test_create_room_fails_unconfigured () {
    var svc = new Vigil.Services.MatrixTransportService ();

    var loop = new MainLoop ();
    string? room_id = "something";

    svc.create_encrypted_room.begin ("@partner:test", (obj, res) => {
        room_id = svc.create_encrypted_room.end (res);
        loop.quit ();
    });

    Timeout.add (100, () => {
        loop.quit ();
        return Source.REMOVE;
    });
    loop.run ();

    assert_true (room_id == null);
}

void test_login_fails_with_bad_url () {
    var svc = new Vigil.Services.MatrixTransportService ();

    var loop = new MainLoop ();
    string? token = "something";

    Test.expect_message (null, LogLevelFlags.LEVEL_WARNING, "*login*");

    svc.login.begin ("http://localhost:1", "user", "pass", (obj, res) => {
        token = svc.login.end (res);
        loop.quit ();
    });

    Timeout.add (5000, () => {
        loop.quit ();
        return Source.REMOVE;
    });
    loop.run ();

    Test.assert_expected_messages ();
    assert_true (token == null);
}

void test_discover_rejects_http_url () {
    var svc = new Vigil.Services.MatrixTransportService ();

    string? result = null;
    var loop = new MainLoop ();

    // http:// URLs should be rejected
    Test.expect_message (null, LogLevelFlags.LEVEL_WARNING,
        "*Refusing insecure http://*");

    svc.discover_homeserver.begin ("http://evil.example.com", (obj, res) => {
        result = svc.discover_homeserver.end (res);
        loop.quit ();
    });
    Timeout.add (500, () => { loop.quit (); return Source.REMOVE; });
    loop.run ();

    Test.assert_expected_messages ();
    assert_true (result == null);
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/matrix/not_configured_default", test_not_configured_by_default);
    Test.add_func ("/matrix/configured_all_set", test_configured_when_all_set);
    Test.add_func ("/matrix/not_configured_missing_room", test_not_configured_missing_room);
    Test.add_func ("/matrix/not_configured_missing_token", test_not_configured_missing_token);
    Test.add_func ("/matrix/txn_id_unique", test_txn_id_unique);
    Test.add_func ("/matrix/txn_id_prefix", test_txn_id_has_prefix);
    Test.add_func ("/matrix/send_screenshot_unconfigured", test_send_screenshot_fails_unconfigured);
    Test.add_func ("/matrix/send_text_unconfigured", test_send_text_fails_unconfigured);
    Test.add_func ("/matrix/verify_connection_unconfigured", test_verify_connection_fails_unconfigured);
    Test.add_func ("/matrix/properties_settable", test_properties_settable);
    Test.add_func ("/matrix/login_fails_bad_url", test_login_fails_with_bad_url);
    Test.add_func ("/matrix/encryption_property", test_encryption_property);
    Test.add_func ("/matrix/last_user_id_default", test_last_user_id_default);
    Test.add_func ("/matrix/create_room_unconfigured", test_create_room_fails_unconfigured);
    Test.add_func ("/matrix/discover_rejects_http", test_discover_rejects_http_url);

    return Test.run ();
}
