/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for the UploadService.
 *
 * Tests configuration validation and error handling.
 * Actual HTTP upload is tested via integration tests.
 */

void test_upload_fails_without_endpoint () {
    var loop = new MainLoop ();
    var service = new Vigil.Services.UploadService ();
    service.endpoint_url = "";

    bool failed = false;
    string? fail_msg = null;
    service.upload_failed.connect ((path, msg) => {
        failed = true;
        fail_msg = msg;
    });

    var now = new DateTime.now_local ();

    service.upload.begin ("/tmp/fake.png", now, (obj, res) => {
        bool result = service.upload.end (res);
        assert_true (result == false);
        loop.quit ();
    });

    Timeout.add_seconds (5, () => {
        loop.quit ();
        return Source.REMOVE;
    });

    loop.run ();

    assert_true (failed);
    assert_true (fail_msg != null);
    assert_true (fail_msg.contains ("endpoint"));
}

void test_upload_fails_with_missing_file () {
    var loop = new MainLoop ();
    var service = new Vigil.Services.UploadService ();
    service.endpoint_url = "https://example.com/upload";

    bool failed = false;
    service.upload_failed.connect ((path, msg) => {
        failed = true;
    });

    var now = new DateTime.now_local ();

    service.upload.begin ("/tmp/nonexistent_screenshot_12345.png", now, (obj, res) => {
        bool result = service.upload.end (res);
        assert_true (result == false);
        loop.quit ();
    });

    Timeout.add_seconds (5, () => {
        loop.quit ();
        return Source.REMOVE;
    });

    loop.run ();

    assert_true (failed);
}

void test_upload_default_properties () {
    var service = new Vigil.Services.UploadService ();

    assert_true (service.endpoint_url == "");
    assert_true (service.api_token == "");
    assert_true (service.device_id == "");
}

void test_upload_properties_are_settable () {
    var service = new Vigil.Services.UploadService ();

    service.endpoint_url = "https://test.com";
    service.api_token = "secret123";
    service.device_id = "device-abc";

    assert_true (service.endpoint_url == "https://test.com");
    assert_true (service.api_token == "secret123");
    assert_true (service.device_id == "device-abc");
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/upload/fails_without_endpoint", test_upload_fails_without_endpoint);
    Test.add_func ("/upload/fails_with_missing_file", test_upload_fails_with_missing_file);
    Test.add_func ("/upload/default_properties", test_upload_default_properties);
    Test.add_func ("/upload/properties_settable", test_upload_properties_are_settable);

    return Test.run ();
}
