/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Integration tests for the ScreenshotService.
 *
 * Uses a mock backend to test the service logic without needing
 * an actual display server.
 */

/**
 * Mock screenshot backend for testing.
 */
public class MockScreenshotBackend : Object, Vigil.Services.IScreenshotBackend {

    public string backend_name {
        get { return "Mock"; }
    }

    public bool should_succeed { get; set; default = true; }
    public bool is_backend_available { get; set; default = true; }
    public int capture_count { get; private set; default = 0; }
    public string? last_destination { get; private set; default = null; }

    public async bool is_available () {
        return is_backend_available;
    }

    public async bool capture (string destination_path) throws Error {
        capture_count++;
        last_destination = destination_path;

        if (!should_succeed) {
            throw new IOError.FAILED ("Mock capture failure");
        }

        var dest_file = File.new_for_path (destination_path);
        var dest_dir = dest_file.get_parent ();
        if (dest_dir != null && !dest_dir.query_exists ()) {
            dest_dir.make_directory_with_parents (null);
        }

        FileUtils.set_contents (destination_path, "fake screenshot data");
        return true;
    }
}

void test_screenshot_service_no_backend_emits_failure () {
    var loop = new MainLoop ();
    var service = new Vigil.Services.ScreenshotService ();

    // Don't initialize -- leave with no backend
    bool failed = false;
    service.screenshot_failed.connect ((msg) => {
        failed = true;
    });

    // Expect the "No screenshot backend is available" warning
    Test.expect_message (null, LogLevelFlags.LEVEL_WARNING, "*No screenshot backend*");

    service.take_screenshot.begin ("/tmp/test.png", (obj, res) => {
        bool result = service.take_screenshot.end (res);
        assert_true (result == false);
        loop.quit ();
    });

    Timeout.add_seconds (5, () => {
        loop.quit ();
        return Source.REMOVE;
    });

    loop.run ();

    Test.assert_expected_messages ();

    assert_true (failed);
}

void test_screenshot_service_initialize () {
    // Initialize should either find a backend (graphical session)
    // or gracefully find none (headless/CI) without crashing.
    var loop = new MainLoop ();
    var service = new Vigil.Services.ScreenshotService ();

    // In headless environments (CI containers), no backend will be found
    // and initialize() emits a g_warning. GTest treats warnings as fatal,
    // so we must expect it to prevent the test from aborting.
    var display = Environment.get_variable ("DISPLAY");
    var wayland = Environment.get_variable ("WAYLAND_DISPLAY");
    bool headless = (display == null || display == "") &&
                    (wayland == null || wayland == "");

    if (headless) {
        Test.expect_message (null, LogLevelFlags.LEVEL_WARNING,
            "*No screenshot backend*");
    }

    service.initialize.begin ((obj, res) => {
        service.initialize.end (res);

        if (service.active_backend_name == null) {
            debug ("No backend found (headless environment)");
        } else {
            debug ("Backend found: %s", service.active_backend_name);
        }

        loop.quit ();
    });

    Timeout.add_seconds (10, () => {
        loop.quit ();
        return Source.REMOVE;
    });

    loop.run ();

    if (headless) {
        Test.assert_expected_messages ();
    }
}

void test_mock_backend_interface () {
    var loop = new MainLoop ();
    var mock = new MockScreenshotBackend ();

    assert_true (mock.backend_name == "Mock");
    assert_true (mock.capture_count == 0);

    var path = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-mock-test-%s.png".printf (GLib.Uuid.string_random ().substring (0, 8))
    );

    mock.capture.begin (path, (obj, res) => {
        try {
            bool result = mock.capture.end (res);
            assert_true (result);
            assert_true (mock.capture_count == 1);
            assert_true (mock.last_destination == path);
            assert_true (FileUtils.test (path, FileTest.EXISTS));
        } catch (Error e) {
            assert_not_reached ();
        }

        FileUtils.remove (path);
        loop.quit ();
    });

    loop.run ();
}

void test_mock_backend_failure () {
    var loop = new MainLoop ();
    var mock = new MockScreenshotBackend ();
    mock.should_succeed = false;

    mock.capture.begin ("/tmp/test.png", (obj, res) => {
        try {
            mock.capture.end (res);
            assert_not_reached ();
        } catch (Error e) {
            assert_true (e.message.contains ("Mock capture failure"));
            assert_true (mock.capture_count == 1);
        }
        loop.quit ();
    });

    loop.run ();
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/screenshot_service/no_backend_failure", test_screenshot_service_no_backend_emits_failure);
    Test.add_func ("/screenshot_service/initialize", test_screenshot_service_initialize);
    Test.add_func ("/screenshot_service/mock_backend", test_mock_backend_interface);
    Test.add_func ("/screenshot_service/mock_failure", test_mock_backend_failure);

    return Test.run ();
}
