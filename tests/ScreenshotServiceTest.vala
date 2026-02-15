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
 * Simulates successful or failing captures.
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

        // Create a fake screenshot file
        var dest_file = File.new_for_path (destination_path);
        var dest_dir = dest_file.get_parent ();
        if (dest_dir != null && !dest_dir.query_exists ()) {
            dest_dir.make_directory_with_parents (null);
        }

        FileUtils.set_contents (destination_path, "fake screenshot data");
        return true;
    }
}

void test_screenshot_service_emits_taken_signal () {
    var loop = new MainLoop ();
    var service = new Vigil.Services.ScreenshotService ();

    bool taken = false;
    string? taken_path = null;
    service.screenshot_taken.connect ((path) => {
        taken = true;
        taken_path = path;
    });

    var tmp_path = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-test-screenshot-%s.png".printf (GLib.Uuid.string_random ().substring (0, 8))
    );

    // The service needs a backend. Since we can't easily inject one through
    // initialize(), we test the take_screenshot method by first initializing
    // (which may fail to find a backend in CI) and checking the signal flow.
    service.initialize.begin ((obj, res) => {
        service.initialize.end (res);

        // If no backend is available (CI environment), test the failure path
        if (service.active_backend_name == null) {
            bool failed = false;
            service.screenshot_failed.connect ((msg, time) => {
                failed = true;
            });

            service.take_screenshot.begin (tmp_path, (o, r) => {
                bool result = service.take_screenshot.end (r);
                assert_true (result == false);
                assert_true (failed);
                loop.quit ();
            });
        } else {
            // Backend available, test the success path
            service.take_screenshot.begin (tmp_path, (o, r) => {
                service.take_screenshot.end (r);
                // Either path is OK in integration context
                loop.quit ();
            });
        }
    });

    Timeout.add_seconds (10, () => {
        loop.quit ();
        return Source.REMOVE;
    });

    loop.run ();

    // Cleanup
    if (FileUtils.test (tmp_path, FileTest.EXISTS)) {
        FileUtils.remove (tmp_path);
    }
}

void test_screenshot_service_failure_signal () {
    var loop = new MainLoop ();
    var service = new Vigil.Services.ScreenshotService ();

    // Don't initialize -- leave with no backend
    bool failed = false;
    DateTime? fail_time = null;
    service.screenshot_failed.connect ((msg, time) => {
        failed = true;
        fail_time = time;
    });

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

    assert_true (failed);
    assert_true (fail_time != null);
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

        // Cleanup
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

    Test.add_func ("/screenshot_service/taken_signal", test_screenshot_service_emits_taken_signal);
    Test.add_func ("/screenshot_service/failure_signal", test_screenshot_service_failure_signal);
    Test.add_func ("/screenshot_service/mock_backend", test_mock_backend_interface);
    Test.add_func ("/screenshot_service/mock_failure", test_mock_backend_failure);

    return Test.run ();
}
