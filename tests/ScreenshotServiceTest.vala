/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Integration tests for the ScreenshotService.
 */

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

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/screenshot_service/no_backend_failure", test_screenshot_service_no_backend_emits_failure);
    Test.add_func ("/screenshot_service/initialize", test_screenshot_service_initialize);

    return Test.run ();
}
