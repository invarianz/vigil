/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for the session type detector.
 *
 * These tests manipulate environment variables to simulate different
 * display server configurations.
 */

void test_detect_wayland_from_xdg_session_type () {
    Environment.set_variable ("XDG_SESSION_TYPE", "wayland", true);
    Environment.unset_variable ("WAYLAND_DISPLAY");
    Environment.unset_variable ("DISPLAY");

    var result = Vigil.Utils.detect_session_type ();
    assert_true (result == Vigil.Utils.SessionType.WAYLAND);
}

void test_detect_x11_from_xdg_session_type () {
    Environment.set_variable ("XDG_SESSION_TYPE", "x11", true);
    Environment.unset_variable ("WAYLAND_DISPLAY");
    Environment.unset_variable ("DISPLAY");

    var result = Vigil.Utils.detect_session_type ();
    assert_true (result == Vigil.Utils.SessionType.X11);
}

void test_detect_wayland_from_wayland_display () {
    Environment.unset_variable ("XDG_SESSION_TYPE");
    Environment.set_variable ("WAYLAND_DISPLAY", "wayland-0", true);
    Environment.unset_variable ("DISPLAY");

    var result = Vigil.Utils.detect_session_type ();
    assert_true (result == Vigil.Utils.SessionType.WAYLAND);
}

void test_detect_x11_from_display () {
    Environment.unset_variable ("XDG_SESSION_TYPE");
    Environment.unset_variable ("WAYLAND_DISPLAY");
    Environment.set_variable ("DISPLAY", ":0", true);

    var result = Vigil.Utils.detect_session_type ();
    assert_true (result == Vigil.Utils.SessionType.X11);
}

void test_detect_unknown_no_env () {
    Environment.unset_variable ("XDG_SESSION_TYPE");
    Environment.unset_variable ("WAYLAND_DISPLAY");
    Environment.unset_variable ("DISPLAY");

    var result = Vigil.Utils.detect_session_type ();
    assert_true (result == Vigil.Utils.SessionType.UNKNOWN);
}

void test_xdg_session_type_takes_precedence () {
    // XDG_SESSION_TYPE should take priority over WAYLAND_DISPLAY
    Environment.set_variable ("XDG_SESSION_TYPE", "x11", true);
    Environment.set_variable ("WAYLAND_DISPLAY", "wayland-0", true);
    Environment.set_variable ("DISPLAY", ":0", true);

    var result = Vigil.Utils.detect_session_type ();
    assert_true (result == Vigil.Utils.SessionType.X11);
}

void test_session_type_to_string () {
    assert_true (Vigil.Utils.SessionType.X11.to_string () == "X11");
    assert_true (Vigil.Utils.SessionType.WAYLAND.to_string () == "Wayland");
    assert_true (Vigil.Utils.SessionType.UNKNOWN.to_string () == "Unknown");
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/session_detector/wayland_from_xdg", test_detect_wayland_from_xdg_session_type);
    Test.add_func ("/session_detector/x11_from_xdg", test_detect_x11_from_xdg_session_type);
    Test.add_func ("/session_detector/wayland_from_env", test_detect_wayland_from_wayland_display);
    Test.add_func ("/session_detector/x11_from_display", test_detect_x11_from_display);
    Test.add_func ("/session_detector/unknown", test_detect_unknown_no_env);
    Test.add_func ("/session_detector/precedence", test_xdg_session_type_takes_precedence);
    Test.add_func ("/session_detector/to_string", test_session_type_to_string);

    return Test.run ();
}
