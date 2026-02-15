/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * High-level screenshot service that selects the appropriate backend
 * based on the current session type and backend availability.
 *
 * Falls back gracefully: Portal -> Gala -> error.
 */
public class Vigil.Services.ScreenshotService : Object {

    public signal void screenshot_taken (string file_path);
    public signal void screenshot_failed (string error_message);

    private IScreenshotBackend? _active_backend = null;

    public string? active_backend_name {
        get {
            return _active_backend != null ? _active_backend.backend_name : null;
        }
    }

    /**
     * Initialize the service by detecting and selecting the best backend.
     */
    public async void initialize () {
        var session = Vigil.Utils.detect_session_type ();
        debug ("Detected session type: %s", session.to_string ());

        if (session == Vigil.Utils.SessionType.WAYLAND) {
            // On Wayland, prefer the portal backend
            var portal = new PortalScreenshotBackend ();
            if (yield portal.is_available ()) {
                _active_backend = portal;
                debug ("Using Portal screenshot backend");
                return;
            }
        }

        // On X11, try Gala first (direct, no confirmation needed)
        var gala = new GalaScreenshotBackend ();
        if (yield gala.is_available ()) {
            _active_backend = gala;
            debug ("Using Gala screenshot backend");
            return;
        }

        // On X11 or if Gala isn't available, fall back to Portal
        var portal_fallback = new PortalScreenshotBackend ();
        if (yield portal_fallback.is_available ()) {
            _active_backend = portal_fallback;
            debug ("Using Portal screenshot backend (fallback)");
            return;
        }

        warning ("No screenshot backend available!");
    }

    /**
     * Take a screenshot and save it to the given path.
     *
     * @param destination_path Where to save the screenshot PNG.
     * @return true on success.
     */
    public async bool take_screenshot (string destination_path) {
        if (_active_backend == null) {
            var msg = "No screenshot backend is available";
            warning (msg);
            screenshot_failed (msg);
            return false;
        }

        try {
            bool success = yield _active_backend.capture (destination_path);
            if (success) {
                screenshot_taken (destination_path);
            }
            return success;
        } catch (Error e) {
            var msg = "Screenshot failed (%s): %s".printf (
                _active_backend.backend_name, e.message
            );
            warning (msg);
            screenshot_failed (msg);
            return false;
        }
    }
}
