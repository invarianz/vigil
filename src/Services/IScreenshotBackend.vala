/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Interface for screenshot backends.
 *
 * Different display servers (X11, Wayland) require different mechanisms
 * for taking screenshots. This interface abstracts over those differences.
 */
public interface Vigil.Services.IScreenshotBackend : Object {

    /**
     * Take a full-screen screenshot and save it to the given path.
     *
     * @param destination_path The absolute file path to save the screenshot to (PNG).
     * @return true if the screenshot was captured successfully.
     */
    public abstract async bool capture (string destination_path) throws Error;

    /**
     * Human-readable name of this backend, for logging.
     */
    public abstract string backend_name { get; }

    /**
     * Check if this backend is available on the current system.
     *
     * @return true if the backend can be used.
     */
    public abstract async bool is_available ();
}
