/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

namespace Vigil.Utils {

    public enum SessionType {
        X11,
        WAYLAND,
        UNKNOWN;

        public string to_string () {
            switch (this) {
                case X11: return "X11";
                case WAYLAND: return "Wayland";
                default: return "Unknown";
            }
        }
    }

    public SessionType detect_session_type () {
        string? session_type = Environment.get_variable ("XDG_SESSION_TYPE");
        if (session_type != null) {
            if (session_type == "wayland") {
                return SessionType.WAYLAND;
            }
            if (session_type == "x11") {
                return SessionType.X11;
            }
        }

        if (Environment.get_variable ("WAYLAND_DISPLAY") != null) {
            return SessionType.WAYLAND;
        }

        if (Environment.get_variable ("DISPLAY") != null) {
            return SessionType.X11;
        }

        return SessionType.UNKNOWN;
    }
}
