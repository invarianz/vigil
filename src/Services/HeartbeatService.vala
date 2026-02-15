/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Sends regular heartbeat messages to the Matrix room.
 *
 * This is the core tamper-resistance mechanism: the accountability partner
 * EXPECTS regular heartbeats. If they stop arriving, something is wrong.
 * Silence itself is the signal -- this handles kill, uninstall, network
 * block, and every other "make it stop running" attack.
 *
 * Heartbeats include system health info so the partner can detect
 * configuration tampering even when the daemon is still running.
 */
public class Vigil.Services.HeartbeatService : Object {

    public signal void heartbeat_sent (DateTime timestamp);
    public signal void heartbeat_failed (string error_message);

    /** Heartbeat interval in seconds. */
    public int interval_seconds { get; set; default = 60; }

    /** Whether the heartbeat loop is running. */
    public bool is_running { get; private set; default = false; }

    /** Daemon start time, for uptime calculation. */
    public DateTime start_time { get; private set; }

    /** Count of screenshots taken since last heartbeat. */
    public int screenshots_since_last { get; set; default = 0; }

    /** Current pending upload count. */
    public int pending_upload_count { get; set; default = 0; }

    /** Whether screenshot monitoring is active. */
    public bool monitoring_active { get; set; default = false; }

    /** Whether screenshot permission is granted. */
    public bool screenshot_permission_ok { get; set; default = true; }

    /** Hash of current configuration for tamper detection. */
    public string config_hash { get; set; default = ""; }

    /** List of tamper events since last heartbeat. */
    private GenericArray<string> _tamper_events;

    private Vigil.Services.MatrixTransportService? _matrix_svc;
    private uint _timeout_source = 0;

    /**
     * Create a HeartbeatService.
     *
     * @param matrix_svc The Matrix transport to send heartbeats through.
     *                   May be null for testing.
     */
    public HeartbeatService (Vigil.Services.MatrixTransportService? matrix_svc = null) {
        _matrix_svc = matrix_svc;
    }

    construct {
        start_time = new DateTime.now_local ();
        _tamper_events = new GenericArray<string> ();
    }

    /**
     * Add a tamper event to be reported in the next heartbeat.
     */
    public void report_tamper_event (string event_description) {
        _tamper_events.add (event_description);
    }

    /**
     * Start the heartbeat loop.
     */
    public void start () {
        if (is_running) {
            return;
        }

        is_running = true;
        start_time = new DateTime.now_local ();

        // Send first heartbeat immediately
        send_heartbeat.begin ();
        schedule_next ();
    }

    /**
     * Stop the heartbeat loop.
     */
    public void stop () {
        if (!is_running) {
            return;
        }

        if (_timeout_source != 0) {
            Source.remove (_timeout_source);
            _timeout_source = 0;
        }

        is_running = false;
    }

    /**
     * Calculate uptime in seconds since daemon start.
     */
    public int64 get_uptime_seconds () {
        var now = new DateTime.now_local ();
        return now.difference (start_time) / TimeSpan.SECOND;
    }

    /**
     * Build a human-readable heartbeat message for the Matrix room.
     */
    public string build_heartbeat_message () {
        var uptime = get_uptime_seconds ();
        var hours = uptime / 3600;
        var minutes = (uptime % 3600) / 60;

        var sb = new StringBuilder ();
        sb.append ("Vigil active | uptime: %lldh %lldm | screenshots: %d | pending: %d".printf (
            hours, minutes, screenshots_since_last, pending_upload_count
        ));

        if (_tamper_events.length > 0) {
            sb.append ("\nTamper events:");
            for (int i = 0; i < _tamper_events.length; i++) {
                sb.append ("\n  - %s".printf (_tamper_events[i]));
            }
        }

        return sb.str;
    }

    /**
     * Send a heartbeat via Matrix.
     */
    public async bool send_heartbeat () {
        if (_matrix_svc == null || !_matrix_svc.is_configured) {
            heartbeat_failed ("Matrix transport not configured");
            return false;
        }

        var message = build_heartbeat_message ();
        var sent = yield _matrix_svc.send_text_message (message);

        if (sent) {
            screenshots_since_last = 0;
            _tamper_events.remove_range (0, _tamper_events.length);
            heartbeat_sent (new DateTime.now_local ());
            return true;
        } else {
            heartbeat_failed ("Failed to send heartbeat via Matrix");
            return false;
        }
    }

    private void schedule_next () {
        if (!is_running) {
            return;
        }

        _timeout_source = Timeout.add_seconds ((uint) interval_seconds, () => {
            _timeout_source = 0;
            send_heartbeat.begin ();

            if (is_running) {
                schedule_next ();
            }

            return Source.REMOVE;
        });
    }
}
