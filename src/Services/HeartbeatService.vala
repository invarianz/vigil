/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Sends regular heartbeat pings to the accountability server.
 *
 * This is the core tamper-resistance mechanism: the server EXPECTS
 * regular heartbeats. If they stop arriving, the accountability partner
 * is notified. This handles kill, uninstall, network block, and every
 * other "make it stop running" attack -- silence itself is the signal.
 *
 * Heartbeat payload includes system health info so the server can
 * detect configuration tampering even when the daemon is still running.
 */
public class Vigil.Services.HeartbeatService : Object {

    public signal void heartbeat_sent (DateTime timestamp);
    public signal void heartbeat_failed (string error_message);

    /** Heartbeat interval in seconds. */
    public int interval_seconds { get; set; default = 60; }

    /** Server endpoint URL (same as upload, but /heartbeat path). */
    public string endpoint_url { get; set; default = ""; }

    /** API token for authentication. */
    public string api_token { get; set; default = ""; }

    /** Device identifier. */
    public string device_id { get; set; default = ""; }

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

    private Soup.Session _session;
    private uint _timeout_source = 0;

    construct {
        start_time = new DateTime.now_local ();
        _tamper_events = new GenericArray<string> ();
        _session = new Soup.Session () {
            timeout = 15,
            user_agent = "Vigil-Heartbeat/1.0"
        };
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
     * Build the heartbeat payload as a JSON string.
     */
    public string build_payload () {
        var builder = new Json.Builder ();
        builder.begin_object ();

        builder.set_member_name ("type");
        builder.add_string_value ("heartbeat");

        builder.set_member_name ("timestamp");
        builder.add_string_value (new DateTime.now_local ().format_iso8601 ());

        builder.set_member_name ("device_id");
        builder.add_string_value (device_id);

        builder.set_member_name ("uptime_seconds");
        builder.add_int_value (get_uptime_seconds ());

        builder.set_member_name ("monitoring_active");
        builder.add_boolean_value (monitoring_active);

        builder.set_member_name ("screenshot_permission_ok");
        builder.add_boolean_value (screenshot_permission_ok);

        builder.set_member_name ("config_hash");
        builder.add_string_value (config_hash);

        builder.set_member_name ("screenshots_since_last");
        builder.add_int_value (screenshots_since_last);

        builder.set_member_name ("pending_uploads");
        builder.add_int_value (pending_upload_count);

        // Tamper events
        builder.set_member_name ("tamper_events");
        builder.begin_array ();
        for (int i = 0; i < _tamper_events.length; i++) {
            builder.add_string_value (_tamper_events[i]);
        }
        builder.end_array ();

        builder.end_object ();

        var generator = new Json.Generator ();
        generator.set_root (builder.get_root ());
        return generator.to_data (null);
    }

    /**
     * Send a heartbeat to the server.
     */
    public async bool send_heartbeat () {
        if (endpoint_url == "") {
            return false;
        }

        try {
            var heartbeat_url = derive_heartbeat_url (endpoint_url);
            var payload = build_payload ();

            var message = new Soup.Message ("POST", heartbeat_url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (payload.data)
            );

            if (api_token != "") {
                message.get_request_headers ().append (
                    "Authorization", "Bearer %s".printf (api_token)
                );
            }

            yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status == Soup.Status.OK || status == Soup.Status.ACCEPTED || status == Soup.Status.NO_CONTENT) {
                // Reset counters after successful heartbeat
                screenshots_since_last = 0;
                _tamper_events.remove_range (0, _tamper_events.length);

                heartbeat_sent (new DateTime.now_local ());
                return true;
            } else {
                heartbeat_failed ("HTTP %u".printf (status));
                return false;
            }
        } catch (Error e) {
            heartbeat_failed (e.message);
            return false;
        }
    }

    /**
     * Derive the heartbeat URL from the upload endpoint URL.
     * If endpoint is https://example.com/api/screenshots,
     * heartbeat goes to https://example.com/api/heartbeat
     */
    public static string derive_heartbeat_url (string upload_url) {
        // Replace the last path component with "heartbeat"
        int last_slash = upload_url.last_index_of ("/");
        if (last_slash > 8) { // after "https://"
            return upload_url.substring (0, last_slash) + "/heartbeat";
        }
        return upload_url + "/heartbeat";
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
