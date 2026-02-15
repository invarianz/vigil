/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Sends screenshots and heartbeat messages to a Matrix room.
 *
 * Uses the Matrix client-server API (HTTP/JSON) via libsoup.
 * Screenshots are uploaded to the content repository, then posted
 * as m.image events in the configured room.
 *
 * For end-to-end encryption, configure the homeserver URL to point
 * at a pantalaimon proxy (http://localhost:8009). Pantalaimon handles
 * all Olm/Megolm crypto transparently -- this service just sends
 * plain Matrix API calls.
 *
 * Matrix API reference:
 *   Upload: POST /_matrix/media/v3/upload
 *   Send event: PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
 */
public class Vigil.Services.MatrixTransportService : Object {

    public signal void screenshot_sent (string file_path, string event_id);
    public signal void screenshot_send_failed (string file_path, string error_message);
    public signal void heartbeat_message_sent ();
    public signal void heartbeat_message_failed (string error_message);

    /** Matrix homeserver URL (or pantalaimon proxy URL for E2EE). */
    public string homeserver_url { get; set; default = ""; }

    /** Matrix access token for authentication. */
    public string access_token { get; set; default = ""; }

    /** Matrix room ID to send screenshots to (e.g. !abc123:matrix.org). */
    public string room_id { get; set; default = ""; }

    /** Device display name for messages. */
    public string device_name { get; set; default = "Vigil"; }

    /** Whether this transport is configured and usable. */
    public bool is_configured {
        get {
            return homeserver_url != "" && access_token != "" && room_id != "";
        }
    }

    private Soup.Session _session;
    private int64 _txn_counter = 0;

    private static string strip_trailing_slash (string url) {
        if (url.has_suffix ("/")) {
            return url.substring (0, url.length - 1);
        }
        return url;
    }

    construct {
        _session = new Soup.Session () {
            timeout = 30,
            user_agent = "Vigil-Matrix/1.0"
        };
    }

    /**
     * Generate a unique transaction ID for idempotent event sending.
     */
    public string generate_txn_id () {
        _txn_counter++;
        return "vigil_%lld_%s".printf (
            _txn_counter,
            GLib.Uuid.string_random ().substring (0, 8)
        );
    }

    /**
     * Upload a screenshot image to the Matrix content repository.
     *
     * @param file_path Path to the PNG screenshot file.
     * @return The mxc:// content URI, or null on failure.
     */
    public async string? upload_media (string file_path) {
        if (!is_configured) {
            return null;
        }

        try {
            var file = File.new_for_path (file_path);
            if (!file.query_exists ()) {
                screenshot_send_failed (file_path, "File not found: %s".printf (file_path));
                return null;
            }

            var file_info = yield file.query_info_async (
                "standard::size",
                FileQueryInfoFlags.NONE,
                Priority.DEFAULT,
                null
            );
            var file_size = file_info.get_size ();

            var input_stream = yield file.read_async (Priority.DEFAULT, null);
            var bytes = yield input_stream.read_bytes_async ((size_t) file_size, Priority.DEFAULT, null);
            input_stream.close ();

            var filename = Path.get_basename (file_path);
            var upload_url = "%s/_matrix/media/v3/upload?filename=%s".printf (
                strip_trailing_slash (homeserver_url),
                GLib.Uri.escape_string (filename, null, true)
            );

            var message = new Soup.Message ("POST", upload_url);
            message.set_request_body_from_bytes ("image/png", bytes);
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Matrix media upload failed (HTTP %u): %s", status, resp ?? "");
                return null;
            }

            // Parse {"content_uri": "mxc://..."}
            var parser = new Json.Parser ();
            parser.load_from_data ((string) response_bytes.get_data ());
            var root = parser.get_root ().get_object ();

            if (root.has_member ("content_uri")) {
                return root.get_string_member ("content_uri");
            } else {
                warning ("Matrix upload response missing content_uri");
                return null;
            }
        } catch (Error e) {
            warning ("Matrix media upload error: %s", e.message);
            return null;
        }
    }

    /**
     * Send a room event (m.room.message) to the configured room.
     *
     * @param event_type The event type (e.g. "m.room.message").
     * @param content_json The JSON content body as a string.
     * @return The event ID, or null on failure.
     */
    public async string? send_room_event (string event_type, string content_json) {
        if (!is_configured) {
            return null;
        }

        try {
            var txn_id = generate_txn_id ();
            var encoded_room = GLib.Uri.escape_string (room_id, null, true);

            var url = "%s/_matrix/client/v3/rooms/%s/send/%s/%s".printf (
                strip_trailing_slash (homeserver_url),
                encoded_room,
                event_type,
                txn_id
            );

            var message = new Soup.Message ("PUT", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (content_json.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Matrix send event failed (HTTP %u): %s", status, resp ?? "");
                return null;
            }

            var parser = new Json.Parser ();
            parser.load_from_data ((string) response_bytes.get_data ());
            var root = parser.get_root ().get_object ();

            if (root.has_member ("event_id")) {
                return root.get_string_member ("event_id");
            }
            return null;
        } catch (Error e) {
            warning ("Matrix send event error: %s", e.message);
            return null;
        }
    }

    /**
     * Upload and send a screenshot to the Matrix room.
     *
     * @param file_path Path to the screenshot PNG file.
     * @param capture_time When the screenshot was taken.
     * @return true if successfully sent.
     */
    public async bool send_screenshot (string file_path, DateTime capture_time) {
        if (!is_configured) {
            var msg = "Matrix transport not configured";
            warning (msg);
            screenshot_send_failed (file_path, msg);
            return false;
        }

        // Step 1: Upload the image
        var content_uri = yield upload_media (file_path);
        if (content_uri == null) {
            screenshot_send_failed (file_path, "Media upload failed");
            return false;
        }

        // Step 2: Send the image event
        var time_str = capture_time.format ("%Y-%m-%d %H:%M:%S");
        var body = "Screenshot %s".printf (time_str);

        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("msgtype");
        builder.add_string_value ("m.image");
        builder.set_member_name ("body");
        builder.add_string_value (body);
        builder.set_member_name ("url");
        builder.add_string_value (content_uri);
        builder.set_member_name ("info");
        builder.begin_object ();
        builder.set_member_name ("mimetype");
        builder.add_string_value ("image/png");
        builder.end_object ();
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        var content_json = gen.to_data (null);

        var event_id = yield send_room_event ("m.room.message", content_json);
        if (event_id == null) {
            screenshot_send_failed (file_path, "Failed to send image event");
            return false;
        }

        debug ("Matrix: sent screenshot %s as %s", file_path, event_id);
        screenshot_sent (file_path, event_id);
        return true;
    }

    /**
     * Send a text message to the Matrix room (for heartbeats/alerts).
     *
     * @param text The message text.
     * @return true if successfully sent.
     */
    public async bool send_text_message (string text) {
        if (!is_configured) {
            heartbeat_message_failed ("Matrix transport not configured");
            return false;
        }

        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("msgtype");
        builder.add_string_value ("m.text");
        builder.set_member_name ("body");
        builder.add_string_value (text);
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        var content_json = gen.to_data (null);

        var event_id = yield send_room_event ("m.room.message", content_json);
        if (event_id == null) {
            heartbeat_message_failed ("Failed to send text event");
            return false;
        }

        heartbeat_message_sent ();
        return true;
    }

    /**
     * Send a heartbeat status message to the Matrix room.
     *
     * @param screenshots_count Screenshots taken since last heartbeat.
     * @param pending_count Number of screenshots pending delivery.
     * @param uptime_seconds Daemon uptime in seconds.
     * @return true if successfully sent.
     */
    public async bool send_heartbeat (int screenshots_count, int pending_count, int64 uptime_seconds) {
        var hours = uptime_seconds / 3600;
        var minutes = (uptime_seconds % 3600) / 60;

        var text = "Vigil active | uptime: %lldh %lldm | screenshots: %d | pending: %d".printf (
            hours, minutes, screenshots_count, pending_count
        );

        return yield send_text_message (text);
    }

    /**
     * Send a tamper alert message to the Matrix room.
     *
     * @param event_type The type of tamper event.
     * @param details Description of the issue.
     * @return true if successfully sent.
     */
    public async bool send_alert (string event_type, string details) {
        var text = "ALERT [%s]: %s".printf (event_type, details);
        return yield send_text_message (text);
    }

    /**
     * Verify the Matrix connection by calling the /whoami endpoint.
     *
     * @return The Matrix user ID if successful, null otherwise.
     */
    public async string? verify_connection () {
        if (homeserver_url == "" || access_token == "") {
            return null;
        }

        try {
            var url = "%s/_matrix/client/v3/account/whoami".printf (
                strip_trailing_slash (homeserver_url)
            );

            var message = new Soup.Message ("GET", url);
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                return null;
            }

            var parser = new Json.Parser ();
            parser.load_from_data ((string) response_bytes.get_data ());
            var root = parser.get_root ().get_object ();

            if (root.has_member ("user_id")) {
                return root.get_string_member ("user_id");
            }
            return null;
        } catch (Error e) {
            warning ("Matrix whoami failed: %s", e.message);
            return null;
        }
    }
}
