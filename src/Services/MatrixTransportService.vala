/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Sends screenshots and messages to a Matrix room.
 *
 * Uses the Matrix client-server API (HTTP/JSON) via libsoup.
 * With native E2EE via libolm, this service handles:
 *   - Login (m.login.password)
 *   - Homeserver auto-discovery via .well-known
 *   - Encrypted room creation with partner invite
 *   - Device key upload/query/claim
 *   - Room key sharing via to-device messages
 *   - Sending encrypted events (m.room.encrypted)
 *   - Media upload and encrypted image sending
 *
 * Matrix API reference:
 *   Login:       POST /_matrix/client/v3/login
 *   Upload:      POST /_matrix/media/v3/upload
 *   Send event:  PUT  /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
 *   Who am I:    GET  /_matrix/client/v3/account/whoami
 *   Create room: POST /_matrix/client/v3/createRoom
 *   Keys upload: POST /_matrix/client/v3/keys/upload
 *   Keys query:  POST /_matrix/client/v3/keys/query
 *   Keys claim:  POST /_matrix/client/v3/keys/claim
 *   To-device:   PUT  /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
 */
public class Vigil.Services.MatrixTransportService : Object {

    public signal void screenshot_sent (string file_path, string event_id);
    public signal void screenshot_send_failed (string file_path, string error_message);

    /** Matrix homeserver URL (trailing slash stripped automatically). */
    private string _homeserver_url = "";
    public string homeserver_url {
        get { return _homeserver_url; }
        set { _homeserver_url = strip_trailing_slash (value); }
    }

    /** Matrix access token for authentication. */
    public string access_token { get; set; default = ""; }

    /** Matrix room ID to send screenshots to (e.g. !abc123:matrix.org). */
    public string room_id { get; set; default = ""; }

    /** Whether this transport is configured and usable. */
    public bool is_configured {
        get {
            return homeserver_url != "" && access_token != "" && room_id != "";
        }
    }

    /** Optional EncryptionService for E2EE. */
    public Vigil.Services.EncryptionService? encryption { get; set; default = null; }

    private Soup.Session _session;
    private int64 _txn_counter = 0;

    private static string strip_trailing_slash (string url) {
        if (url.has_suffix ("/")) {
            return url.substring (0, url.length - 1);
        }
        return url;
    }

    private static string safe_log (string? resp) {
        if (resp == null) return "";
        if (resp.length > 200) return resp.substring (0, 200) + "[truncated]";
        return resp;
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
     * Discover the homeserver URL from a server name via .well-known.
     *
     * If the user enters "matrix.org", this resolves it to
     * "https://matrix-client.matrix.org" (or whatever the server advertises).
     *
     * @param server_name The server name (e.g. "matrix.org").
     * @return The resolved homeserver URL, or null on failure.
     */
    public async string? discover_homeserver (string server_name) {
        var name = server_name.strip ();

        // Reject empty input
        if (name == "") {
            return null;
        }

        // If it's already a full URL, validate and use it directly
        if (name.has_prefix ("https://")) {
            // Validate URL structure
            try {
                Uri.parse (name, UriFlags.NONE);
            } catch (UriError e) {
                warning ("Invalid homeserver URL: %s", e.message);
                return null;
            }
            return strip_trailing_slash (name);
        }
        if (name.has_prefix ("http://")) {
            warning ("Refusing insecure http:// homeserver URL. Use https:// instead.");
            return null;
        }

        // Validate server name: must not contain path separators or query strings
        if ("/" in name || "?" in name || "#" in name || " " in name) {
            warning ("Invalid server name: contains disallowed characters");
            return null;
        }

        // Try .well-known discovery
        var well_known_url = "https://%s/.well-known/matrix/client".printf (name);

        try {
            var message = new Soup.Message ("GET", well_known_url);
            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status == Soup.Status.OK) {
                var parser = new Json.Parser ();
                parser.load_from_data ((string) response_bytes.get_data ());
                var root = parser.get_root ().get_object ();

                if (root.has_member ("m.homeserver")) {
                    var hs_obj = root.get_object_member ("m.homeserver");
                    if (hs_obj.has_member ("base_url")) {
                        var url = hs_obj.get_string_member ("base_url");
                        if (!url.has_prefix ("https://")) {
                            warning ("Discovered homeserver URL is not HTTPS: %s", url);
                            return null;
                        }
                        debug ("Discovered homeserver: %s -> %s", name, url);
                        return strip_trailing_slash (url);
                    }
                }
            }
        } catch (Error e) {
            debug ("Well-known discovery failed for %s: %s", name, e.message);
        }

        // Fallback: assume https://<server_name>
        var fallback = "https://%s".printf (name);
        try {
            Uri.parse (fallback, UriFlags.NONE);
        } catch (UriError e) {
            warning ("Invalid fallback URL for server %s: %s", name, e.message);
            return null;
        }
        return fallback;
    }

    /**
     * Log in to a Matrix homeserver with username and password.
     *
     * On success, sets the access_token and homeserver_url properties.
     * Returns the access token.
     *
     * @param server_url The homeserver URL.
     * @param username The Matrix username (without @).
     * @param password The password.
     * @return The access token on success, or null on failure.
     */
    public async string? login (string server_url, string username, string password) {
        try {
            var url = "%s/_matrix/client/v3/login".printf (
                strip_trailing_slash (server_url)
            );

            var builder = new Json.Builder ();
            builder.begin_object ();
            builder.set_member_name ("type");
            builder.add_string_value ("m.login.password");
            builder.set_member_name ("identifier");
            builder.begin_object ();
            builder.set_member_name ("type");
            builder.add_string_value ("m.id.user");
            builder.set_member_name ("user");
            builder.add_string_value (username);
            builder.end_object ();
            builder.set_member_name ("password");
            builder.add_string_value (password);
            builder.set_member_name ("initial_device_display_name");
            builder.add_string_value ("Vigil");
            builder.end_object ();

            var gen = new Json.Generator ();
            gen.set_root (builder.get_root ());
            var body_json = gen.to_data (null);

            var message = new Soup.Message ("POST", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (body_json.data)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Matrix login failed (HTTP %u): %s", status, safe_log (resp));
                return null;
            }

            var parser = new Json.Parser ();
            parser.load_from_data ((string) response_bytes.get_data ());
            var root = parser.get_root ().get_object ();

            if (root.has_member ("access_token")) {
                var token = root.get_string_member ("access_token");
                access_token = token;
                homeserver_url = server_url;

                // Store user_id and device_id from login response
                if (root.has_member ("user_id")) {
                    _last_user_id = root.get_string_member ("user_id");
                }
                if (root.has_member ("device_id")) {
                    _last_device_id = root.get_string_member ("device_id");
                }

                return token;
            } else {
                warning ("Matrix login response missing access_token");
                return null;
            }
        } catch (Error e) {
            warning ("Matrix login error: %s", e.message);
            return null;
        }
    }

    /** User ID from the most recent login response. */
    private string _last_user_id = "";
    public string last_user_id { get { return _last_user_id; } }

    /** Device ID from the most recent login response. */
    private string _last_device_id = "";
    public string last_device_id { get { return _last_device_id; } }

    /**
     * Create a private encrypted DM room and invite the partner.
     *
     * This eliminates the need for users to manually create a room.
     * The room is created with E2EE enabled from the start.
     *
     * @param partner_id The partner's Matrix user ID (e.g. @partner:matrix.org).
     * @return The room ID on success, or null on failure.
     */
    public async string? create_encrypted_room (string partner_id) {
        if (homeserver_url == "" || access_token == "") {
            return null;
        }

        try {
            var url = "%s/_matrix/client/v3/createRoom".printf (
                homeserver_url
            );

            var builder = new Json.Builder ();
            builder.begin_object ();

            builder.set_member_name ("visibility");
            builder.add_string_value ("private");

            builder.set_member_name ("preset");
            builder.add_string_value ("trusted_private_chat");

            builder.set_member_name ("name");
            builder.add_string_value ("Vigil Accountability");

            builder.set_member_name ("topic");
            builder.add_string_value ("Vigil screenshot monitoring");

            builder.set_member_name ("is_direct");
            builder.add_boolean_value (true);

            // Invite the partner
            builder.set_member_name ("invite");
            builder.begin_array ();
            builder.add_string_value (partner_id);
            builder.end_array ();

            // Enable encryption from the start
            builder.set_member_name ("initial_state");
            builder.begin_array ();
            builder.begin_object ();
            builder.set_member_name ("type");
            builder.add_string_value ("m.room.encryption");
            builder.set_member_name ("state_key");
            builder.add_string_value ("");
            builder.set_member_name ("content");
            builder.begin_object ();
            builder.set_member_name ("algorithm");
            builder.add_string_value ("m.megolm.v1.aes-sha2");
            builder.end_object ();
            builder.end_object ();
            builder.end_array ();

            builder.end_object ();

            var gen = new Json.Generator ();
            gen.set_root (builder.get_root ());
            var body_json = gen.to_data (null);

            var message = new Soup.Message ("POST", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (body_json.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Matrix room creation failed (HTTP %u): %s", status, safe_log (resp));
                return null;
            }

            var parser = new Json.Parser ();
            parser.load_from_data ((string) response_bytes.get_data ());
            var root = parser.get_root ().get_object ();

            if (root.has_member ("room_id")) {
                var new_room_id = root.get_string_member ("room_id");
                room_id = new_room_id;
                debug ("Created encrypted room: %s", new_room_id);
                return new_room_id;
            }

            return null;
        } catch (Error e) {
            warning ("Matrix room creation error: %s", e.message);
            return null;
        }
    }

    /**
     * Lock down room power levels after creation.
     *
     * Must be called while the creator still has power level 100 (before
     * any demotion). This is done as a separate step because the Matrix
     * createRoom endpoint processes invites AFTER initial_state, so
     * demoting the creator in initial_state blocks the invite.
     *
     * PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.power_levels
     *
     * @param target_room_id The room to lock down.
     * @param partner_id The partner's Matrix user ID.
     * @return true on success.
     */
    public async bool set_room_power_levels (string target_room_id,
                                             string partner_id) {
        if (homeserver_url == "" || access_token == "" ||
            _last_user_id == "") {
            return false;
        }

        try {
            var url = "%s/_matrix/client/v3/rooms/%s/state/m.room.power_levels".printf (
                homeserver_url,
                Uri.escape_string (target_room_id, null, false)
            );

            var builder = new Json.Builder ();
            builder.begin_object ();
            builder.set_member_name ("users");
            builder.begin_object ();
            builder.set_member_name (_last_user_id);
            builder.add_int_value (10);
            builder.set_member_name (partner_id);
            builder.add_int_value (100);
            builder.end_object ();
            builder.set_member_name ("users_default");
            builder.add_int_value (0);
            builder.set_member_name ("events_default");
            builder.add_int_value (10);
            builder.set_member_name ("state_default");
            builder.add_int_value (100);
            builder.set_member_name ("redact");
            builder.add_int_value (100);
            builder.set_member_name ("ban");
            builder.add_int_value (100);
            builder.set_member_name ("kick");
            builder.add_int_value (100);
            builder.set_member_name ("invite");
            builder.add_int_value (100);
            builder.end_object ();

            var gen = new Json.Generator ();
            gen.set_root (builder.get_root ());
            var body_json = gen.to_data (null);

            var message = new Soup.Message ("PUT", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (body_json.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (
                message, Priority.DEFAULT, null
            );
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Power levels update failed (HTTP %u): %s",
                    status, safe_log (resp));
                return false;
            }

            debug ("Room power levels locked down");
            return true;
        } catch (Error e) {
            warning ("Power levels update error: %s", e.message);
            return false;
        }
    }

    /**
     * Upload device keys to the Matrix homeserver for E2EE.
     *
     * POST /_matrix/client/v3/keys/upload
     *
     * @param keys_json The JSON body from EncryptionService.get_device_keys_json().
     * @return true if upload succeeded.
     */
    public async bool upload_device_keys (string keys_json) {
        if (homeserver_url == "" || access_token == "") {
            return false;
        }

        try {
            var url = "%s/_matrix/client/v3/keys/upload".printf (
                homeserver_url
            );

            var message = new Soup.Message ("POST", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (keys_json.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Keys upload failed (HTTP %u): %s", status, safe_log (resp));
                return false;
            }

            debug ("Device keys uploaded successfully");
            return true;
        } catch (Error e) {
            warning ("Keys upload error: %s", e.message);
            return false;
        }
    }

    /**
     * Query a user's device keys from the homeserver.
     *
     * POST /_matrix/client/v3/keys/query
     *
     * @param user_id The user whose devices to query.
     * @return JSON response string, or null on failure.
     */
    private async string? query_device_keys (string user_id) {
        if (homeserver_url == "" || access_token == "") {
            return null;
        }

        try {
            var url = "%s/_matrix/client/v3/keys/query".printf (
                homeserver_url
            );

            var builder = new Json.Builder ();
            builder.begin_object ();
            builder.set_member_name ("device_keys");
            builder.begin_object ();
            builder.set_member_name (user_id);
            builder.begin_array ();
            builder.end_array (); // empty = all devices
            builder.end_object ();
            builder.end_object ();

            var gen = new Json.Generator ();
            gen.set_root (builder.get_root ());
            var body_json = gen.to_data (null);

            var message = new Soup.Message ("POST", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (body_json.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Keys query failed (HTTP %u): %s", status, safe_log (resp));
                return null;
            }

            return (string) response_bytes.get_data ();
        } catch (Error e) {
            warning ("Keys query error: %s", e.message);
            return null;
        }
    }

    /**
     * Claim one-time keys for a list of devices.
     *
     * POST /_matrix/client/v3/keys/claim
     *
     * @param user_id The target user.
     * @param device_ids Array of device IDs to claim keys for.
     * @return JSON response string, or null on failure.
     */
    private async string? claim_one_time_keys (string user_id, string[] device_ids) {
        if (homeserver_url == "" || access_token == "") {
            return null;
        }

        try {
            var url = "%s/_matrix/client/v3/keys/claim".printf (
                homeserver_url
            );

            var builder = new Json.Builder ();
            builder.begin_object ();
            builder.set_member_name ("one_time_keys");
            builder.begin_object ();
            builder.set_member_name (user_id);
            builder.begin_object ();
            foreach (var dev_id in device_ids) {
                builder.set_member_name (dev_id);
                builder.add_string_value ("signed_curve25519");
            }
            builder.end_object ();
            builder.end_object ();
            builder.end_object ();

            var gen = new Json.Generator ();
            gen.set_root (builder.get_root ());
            var body_json = gen.to_data (null);

            var message = new Soup.Message ("POST", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (body_json.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Keys claim failed (HTTP %u): %s", status, safe_log (resp));
                return null;
            }

            return (string) response_bytes.get_data ();
        } catch (Error e) {
            warning ("Keys claim error: %s", e.message);
            return null;
        }
    }

    /**
     * Send to-device messages (for sharing Megolm room keys).
     *
     * PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
     *
     * @param event_type Event type (e.g. "m.room.encrypted").
     * @param messages_json The JSON messages object { user_id: { device_id: content } }.
     * @return true if successfully sent.
     */
    public async bool send_to_device (string event_type, string messages_json) {
        if (homeserver_url == "" || access_token == "") {
            return false;
        }

        try {
            var txn_id = generate_txn_id ();
            var encoded_type = GLib.Uri.escape_string (
                event_type, null, true
            );
            var url = "%s/_matrix/client/v3/sendToDevice/%s/%s".printf (
                homeserver_url,
                encoded_type,
                txn_id
            );

            // Wrap in { "messages": ... }
            var body = "{\"messages\":%s}".printf (messages_json);

            var message = new Soup.Message ("PUT", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (body.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("To-device send failed (HTTP %u): %s", status, safe_log (resp));
                return false;
            }

            return true;
        } catch (Error e) {
            warning ("To-device send error: %s", e.message);
            return false;
        }
    }

    /**
     * Upload raw bytes to the Matrix content repository.
     *
     * @param data The bytes to upload.
     * @param content_type MIME type (e.g. "image/png" or "application/octet-stream").
     * @param filename Filename for the upload.
     * @return The mxc:// content URI, or null on failure.
     */
    public async string? upload_bytes (Bytes data, string content_type, string filename) {
        if (!is_configured) {
            return null;
        }

        try {
            var upload_url = "%s/_matrix/media/v3/upload?filename=%s".printf (
                homeserver_url,
                GLib.Uri.escape_string (filename, null, true)
            );

            var message = new Soup.Message ("POST", upload_url);
            message.set_request_body_from_bytes (content_type, data);
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Matrix media upload failed (HTTP %u): %s", status, safe_log (resp));
                return null;
            }

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
     * Send a room event to the configured room.
     *
     * If an EncryptionService is set, the event is encrypted before sending.
     *
     * @param event_type The event type (e.g. "m.room.message").
     * @param content_json The JSON content body as a string.
     * @return The event ID, or null on failure.
     */
    public async string? send_room_event (string event_type, string content_json) {
        if (!is_configured) {
            return null;
        }

        // If E2EE is enabled, encrypt the event
        string actual_type = event_type;
        string actual_content = content_json;

        if (encryption != null && encryption.is_ready) {
            var encrypted = encryption.encrypt_event (room_id, event_type, content_json);
            if (encrypted != null) {
                actual_type = "m.room.encrypted";
                actual_content = encrypted;
            } else {
                warning ("E2EE encryption failed; refusing to send unencrypted");
                return null;
            }
        }

        try {
            var txn_id = generate_txn_id ();
            var encoded_room = GLib.Uri.escape_string (room_id, null, true);

            var encoded_type = GLib.Uri.escape_string (
                actual_type, null, true
            );
            var url = "%s/_matrix/client/v3/rooms/%s/send/%s/%s".printf (
                homeserver_url,
                encoded_room,
                encoded_type,
                txn_id
            );

            var message = new Soup.Message ("PUT", url);
            message.set_request_body_from_bytes (
                "application/json",
                new Bytes (actual_content.data)
            );
            message.get_request_headers ().append (
                "Authorization", "Bearer %s".printf (access_token)
            );

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status != Soup.Status.OK) {
                var resp = (string) response_bytes.get_data ();
                warning ("Matrix send event failed (HTTP %u): %s", status, safe_log (resp));
                return null;
            }

            var parser = new Json.Parser ();
            parser.load_from_data ((string) response_bytes.get_data ());
            var root = parser.get_root ().get_object ();

            if (root.has_member ("event_id")) {
                // Persist Megolm state after successful send
                if (encryption != null) {
                    encryption.save_session_if_needed ();
                }
                return root.get_string_member ("event_id");
            }
            return null;
        } catch (Error e) {
            warning ("Matrix send event error: %s", e.message);
            return null;
        }
    }

    /**
     * Upload and send pre-loaded screenshot data to the Matrix room.
     *
     * Accepts file data that has already been read into memory, avoiding
     * a redundant file read when the caller has the data (e.g. after
     * integrity verification in the upload pipeline).
     */
    public async bool send_screenshot_data (owned uint8[] file_data,
                                             string file_path,
                                             DateTime capture_time) {
        if (!is_configured) {
            var msg = "Matrix transport not configured";
            warning (msg);
            screenshot_send_failed (file_path, msg);
            return false;
        }

        var time_str = capture_time.format ("%Y-%m-%d %H:%M:%S");
        var body = "Screenshot %s".printf (time_str);
        var filename = Path.get_basename (file_path);

        // Extract PNG dimensions for inline preview in Matrix clients
        int img_w = 0, img_h = 0;
        read_png_dimensions (file_data, out img_w, out img_h);

        // Never send screenshots without E2EE — they contain sensitive screen content
        if (encryption == null || !encryption.is_ready) {
            var msg = "E2EE not ready -- screenshot will be retried later";
            warning (msg);
            screenshot_send_failed (file_path, msg);
            return false;
        }

        return yield send_encrypted_screenshot (file_data, filename, body, img_w, img_h);
    }

    /**
     * Upload and send a screenshot to the Matrix room (reads file from disk).
     *
     * Delegates to send_screenshot_data() after reading the file.
     * Use send_screenshot_data() directly when the caller already
     * has the file in memory to avoid a redundant read.
     */
    public async bool send_screenshot (string file_path, DateTime capture_time) {
        if (!is_configured) {
            var msg = "Matrix transport not configured";
            warning (msg);
            screenshot_send_failed (file_path, msg);
            return false;
        }

        uint8[] file_data;
        try {
            FileUtils.get_data (file_path, out file_data);
        } catch (Error e) {
            screenshot_send_failed (file_path, "Failed to read file: %s".printf (e.message));
            return false;
        }

        return yield send_screenshot_data ((owned) file_data, file_path, capture_time);
    }

    /**
     * Read width and height from a PNG file's IHDR chunk (bytes 16-23).
     */
    private static void read_png_dimensions (uint8[] data, out int width, out int height) {
        width = 0;
        height = 0;
        // PNG: 8-byte signature, then IHDR chunk: 4-byte length, 4-byte "IHDR",
        // 4-byte width (big-endian), 4-byte height (big-endian) → offsets 16..23
        if (data.length >= 24) {
            width  = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
            height = (data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23];
        }
    }

    /**
     * Encrypt a screenshot with AES-256-CTR, upload the ciphertext,
     * and send the event with embedded decryption metadata.
     */
    private async bool send_encrypted_screenshot (uint8[] plaintext_data,
                                                   string filename,
                                                   string body,
                                                   int img_w = 0,
                                                   int img_h = 0) {
        // Step 1: Encrypt the file with AES-256-CTR
        var enc_result = encryption.encrypt_attachment (plaintext_data);
        if (enc_result == null) {
            screenshot_send_failed (filename, "Attachment encryption failed");
            return false;
        }

        // Step 2: Upload encrypted blob (opaque binary, not image/png)
        // Use Bytes.take to transfer ownership instead of copying the 2MB ciphertext
        var content_uri = yield upload_bytes (
            new Bytes.take ((owned) enc_result.ciphertext),
            "application/octet-stream",
            filename
        );
        if (content_uri == null) {
            screenshot_send_failed (filename, "Encrypted media upload failed");
            return false;
        }

        // Step 3: Build event with EncryptedFile metadata per Matrix spec
        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("msgtype");
        builder.add_string_value ("m.image");
        builder.set_member_name ("body");
        builder.add_string_value (body);

        // "file" object replaces "url" for encrypted attachments
        builder.set_member_name ("file");
        builder.begin_object ();
        builder.set_member_name ("url");
        builder.add_string_value (content_uri);
        builder.set_member_name ("mimetype");
        builder.add_string_value ("image/png");

        // JWK key
        builder.set_member_name ("key");
        builder.begin_object ();
        builder.set_member_name ("kty");
        builder.add_string_value ("oct");
        builder.set_member_name ("key_ops");
        builder.begin_array ();
        builder.add_string_value ("encrypt");
        builder.add_string_value ("decrypt");
        builder.end_array ();
        builder.set_member_name ("alg");
        builder.add_string_value ("A256CTR");
        builder.set_member_name ("k");
        builder.add_string_value (
            Vigil.Services.EncryptionService.base64url_encode_unpadded (enc_result.key)
        );
        builder.set_member_name ("ext");
        builder.add_boolean_value (true);
        builder.end_object (); // key

        builder.set_member_name ("iv");
        builder.add_string_value (
            Vigil.Services.EncryptionService.base64_encode_unpadded (enc_result.iv)
        );

        builder.set_member_name ("hashes");
        builder.begin_object ();
        builder.set_member_name ("sha256");
        builder.add_string_value (
            Vigil.Services.EncryptionService.base64_encode_unpadded (enc_result.sha256)
        );
        builder.end_object (); // hashes

        builder.set_member_name ("v");
        builder.add_string_value ("v2");
        builder.end_object (); // file

        builder.set_member_name ("info");
        builder.begin_object ();
        builder.set_member_name ("mimetype");
        builder.add_string_value ("image/png");
        builder.set_member_name ("size");
        builder.add_int_value (plaintext_data.length);
        if (img_w > 0 && img_h > 0) {
            builder.set_member_name ("w");
            builder.add_int_value (img_w);
            builder.set_member_name ("h");
            builder.add_int_value (img_h);
        }
        builder.end_object ();

        builder.end_object (); // root

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        var content_json = gen.to_data (null);

        // Step 4: Send via Megolm-encrypted room event
        var event_id = yield send_room_event ("m.room.message", content_json);
        if (event_id == null) {
            screenshot_send_failed (filename, "Failed to send encrypted image event");
            return false;
        }

        debug ("Matrix: sent encrypted screenshot %s as %s", filename, event_id);
        screenshot_sent (filename, event_id);
        return true;
    }

    /**
     * Send a text message to the Matrix room (for heartbeats/alerts).
     */
    public async bool send_text_message (string text) {
        if (!is_configured) {
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
        return event_id != null;
    }

    /**
     * Send a tamper alert to the Matrix room with HTML formatting.
     *
     * Tamper alerts use bold + blockquote so they stand out visually
     * in Element and other Matrix clients, clearly distinguishable
     * from regular heartbeat/status messages.
     */
    public async bool send_alert (string event_type, string details) {
        if (!is_configured) {
            return false;
        }

        var plain = "TAMPER ALERT [%s]: %s".printf (event_type, details);
        var html = "<strong>TAMPER ALERT [%s]</strong><br><blockquote>%s</blockquote>".printf (
            Markup.escape_text (event_type),
            Markup.escape_text (details)
        );

        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("msgtype");
        builder.add_string_value ("m.text");
        builder.set_member_name ("body");
        builder.add_string_value (plain);
        builder.set_member_name ("format");
        builder.add_string_value ("org.matrix.custom.html");
        builder.set_member_name ("formatted_body");
        builder.add_string_value (html);
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        var content_json = gen.to_data (null);

        var event_id = yield send_room_event ("m.room.message", content_json);
        return event_id != null;
    }

    /**
     * Verify the Matrix connection by calling the /whoami endpoint.
     */
    public async string? verify_connection () {
        if (homeserver_url == "" || access_token == "") {
            return null;
        }

        try {
            var url = "%s/_matrix/client/v3/account/whoami".printf (
                homeserver_url
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

    /**
     * Save an access token to a secure file in the crypto directory.
     *
     * The file is stored with 0600 permissions in a directory with 0700
     * permissions, making it harder to discover than the dconf database.
     */
    public static void save_access_token_to_file (string token) {
        var dir = SecurityUtils.get_crypto_dir ();
        SecurityUtils.ensure_secure_directory (dir);

        var path = Path.build_filename (dir, "access_token");
        try {
            SecurityUtils.write_secure_file (path, token);
        } catch (Error e) {
            warning ("Failed to save access token to file: %s", e.message);
        }
    }

    /**
     * Load an access token from the secure file, or return null.
     */
    public static string? load_access_token_from_file () {
        return SecurityUtils.load_secure_file_string ("access_token");
    }

    /**
     * Full E2EE setup: upload keys, create Megolm session,
     * query partner devices, share room keys.
     *
     * This is the one-shot setup called from the GUI when the
     * user clicks "Setup". Inspired by pantalaimon's session
     * establishment flow.
     *
     * @param enc The EncryptionService with initialized OlmAccount.
     * @param partner_id The partner's Matrix user ID.
     * @return true if E2EE setup completed successfully.
     */
    public async bool setup_e2ee (Vigil.Services.EncryptionService enc, string partner_id) {
        encryption = enc;

        // Step 1: Upload device keys
        var keys_json = enc.get_device_keys_json ();
        bool uploaded = yield upload_device_keys (keys_json);
        if (!uploaded) {
            warning ("Failed to upload device keys");
            return false;
        }
        enc.mark_keys_as_published ();
        debug ("E2EE: device keys uploaded");

        // Step 2: Create Megolm outbound session or restore existing
        if (!enc.restore_group_session ()) {
            if (!enc.create_outbound_group_session ()) {
                warning ("Failed to create Megolm session");
                return false;
            }
        }
        debug ("E2EE: Megolm session ready (ID: %s)", enc.megolm_session_id);

        // Step 3: Share room keys with partner's devices
        bool shared = yield share_room_keys (enc, partner_id);
        if (!shared) {
            // Key sharing failure is non-fatal - partner may not have
            // any devices yet (not logged in). Keys will be reshared
            // when they join.
            debug ("E2EE: room key sharing deferred (partner may not be online)");
        } else {
            debug ("E2EE: room keys shared with partner");
        }

        return true;
    }

    /**
     * Share the current Megolm room key with the partner.
     *
     * Public wrapper for share_room_keys() so the daemon can retry
     * key sharing periodically until it succeeds.
     *
     * @param partner_id The partner's Matrix user ID.
     * @return true if keys were successfully shared.
     */
    public async bool share_room_keys_with_partner (string partner_id) {
        if (encryption == null || !encryption.is_ready || !is_configured) {
            return false;
        }
        return yield share_room_keys (encryption, partner_id);
    }

    /**
     * Share the Megolm room key with the partner's devices.
     *
     * Follows pantalaimon's approach:
     *   1. Query partner's device keys
     *   2. Claim one-time keys for each device
     *   3. Establish Olm sessions and encrypt room key
     *   4. Send via to-device messages
     */
    private async bool share_room_keys (Vigil.Services.EncryptionService enc, string partner_id) {
        // Query partner's device keys
        var query_response = yield query_device_keys (partner_id);
        if (query_response == null) {
            return false;
        }

        try {
            var parser = new Json.Parser ();
            parser.load_from_data (query_response);
            var root = parser.get_root ().get_object ();

            if (!root.has_member ("device_keys")) {
                return false;
            }

            var dk_obj = root.get_object_member ("device_keys");
            if (!dk_obj.has_member (partner_id)) {
                return false;
            }

            var partner_devices = dk_obj.get_object_member (partner_id);
            var device_ids = new GenericArray<string> ();
            var device_curve_keys = new HashTable<string, string> (str_hash, str_equal);
            var device_ed_keys = new HashTable<string, string> (str_hash, str_equal);

            partner_devices.foreach_member ((obj, dev_id, dev_node) => {
                var dev = dev_node.get_object ();
                if (dev == null) {
                    return;
                }
                if (dev.has_member ("keys")) {
                    var keys = dev.get_object_member ("keys");
                    var curve_key_name = "curve25519:%s".printf (dev_id);
                    var ed_key_name = "ed25519:%s".printf (dev_id);
                    if (keys.has_member (curve_key_name)) {
                        device_ids.add (dev_id);
                        device_curve_keys.insert (
                            dev_id,
                            keys.get_string_member (curve_key_name)
                        );
                        if (keys.has_member (ed_key_name)) {
                            device_ed_keys.insert (
                                dev_id,
                                keys.get_string_member (ed_key_name)
                            );
                        }
                    }
                }
            });

            if (device_ids.length == 0) {
                return false;
            }

            // Claim one-time keys
            string[] dev_id_array = new string[device_ids.length];
            for (int i = 0; i < device_ids.length; i++) {
                dev_id_array[i] = device_ids[i];
            }

            var claim_response = yield claim_one_time_keys (partner_id, dev_id_array);
            if (claim_response == null) {
                return false;
            }

            var claim_parser = new Json.Parser ();
            claim_parser.load_from_data (claim_response);
            var claim_root = claim_parser.get_root ().get_object ();

            if (!claim_root.has_member ("one_time_keys")) {
                return false;
            }

            var otk_obj = claim_root.get_object_member ("one_time_keys");
            if (!otk_obj.has_member (partner_id)) {
                return false;
            }

            var partner_otks = otk_obj.get_object_member (partner_id);

            // Build room key content and parse it once for reuse
            var room_key_json = enc.build_room_key_content (room_id);
            if (room_key_json == null) {
                return false;
            }

            var rk_parser = new Json.Parser ();
            rk_parser.load_from_data (room_key_json);
            var room_key_node = rk_parser.get_root ();

            // Build to-device messages
            var msg_builder = new Json.Builder ();
            msg_builder.begin_object ();
            msg_builder.set_member_name (partner_id);
            msg_builder.begin_object ();

            int shared_count = 0;
            partner_otks.foreach_member ((obj, dev_id, otk_node) => {
                var otk_container = otk_node.get_object ();
                if (otk_container == null) {
                    return;
                }

                // Find the claimed key
                string? claimed_key = null;
                otk_container.foreach_member ((inner_obj, key_name, key_val) => {
                    if (key_name.has_prefix ("signed_curve25519:")) {
                        var key_obj = key_val.get_object ();
                        if (key_obj != null && key_obj.has_member ("key")) {
                            claimed_key = key_obj.get_string_member ("key");
                        }
                    }
                });

                if (claimed_key == null) {
                    return;
                }

                var their_curve = device_curve_keys.lookup (dev_id);
                if (their_curve == null) {
                    return;
                }

                // Build proper Olm plaintext envelope per Matrix spec.
                // The decrypted payload must include type, content, sender,
                // recipient, recipient_keys, and keys for Element to process it.
                var their_ed = device_ed_keys.lookup (dev_id);
                var wrap = new Json.Builder ();
                wrap.begin_object ();
                wrap.set_member_name ("type");
                wrap.add_string_value ("m.room_key");
                wrap.set_member_name ("content");
                wrap.add_value (room_key_node.copy ());
                wrap.set_member_name ("sender");
                wrap.add_string_value (enc.user_id);
                wrap.set_member_name ("sender_device");
                wrap.add_string_value (enc.device_id);
                wrap.set_member_name ("recipient");
                wrap.add_string_value (partner_id);
                wrap.set_member_name ("recipient_keys");
                wrap.begin_object ();
                wrap.set_member_name ("ed25519");
                wrap.add_string_value (their_ed ?? "");
                wrap.end_object ();
                wrap.set_member_name ("keys");
                wrap.begin_object ();
                wrap.set_member_name ("ed25519");
                wrap.add_string_value (enc.ed25519_key);
                wrap.end_object ();
                wrap.end_object ();

                var wrap_gen = new Json.Generator ();
                wrap_gen.set_root (wrap.get_root ());
                var wrapped_plaintext = wrap_gen.to_data (null);

                // Encrypt wrapped room key for this device using Olm
                var encrypted = enc.olm_encrypt_for_device (
                    their_curve,
                    claimed_key,
                    wrapped_plaintext
                );

                if (encrypted != null) {
                    // Build the m.room.encrypted to-device content
                    var dev_builder = new Json.Builder ();
                    dev_builder.begin_object ();
                    dev_builder.set_member_name ("algorithm");
                    dev_builder.add_string_value ("m.olm.v1.curve25519-aes-sha2");
                    dev_builder.set_member_name ("sender_key");
                    dev_builder.add_string_value (enc.curve25519_key);
                    dev_builder.set_member_name ("ciphertext");
                    dev_builder.begin_object ();
                    dev_builder.set_member_name (their_curve);

                    try {
                        var enc_parser = new Json.Parser ();
                        enc_parser.load_from_data (encrypted);
                        dev_builder.add_value (enc_parser.get_root ());
                    } catch (Error e) {
                        warning ("Failed to parse encrypted content: %s", e.message);
                        dev_builder.end_object ();
                        dev_builder.end_object ();
                        return;
                    }

                    dev_builder.end_object (); // ciphertext
                    dev_builder.end_object ();

                    var dev_gen = new Json.Generator ();
                    dev_gen.set_root (dev_builder.get_root ());

                    msg_builder.set_member_name (dev_id);
                    try {
                        var content_parser = new Json.Parser ();
                        content_parser.load_from_data (dev_gen.to_data (null));
                        msg_builder.add_value (content_parser.get_root ());
                    } catch (Error e) {
                        warning ("Failed to build to-device content: %s", e.message);
                        return;
                    }

                    shared_count++;
                }
            });

            msg_builder.end_object (); // partner devices
            msg_builder.end_object ();

            if (shared_count == 0) {
                return false;
            }

            var msg_gen = new Json.Generator ();
            msg_gen.set_root (msg_builder.get_root ());
            var messages_json = msg_gen.to_data (null);

            return yield send_to_device ("m.room.encrypted", messages_json);
        } catch (Error e) {
            warning ("Room key sharing error: %s", e.message);
            return false;
        }
    }
}
