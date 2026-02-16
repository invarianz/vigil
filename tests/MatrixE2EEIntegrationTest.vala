/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 *
 * End-to-end integration test for the full Matrix E2EE pipeline.
 *
 * Spins up a mock Matrix homeserver on localhost (Soup.Server) that
 * implements just enough of the CS API for:
 *   - Login (POST /login)
 *   - Room creation (POST /createRoom)
 *   - Key upload (POST /keys/upload)
 *   - Key query (POST /keys/query)
 *   - Key claim (POST /keys/claim)
 *   - To-device messages (PUT /sendToDevice)
 *   - Media upload (POST /media/v3/upload)
 *   - Room events (PUT /rooms/.../send)
 *   - Sync (GET /sync) -- returns to-device + room events
 *
 * The test acts as both Vigil (sender) and the accountability partner
 * (receiver), verifying the full chain:
 *   1. Login both users
 *   2. Create encrypted room
 *   3. Setup E2EE (upload keys, create Megolm session)
 *   4. Partner uploads keys, Vigil queries + claims + shares room key
 *   5. Partner decrypts the Olm-wrapped room key (m.room_key)
 *   6. Vigil sends an encrypted text message
 *   7. Partner decrypts the Megolm ciphertext and verifies plaintext
 *   8. Vigil sends an encrypted attachment (AES-256-CTR)
 *   9. Partner decrypts the attachment and verifies content
 */

string test_data_dir;
string crypto_dir;

/* ── Mock server state ────────────────────────────────────────── */

// Device keys uploaded by each user
HashTable<string, string> uploaded_device_keys;   // user_id -> full keys/upload JSON
// One-time keys uploaded by each user (user_id -> { key_id: key_value })
HashTable<string, HashTable<string, string>> uploaded_otks;
// To-device messages: recipient user_id -> list of event JSON strings
HashTable<string, GenericArray<string>> to_device_inbox;
// Room events: room_id -> list of event JSON strings
HashTable<string, GenericArray<string>> room_events;
// Uploaded media: content_uri -> raw bytes
HashTable<string, Bytes> uploaded_media;

int next_media_id;
string mock_room_id;

Soup.Server? mock_server;
uint16 mock_port;

/* ── Mock server setup ────────────────────────────────────────── */

void setup_mock_server () {
    next_media_id = 1;
    mock_room_id = "!testroom:localhost";
    mock_port = 0;

    uploaded_device_keys = new HashTable<string, string> (str_hash, str_equal);
    uploaded_otks = new HashTable<string, HashTable<string, string>> (str_hash, str_equal);
    to_device_inbox = new HashTable<string, GenericArray<string>> (str_hash, str_equal);
    room_events = new HashTable<string, GenericArray<string>> (str_hash, str_equal);
    uploaded_media = new HashTable<string, Bytes> (str_hash, str_equal);

    mock_server = new Soup.Server ("server-header", "MockMatrix/1.0");
    mock_server.add_handler ("/_matrix", handle_matrix_request);

    try {
        mock_server.listen_local (0, Soup.ServerListenOptions.IPV4_ONLY);
    } catch (Error e) {
        error ("Failed to start mock server: %s", e.message);
    }

    // Get the actual port
    var uris = mock_server.get_uris ();
    mock_port = (uint16) uris.data.get_port ();
    debug ("Mock Matrix server on port %u", mock_port);
}

string mock_url () {
    return "http://localhost:%u".printf (mock_port);
}

void respond_json (Soup.ServerMessage msg, int status, string json) {
    msg.set_status (status, null);
    msg.get_response_headers ().append ("Content-Type", "application/json");
    msg.set_response ("application/json", Soup.MemoryUse.COPY, json.data);
}

void handle_matrix_request (Soup.Server server, Soup.ServerMessage msg,
                             string path, HashTable<string, string>? query) {
    var method = msg.get_method ();

    // POST /_matrix/client/v3/login
    if (method == "POST" && path.has_suffix ("/login")) {
        handle_login (msg);
        return;
    }

    // POST /_matrix/client/v3/createRoom
    if (method == "POST" && path.has_suffix ("/createRoom")) {
        respond_json (msg, 200, "{\"room_id\":\"%s\"}".printf (mock_room_id));
        return;
    }

    // POST /_matrix/client/v3/keys/upload
    if (method == "POST" && path.has_suffix ("/keys/upload")) {
        handle_keys_upload (msg);
        return;
    }

    // POST /_matrix/client/v3/keys/query
    if (method == "POST" && path.has_suffix ("/keys/query")) {
        handle_keys_query (msg);
        return;
    }

    // POST /_matrix/client/v3/keys/claim
    if (method == "POST" && path.has_suffix ("/keys/claim")) {
        handle_keys_claim (msg);
        return;
    }

    // PUT /_matrix/client/v3/sendToDevice
    if (method == "PUT" && path.contains ("/sendToDevice/")) {
        handle_send_to_device (msg);
        return;
    }

    // POST /_matrix/media/v3/upload
    if (method == "POST" && path.contains ("/media/") && path.has_suffix ("/upload")) {
        handle_media_upload (msg, query);
        return;
    }

    // PUT /_matrix/client/v3/rooms/.../send/...
    if (method == "PUT" && path.contains ("/rooms/") && path.contains ("/send/")) {
        handle_room_send (msg, path);
        return;
    }

    // GET /_matrix/client/v3/sync
    if (method == "GET" && path.has_suffix ("/sync")) {
        respond_json (msg, 200, "{\"next_batch\":\"s1\"}");
        return;
    }

    respond_json (msg, 404, "{\"errcode\":\"M_NOT_FOUND\"}");
}

void handle_login (Soup.ServerMessage msg) {
    try {
        var body = (string) msg.get_request_body ().flatten ().get_data ();
        var parser = new Json.Parser ();
        parser.load_from_data (body);
        var root = parser.get_root ().get_object ();

        var ident = root.get_object_member ("identifier");
        var username = ident.get_string_member ("user");
        var user_id = "@%s:localhost".printf (username);
        var device_id = "DEV_%s".printf (username.up ());

        var resp = "{\"user_id\":\"%s\",\"access_token\":\"tok_%s\",\"device_id\":\"%s\"}".printf (
            user_id, username, device_id
        );
        respond_json (msg, 200, resp);
    } catch (Error e) {
        respond_json (msg, 400, "{\"errcode\":\"M_UNKNOWN\"}");
    }
}

void handle_keys_upload (Soup.ServerMessage msg) {
    try {
        var body = (string) msg.get_request_body ().flatten ().get_data ();
        var parser = new Json.Parser ();
        parser.load_from_data (body);
        var root = parser.get_root ().get_object ();

        // Extract user from Authorization header to store keys
        var auth = msg.get_request_headers ().get_one ("Authorization");
        string user_id = "";
        if (auth != null && auth.has_prefix ("Bearer tok_")) {
            var username = auth.substring ("Bearer tok_".length);
            user_id = "@%s:localhost".printf (username);
        }

        if (root.has_member ("device_keys") && user_id != "") {
            // Store the full body so keys/query can return it
            uploaded_device_keys.insert (user_id, body);
        }

        // Store one-time keys
        if (root.has_member ("one_time_keys") && user_id != "") {
            var otk_obj = root.get_object_member ("one_time_keys");
            var user_otks = uploaded_otks.lookup (user_id);
            if (user_otks == null) {
                user_otks = new HashTable<string, string> (str_hash, str_equal);
                uploaded_otks.insert (user_id, user_otks);
            }
            otk_obj.foreach_member ((obj, key_name, key_val) => {
                user_otks.insert (key_name, key_val.get_string ());
            });
        }

        respond_json (msg, 200, "{\"one_time_key_counts\":{\"signed_curve25519\":50}}");
    } catch (Error e) {
        respond_json (msg, 400, "{\"errcode\":\"M_UNKNOWN\"}");
    }
}

void handle_keys_query (Soup.ServerMessage msg) {
    try {
        var body = (string) msg.get_request_body ().flatten ().get_data ();
        var parser = new Json.Parser ();
        parser.load_from_data (body);
        var root = parser.get_root ().get_object ();
        var dk_query = root.get_object_member ("device_keys");

        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("device_keys");
        builder.begin_object ();

        dk_query.foreach_member ((obj, queried_user, val) => {
            var stored = uploaded_device_keys.lookup (queried_user);
            if (stored != null) {
                try {
                    var stored_parser = new Json.Parser ();
                    stored_parser.load_from_data (stored);
                    var stored_root = stored_parser.get_root ().get_object ();

                    if (stored_root.has_member ("device_keys")) {
                        var dk = stored_root.get_object_member ("device_keys");
                        var dev_id = dk.get_string_member ("device_id");

                        builder.set_member_name (queried_user);
                        builder.begin_object ();
                        builder.set_member_name (dev_id);
                        builder.add_value (stored_root.get_member ("device_keys"));
                        builder.end_object ();
                    }
                } catch (Error e) {}
            }
        });

        builder.end_object (); // device_keys
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        respond_json (msg, 200, gen.to_data (null));
    } catch (Error e) {
        respond_json (msg, 400, "{\"errcode\":\"M_UNKNOWN\"}");
    }
}

void handle_keys_claim (Soup.ServerMessage msg) {
    try {
        var body = (string) msg.get_request_body ().flatten ().get_data ();
        var parser = new Json.Parser ();
        parser.load_from_data (body);
        var root = parser.get_root ().get_object ();
        var otk_req = root.get_object_member ("one_time_keys");

        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("one_time_keys");
        builder.begin_object ();

        otk_req.foreach_member ((obj, claim_user, user_devs_node) => {
            var user_otks = uploaded_otks.lookup (claim_user);
            if (user_otks == null) return;

            builder.set_member_name (claim_user);
            builder.begin_object ();

            var user_devs = user_devs_node.get_object ();
            user_devs.foreach_member ((dobj, dev_id, algo_node) => {
                builder.set_member_name (dev_id);
                builder.begin_object ();

                // Find a matching OTK
                var iter = HashTableIter<string, string> (user_otks);
                string? key_name;
                string? key_val;
                bool found = false;
                while (iter.next (out key_name, out key_val)) {
                    if (key_name.has_prefix ("curve25519:")) {
                        // Return as signed_curve25519
                        var short_id = key_name.substring ("curve25519:".length);
                        builder.set_member_name ("signed_curve25519:%s".printf (short_id));
                        builder.begin_object ();
                        builder.set_member_name ("key");
                        builder.add_string_value (key_val);
                        builder.end_object ();
                        // Remove consumed key
                        iter.remove ();
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    // No keys available -- return empty
                }

                builder.end_object (); // dev_id
            });

            builder.end_object (); // claim_user
        });

        builder.end_object (); // one_time_keys
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        respond_json (msg, 200, gen.to_data (null));
    } catch (Error e) {
        respond_json (msg, 400, "{\"errcode\":\"M_UNKNOWN\"}");
    }
}

void handle_send_to_device (Soup.ServerMessage msg) {
    try {
        var body = (string) msg.get_request_body ().flatten ().get_data ();
        var parser = new Json.Parser ();
        parser.load_from_data (body);
        var root = parser.get_root ().get_object ();

        if (root.has_member ("messages")) {
            var messages = root.get_object_member ("messages");
            messages.foreach_member ((obj, recipient_user, devs_node) => {
                var inbox = to_device_inbox.lookup (recipient_user);
                if (inbox == null) {
                    inbox = new GenericArray<string> ();
                    to_device_inbox.insert (recipient_user, inbox);
                }
                // Store per-device messages
                var devs = devs_node.get_object ();
                devs.foreach_member ((dobj, dev_id, content_node) => {
                    var gen = new Json.Generator ();
                    gen.set_root (content_node);
                    inbox.add (gen.to_data (null));
                });
            });
        }

        respond_json (msg, 200, "{}");
    } catch (Error e) {
        respond_json (msg, 400, "{\"errcode\":\"M_UNKNOWN\"}");
    }
}

void handle_media_upload (Soup.ServerMessage msg, HashTable<string, string>? query) {
    var body_data = msg.get_request_body ().flatten ();
    var content_uri = "mxc://localhost/media_%d".printf (next_media_id++);

    uploaded_media.insert (content_uri, body_data);

    respond_json (msg, 200, "{\"content_uri\":\"%s\"}".printf (content_uri));
}

void handle_room_send (Soup.ServerMessage msg, string path) {
    var body = (string) msg.get_request_body ().flatten ().get_data ();

    var events = room_events.lookup (mock_room_id);
    if (events == null) {
        events = new GenericArray<string> ();
        room_events.insert (mock_room_id, events);
    }
    events.add (body);

    var event_id = "$evt_%d".printf (events.length);
    respond_json (msg, 200, "{\"event_id\":\"%s\"}".printf (event_id));
}

/* ── Partner crypto helpers ───────────────────────────────────── */

/**
 * Create a partner OlmAccount (for key exchange).
 */
void create_partner_account (out uint8[] acct_buf, out void* acct,
                              out string curve_key, out string ed_key) {
    acct_buf = new uint8[Olm.account_size ()];
    acct = Olm.account_init (acct_buf);

    var random_len = Olm.create_account_random_length (acct);
    var random = read_urandom (random_len);
    var result = Olm.create_account (acct, random, random_len);
    assert_true (result != Olm.error_val ());

    // Extract identity keys
    var keys_len = Olm.account_identity_keys_length (acct);
    var keys_buf = new uint8[keys_len + 1];
    Olm.account_identity_keys (acct, keys_buf, keys_len);
    keys_buf[keys_len] = 0;

    try {
        var parser = new Json.Parser ();
        parser.load_from_data ((string) keys_buf);
        var obj = parser.get_root ().get_object ();
        curve_key = obj.get_string_member ("curve25519");
        ed_key = obj.get_string_member ("ed25519");
    } catch (Error e) {
        error ("Failed to parse partner keys: %s", e.message);
    }
}

/**
 * Upload partner's device keys + OTKs to the mock server.
 */
void upload_partner_keys (string user_id, string device_id,
                           string curve_key, string ed_key, void* acct) {
    // Get one-time keys
    var otk_len = Olm.account_one_time_keys_length (acct);
    var otk_buf = new uint8[otk_len + 1];
    Olm.account_one_time_keys (acct, otk_buf, otk_len);
    otk_buf[otk_len] = 0;
    var otk_json = (string) otk_buf;

    // Build the keys/upload body
    var builder = new Json.Builder ();
    builder.begin_object ();

    builder.set_member_name ("device_keys");
    builder.begin_object ();
    builder.set_member_name ("user_id");
    builder.add_string_value (user_id);
    builder.set_member_name ("device_id");
    builder.add_string_value (device_id);
    builder.set_member_name ("algorithms");
    builder.begin_array ();
    builder.add_string_value ("m.olm.v1.curve25519-aes-sha2");
    builder.add_string_value ("m.megolm.v1.aes-sha2");
    builder.end_array ();
    builder.set_member_name ("keys");
    builder.begin_object ();
    builder.set_member_name ("curve25519:%s".printf (device_id));
    builder.add_string_value (curve_key);
    builder.set_member_name ("ed25519:%s".printf (device_id));
    builder.add_string_value (ed_key);
    builder.end_object ();
    builder.end_object (); // device_keys

    // One-time keys
    builder.set_member_name ("one_time_keys");
    builder.begin_object ();
    try {
        var otk_parser = new Json.Parser ();
        otk_parser.load_from_data (otk_json);
        var otk_root = otk_parser.get_root ().get_object ();
        if (otk_root.has_member ("curve25519")) {
            var curve_obj = otk_root.get_object_member ("curve25519");
            curve_obj.foreach_member ((obj, key_id, val) => {
                builder.set_member_name ("curve25519:%s".printf (key_id));
                builder.add_string_value (val.get_string ());
            });
        }
    } catch (Error e) {}
    builder.end_object (); // one_time_keys

    builder.end_object ();

    var gen = new Json.Generator ();
    gen.set_root (builder.get_root ());
    var body = gen.to_data (null);

    // Store directly in mock server state
    uploaded_device_keys.insert (user_id, body);

    // Also store OTKs
    try {
        var otk_parser = new Json.Parser ();
        otk_parser.load_from_data (otk_json);
        var otk_root = otk_parser.get_root ().get_object ();
        if (otk_root.has_member ("curve25519")) {
            var user_otks = new HashTable<string, string> (str_hash, str_equal);
            var curve_obj = otk_root.get_object_member ("curve25519");
            curve_obj.foreach_member ((obj, key_id, val) => {
                user_otks.insert ("curve25519:%s".printf (key_id), val.get_string ());
            });
            uploaded_otks.insert (user_id, user_otks);
        }
    } catch (Error e) {}
}

/**
 * Decrypt an Olm pre-key message and extract the m.room_key content.
 */
string? partner_decrypt_olm (void* partner_acct, string partner_curve,
                              string sender_curve, string to_device_json) {
    try {
        var parser = new Json.Parser ();
        parser.load_from_data (to_device_json);
        var root = parser.get_root ().get_object ();

        // Expected structure: { algorithm, sender_key, ciphertext: { <our_curve>: { type, body } } }
        var ciphertext_obj = root.get_object_member ("ciphertext");
        if (!ciphertext_obj.has_member (partner_curve)) {
            warning ("No ciphertext for our curve key");
            return null;
        }

        var our_ct = ciphertext_obj.get_object_member (partner_curve);
        var msg_type = (size_t) our_ct.get_int_member ("type");
        var msg_body = our_ct.get_string_member ("body");

        // Create inbound Olm session
        var session_buf = new uint8[Olm.session_size ()];
        var session = Olm.session_init (session_buf);

        var sender_curve_data = sender_curve.data;

        // Make a mutable copy of the message for decrypt_max_plaintext_length
        var msg_data1 = msg_body.data;
        var msg_copy1 = new uint8[msg_data1.length];
        Memory.copy (msg_copy1, msg_data1, msg_data1.length);

        // Create session from pre-key message
        var msg_for_session = new uint8[msg_data1.length];
        Memory.copy (msg_for_session, msg_data1, msg_data1.length);

        var result = Olm.create_inbound_session_from (
            session, partner_acct,
            sender_curve_data, sender_curve_data.length,
            msg_for_session, msg_for_session.length
        );
        if (result == Olm.error_val ()) {
            warning ("create_inbound_session_from failed: %s",
                Olm.session_last_error (session));
            Olm.clear_session (session);
            return null;
        }

        // Remove used one-time key
        Olm.remove_one_time_keys (partner_acct, session);

        // Get max plaintext length (destroys the message copy)
        var msg_copy2 = new uint8[msg_data1.length];
        Memory.copy (msg_copy2, msg_data1, msg_data1.length);
        var max_pt = Olm.decrypt_max_plaintext_length (
            session, msg_type, msg_copy2, msg_copy2.length
        );
        if (max_pt == Olm.error_val ()) {
            warning ("decrypt_max_plaintext_length failed: %s",
                Olm.session_last_error (session));
            Olm.clear_session (session);
            return null;
        }

        // Decrypt
        var pt_buf = new uint8[max_pt + 1];
        var msg_copy3 = new uint8[msg_data1.length];
        Memory.copy (msg_copy3, msg_data1, msg_data1.length);

        var pt_len = Olm.decrypt (
            session, msg_type,
            msg_copy3, msg_copy3.length,
            pt_buf, max_pt
        );
        if (pt_len == Olm.error_val ()) {
            warning ("olm_decrypt failed: %s", Olm.session_last_error (session));
            Olm.clear_session (session);
            return null;
        }

        pt_buf[pt_len] = 0;
        Olm.clear_session (session);
        return (string) pt_buf;
    } catch (Error e) {
        warning ("partner_decrypt_olm error: %s", e.message);
        return null;
    }
}

/**
 * Decrypt a Megolm-encrypted room event.
 */
string? partner_megolm_decrypt (void* inbound_session, string ciphertext) {
    // group_decrypt_max_plaintext_length destroys the message, so copy
    var ct_data = ciphertext.data;

    var ct_copy1 = new uint8[ct_data.length];
    Memory.copy (ct_copy1, ct_data, ct_data.length);

    var max_pt = Olm.group_decrypt_max_plaintext_length (
        inbound_session, ct_copy1, ct_copy1.length
    );
    if (max_pt == Olm.error_val ()) {
        warning ("group_decrypt_max_plaintext_length failed: %s",
            Olm.inbound_group_session_last_error (inbound_session));
        return null;
    }

    var pt_buf = new uint8[max_pt + 1];
    uint32 message_index;

    var ct_copy2 = new uint8[ct_data.length];
    Memory.copy (ct_copy2, ct_data, ct_data.length);

    var pt_len = Olm.group_decrypt (
        inbound_session,
        ct_copy2, ct_copy2.length,
        pt_buf, max_pt,
        out message_index
    );
    if (pt_len == Olm.error_val ()) {
        warning ("group_decrypt failed: %s",
            Olm.inbound_group_session_last_error (inbound_session));
        return null;
    }

    pt_buf[pt_len] = 0;
    return (string) pt_buf;
}

/**
 * Decrypt an AES-256-CTR encrypted attachment.
 */
uint8[]? decrypt_attachment (uint8[] ciphertext, uint8[] key, uint8[] iv) {
    var ctx = new OpenSSL.CipherCtx ();
    if (ctx.decrypt_init (OpenSSL.aes_256_ctr (), null, key, iv) != 1) {
        warning ("EVP_DecryptInit_ex failed");
        return null;
    }
    ctx.set_padding (0);

    var plaintext = new uint8[ciphertext.length];
    int out_len = 0;

    if (ctx.decrypt_update (plaintext, out out_len, ciphertext, ciphertext.length) != 1) {
        warning ("EVP_DecryptUpdate failed");
        return null;
    }

    return plaintext;
}

uint8[] read_urandom (size_t length) {
    if (length == 0) {
        return new uint8[0];
    }
    var buf = new uint8[length];
    try {
        var file = File.new_for_path ("/dev/urandom");
        var stream = new DataInputStream (file.read (null));
        size_t bytes_read;
        stream.read_all (buf, out bytes_read, null);
        stream.close (null);
    } catch (Error e) {
        error ("Failed to read /dev/urandom: %s", e.message);
    }
    return buf;
}

void clean_crypto_dir () {
    var account_pickle = Path.build_filename (crypto_dir, "account.pickle");
    var megolm_pickle = Path.build_filename (crypto_dir, "megolm_outbound.pickle");
    FileUtils.remove (account_pickle);
    FileUtils.remove (megolm_pickle);
}

/* ── The actual test ──────────────────────────────────────────── */

void test_full_e2ee_flow () {
    clean_crypto_dir ();
    setup_mock_server ();

    var loop = new MainLoop ();
    bool test_passed = false;

    test_full_e2ee_flow_async.begin ((obj, res) => {
        test_passed = test_full_e2ee_flow_async.end (res);
        loop.quit ();
    });

    // Timeout after 30 seconds
    Timeout.add_seconds (30, () => {
        warning ("Test timed out");
        loop.quit ();
        return Source.REMOVE;
    });

    loop.run ();
    assert_true (test_passed);

    mock_server.disconnect ();
    mock_server = null;
}

async bool test_full_e2ee_flow_async () {
    var url = mock_url ();
    var sender_user = "@vigil:localhost";
    var partner_user = "@partner:localhost";
    var partner_device = "DEV_PARTNER";

    /* ── Step 1: Login Vigil (sender) ────────────────────────── */

    var transport = new Vigil.Services.MatrixTransportService ();
    var token = yield transport.login (url, "vigil", "password");
    if (token == null) {
        warning ("FAIL: Vigil login failed");
        return false;
    }
    debug ("Vigil logged in: token=%s, device=%s", token, transport.last_device_id);

    /* ── Step 2: Create encrypted room ───────────────────────── */

    var created_room = yield transport.create_encrypted_room (partner_user);
    if (created_room == null) {
        warning ("FAIL: Room creation failed");
        return false;
    }
    debug ("Room created: %s", created_room);

    /* ── Step 3: Create partner account and upload keys ──────── */

    uint8[] partner_acct_buf;
    void* partner_acct;
    string partner_curve;
    string partner_ed;
    create_partner_account (out partner_acct_buf, out partner_acct,
                            out partner_curve, out partner_ed);

    // Generate one-time keys for partner
    var random_len = Olm.account_generate_one_time_keys_random_length (partner_acct, 5);
    var random = read_urandom (random_len);
    Olm.account_generate_one_time_keys (partner_acct, 5, random, random_len);

    upload_partner_keys (partner_user, partner_device,
                         partner_curve, partner_ed, partner_acct);
    debug ("Partner keys uploaded (curve25519: %s)", partner_curve);

    /* ── Step 4: Setup E2EE on Vigil side ────────────────────── */

    var enc = new Vigil.Services.EncryptionService ();
    enc.user_id = sender_user;
    enc.device_id = transport.last_device_id;

    if (!enc.initialize ("test-pickle-key")) {
        warning ("FAIL: EncryptionService init failed");
        return false;
    }

    var e2ee_ok = yield transport.setup_e2ee (enc, partner_user);
    if (!e2ee_ok) {
        warning ("FAIL: E2EE setup failed");
        enc.cleanup ();
        return false;
    }
    debug ("E2EE setup complete, Megolm session: %s", enc.megolm_session_id);

    /* ── Step 5: Partner receives and decrypts the room key ──── */

    var partner_inbox = to_device_inbox.lookup (partner_user);
    if (partner_inbox == null || partner_inbox.length == 0) {
        warning ("FAIL: No to-device messages for partner");
        enc.cleanup ();
        return false;
    }
    debug ("Partner has %d to-device message(s)", (int) partner_inbox.length);

    // Decrypt the Olm-wrapped room key
    var room_key_json = partner_decrypt_olm (
        partner_acct, partner_curve,
        enc.curve25519_key, partner_inbox[0]
    );

    if (room_key_json == null) {
        warning ("FAIL: Could not decrypt Olm message");
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        return false;
    }
    debug ("Decrypted room key: %s", room_key_json);

    // Parse the m.room_key content
    string? session_key = null;
    string? session_id = null;
    try {
        var parser = new Json.Parser ();
        parser.load_from_data (room_key_json);
        var rk = parser.get_root ().get_object ();

        // Verify it's an m.room_key
        if (rk.has_member ("algorithm")) {
            assert_true (rk.get_string_member ("algorithm") == "m.megolm.v1.aes-sha2");
        }
        if (rk.has_member ("room_id")) {
            assert_true (rk.get_string_member ("room_id") == mock_room_id);
        }
        session_key = rk.get_string_member ("session_key");
        session_id = rk.get_string_member ("session_id");

        assert_true (session_id == enc.megolm_session_id);
    } catch (Error e) {
        warning ("FAIL: Could not parse room key: %s", e.message);
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        return false;
    }

    // Create inbound Megolm session from the shared key
    var igs_buf = new uint8[Olm.inbound_group_session_size ()];
    var igs = Olm.inbound_group_session_init (igs_buf);

    var sk_data = session_key.data;
    var igs_result = Olm.init_inbound_group_session (igs, sk_data, sk_data.length);
    if (igs_result == Olm.error_val ()) {
        warning ("FAIL: init_inbound_group_session failed: %s",
            Olm.inbound_group_session_last_error (igs));
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        return false;
    }
    debug ("Partner: inbound Megolm session created");

    /* ── Step 6: Vigil sends an encrypted text message ───────── */

    var sent_ok = yield transport.send_text_message ("Hello from Vigil integration test!");
    if (!sent_ok) {
        warning ("FAIL: send_text_message failed");
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        Olm.clear_inbound_group_session (igs);
        return false;
    }
    debug ("Vigil sent encrypted text message");

    /* ── Step 7: Partner decrypts the Megolm event ───────────── */

    var events = room_events.lookup (mock_room_id);
    if (events == null || events.length == 0) {
        warning ("FAIL: No room events recorded");
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        Olm.clear_inbound_group_session (igs);
        return false;
    }

    // The event should be m.room.encrypted
    var event_json = events[events.length - 1];
    try {
        var parser = new Json.Parser ();
        parser.load_from_data (event_json);
        var evt = parser.get_root ().get_object ();

        assert_true (evt.get_string_member ("algorithm") == "m.megolm.v1.aes-sha2");
        assert_true (evt.has_member ("ciphertext"));
        assert_true (evt.get_string_member ("session_id") == enc.megolm_session_id);

        var ciphertext = evt.get_string_member ("ciphertext");

        // Decrypt with the inbound Megolm session
        var plaintext = partner_megolm_decrypt (igs, ciphertext);
        if (plaintext == null) {
            warning ("FAIL: Megolm decryption failed");
            enc.cleanup ();
            Olm.clear_account (partner_acct);
            Olm.clear_inbound_group_session (igs);
            return false;
        }

        debug ("Partner decrypted: %s", plaintext);

        // Verify the plaintext contains the original message
        var pt_parser = new Json.Parser ();
        pt_parser.load_from_data (plaintext);
        var pt_obj = pt_parser.get_root ().get_object ();

        assert_true (pt_obj.get_string_member ("type") == "m.room.message");
        assert_true (pt_obj.get_string_member ("room_id") == mock_room_id);

        var content = pt_obj.get_object_member ("content");
        assert_true (content.get_string_member ("msgtype") == "m.text");
        assert_true (content.get_string_member ("body") == "Hello from Vigil integration test!");
    } catch (Error e) {
        warning ("FAIL: Event parsing failed: %s", e.message);
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        Olm.clear_inbound_group_session (igs);
        return false;
    }

    debug ("Text message E2EE round-trip: PASSED");

    /* ── Step 8: Vigil sends an encrypted attachment ─────────── */

    // Create a test "screenshot" file
    var test_png = new uint8[1024];
    for (int i = 0; i < test_png.length; i++) {
        test_png[i] = (uint8) (i % 251);
    }
    var test_file = Path.build_filename (test_data_dir, "test_screenshot.png");
    try {
        FileUtils.set_data (test_file, test_png);
    } catch (Error e) {
        warning ("FAIL: Could not write test file: %s", e.message);
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        Olm.clear_inbound_group_session (igs);
        return false;
    }

    var capture_time = new DateTime.now_local ();
    var screenshot_ok = yield transport.send_screenshot (test_file, capture_time);
    if (!screenshot_ok) {
        warning ("FAIL: send_screenshot failed");
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        Olm.clear_inbound_group_session (igs);
        return false;
    }
    debug ("Vigil sent encrypted screenshot");

    /* ── Step 9: Partner decrypts the attachment ──────────────── */

    // The screenshot event is the latest room event
    events = room_events.lookup (mock_room_id);
    var screenshot_event_json = events[events.length - 1];

    try {
        var parser = new Json.Parser ();
        parser.load_from_data (screenshot_event_json);
        var evt = parser.get_root ().get_object ();

        // Decrypt the Megolm layer
        var ciphertext = evt.get_string_member ("ciphertext");
        var plaintext = partner_megolm_decrypt (igs, ciphertext);
        if (plaintext == null) {
            warning ("FAIL: Screenshot Megolm decryption failed");
            enc.cleanup ();
            Olm.clear_account (partner_acct);
            Olm.clear_inbound_group_session (igs);
            return false;
        }

        debug ("Partner decrypted screenshot event: %s",
            plaintext.length > 200 ? plaintext.substring (0, 200) + "..." : plaintext);

        // Parse the decrypted event
        var pt_parser = new Json.Parser ();
        pt_parser.load_from_data (plaintext);
        var pt_obj = pt_parser.get_root ().get_object ();
        var content = pt_obj.get_object_member ("content");

        assert_true (content.get_string_member ("msgtype") == "m.image");
        assert_true (content.has_member ("file"));

        var file_obj = content.get_object_member ("file");
        var mxc_url = file_obj.get_string_member ("url");
        assert_true (mxc_url.has_prefix ("mxc://"));

        // Extract the AES key (JWK base64url-encoded)
        var key_obj = file_obj.get_object_member ("key");
        var k_b64url = key_obj.get_string_member ("k");

        // Decode base64url key
        var k_b64 = k_b64url.replace ("-", "+").replace ("_", "/");
        // Add padding
        while (k_b64.length % 4 != 0) k_b64 += "=";
        var aes_key = Base64.decode (k_b64);
        assert_true (aes_key.length == 32);

        // Extract IV (standard base64, unpadded)
        var iv_b64 = file_obj.get_string_member ("iv");
        while (iv_b64.length % 4 != 0) iv_b64 += "=";
        var iv = Base64.decode (iv_b64);
        assert_true (iv.length == 16);

        // Extract expected SHA-256 hash
        var hashes = file_obj.get_object_member ("hashes");
        var expected_sha_b64 = hashes.get_string_member ("sha256");

        // Get the uploaded ciphertext from mock media store
        var enc_bytes = uploaded_media.lookup (mxc_url);
        if (enc_bytes == null) {
            warning ("FAIL: Encrypted media not found at %s", mxc_url);
            enc.cleanup ();
            Olm.clear_account (partner_acct);
            Olm.clear_inbound_group_session (igs);
            return false;
        }

        var enc_data = enc_bytes.get_data ();

        // Verify SHA-256 of ciphertext
        var checksum = new Checksum (ChecksumType.SHA256);
        checksum.update (enc_data, enc_data.length);
        var hash_hex = checksum.get_string ();

        // Decode expected hash for comparison
        var exp_sha_padded = expected_sha_b64;
        while (exp_sha_padded.length % 4 != 0) exp_sha_padded += "=";
        var expected_sha = Base64.decode (exp_sha_padded);
        var exp_hex = new StringBuilder ();
        for (int i = 0; i < expected_sha.length; i++) {
            exp_hex.append ("%02x".printf (expected_sha[i]));
        }
        assert_true (hash_hex == exp_hex.str);
        debug ("SHA-256 integrity check: PASSED");

        // Decrypt the attachment
        // Need to make a mutable copy of enc_data for the decrypt function
        var enc_copy = new uint8[enc_data.length];
        Memory.copy (enc_copy, enc_data, enc_data.length);
        var decrypted = decrypt_attachment (enc_copy, aes_key, iv);
        if (decrypted == null) {
            warning ("FAIL: Attachment decryption failed");
            enc.cleanup ();
            Olm.clear_account (partner_acct);
            Olm.clear_inbound_group_session (igs);
            return false;
        }

        // Verify decrypted content matches original
        assert_true (decrypted.length == test_png.length);
        for (int i = 0; i < test_png.length; i++) {
            if (decrypted[i] != test_png[i]) {
                warning ("FAIL: Decrypted byte %d differs: %u vs %u",
                    i, decrypted[i], test_png[i]);
                enc.cleanup ();
                Olm.clear_account (partner_acct);
                Olm.clear_inbound_group_session (igs);
                return false;
            }
        }
        debug ("Attachment decryption: content matches original (%d bytes)", test_png.length);
    } catch (Error e) {
        warning ("FAIL: Screenshot event parsing failed: %s", e.message);
        enc.cleanup ();
        Olm.clear_account (partner_acct);
        Olm.clear_inbound_group_session (igs);
        return false;
    }

    debug ("Encrypted attachment round-trip: PASSED");

    /* ── Cleanup ─────────────────────────────────────────────── */

    enc.cleanup ();
    Olm.clear_account (partner_acct);
    Olm.clear_inbound_group_session (igs);
    FileUtils.remove (test_file);

    debug ("ALL E2EE INTEGRATION TESTS PASSED");
    return true;
}

/* ── Test runner ──────────────────────────────────────────────── */

public static int main (string[] args) {
    test_data_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-e2ee-test-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
    DirUtils.create_with_parents (test_data_dir, 0755);
    Environment.set_variable ("XDG_DATA_HOME", test_data_dir, true);

    crypto_dir = Path.build_filename (
        test_data_dir, "io.github.invarianz.vigil", "crypto"
    );

    Test.init (ref args);

    Test.add_func ("/e2ee_integration/full_flow", test_full_e2ee_flow);

    var result = Test.run ();

    TestUtils.delete_directory_recursive (test_data_dir);

    return result;
}
