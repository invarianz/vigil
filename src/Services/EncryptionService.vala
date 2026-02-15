/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Native E2EE implementation using libolm (Olm/Megolm).
 *
 * Inspired by pantalaimon's crypto layer, this manages:
 *   - OlmAccount: device identity keys (Ed25519 + Curve25519)
 *   - OlmOutboundGroupSession: Megolm encryption for room messages
 *   - OlmSession: Olm 1:1 encryption for sharing Megolm room keys
 *
 * The user provides a "pickle key" (E2EE password) that encrypts
 * the cryptographic state at rest. All crypto state is stored in
 * ~/.local/share/io.github.invarianz.vigil/crypto/
 *
 * Flow (following pantalaimon's pattern):
 *   1. Create or restore OlmAccount
 *   2. Upload device keys + one-time keys to homeserver
 *   3. Create Megolm outbound session for the room
 *   4. Query partner's device keys, establish Olm sessions
 *   5. Share Megolm room key via Olm-encrypted to-device messages
 *   6. Encrypt all outgoing messages with Megolm
 */
public class Vigil.Services.EncryptionService : Object {

    /** Curve25519 identity key (public). */
    public string curve25519_key { get; private set; default = ""; }

    /** Ed25519 identity key (public). */
    public string ed25519_key { get; private set; default = ""; }

    /** Device ID assigned by the homeserver. */
    public string device_id { get; set; default = ""; }

    /** User ID (e.g. @user:matrix.org). */
    public string user_id { get; set; default = ""; }

    /** Whether E2EE is initialized and ready. */
    public bool is_ready { get; private set; default = false; }

    /** Megolm session ID for the current room. */
    public string megolm_session_id { get; private set; default = ""; }

    /* Backing memory for libolm objects */
    private uint8[] _account_buf;
    private void* _account;

    private uint8[] _group_session_buf;
    private void* _group_session;

    /* Pickle key for encrypting state at rest */
    private string _pickle_key = "";

    /* Crypto state storage directory */
    private string _crypto_dir;

    /* Cached /dev/urandom stream for fast random generation */
    private DataInputStream? _urandom_stream;

    /* Whether the Megolm session state needs to be persisted */
    private bool _group_session_dirty = false;

    private const int ONE_TIME_KEY_COUNT = 50;

    construct {
        _crypto_dir = Path.build_filename (
            Environment.get_user_data_dir (),
            "io.github.invarianz.vigil",
            "crypto"
        );
    }

    /**
     * Initialize the encryption layer.
     *
     * Creates a new OlmAccount or restores one from a previous pickle.
     *
     * @param pickle_key The user's E2EE password used to encrypt state at rest.
     * @return true if initialization succeeded.
     */
    public bool initialize (string pickle_key) {
        _pickle_key = pickle_key;

        // Ensure crypto directory exists
        var dir = File.new_for_path (_crypto_dir);
        try {
            dir.make_directory_with_parents (null);
        } catch (Error e) {
            // Directory may already exist
            if (!(e is IOError.EXISTS)) {
                warning ("Cannot create crypto dir: %s", e.message);
                return false;
            }
        }

        // Allocate OlmAccount
        _account_buf = new uint8[Olm.account_size ()];
        _account = Olm.account_init (_account_buf);

        // Try to restore from pickle
        var pickle_path = Path.build_filename (_crypto_dir, "account.pickle");
        if (FileUtils.test (pickle_path, FileTest.EXISTS)) {
            if (restore_account (pickle_path)) {
                extract_identity_keys ();
                is_ready = true;
                debug ("Restored OlmAccount from pickle");
                return true;
            }
            warning ("Failed to restore OlmAccount, creating new one");
        }

        // Create new account
        var random_len = Olm.create_account_random_length (_account);
        var random = generate_random (random_len);
        var result = Olm.create_account (_account, random, random_len);
        if (result == Olm.error_val ()) {
            warning ("olm_create_account failed: %s", Olm.account_last_error (_account));
            return false;
        }

        extract_identity_keys ();
        generate_one_time_keys ();
        save_account ();

        is_ready = true;
        debug ("Created new OlmAccount (curve25519: %s)", curve25519_key);
        return true;
    }

    /**
     * Get the device keys JSON for uploading to the Matrix homeserver.
     *
     * Returns the signed device keys object as per the Matrix spec:
     * POST /_matrix/client/v3/keys/upload
     */
    public string get_device_keys_json () {
        // Pass 1: Build unsigned device_keys JSON for signing
        var dk_builder = new Json.Builder ();
        dk_builder.begin_object ();

        dk_builder.set_member_name ("algorithms");
        dk_builder.begin_array ();
        dk_builder.add_string_value ("m.olm.v1.curve25519-aes-sha2");
        dk_builder.add_string_value ("m.megolm.v1.aes-sha2");
        dk_builder.end_array ();

        dk_builder.set_member_name ("device_id");
        dk_builder.add_string_value (device_id);

        dk_builder.set_member_name ("keys");
        dk_builder.begin_object ();
        dk_builder.set_member_name ("curve25519:%s".printf (device_id));
        dk_builder.add_string_value (curve25519_key);
        dk_builder.set_member_name ("ed25519:%s".printf (device_id));
        dk_builder.add_string_value (ed25519_key);
        dk_builder.end_object ();

        dk_builder.set_member_name ("user_id");
        dk_builder.add_string_value (user_id);

        dk_builder.end_object ();

        // Sign the unsigned device_keys
        var dk_gen = new Json.Generator ();
        dk_gen.set_root (dk_builder.get_root ());
        var unsigned_json = dk_gen.to_data (null);
        var signature = sign_string (unsigned_json);

        // Pass 2: Build the full upload body with signatures included
        var builder = new Json.Builder ();
        builder.begin_object ();

        builder.set_member_name ("device_keys");
        builder.begin_object ();

        builder.set_member_name ("algorithms");
        builder.begin_array ();
        builder.add_string_value ("m.olm.v1.curve25519-aes-sha2");
        builder.add_string_value ("m.megolm.v1.aes-sha2");
        builder.end_array ();

        builder.set_member_name ("device_id");
        builder.add_string_value (device_id);

        builder.set_member_name ("keys");
        builder.begin_object ();
        builder.set_member_name ("curve25519:%s".printf (device_id));
        builder.add_string_value (curve25519_key);
        builder.set_member_name ("ed25519:%s".printf (device_id));
        builder.add_string_value (ed25519_key);
        builder.end_object ();

        builder.set_member_name ("signatures");
        builder.begin_object ();
        builder.set_member_name (user_id);
        builder.begin_object ();
        builder.set_member_name ("ed25519:%s".printf (device_id));
        builder.add_string_value (signature);
        builder.end_object ();
        builder.end_object ();

        builder.set_member_name ("user_id");
        builder.add_string_value (user_id);

        builder.end_object (); // device_keys

        // One-time keys
        builder.set_member_name ("one_time_keys");
        builder.begin_object ();

        var otk_json = get_one_time_keys_json ();
        if (otk_json != null) {
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
            } catch (Error e) {
                warning ("Failed to parse OTK JSON: %s", e.message);
            }
        }

        builder.end_object (); // one_time_keys
        builder.end_object (); // root

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        return gen.to_data (null);
    }

    /**
     * Mark one-time keys as published after successful upload.
     */
    public void mark_keys_as_published () {
        Olm.account_mark_keys_as_published (_account);
        save_account ();
    }

    /**
     * Create a new Megolm outbound group session for a room.
     *
     * @return true if session was created successfully.
     */
    public bool create_outbound_group_session () {
        _group_session_buf = new uint8[Olm.outbound_group_session_size ()];
        _group_session = Olm.outbound_group_session_init (_group_session_buf);

        var random_len = Olm.init_outbound_group_session_random_length (_group_session);
        var random = generate_random (random_len);

        var result = Olm.init_outbound_group_session (_group_session, random, random_len);
        if (result == Olm.error_val ()) {
            warning ("Failed to create Megolm session: %s",
                Olm.outbound_group_session_last_error (_group_session));
            return false;
        }

        // Get session ID
        var id_len = Olm.outbound_group_session_id_length (_group_session);
        var id_buf = new uint8[id_len];
        Olm.outbound_group_session_id (_group_session, id_buf, id_len);
        megolm_session_id = (string) id_buf;

        save_group_session ();
        debug ("Created Megolm outbound session: %s", megolm_session_id);
        return true;
    }

    /**
     * Get the Megolm session key for sharing with room members.
     *
     * This key is encrypted per-device via Olm and sent as
     * m.room_key to-device events.
     */
    public string? get_megolm_session_key () {
        if (_group_session == null) {
            return null;
        }

        var key_len = Olm.outbound_group_session_key_length (_group_session);
        var key_buf = new uint8[key_len];
        var result = Olm.outbound_group_session_key (_group_session, key_buf, key_len);
        if (result == Olm.error_val ()) {
            warning ("Failed to get Megolm session key: %s",
                Olm.outbound_group_session_last_error (_group_session));
            return null;
        }

        return (string) key_buf;
    }

    /**
     * Encrypt a plaintext JSON string using the Megolm group session.
     *
     * @param plaintext The JSON content to encrypt.
     * @return The base64-encoded ciphertext, or null on failure.
     */
    public string? megolm_encrypt (string plaintext) {
        if (_group_session == null) {
            warning ("No Megolm session available for encryption");
            return null;
        }

        var pt_bytes = plaintext.data;
        var ct_len = Olm.group_encrypt_message_length (_group_session, pt_bytes.length);
        var ct_buf = new uint8[ct_len];

        var result = Olm.group_encrypt (
            _group_session,
            pt_bytes, pt_bytes.length,
            ct_buf, ct_len
        );

        if (result == Olm.error_val ()) {
            warning ("Megolm encrypt failed: %s",
                Olm.outbound_group_session_last_error (_group_session));
            return null;
        }

        _group_session_dirty = true;
        return ((string) ct_buf).substring (0, (long) result);
    }

    /**
     * Build an m.room.encrypted event content JSON from a plaintext event.
     *
     * @param room_id The room the message is for.
     * @param event_type The original event type (e.g. "m.room.message").
     * @param content_json The original unencrypted content JSON.
     * @return The encrypted event content JSON, or null on failure.
     */
    public string? encrypt_event (string room_id, string event_type, string content_json) {
        // Build the plaintext payload that gets encrypted
        var pt_builder = new Json.Builder ();
        pt_builder.begin_object ();
        pt_builder.set_member_name ("type");
        pt_builder.add_string_value (event_type);
        pt_builder.set_member_name ("room_id");
        pt_builder.add_string_value (room_id);

        // Parse and embed the content
        try {
            var parser = new Json.Parser ();
            parser.load_from_data (content_json);
            pt_builder.set_member_name ("content");
            pt_builder.add_value (parser.get_root ());
        } catch (Error e) {
            warning ("Failed to parse content JSON: %s", e.message);
            return null;
        }

        pt_builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (pt_builder.get_root ());
        var plaintext = gen.to_data (null);

        // Encrypt with Megolm
        var ciphertext = megolm_encrypt (plaintext);
        if (ciphertext == null) {
            return null;
        }

        // Build the m.room.encrypted content
        var enc_builder = new Json.Builder ();
        enc_builder.begin_object ();
        enc_builder.set_member_name ("algorithm");
        enc_builder.add_string_value ("m.megolm.v1.aes-sha2");
        enc_builder.set_member_name ("sender_key");
        enc_builder.add_string_value (curve25519_key);
        enc_builder.set_member_name ("ciphertext");
        enc_builder.add_string_value (ciphertext);
        enc_builder.set_member_name ("session_id");
        enc_builder.add_string_value (megolm_session_id);
        enc_builder.set_member_name ("device_id");
        enc_builder.add_string_value (device_id);
        enc_builder.end_object ();

        var enc_gen = new Json.Generator ();
        enc_gen.set_root (enc_builder.get_root ());
        return enc_gen.to_data (null);
    }

    /**
     * Create an Olm session with a device and encrypt a payload.
     *
     * Used for sharing Megolm room keys via to-device messages,
     * following pantalaimon's key-sharing approach.
     *
     * @param their_curve25519 The device's Curve25519 identity key.
     * @param their_one_time_key The claimed one-time key.
     * @param plaintext The JSON payload to encrypt.
     * @return Object with "type" (int) and "body" (string), or null.
     */
    public string? olm_encrypt_for_device (string their_curve25519,
                                            string their_one_time_key,
                                            string plaintext) {
        var session_buf = new uint8[Olm.session_size ()];
        var session = Olm.session_init (session_buf);

        var random_len = Olm.create_outbound_session_random_length (session);
        var random = generate_random (random_len);

        var id_key_data = their_curve25519.data;
        var otk_data = their_one_time_key.data;

        var result = Olm.create_outbound_session (
            session, _account,
            id_key_data, id_key_data.length,
            otk_data, otk_data.length,
            random, random_len
        );

        if (result == Olm.error_val ()) {
            warning ("Failed to create Olm session: %s", Olm.session_last_error (session));
            Olm.clear_session (session);
            return null;
        }

        // Encrypt the plaintext
        var msg_type = Olm.encrypt_message_type (session);
        var enc_random_len = Olm.encrypt_random_length (session);
        var enc_random = generate_random (enc_random_len);
        var pt_data = plaintext.data;
        var msg_len = Olm.encrypt_message_length (session, pt_data.length);
        var msg_buf = new uint8[msg_len];

        result = Olm.encrypt (
            session,
            pt_data, pt_data.length,
            enc_random, enc_random_len,
            msg_buf, msg_len
        );

        if (result == Olm.error_val ()) {
            warning ("Olm encrypt failed: %s", Olm.session_last_error (session));
            Olm.clear_session (session);
            return null;
        }

        var body = ((string) msg_buf).substring (0, (long) result);

        // Build the encrypted content
        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("type");
        builder.add_int_value ((int64) msg_type);
        builder.set_member_name ("body");
        builder.add_string_value (body);
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());

        Olm.clear_session (session);
        return gen.to_data (null);
    }

    /**
     * Build the m.room_key to-device event content for sharing
     * the Megolm session key with a specific device.
     *
     * @param room_id The room this session key is for.
     * @return The plaintext JSON to be Olm-encrypted per device.
     */
    public string? build_room_key_content (string room_id) {
        var session_key = get_megolm_session_key ();
        if (session_key == null) {
            return null;
        }

        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("algorithm");
        builder.add_string_value ("m.megolm.v1.aes-sha2");
        builder.set_member_name ("room_id");
        builder.add_string_value (room_id);
        builder.set_member_name ("session_id");
        builder.add_string_value (megolm_session_id);
        builder.set_member_name ("session_key");
        builder.add_string_value (session_key);
        builder.set_member_name ("chain_index");
        builder.add_int_value ((int64) Olm.outbound_group_session_message_index (_group_session));
        builder.end_object ();

        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        return gen.to_data (null);
    }

    /**
     * Sign a string with the account's Ed25519 key.
     */
    public string sign_string (string message) {
        var msg_data = message.data;
        var sig_len = Olm.account_signature_length (_account);
        var sig_buf = new uint8[sig_len + 1];

        var result = Olm.account_sign (
            _account,
            msg_data, msg_data.length,
            sig_buf, sig_len
        );

        if (result == Olm.error_val ()) {
            warning ("olm_account_sign failed: %s", Olm.account_last_error (_account));
            return "";
        }

        sig_buf[sig_len] = 0; // null-terminate
        return (string) sig_buf;
    }

    /**
     * Restore the Megolm outbound group session from pickle.
     */
    public bool restore_group_session () {
        var pickle_path = Path.build_filename (_crypto_dir, "megolm_outbound.pickle");
        if (!FileUtils.test (pickle_path, FileTest.EXISTS)) {
            return false;
        }

        try {
            string pickle_data;
            FileUtils.get_contents (pickle_path, out pickle_data);

            _group_session_buf = new uint8[Olm.outbound_group_session_size ()];
            _group_session = Olm.outbound_group_session_init (_group_session_buf);

            var key_data = _pickle_key.data;
            var pickle_bytes = pickle_data.data;
            // Need a mutable copy since unpickle destroys the input
            var pickle_copy = new uint8[pickle_bytes.length];
            Memory.copy (pickle_copy, pickle_bytes, pickle_bytes.length);

            var result = Olm.unpickle_outbound_group_session (
                _group_session,
                key_data, key_data.length,
                pickle_copy, pickle_copy.length
            );

            if (result == Olm.error_val ()) {
                warning ("Failed to restore Megolm session: %s",
                    Olm.outbound_group_session_last_error (_group_session));
                _group_session = null;
                return false;
            }

            // Recover session ID
            var id_len = Olm.outbound_group_session_id_length (_group_session);
            var id_buf = new uint8[id_len + 1];
            Olm.outbound_group_session_id (_group_session, id_buf, id_len);
            id_buf[id_len] = 0;
            megolm_session_id = (string) id_buf;

            debug ("Restored Megolm session: %s", megolm_session_id);
            return true;
        } catch (Error e) {
            warning ("Error restoring Megolm session: %s", e.message);
            return false;
        }
    }

    /**
     * Clean up all libolm objects.
     */
    public void cleanup () {
        if (_account != null) {
            Olm.clear_account (_account);
            _account = null;
        }
        if (_group_session != null) {
            Olm.clear_outbound_group_session (_group_session);
            _group_session = null;
        }
        if (_urandom_stream != null) {
            try { _urandom_stream.close (null); } catch (Error e) {}
            _urandom_stream = null;
        }
        is_ready = false;
    }

    /**
     * Persist the Megolm session state to disk if it has changed.
     *
     * Call this after a successful send rather than on every encrypt,
     * to avoid a disk write on the hot path.
     */
    public void save_session_if_needed () {
        if (_group_session_dirty && _group_session != null) {
            save_group_session ();
            _group_session_dirty = false;
        }
    }

    /* ───── Encrypted attachments (AES-256-CTR per Matrix spec) ───── */

    /**
     * Result of encrypting a file attachment for Matrix.
     */
    public struct EncryptedAttachment {
        /** The encrypted ciphertext bytes. */
        public uint8[] ciphertext;
        /** 256-bit AES key, raw bytes (32 bytes). */
        public uint8[] key;
        /** 128-bit IV with high-order bits as counter (16 bytes). */
        public uint8[] iv;
        /** SHA-256 hash of the ciphertext, raw bytes (32 bytes). */
        public uint8[] sha256;
    }

    /**
     * Encrypt file data for a Matrix encrypted attachment.
     *
     * Per the Matrix spec, attachments are encrypted with AES-256-CTR
     * before upload. The key, IV, and SHA-256 hash are embedded in the
     * Megolm-encrypted event so only room members can decrypt.
     *
     * @param plaintext The raw file bytes to encrypt.
     * @return The encrypted attachment data, or null on failure.
     */
    public EncryptedAttachment? encrypt_attachment (uint8[] plaintext) {
        // Generate 256-bit key and 128-bit IV
        var key = generate_random (32);
        var iv = generate_random (16);

        // Matrix spec: set the lower 8 bytes of IV to zero (counter portion)
        // The upper 8 bytes are random, lower 8 are the counter starting at 0
        for (int i = 8; i < 16; i++) {
            iv[i] = 0;
        }

        var ctx = new OpenSSL.CipherCtx ();
        if (ctx.encrypt_init (OpenSSL.aes_256_ctr (), null, key, iv) != 1) {
            warning ("EVP_EncryptInit_ex failed");
            return null;
        }
        ctx.set_padding (0); // CTR mode doesn't need padding

        // Allocate output buffer (CTR mode: ciphertext length == plaintext length)
        var ciphertext = new uint8[plaintext.length + 16]; // +16 for block safety
        int out_len = 0;
        int final_len = 0;

        if (ctx.encrypt_update (ciphertext, out out_len, plaintext, plaintext.length) != 1) {
            warning ("EVP_EncryptUpdate failed");
            return null;
        }

        if (ctx.encrypt_final (ciphertext[out_len:ciphertext.length], out final_len) != 1) {
            warning ("EVP_EncryptFinal_ex failed");
            return null;
        }

        int total_len = out_len + final_len;

        // Trim to actual size
        var result_ct = new uint8[total_len];
        Memory.copy (result_ct, ciphertext, total_len);

        // SHA-256 of ciphertext
        var checksum = new Checksum (ChecksumType.SHA256);
        checksum.update (result_ct, total_len);
        var hash_hex = checksum.get_string ();

        // Convert hex to raw bytes
        var sha256 = new uint8[32];
        for (int i = 0; i < 32; i++) {
            sha256[i] = (uint8) uint64.parse (
                hash_hex.substring (i * 2, 2), 16
            );
        }

        var attachment = EncryptedAttachment ();
        attachment.ciphertext = (owned) result_ct;
        attachment.key = (owned) key;
        attachment.iv = (owned) iv;
        attachment.sha256 = (owned) sha256;
        return attachment;
    }

    /**
     * Encode raw bytes to unpadded base64 (standard alphabet).
     */
    public static string base64_encode_unpadded (uint8[] data) {
        var encoded = Base64.encode (data);
        // Strip trailing '=' padding
        while (encoded.has_suffix ("=")) {
            encoded = encoded.substring (0, encoded.length - 1);
        }
        return encoded;
    }

    /**
     * Encode raw bytes to unpadded base64url (RFC 4648 §5).
     *
     * Matrix JWK keys use base64url encoding.
     */
    public static string base64url_encode_unpadded (uint8[] data) {
        var encoded = base64_encode_unpadded (data);
        // base64 → base64url: replace + with -, / with _
        return encoded.replace ("+", "-").replace ("/", "_");
    }

    /* ───── Private helpers ───── */

    private void extract_identity_keys () {
        var keys_len = Olm.account_identity_keys_length (_account);
        var keys_buf = new uint8[keys_len + 1];

        var result = Olm.account_identity_keys (_account, keys_buf, keys_len);
        if (result == Olm.error_val ()) {
            warning ("Failed to get identity keys: %s", Olm.account_last_error (_account));
            return;
        }

        keys_buf[keys_len] = 0; // null-terminate
        var keys_json = (string) keys_buf;

        try {
            var parser = new Json.Parser ();
            parser.load_from_data (keys_json);
            var obj = parser.get_root ().get_object ();

            curve25519_key = obj.get_string_member ("curve25519");
            ed25519_key = obj.get_string_member ("ed25519");
        } catch (Error e) {
            warning ("Failed to parse identity keys: %s", e.message);
        }
    }

    private void generate_one_time_keys () {
        var random_len = Olm.account_generate_one_time_keys_random_length (
            _account, ONE_TIME_KEY_COUNT
        );
        var random = generate_random (random_len);

        var result = Olm.account_generate_one_time_keys (
            _account, ONE_TIME_KEY_COUNT, random, random_len
        );

        if (result == Olm.error_val ()) {
            warning ("Failed to generate OTKs: %s", Olm.account_last_error (_account));
        }
    }

    private string? get_one_time_keys_json () {
        var keys_len = Olm.account_one_time_keys_length (_account);
        if (keys_len == 0) {
            return null;
        }

        var keys_buf = new uint8[keys_len + 1];
        var result = Olm.account_one_time_keys (_account, keys_buf, keys_len);
        if (result == Olm.error_val ()) {
            warning ("Failed to get OTKs: %s", Olm.account_last_error (_account));
            return null;
        }

        keys_buf[keys_len] = 0;
        return (string) keys_buf;
    }

    private void save_account () {
        var key_data = _pickle_key.data;
        var pickle_len = Olm.pickle_account_length (_account);
        var pickle_buf = new uint8[pickle_len + 1];

        var result = Olm.pickle_account (
            _account,
            key_data, key_data.length,
            pickle_buf, pickle_len
        );

        if (result == Olm.error_val ()) {
            warning ("Failed to pickle account: %s", Olm.account_last_error (_account));
            return;
        }

        pickle_buf[pickle_len] = 0;
        var pickle_path = Path.build_filename (_crypto_dir, "account.pickle");
        try {
            FileUtils.set_contents (pickle_path, (string) pickle_buf);
        } catch (Error e) {
            warning ("Failed to save account pickle: %s", e.message);
        }
    }

    private bool restore_account (string pickle_path) {
        try {
            string pickle_data;
            FileUtils.get_contents (pickle_path, out pickle_data);

            var key_data = _pickle_key.data;
            var pickle_bytes = pickle_data.data;
            // Unpickle destroys input, so copy
            var pickle_copy = new uint8[pickle_bytes.length];
            Memory.copy (pickle_copy, pickle_bytes, pickle_bytes.length);

            var result = Olm.unpickle_account (
                _account,
                key_data, key_data.length,
                pickle_copy, pickle_copy.length
            );

            if (result == Olm.error_val ()) {
                warning ("Failed to unpickle account: %s", Olm.account_last_error (_account));
                return false;
            }

            return true;
        } catch (Error e) {
            warning ("Error reading account pickle: %s", e.message);
            return false;
        }
    }

    private void save_group_session () {
        if (_group_session == null) {
            return;
        }

        var key_data = _pickle_key.data;
        var pickle_len = Olm.pickle_outbound_group_session_length (_group_session);
        var pickle_buf = new uint8[pickle_len + 1];

        var result = Olm.pickle_outbound_group_session (
            _group_session,
            key_data, key_data.length,
            pickle_buf, pickle_len
        );

        if (result == Olm.error_val ()) {
            warning ("Failed to pickle Megolm session: %s",
                Olm.outbound_group_session_last_error (_group_session));
            return;
        }

        pickle_buf[pickle_len] = 0;
        var pickle_path = Path.build_filename (_crypto_dir, "megolm_outbound.pickle");
        try {
            FileUtils.set_contents (pickle_path, (string) pickle_buf);
        } catch (Error e) {
            warning ("Failed to save Megolm pickle: %s", e.message);
        }
    }

    /**
     * Generate cryptographic random bytes using a cached /dev/urandom fd.
     */
    private uint8[] generate_random (size_t length) {
        var buf = new uint8[length];

        try {
            if (_urandom_stream == null) {
                var file = File.new_for_path ("/dev/urandom");
                _urandom_stream = new DataInputStream (file.read (null));
            }
            size_t bytes_read;
            _urandom_stream.read_all (buf, out bytes_read, null);
        } catch (Error e) {
            // Fallback to GLib random
            warning ("Failed to read /dev/urandom, using GLib.Random: %s", e.message);
            for (size_t i = 0; i < length; i++) {
                buf[i] = (uint8) GLib.Random.int_range (0, 256);
            }
        }

        return buf;
    }

}
