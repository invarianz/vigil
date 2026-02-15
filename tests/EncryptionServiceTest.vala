/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for EncryptionService.
 *
 * Tests OlmAccount creation, identity key extraction, signing,
 * Megolm session creation, encryption, pickle/unpickle persistence,
 * and the device keys JSON output format.
 *
 * Note: XDG_DATA_HOME must be set ONCE before the first GLib call
 * since g_get_user_data_dir() caches the value on first invocation.
 */

string test_data_dir;
string crypto_dir;

void clean_crypto_dir () {
    // Remove just the pickle files, not the directory structure
    var account_pickle = Path.build_filename (crypto_dir, "account.pickle");
    var megolm_pickle = Path.build_filename (crypto_dir, "megolm_outbound.pickle");
    FileUtils.remove (account_pickle);
    FileUtils.remove (megolm_pickle);
}

void test_initialize_creates_account () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";

    bool result = svc.initialize ("test-pickle-key");
    assert_true (result);
    assert_true (svc.is_ready);
    assert_true (svc.curve25519_key != "");
    assert_true (svc.ed25519_key != "");

    svc.cleanup ();
}

void test_identity_keys_are_base64 () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    // Curve25519 and Ed25519 keys should be base64 (43 chars for 32 bytes)
    assert_true (svc.curve25519_key.length >= 40);
    assert_true (svc.ed25519_key.length >= 40);

    svc.cleanup ();
}

void test_sign_string () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    var sig = svc.sign_string ("hello world");
    assert_true (sig != "");
    assert_true (sig.length > 40); // Ed25519 signatures are 64 bytes base64

    // Signing the same message should produce the same signature
    var sig2 = svc.sign_string ("hello world");
    assert_true (sig == sig2);

    // Different messages should produce different signatures
    var sig3 = svc.sign_string ("different message");
    assert_true (sig != sig3);

    svc.cleanup ();
}

void test_device_keys_json () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    var json = svc.get_device_keys_json ();
    assert_true (json != "");

    // Parse and verify structure
    try {
        var parser = new Json.Parser ();
        parser.load_from_data (json);
        var root = parser.get_root ().get_object ();

        assert_true (root.has_member ("device_keys"));
        var dk = root.get_object_member ("device_keys");
        assert_true (dk.get_string_member ("user_id") == "@test:matrix.org");
        assert_true (dk.get_string_member ("device_id") == "TESTDEVICE");
        assert_true (dk.has_member ("keys"));
        assert_true (dk.has_member ("algorithms"));
        assert_true (dk.has_member ("signatures"));

        // Verify key names
        var keys = dk.get_object_member ("keys");
        assert_true (keys.has_member ("curve25519:TESTDEVICE"));
        assert_true (keys.has_member ("ed25519:TESTDEVICE"));

        // Verify signatures structure
        var sigs = dk.get_object_member ("signatures");
        assert_true (sigs.has_member ("@test:matrix.org"));
        var user_sigs = sigs.get_object_member ("@test:matrix.org");
        assert_true (user_sigs.has_member ("ed25519:TESTDEVICE"));

        assert_true (root.has_member ("one_time_keys"));
    } catch (Error e) {
        assert_not_reached ();
    }

    svc.cleanup ();
}

void test_megolm_session_creation () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    bool created = svc.create_outbound_group_session ();
    assert_true (created);
    assert_true (svc.megolm_session_id != "");

    // Session key should be available
    var key = svc.get_megolm_session_key ();
    assert_true (key != null);
    assert_true (key.length > 0);

    svc.cleanup ();
}

void test_megolm_encrypt () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");
    svc.create_outbound_group_session ();

    var ciphertext = svc.megolm_encrypt ("{\"msgtype\":\"m.text\",\"body\":\"hello\"}");
    assert_true (ciphertext != null);
    assert_true (ciphertext.length > 0);

    // Encrypting the same plaintext should produce different ciphertext
    // (because Megolm advances the ratchet)
    var ciphertext2 = svc.megolm_encrypt ("{\"msgtype\":\"m.text\",\"body\":\"hello\"}");
    assert_true (ciphertext2 != null);
    assert_true (ciphertext != ciphertext2);

    svc.cleanup ();
}

void test_encrypt_event () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");
    svc.create_outbound_group_session ();

    var content = "{\"msgtype\":\"m.text\",\"body\":\"hello\"}";
    var encrypted = svc.encrypt_event ("!room:test", "m.room.message", content);
    assert_true (encrypted != null);

    // Verify it's valid JSON with the expected fields
    try {
        var parser = new Json.Parser ();
        parser.load_from_data (encrypted);
        var obj = parser.get_root ().get_object ();

        assert_true (obj.get_string_member ("algorithm") == "m.megolm.v1.aes-sha2");
        assert_true (obj.has_member ("ciphertext"));
        assert_true (obj.has_member ("session_id"));
        assert_true (obj.has_member ("sender_key"));
        assert_true (obj.has_member ("device_id"));
        assert_true (obj.get_string_member ("session_id") == svc.megolm_session_id);
        assert_true (obj.get_string_member ("device_id") == "TESTDEVICE");
    } catch (Error e) {
        assert_not_reached ();
    }

    svc.cleanup ();
}

void test_pickle_and_restore () {
    clean_crypto_dir ();

    string original_curve;
    string original_ed;

    // Create and save
    {
        var svc = new Vigil.Services.EncryptionService ();
        svc.user_id = "@test:matrix.org";
        svc.device_id = "TESTDEVICE";
        svc.initialize ("test-pickle-key");

        original_curve = svc.curve25519_key;
        original_ed = svc.ed25519_key;

        svc.cleanup ();
    }

    // Restore from pickle (same key)
    {
        var svc2 = new Vigil.Services.EncryptionService ();
        svc2.user_id = "@test:matrix.org";
        svc2.device_id = "TESTDEVICE";
        bool restored = svc2.initialize ("test-pickle-key");

        assert_true (restored);
        assert_true (svc2.is_ready);
        // Identity keys should be the same after restore
        assert_true (svc2.curve25519_key == original_curve);
        assert_true (svc2.ed25519_key == original_ed);

        svc2.cleanup ();
    }
}

void test_fresh_init_creates_different_keys () {
    clean_crypto_dir ();

    // Create first account
    var svc1 = new Vigil.Services.EncryptionService ();
    svc1.user_id = "@test:matrix.org";
    svc1.device_id = "TESTDEVICE";
    svc1.initialize ("key1");
    var curve1 = svc1.curve25519_key;
    svc1.cleanup ();

    // Clean up and create a brand new account
    clean_crypto_dir ();

    var svc2 = new Vigil.Services.EncryptionService ();
    svc2.user_id = "@test:matrix.org";
    svc2.device_id = "TESTDEVICE";
    svc2.initialize ("key2");
    var curve2 = svc2.curve25519_key;
    svc2.cleanup ();

    // Different initializations should produce different keys
    assert_true (curve1 != curve2);
}

void test_room_key_content () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");
    svc.create_outbound_group_session ();

    var content = svc.build_room_key_content ("!myroom:matrix.org");
    assert_true (content != null);

    try {
        var parser = new Json.Parser ();
        parser.load_from_data (content);
        var obj = parser.get_root ().get_object ();

        assert_true (obj.get_string_member ("algorithm") == "m.megolm.v1.aes-sha2");
        assert_true (obj.get_string_member ("room_id") == "!myroom:matrix.org");
        assert_true (obj.has_member ("session_id"));
        assert_true (obj.has_member ("session_key"));
        assert_true (obj.has_member ("chain_index"));
    } catch (Error e) {
        assert_not_reached ();
    }

    svc.cleanup ();
}

void test_encrypt_attachment_basic () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    var plaintext = new uint8[256];
    for (int i = 0; i < 256; i++) {
        plaintext[i] = (uint8) (i & 0xFF);
    }

    var result = svc.encrypt_attachment (plaintext);
    assert_true (result != null);

    // Ciphertext should be same length as plaintext (CTR mode, no padding)
    assert_true (result.ciphertext.length == plaintext.length);

    // Key should be 32 bytes (256-bit AES)
    assert_true (result.key.length == 32);

    // IV should be 16 bytes
    assert_true (result.iv.length == 16);

    // Lower 8 bytes of IV should be zero (counter portion)
    for (int i = 8; i < 16; i++) {
        assert_true (result.iv[i] == 0);
    }

    // SHA-256 hash should be 32 bytes
    assert_true (result.sha256.length == 32);

    // Ciphertext should differ from plaintext
    bool differs = false;
    for (int i = 0; i < plaintext.length; i++) {
        if (plaintext[i] != result.ciphertext[i]) {
            differs = true;
            break;
        }
    }
    assert_true (differs);

    svc.cleanup ();
}

void test_encrypt_attachment_different_keys_each_time () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    var plaintext = "test data for encryption".data;

    var result1 = svc.encrypt_attachment (plaintext);
    var result2 = svc.encrypt_attachment (plaintext);

    assert_true (result1 != null);
    assert_true (result2 != null);

    // Each encryption should use a different key
    bool key_differs = false;
    for (int i = 0; i < 32; i++) {
        if (result1.key[i] != result2.key[i]) {
            key_differs = true;
            break;
        }
    }
    assert_true (key_differs);

    // Different key → different ciphertext
    bool ct_differs = false;
    for (int i = 0; i < result1.ciphertext.length; i++) {
        if (result1.ciphertext[i] != result2.ciphertext[i]) {
            ct_differs = true;
            break;
        }
    }
    assert_true (ct_differs);

    svc.cleanup ();
}

void test_encrypt_attachment_sha256_correct () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    var plaintext = "verify sha256 hash".data;
    var result = svc.encrypt_attachment (plaintext);
    assert_true (result != null);

    // Recompute SHA-256 of ciphertext and compare
    var checksum = new Checksum (ChecksumType.SHA256);
    checksum.update (result.ciphertext, result.ciphertext.length);
    var hash_hex = checksum.get_string ();

    // Convert result.sha256 back to hex for comparison
    var result_hex = new StringBuilder ();
    for (int i = 0; i < result.sha256.length; i++) {
        result_hex.append ("%02x".printf (result.sha256[i]));
    }

    assert_true (hash_hex == result_hex.str);

    svc.cleanup ();
}

void test_encrypt_attachment_large_file () {
    clean_crypto_dir ();

    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    // Simulate a ~2MB screenshot
    var plaintext = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < plaintext.length; i++) {
        plaintext[i] = (uint8) (i % 251); // prime modulus for variety
    }

    var result = svc.encrypt_attachment (plaintext);
    assert_true (result != null);
    assert_true (result.ciphertext.length == plaintext.length);

    svc.cleanup ();
}

void test_base64url_encoding () {
    // Test that base64url uses - and _ instead of + and /
    // and strips padding
    var data = new uint8[] { 0xFB, 0xFF, 0xFE };
    var encoded = Vigil.Services.EncryptionService.base64url_encode_unpadded (data);

    // Must not contain + / or =
    assert_true (!encoded.contains ("+"));
    assert_true (!encoded.contains ("/"));
    assert_true (!encoded.contains ("="));

    // Standard base64 of {0xFB, 0xFF, 0xFE} is "+//+"
    // base64url should be "-__-"
    assert_true (encoded == "-__-");
}

void test_base64_unpadded () {
    // 1 byte → 2 base64 chars, normally "AA==" padded
    var data = new uint8[] { 0x00 };
    var encoded = Vigil.Services.EncryptionService.base64_encode_unpadded (data);
    assert_true (!encoded.has_suffix ("="));
    assert_true (encoded == "AA");

    // 2 bytes → 3 base64 chars, normally "AAA=" padded
    var data2 = new uint8[] { 0x00, 0x00 };
    var encoded2 = Vigil.Services.EncryptionService.base64_encode_unpadded (data2);
    assert_true (!encoded2.has_suffix ("="));
    assert_true (encoded2 == "AAA");
}

void test_not_ready_before_init () {
    var svc = new Vigil.Services.EncryptionService ();
    assert_false (svc.is_ready);
    assert_true (svc.curve25519_key == "");
    assert_true (svc.ed25519_key == "");
    assert_true (svc.megolm_session_id == "");
}

void test_megolm_session_restore () {
    clean_crypto_dir ();

    string session_id;

    // Create account and Megolm session
    {
        var svc = new Vigil.Services.EncryptionService ();
        svc.user_id = "@test:matrix.org";
        svc.device_id = "TESTDEVICE";
        svc.initialize ("test-pickle-key");
        svc.create_outbound_group_session ();
        session_id = svc.megolm_session_id;
        svc.cleanup ();
    }

    // Restore both account and Megolm session
    {
        var svc2 = new Vigil.Services.EncryptionService ();
        svc2.user_id = "@test:matrix.org";
        svc2.device_id = "TESTDEVICE";
        svc2.initialize ("test-pickle-key");

        bool restored = svc2.restore_group_session ();
        assert_true (restored);
        assert_true (svc2.megolm_session_id == session_id);

        svc2.cleanup ();
    }
}

uint32 get_unix_mode (string path) {
    try {
        var file = File.new_for_path (path);
        var info = file.query_info ("unix::mode", FileQueryInfoFlags.NONE, null);
        return info.get_attribute_uint32 ("unix::mode") & 0777;
    } catch (Error e) {
        warning ("Cannot stat %s: %s", path, e.message);
        return 0xFFFF;
    }
}

void test_crypto_dir_permissions () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");

    // Crypto directory should be 0700 (owner-only)
    assert_true (get_unix_mode (crypto_dir) == 0700);

    svc.cleanup ();
}

void test_pickle_file_permissions () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@test:matrix.org";
    svc.device_id = "TESTDEVICE";
    svc.initialize ("test-pickle-key");
    svc.create_outbound_group_session ();

    // Account pickle should be 0600 (owner read/write only)
    var account_pickle = Path.build_filename (crypto_dir, "account.pickle");
    assert_true (get_unix_mode (account_pickle) == 0600);

    // Megolm pickle should also be 0600
    var megolm_pickle = Path.build_filename (crypto_dir, "megolm_outbound.pickle");
    assert_true (get_unix_mode (megolm_pickle) == 0600);

    svc.cleanup ();
}

public static int main (string[] args) {
    // Set XDG_DATA_HOME ONCE before Test.init caches it
    test_data_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-crypto-test-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
    DirUtils.create_with_parents (test_data_dir, 0755);
    Environment.set_variable ("XDG_DATA_HOME", test_data_dir, true);

    crypto_dir = Path.build_filename (
        test_data_dir, "io.github.invarianz.vigil", "crypto"
    );

    Test.init (ref args);

    Test.add_func ("/encryption/initialize", test_initialize_creates_account);
    Test.add_func ("/encryption/identity_keys_base64", test_identity_keys_are_base64);
    Test.add_func ("/encryption/sign_string", test_sign_string);
    Test.add_func ("/encryption/device_keys_json", test_device_keys_json);
    Test.add_func ("/encryption/megolm_session", test_megolm_session_creation);
    Test.add_func ("/encryption/megolm_encrypt", test_megolm_encrypt);
    Test.add_func ("/encryption/encrypt_event", test_encrypt_event);
    Test.add_func ("/encryption/pickle_restore", test_pickle_and_restore);
    Test.add_func ("/encryption/fresh_different_keys", test_fresh_init_creates_different_keys);
    Test.add_func ("/encryption/room_key_content", test_room_key_content);
    Test.add_func ("/encryption/not_ready_before_init", test_not_ready_before_init);
    Test.add_func ("/encryption/megolm_session_restore", test_megolm_session_restore);
    Test.add_func ("/encryption/encrypt_attachment_basic", test_encrypt_attachment_basic);
    Test.add_func ("/encryption/encrypt_attachment_different_keys", test_encrypt_attachment_different_keys_each_time);
    Test.add_func ("/encryption/encrypt_attachment_sha256", test_encrypt_attachment_sha256_correct);
    Test.add_func ("/encryption/encrypt_attachment_large_file", test_encrypt_attachment_large_file);
    Test.add_func ("/encryption/base64url_encoding", test_base64url_encoding);
    Test.add_func ("/encryption/base64_unpadded", test_base64_unpadded);
    Test.add_func ("/encryption/crypto_dir_permissions", test_crypto_dir_permissions);
    Test.add_func ("/encryption/pickle_file_permissions", test_pickle_file_permissions);

    var result = Test.run ();

    // Cleanup
    TestUtils.delete_directory_recursive (test_data_dir);

    return result;
}
