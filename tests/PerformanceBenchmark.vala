/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Performance benchmarks for Vigil's hot paths.
 *
 * Measures wall-clock time for:
 *   1.  Random number generation (/dev/urandom open+read+close vs cached fd)
 *   2.  Ed25519 signing
 *   3.  Megolm encryption (with deferred pickle save)
 *   4.  encrypt_event full path (JSON build + Megolm + JSON build)
 *   5.  AES-256-CTR encrypt_attachment at various sizes (1KB, 100KB, 2MB)
 *   6.  SHA-256 of ciphertext (inside encrypt_attachment)
 *   7.  base64url encoding (key/IV serialization)
 *   8.  Encrypted event JSON build (the JWK/EncryptedFile envelope)
 *   9.  StorageService mark_pending / mark_uploaded cycle
 *   10. StorageService get_pending_screenshots (0, 50, 200 files)
 *   11. StorageService cleanup_old_screenshots (100 files)
 *   12. Pending count: cached vs directory scan
 *   13. File read (2MB sync)
 *   14. TamperDetectionService.compute_config_hash
 *   15. Full encrypted pipeline simulation (sans network)
 *
 * Run with: ./PerformanceBenchmark_test
 * Each benchmark prints: operation, iterations, total_us, per_op_us
 */

string bench_data_dir;
string crypto_dir;

delegate void BenchBody ();

/**
 * Run a body N times and print timing.
 */
void bench (string name, int iterations, BenchBody body) {
    // Warmup
    body ();

    var timer = new Timer ();
    timer.start ();

    for (int i = 0; i < iterations; i++) {
        body ();
    }

    timer.stop ();
    double elapsed = timer.elapsed () * 1000000.0; // seconds → microseconds
    double per_op = elapsed / iterations;

    print ("%-50s %6d iters %10.0f us total %8.1f us/op\n",
           name, iterations, elapsed, per_op);
}

void clean_crypto_dir () {
    var account_pickle = Path.build_filename (crypto_dir, "account.pickle");
    var megolm_pickle = Path.build_filename (crypto_dir, "megolm_outbound.pickle");
    FileUtils.remove (account_pickle);
    FileUtils.remove (megolm_pickle);
}

Vigil.Services.EncryptionService make_enc_service () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@bench:test";
    svc.device_id = "BENCHDEV";
    svc.initialize ("bench-key");
    svc.create_outbound_group_session ();
    return svc;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 1: Random Number Generation
 * ════════════════════════════════════════════════════════════════════════════ */

void bench_urandom_open_read_close () {
    bench ("urandom open+read(32)+close", 1000, () => {
        try {
            var file = File.new_for_path ("/dev/urandom");
            var stream = file.read (null);
            var buf = new uint8[32];
            size_t bytes_read;
            stream.read_all (buf, out bytes_read, null);
            stream.close (null);
        } catch (Error e) {}
    });
}

void bench_urandom_cached_fd () {
    FileInputStream? cached_stream = null;
    try {
        var file = File.new_for_path ("/dev/urandom");
        cached_stream = file.read (null);
    } catch (Error e) { return; }

    bench ("urandom cached-fd read(32)", 1000, () => {
        try {
            var buf = new uint8[32];
            size_t bytes_read;
            cached_stream.read_all (buf, out bytes_read, null);
        } catch (Error e) {}
    });

    try { cached_stream.close (null); } catch (Error e) {}
}

void bench_urandom_cached_fd_48 () {
    // 48 bytes = 32 (AES key) + 16 (IV) -- what encrypt_attachment needs
    FileInputStream? cached_stream = null;
    try {
        var file = File.new_for_path ("/dev/urandom");
        cached_stream = file.read (null);
    } catch (Error e) { return; }

    bench ("urandom cached-fd read(48) [key+IV]", 1000, () => {
        try {
            var buf = new uint8[48];
            size_t bytes_read;
            cached_stream.read_all (buf, out bytes_read, null);
        } catch (Error e) {}
    });

    try { cached_stream.close (null); } catch (Error e) {}
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 2: Olm/Megolm Encryption
 * ════════════════════════════════════════════════════════════════════════════ */

void bench_sign_string () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@bench:test";
    svc.device_id = "BENCHDEV";
    svc.initialize ("bench-key");

    var message = "{\"algorithms\":[\"m.olm.v1\",\"m.megolm.v1\"],\"device_id\":\"BENCHDEV\"}";

    bench ("sign_string (Ed25519)", 2000, () => {
        svc.sign_string (message);
    });

    svc.cleanup ();
}

void bench_megolm_encrypt () {
    var svc = make_enc_service ();
    var plaintext = "{\"msgtype\":\"m.text\",\"body\":\"benchmark message payload here\"}";

    bench ("megolm_encrypt (deferred pickle)", 500, () => {
        svc.megolm_encrypt (plaintext);
    });

    svc.cleanup ();
}

void bench_megolm_encrypt_plus_save () {
    var svc = make_enc_service ();
    var plaintext = "{\"msgtype\":\"m.text\",\"body\":\"benchmark message payload here\"}";

    bench ("megolm_encrypt + save_session_if_needed", 500, () => {
        svc.megolm_encrypt (plaintext);
        svc.save_session_if_needed ();
    });

    svc.cleanup ();
}

void bench_encrypt_event () {
    var svc = make_enc_service ();
    var content =
        "{\"msgtype\":\"m.image\",\"body\":\"Screenshot 2025-01-01\"," +
        "\"url\":\"mxc://test/abc\",\"info\":{\"mimetype\":\"image/png\"}}";

    bench ("encrypt_event (JSON + Megolm + JSON)", 500, () => {
        svc.encrypt_event ("!room:test", "m.room.message", content);
    });

    svc.cleanup ();
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 3: AES-256-CTR Attachment Encryption
 * ════════════════════════════════════════════════════════════════════════════ */

void bench_encrypt_attachment_1kb () {
    var svc = make_enc_service ();
    var data = new uint8[1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("encrypt_attachment (1 KB)", 1000, () => {
        svc.encrypt_attachment (data);
    });

    svc.cleanup ();
}

void bench_encrypt_attachment_100kb () {
    var svc = make_enc_service ();
    var data = new uint8[100 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("encrypt_attachment (100 KB)", 500, () => {
        svc.encrypt_attachment (data);
    });

    svc.cleanup ();
}

void bench_encrypt_attachment_2mb () {
    var svc = make_enc_service ();
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("encrypt_attachment (2 MB)", 50, () => {
        svc.encrypt_attachment (data);
    });

    svc.cleanup ();
}

/* Isolate SHA-256 cost */
void bench_sha256_2mb () {
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("SHA-256 of 2 MB (GLib.Checksum)", 100, () => {
        var cs = new Checksum (ChecksumType.SHA256);
        cs.update (data, data.length);
        cs.get_string ();
    });
}

/* Isolate the hex-to-bytes conversion */
void bench_sha256_hex_to_bytes () {
    var hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    bench ("SHA-256 hex→bytes (32 × uint64.parse)", 5000, () => {
        var sha256 = new uint8[32];
        for (int i = 0; i < 32; i++) {
            sha256[i] = (uint8) uint64.parse (hex.substring (i * 2, 2), 16);
        }
    });
}

/* Isolate AES-CTR cost (no random gen, no SHA, no copy) */
void bench_aes_ctr_raw_2mb () {
    var key = new uint8[32];
    var iv = new uint8[16];
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("AES-256-CTR raw encrypt 2 MB (OpenSSL)", 50, () => {
        var ctx = new OpenSSL.CipherCtx ();
        ctx.encrypt_init (OpenSSL.aes_256_ctr (), null, key, iv);
        ctx.set_padding (0);
        var out_buf = new uint8[data.length + 16];
        int out_len, final_len;
        ctx.encrypt_update (out_buf, out out_len, data, data.length);
        ctx.encrypt_final (out_buf[out_len:out_buf.length], out final_len);
    });
}

/* Isolate Memory.copy cost */
void bench_memcpy_2mb () {
    var src = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < src.length; i++) src[i] = (uint8)(i & 0xFF);

    bench ("Memory.copy 2 MB", 200, () => {
        var dst = new uint8[src.length];
        Memory.copy (dst, src, src.length);
    });
}

/* base64url encode 32 bytes (AES key size) */
void bench_base64url_encode () {
    var data = new uint8[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8)(i * 7);

    bench ("base64url_encode_unpadded (32 B)", 5000, () => {
        Vigil.Services.EncryptionService.base64url_encode_unpadded (data);
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 4: Storage Operations
 * ════════════════════════════════════════════════════════════════════════════ */

void bench_storage_mark_cycle () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-cycle");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    int idx = 0;
    bench ("mark_pending + mark_uploaded cycle", 500, () => {
        var path = Path.build_filename (store.screenshots_dir, "cycle_%06d.png".printf (idx));
        try { FileUtils.set_contents (path, "x"); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}
        store.mark_uploaded (path);
        idx++;
    });
}

void bench_storage_pending_scan_empty () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-empty");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    bench ("get_pending_screenshots (0 files)", 1000, () => {
        store.get_pending_screenshots ();
    });
}

void bench_storage_pending_scan_50 () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-50");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    for (int i = 0; i < 50; i++) {
        var path = Path.build_filename (store.screenshots_dir, "bench_%04d.png".printf (i));
        try { FileUtils.set_contents (path, "fake-png-data"); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}
    }

    bench ("get_pending_screenshots (50 files)", 200, () => {
        store.get_pending_screenshots ();
    });
}

void bench_storage_pending_scan_200 () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-200");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    for (int i = 0; i < 200; i++) {
        var path = Path.build_filename (store.screenshots_dir, "bench_%04d.png".printf (i));
        try { FileUtils.set_contents (path, "fake-png-data"); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}
    }

    bench ("get_pending_screenshots (200 files)", 50, () => {
        store.get_pending_screenshots ();
    });
}

/* Cached pending_count vs full directory scan */
void bench_pending_count_cached () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-cached-cnt");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    for (int i = 0; i < 50; i++) {
        var path = Path.build_filename (store.screenshots_dir, "bench_%04d.png".printf (i));
        try { FileUtils.set_contents (path, "fake-png-data"); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}
    }
    // Prime the cache
    store.get_pending_screenshots ();

    bench ("pending_count (cached, O(1))", 10000, () => {
        var _ = store.pending_count;
    });
}

void bench_storage_cleanup_100 () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-cleanup");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    store.max_local_screenshots = 50;
    try { store.initialize (); } catch (Error e) {}

    bench ("cleanup_old_screenshots (100 files, limit 50)", 100, () => {
        // Re-create 100 files each iteration
        for (int i = 0; i < 100; i++) {
            var path = Path.build_filename (store.screenshots_dir, "cleanup_%04d.png".printf (i));
            try { FileUtils.set_contents (path, "fake"); } catch (Error e) {}
        }
        store.cleanup_old_screenshots ();
    });
}

void bench_storage_cleanup_below_limit () {
    var dir = Path.build_filename (bench_data_dir, "storage-bench-cleanup-fast");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    store.max_local_screenshots = 100;
    try { store.initialize (); } catch (Error e) {}

    // Create 10 files (well below limit of 100)
    for (int i = 0; i < 10; i++) {
        var path = Path.build_filename (store.screenshots_dir, "fast_%04d.png".printf (i));
        try { FileUtils.set_contents (path, "fake"); } catch (Error e) {}
    }
    // Prime the _screenshot_file_count cache
    store.cleanup_old_screenshots ();

    bench ("cleanup_old_screenshots (below limit, fast path)", 5000, () => {
        store.cleanup_old_screenshots ();
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 5: I/O
 * ════════════════════════════════════════════════════════════════════════════ */

void bench_file_read_2mb () {
    var fake_path = Path.build_filename (bench_data_dir, "fake_2mb.png");
    var buf = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < buf.length; i++) buf[i] = (uint8) (i & 0xFF);
    try { FileUtils.set_data (fake_path, buf); } catch (Error e) { return; }

    bench ("read 2 MB file into memory (sync)", 100, () => {
        try {
            uint8[] contents;
            FileUtils.get_data (fake_path, out contents);
        } catch (Error e) {}
    });

    FileUtils.remove (fake_path);
}

void bench_config_hash () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    var svc = new Vigil.Services.TamperDetectionService (settings);

    bench ("compute_config_hash (SHA256)", 2000, () => {
        svc.compute_config_hash ();
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 6: Full Pipeline (no network)
 * ════════════════════════════════════════════════════════════════════════════ */

void bench_full_pipeline_no_network () {
    // Simulates: generate_path → mark_pending → encrypt_event → mark_uploaded → cleanup
    var dir = Path.build_filename (bench_data_dir, "storage-bench-pipeline");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    var enc = make_enc_service ();
    var content =
        "{\"msgtype\":\"m.image\",\"body\":\"Screenshot\"," +
        "\"url\":\"mxc://test/abc\",\"info\":{\"mimetype\":\"image/png\"}}";

    bench ("pipeline: event-only (no attachment enc)", 200, () => {
        var path = store.generate_screenshot_path ();
        try { FileUtils.set_contents (path, "fake-png-data-for-benchmarking"); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}
        enc.encrypt_event ("!room:test", "m.room.message", content);
        store.mark_uploaded (path);
        store.cleanup_old_screenshots ();
    });

    enc.cleanup ();
}

void bench_full_encrypted_pipeline () {
    // Simulates the real E2EE path:
    // generate_path → file_read → encrypt_attachment → encrypt_event → mark_uploaded → cleanup
    var dir = Path.build_filename (bench_data_dir, "storage-bench-enc-pipeline");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    var enc = make_enc_service ();

    // Pre-create a 2MB "screenshot"
    var fake_png = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < fake_png.length; i++) fake_png[i] = (uint8)(i & 0xFF);

    bench ("pipeline: full E2EE (2MB attach + Megolm)", 20, () => {
        // 1. Generate path + write fake file
        var path = store.generate_screenshot_path ();
        try { FileUtils.set_data (path, fake_png); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}

        // 2. Read file back (simulating upload_media reading the file)
        uint8[] file_data;
        try { FileUtils.get_data (path, out file_data); } catch (Error e) { return; }

        // 3. AES-256-CTR encrypt attachment
        var att = enc.encrypt_attachment (file_data);

        // 4. Build encrypted event JSON (mimics send_encrypted_screenshot)
        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("msgtype");
        builder.add_string_value ("m.image");
        builder.set_member_name ("body");
        builder.add_string_value ("Screenshot 2025-01-01 12:00:00");
        builder.set_member_name ("file");
        builder.begin_object ();
        builder.set_member_name ("url");
        builder.add_string_value ("mxc://test/fake");
        builder.set_member_name ("key");
        builder.begin_object ();
        builder.set_member_name ("kty");
        builder.add_string_value ("oct");
        builder.set_member_name ("alg");
        builder.add_string_value ("A256CTR");
        builder.set_member_name ("k");
        builder.add_string_value (
            Vigil.Services.EncryptionService.base64url_encode_unpadded (att.key)
        );
        builder.set_member_name ("ext");
        builder.add_boolean_value (true);
        builder.end_object ();
        builder.set_member_name ("iv");
        builder.add_string_value (
            Vigil.Services.EncryptionService.base64_encode_unpadded (att.iv)
        );
        builder.set_member_name ("hashes");
        builder.begin_object ();
        builder.set_member_name ("sha256");
        builder.add_string_value (
            Vigil.Services.EncryptionService.base64_encode_unpadded (att.sha256)
        );
        builder.end_object ();
        builder.set_member_name ("v");
        builder.add_string_value ("v2");
        builder.end_object ();
        builder.end_object ();
        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        var content_json = gen.to_data (null);

        // 5. Megolm encrypt the event
        enc.encrypt_event ("!room:test", "m.room.message", content_json);

        // 6. Mark uploaded + cleanup
        store.mark_uploaded (path);
        store.cleanup_old_screenshots ();
    });

    enc.cleanup ();
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 7: Upload Path Overhead (copy vs zero-copy, file delete patterns)
 * ════════════════════════════════════════════════════════════════════════════ */

/* Measure Bytes construction: copy vs take (zero-copy) */
void bench_bytes_copy_2mb () {
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("new Bytes(data) - COPIES 2 MB", 100, () => {
        var b = new Bytes (data);
        // Access to prevent optimization
        b.get_data ();
    });
}

void bench_bytes_take_2mb () {
    bench ("new Bytes.take(data) - zero-copy 2 MB", 100, () => {
        var data = new uint8[2 * 1024 * 1024];
        var b = new Bytes.take ((owned) data);
        b.get_data ();
    });
}

/* File delete: query_exists+delete vs direct delete with error handling */
void bench_file_delete_exists_then_delete () {
    var dir = Path.build_filename (bench_data_dir, "bench-delete-exists");
    DirUtils.create_with_parents (dir, 0755);

    bench ("file delete: query_exists + delete (exists)", 500, () => {
        var path = Path.build_filename (dir, "testfile.tmp");
        try { FileUtils.set_contents (path, "x"); } catch (Error e) {}

        var f = File.new_for_path (path);
        try {
            if (f.query_exists ()) {
                f.delete ();
            }
        } catch (Error e) {}
    });
}

void bench_file_delete_direct () {
    var dir = Path.build_filename (bench_data_dir, "bench-delete-direct");
    DirUtils.create_with_parents (dir, 0755);

    bench ("file delete: direct delete (exists)", 500, () => {
        var path = Path.build_filename (dir, "testfile.tmp");
        try { FileUtils.set_contents (path, "x"); } catch (Error e) {}

        try {
            File.new_for_path (path).delete ();
        } catch (Error e) {}
    });
}

void bench_file_delete_exists_then_delete_missing () {
    var dir = Path.build_filename (bench_data_dir, "bench-delete-missing-e");
    DirUtils.create_with_parents (dir, 0755);
    var path = Path.build_filename (dir, "nonexistent.tmp");

    bench ("file delete: query_exists + delete (missing)", 2000, () => {
        var f = File.new_for_path (path);
        try {
            if (f.query_exists ()) {
                f.delete ();
            }
        } catch (Error e) {}
    });
}

void bench_file_delete_direct_missing () {
    var dir = Path.build_filename (bench_data_dir, "bench-delete-missing-d");
    DirUtils.create_with_parents (dir, 0755);
    var path = Path.build_filename (dir, "nonexistent.tmp");

    bench ("file delete: direct delete (missing)", 2000, () => {
        try {
            File.new_for_path (path).delete ();
        } catch (Error e) {}
    });
}

/* OpenSSL SHA-256 (actual hot path) vs GLib.Checksum */
void bench_sha256_openssl_2mb () {
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("SHA-256 of 2 MB (OpenSSL EVP_Digest)", 100, () => {
        var sha256 = new uint8[32];
        uint md_size;
        OpenSSL.digest (data, data.length, sha256, out md_size, OpenSSL.sha256 ());
    });
}

/* base64url encoding: current implementation (multiple string copies) */
void bench_base64url_current () {
    var data = new uint8[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8)(i * 7 + 0xAB);

    bench ("base64url (current: encode+strip+replace)", 5000, () => {
        // Current implementation path:
        var encoded = Base64.encode (data);
        while (encoded.has_suffix ("=")) {
            encoded = encoded.substring (0, encoded.length - 1);
        }
        var _result = encoded.replace ("+", "-").replace ("/", "_");
    });
}

/* base64url encoding: single-pass alternative */
void bench_base64url_singlepass () {
    var data = new uint8[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8)(i * 7 + 0xAB);

    bench ("base64url (single-pass StringBuilder)", 5000, () => {
        var encoded = Base64.encode (data);
        var sb = new StringBuilder.sized (encoded.length);
        for (int i = 0; i < encoded.length; i++) {
            char c = encoded[i];
            if (c == '=') break;
            else if (c == '+') sb.append_c ('-');
            else if (c == '/') sb.append_c ('_');
            else sb.append_c (c);
        }
        var _result = sb.str;
    });
}

/* Measure mark_uploaded file count cache invalidation */
void bench_mark_uploaded_then_cleanup () {
    var dir = Path.build_filename (bench_data_dir, "bench-upload-cleanup");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    store.max_local_screenshots = 50;
    try { store.initialize (); } catch (Error e) {}

    bench ("mark_uploaded + cleanup (stale count cache)", 100, () => {
        // Create 60 files (above 50 limit)
        for (int i = 0; i < 60; i++) {
            var path = Path.build_filename (store.screenshots_dir, "mu_%04d.png".printf (i));
            try { FileUtils.set_contents (path, "fake"); } catch (Error e) {}
            try { store.mark_pending (path); } catch (Error e) {}
        }
        // Upload first 20 (deletes them, but _screenshot_file_count not updated)
        for (int i = 0; i < 20; i++) {
            var path = Path.build_filename (store.screenshots_dir, "mu_%04d.png".printf (i));
            store.mark_uploaded (path);
        }
        // Cleanup should do a full dir scan since count cache is stale
        store.cleanup_old_screenshots ();
    });
}

/* JSON builder cost for encrypted event envelope */
void bench_json_encrypted_event () {
    bench ("JSON build: encrypted event envelope", 2000, () => {
        var builder = new Json.Builder ();
        builder.begin_object ();
        builder.set_member_name ("msgtype");
        builder.add_string_value ("m.image");
        builder.set_member_name ("body");
        builder.add_string_value ("Screenshot 2025-01-01 12:00:00");
        builder.set_member_name ("file");
        builder.begin_object ();
        builder.set_member_name ("url");
        builder.add_string_value ("mxc://test/fake");
        builder.set_member_name ("mimetype");
        builder.add_string_value ("image/png");
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
        builder.add_string_value ("dGVzdGtleQ");
        builder.set_member_name ("ext");
        builder.add_boolean_value (true);
        builder.end_object ();
        builder.set_member_name ("iv");
        builder.add_string_value ("dGVzdGl2");
        builder.set_member_name ("hashes");
        builder.begin_object ();
        builder.set_member_name ("sha256");
        builder.add_string_value ("dGVzdGhhc2g");
        builder.end_object ();
        builder.set_member_name ("v");
        builder.add_string_value ("v2");
        builder.end_object ();
        builder.set_member_name ("info");
        builder.begin_object ();
        builder.set_member_name ("mimetype");
        builder.add_string_value ("image/png");
        builder.end_object ();
        builder.end_object ();
        var gen = new Json.Generator ();
        gen.set_root (builder.get_root ());
        gen.to_data (null);
    });
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Section 8: Optimization Candidates (before/after comparison data)
 * ════════════════════════════════════════════════════════════════════════════ */

/* SHA-256 with hex output: OpenSSL vs GLib.Checksum (fair comparison) */
void bench_sha256_openssl_hex_2mb () {
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("SHA-256 hex: OpenSSL + hex encode", 100, () => {
        var sha256 = new uint8[32];
        uint md_size;
        OpenSSL.digest (data, data.length, sha256, out md_size, OpenSSL.sha256 ());
        // Convert to hex string (same output format as GLib.Checksum)
        var sb = new StringBuilder.sized (64);
        for (int i = 0; i < 32; i++) {
            sb.append_printf ("%02x", sha256[i]);
        }
        var _hex = sb.str;
    });
}

void bench_sha256_glib_hex_2mb () {
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);

    bench ("SHA-256 hex: GLib.Checksum (current)", 100, () => {
        Checksum.compute_for_data (ChecksumType.SHA256, data);
    });
}

/* Integrity verification: current GLib path vs OpenSSL path */
void bench_integrity_verify_glib () {
    // Simulates verify_screenshot_integrity with GLib.Checksum
    var dir = Path.build_filename (bench_data_dir, "bench-integrity-glib");
    DirUtils.create_with_parents (dir, 0755);
    var fake_path = Path.build_filename (dir, "screenshot.png");
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);
    try { FileUtils.set_data (fake_path, data); } catch (Error e) { return; }
    var stored_hash = Checksum.compute_for_data (ChecksumType.SHA256, data);

    bench ("integrity verify: file read + GLib SHA-256", 50, () => {
        try {
            uint8[] file_data;
            FileUtils.get_data (fake_path, out file_data);
            var current = Checksum.compute_for_data (ChecksumType.SHA256, file_data);
            var _match = (current == stored_hash);
        } catch (Error e) {}
    });

    FileUtils.remove (fake_path);
}

void bench_integrity_verify_openssl () {
    // Same verification using OpenSSL
    var dir = Path.build_filename (bench_data_dir, "bench-integrity-openssl");
    DirUtils.create_with_parents (dir, 0755);
    var fake_path = Path.build_filename (dir, "screenshot.png");
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);
    try { FileUtils.set_data (fake_path, data); } catch (Error e) { return; }

    // Pre-compute OpenSSL hash as hex
    var ref_hash = new uint8[32];
    uint ref_size;
    OpenSSL.digest (data, data.length, ref_hash, out ref_size, OpenSSL.sha256 ());
    var ref_sb = new StringBuilder.sized (64);
    for (int i = 0; i < 32; i++) ref_sb.append_printf ("%02x", ref_hash[i]);
    var stored_hash = ref_sb.str;

    bench ("integrity verify: file read + OpenSSL SHA-256", 50, () => {
        try {
            uint8[] file_data;
            FileUtils.get_data (fake_path, out file_data);
            var sha256 = new uint8[32];
            uint md_size;
            OpenSSL.digest (file_data, file_data.length, sha256, out md_size, OpenSSL.sha256 ());
            var sb = new StringBuilder.sized (64);
            for (int i = 0; i < 32; i++) sb.append_printf ("%02x", sha256[i]);
            var _match = (sb.str == stored_hash);
        } catch (Error e) {}
    });

    FileUtils.remove (fake_path);
}

/* Upload pipeline: triple-read (current) vs single-read (optimized) */
void bench_upload_pipeline_triple_read () {
    // Current: mark_pending reads+hashes, verify reads+hashes, send reads
    var dir = Path.build_filename (bench_data_dir, "bench-pipeline-triple");
    DirUtils.create_with_parents (dir, 0755);
    var fake_path = Path.build_filename (dir, "screenshot.png");
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);
    try { FileUtils.set_data (fake_path, data); } catch (Error e) { return; }

    var enc = make_enc_service ();
    var stored_hash = Checksum.compute_for_data (ChecksumType.SHA256, data);

    bench ("upload path: 3 reads + 2 GLib hashes + encrypt", 20, () => {
        // Read 1: verify integrity (re-hash with GLib)
        try {
            uint8[] d1;
            FileUtils.get_data (fake_path, out d1);
            var h1 = Checksum.compute_for_data (ChecksumType.SHA256, d1);
            var _match = (h1 == stored_hash);
        } catch (Error e) {}

        // Read 2: send_screenshot file read
        try {
            uint8[] d2;
            FileUtils.get_data (fake_path, out d2);
            enc.encrypt_attachment (d2);
        } catch (Error e) {}
    });

    enc.cleanup ();
    FileUtils.remove (fake_path);
}

void bench_upload_pipeline_single_read () {
    // Optimized: read once, OpenSSL hash, pass to encrypt
    var dir = Path.build_filename (bench_data_dir, "bench-pipeline-single");
    DirUtils.create_with_parents (dir, 0755);
    var fake_path = Path.build_filename (dir, "screenshot.png");
    var data = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < data.length; i++) data[i] = (uint8)(i & 0xFF);
    try { FileUtils.set_data (fake_path, data); } catch (Error e) { return; }

    var enc = make_enc_service ();

    // Pre-compute stored hash with OpenSSL
    var ref_hash = new uint8[32];
    uint ref_size;
    OpenSSL.digest (data, data.length, ref_hash, out ref_size, OpenSSL.sha256 ());
    var ref_sb = new StringBuilder.sized (64);
    for (int i = 0; i < 32; i++) ref_sb.append_printf ("%02x", ref_hash[i]);
    var stored_hash = ref_sb.str;

    bench ("upload path: 1 read + 1 OpenSSL hash + encrypt", 20, () => {
        // Single read, verify + encrypt from same buffer
        try {
            uint8[] file_data;
            FileUtils.get_data (fake_path, out file_data);

            // Verify with OpenSSL
            var sha256 = new uint8[32];
            uint md_size;
            OpenSSL.digest (file_data, file_data.length, sha256, out md_size, OpenSSL.sha256 ());
            var sb = new StringBuilder.sized (64);
            for (int i = 0; i < 32; i++) sb.append_printf ("%02x", sha256[i]);
            if (sb.str != stored_hash) return;

            // Encrypt same buffer (no re-read)
            enc.encrypt_attachment (file_data);
        } catch (Error e) {}
    });

    enc.cleanup ();
    FileUtils.remove (fake_path);
}

/* Scheduler CSPRNG: open/close vs cached fd */
void bench_scheduler_urandom_per_call () {
    bench ("scheduler CSPRNG: open+read(4)+close per interval", 1000, () => {
        try {
            uint8[] buf = new uint8[4];
            size_t bytes_read;
            var stream = File.new_for_path ("/dev/urandom").read (null);
            stream.read_all (buf, out bytes_read, null);
            stream.close (null);
            var _val = ((uint32) buf[0] << 24) | ((uint32) buf[1] << 16) |
                       ((uint32) buf[2] << 8) | (uint32) buf[3];
        } catch (Error e) {}
    });
}

void bench_scheduler_urandom_cached () {
    FileInputStream? cached_stream = null;
    try {
        cached_stream = File.new_for_path ("/dev/urandom").read (null);
    } catch (Error e) { return; }

    bench ("scheduler CSPRNG: cached-fd read(4)", 1000, () => {
        try {
            uint8[] buf = new uint8[4];
            size_t bytes_read;
            cached_stream.read_all (buf, out bytes_read, null);
            var _val = ((uint32) buf[0] << 24) | ((uint32) buf[1] << 16) |
                       ((uint32) buf[2] << 8) | (uint32) buf[3];
        } catch (Error e) {}
    });

    try { cached_stream.close (null); } catch (Error e) {}
}

/* PBKDF2 unlock code hashing (600K iterations) */
void bench_pbkdf2_unlock () {
    var salt = new uint8[16];
    try {
        var stream = File.new_for_path ("/dev/urandom").read (null);
        size_t br;
        stream.read_all (salt, out br, null);
        stream.close (null);
    } catch (Error e) { return; }

    bench ("PBKDF2-SHA256 unlock hash (600K iters)", 5, () => {
        var derived = new uint8[32];
        OpenSSL.pbkdf2_hmac (
            "test123", 7, salt, 16,
            600000, OpenSSL.sha256 (),
            32, derived
        );
    });
}

/* ════════════════════════════════════════════════════════════════════════════ */

public static int main (string[] args) {
    bench_data_dir = Path.build_filename (
        Environment.get_tmp_dir (),
        "vigil-perf-bench-%s".printf (GLib.Uuid.string_random ().substring (0, 8))
    );
    DirUtils.create_with_parents (bench_data_dir, 0755);
    Environment.set_variable ("XDG_DATA_HOME", bench_data_dir, true);

    crypto_dir = Path.build_filename (
        bench_data_dir, "io.github.invarianz.vigil", "crypto"
    );

    Test.init (ref args);

    print ("\n══════════════════════════════════════════════════════════════════════════════\n");
    print ("  Vigil Performance Benchmark (comprehensive)\n");
    print ("══════════════════════════════════════════════════════════════════════════════\n");

    print ("\n── 1. Random Number Generation ──────────────────────────────────────────────\n");
    bench_urandom_open_read_close ();
    bench_urandom_cached_fd ();
    bench_urandom_cached_fd_48 ();

    print ("\n── 2. Olm / Megolm Encryption ───────────────────────────────────────────────\n");
    bench_sign_string ();
    bench_megolm_encrypt ();
    bench_megolm_encrypt_plus_save ();
    bench_encrypt_event ();

    print ("\n── 3. AES-256-CTR Attachment Encryption ─────────────────────────────────────\n");
    bench_encrypt_attachment_1kb ();
    bench_encrypt_attachment_100kb ();
    bench_encrypt_attachment_2mb ();
    print ("   -- component breakdown for 2 MB --\n");
    bench_aes_ctr_raw_2mb ();
    bench_sha256_2mb ();
    bench_sha256_hex_to_bytes ();
    bench_memcpy_2mb ();
    bench_base64url_encode ();

    print ("\n── 4. Storage Operations ────────────────────────────────────────────────────\n");
    bench_storage_mark_cycle ();
    bench_storage_pending_scan_empty ();
    bench_storage_pending_scan_50 ();
    bench_storage_pending_scan_200 ();
    bench_pending_count_cached ();
    bench_storage_cleanup_100 ();
    bench_storage_cleanup_below_limit ();

    print ("\n── 5. I/O ──────────────────────────────────────────────────────────────────\n");
    bench_file_read_2mb ();
    bench_config_hash ();

    print ("\n── 6. Full Pipeline (no network) ────────────────────────────────────────────\n");
    bench_full_pipeline_no_network ();
    bench_full_encrypted_pipeline ();

    print ("\n── 7. Upload Path Overhead ──────────────────────────────────────────────────\n");
    bench_bytes_copy_2mb ();
    bench_bytes_take_2mb ();
    print ("   -- file delete patterns --\n");
    bench_file_delete_exists_then_delete ();
    bench_file_delete_direct ();
    bench_file_delete_exists_then_delete_missing ();
    bench_file_delete_direct_missing ();
    print ("   -- SHA-256 hot path --\n");
    bench_sha256_openssl_2mb ();
    bench_sha256_2mb ();
    print ("   -- base64url encoding --\n");
    bench_base64url_current ();
    bench_base64url_singlepass ();
    print ("   -- storage cache invalidation --\n");
    bench_mark_uploaded_then_cleanup ();
    print ("   -- JSON building --\n");
    bench_json_encrypted_event ();

    print ("\n── 8. Optimization Candidates ──────────────────────────────────────────────\n");
    print ("   -- SHA-256 integrity hashing (2 MB) --\n");
    bench_sha256_openssl_hex_2mb ();
    bench_sha256_glib_hex_2mb ();
    print ("   -- full integrity verify (file read + hash) --\n");
    bench_integrity_verify_openssl ();
    bench_integrity_verify_glib ();
    print ("   -- upload pipeline (verify + encrypt, 2 MB) --\n");
    bench_upload_pipeline_single_read ();
    bench_upload_pipeline_triple_read ();
    print ("   -- scheduler CSPRNG --\n");
    bench_scheduler_urandom_cached ();
    bench_scheduler_urandom_per_call ();
    print ("   -- PBKDF2 unlock --\n");
    bench_pbkdf2_unlock ();

    print ("\n══════════════════════════════════════════════════════════════════════════════\n");

    TestUtils.delete_directory_recursive (bench_data_dir);
    return 0;
}
