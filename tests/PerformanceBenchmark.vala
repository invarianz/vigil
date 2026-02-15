/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Performance benchmarks for Vigil's hot paths.
 *
 * Measures wall-clock time for:
 *   1. Random number generation (/dev/urandom open+read+close)
 *   2. Megolm encryption (encrypt + pickle-save per message)
 *   3. encrypt_event full path (JSON build + Megolm + JSON build)
 *   4. StorageService.get_pending_screenshots (directory scan)
 *   5. StorageService.cleanup_old_screenshots (scan + sort + delete)
 *   6. StorageService.mark_pending + mark_uploaded cycle
 *   7. TamperDetectionService.compute_config_hash
 *   8. Full capture pipeline simulation (sans network)
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
    double elapsed = timer.elapsed () * 1000000.0; // seconds -> microseconds
    double per_op = elapsed / iterations;

    print ("%-45s %6d iterations %10.0f us total %8.1f us/op\n",
           name, iterations, elapsed, per_op);
}

void clean_crypto_dir () {
    var account_pickle = Path.build_filename (crypto_dir, "account.pickle");
    var megolm_pickle = Path.build_filename (crypto_dir, "megolm_outbound.pickle");
    FileUtils.remove (account_pickle);
    FileUtils.remove (megolm_pickle);
}

/* ─── Benchmark: /dev/urandom ─── */

void bench_urandom_open_read_close () {
    bench ("urandom open+read(32)+close", 1000, () => {
        try {
            var file = File.new_for_path ("/dev/urandom");
            var stream = file.read (null);
            var buf = new uint8[32];
            size_t bytes_read;
            stream.read_all (buf, out bytes_read, null);
            stream.close (null);
        } catch (Error e) {
            // ignore
        }
    });
}

void bench_urandom_cached_fd () {
    FileInputStream? cached_stream = null;
    try {
        var file = File.new_for_path ("/dev/urandom");
        cached_stream = file.read (null);
    } catch (Error e) {
        return;
    }

    bench ("urandom cached-fd read(32)", 1000, () => {
        try {
            var buf = new uint8[32];
            size_t bytes_read;
            cached_stream.read_all (buf, out bytes_read, null);
        } catch (Error e) {
            // ignore
        }
    });

    try { cached_stream.close (null); } catch (Error e) {}
}

/* ─── Benchmark: Megolm encrypt ─── */

void bench_megolm_encrypt () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@bench:test";
    svc.device_id = "BENCHDEV";
    svc.initialize ("bench-key");
    svc.create_outbound_group_session ();

    var plaintext = "{\"msgtype\":\"m.text\",\"body\":\"benchmark message payload here\"}";

    bench ("megolm_encrypt (includes pickle save)", 500, () => {
        svc.megolm_encrypt (plaintext);
    });

    svc.cleanup ();
}

void bench_encrypt_event () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@bench:test";
    svc.device_id = "BENCHDEV";
    svc.initialize ("bench-key");
    svc.create_outbound_group_session ();

    var content = "{\"msgtype\":\"m.image\",\"body\":\"Screenshot 2025-01-01\",\"url\":\"mxc://test/abc\",\"info\":{\"mimetype\":\"image/png\"}}";

    bench ("encrypt_event (JSON + Megolm + JSON)", 500, () => {
        svc.encrypt_event ("!room:test", "m.room.message", content);
    });

    svc.cleanup ();
}

/* ─── Benchmark: Storage operations ─── */

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

    // Create 50 pending screenshots
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

    // Create 200 pending screenshots
    for (int i = 0; i < 200; i++) {
        var path = Path.build_filename (store.screenshots_dir, "bench_%04d.png".printf (i));
        try { FileUtils.set_contents (path, "fake-png-data"); } catch (Error e) {}
        try { store.mark_pending (path); } catch (Error e) {}
    }

    bench ("get_pending_screenshots (200 files)", 50, () => {
        store.get_pending_screenshots ();
    });
}

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
        FileUtils.remove (path);
        idx++;
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

/* ─── Benchmark: Config hash ─── */

void bench_config_hash () {
    var settings = new GLib.Settings ("io.github.invarianz.vigil");
    var svc = new Vigil.Services.TamperDetectionService (settings);

    bench ("compute_config_hash (SHA256)", 2000, () => {
        svc.compute_config_hash ();
    });
}

/* ─── Benchmark: Full capture pipeline (no network) ─── */

void bench_full_pipeline_no_network () {
    // Simulates: generate_path → mark_pending → encrypt_event → mark_uploaded → cleanup
    var dir = Path.build_filename (bench_data_dir, "storage-bench-pipeline");
    DirUtils.create_with_parents (dir, 0755);
    var store = new Vigil.Services.StorageService (dir);
    try { store.initialize (); } catch (Error e) {}

    clean_crypto_dir ();
    var enc = new Vigil.Services.EncryptionService ();
    enc.user_id = "@bench:test";
    enc.device_id = "BENCHDEV";
    enc.initialize ("bench-key");
    enc.create_outbound_group_session ();

    var content = "{\"msgtype\":\"m.image\",\"body\":\"Screenshot\",\"url\":\"mxc://test/abc\",\"info\":{\"mimetype\":\"image/png\"}}";

    bench ("full pipeline (no network)", 200, () => {
        // 1. Generate path
        var path = store.generate_screenshot_path ();
        // 2. Fake screenshot file
        try { FileUtils.set_contents (path, "fake-png-data-for-benchmarking"); } catch (Error e) {}
        // 3. Mark pending
        try { store.mark_pending (path); } catch (Error e) {}
        // 4. Encrypt
        enc.encrypt_event ("!room:test", "m.room.message", content);
        // 5. Mark uploaded
        store.mark_uploaded (path);
        // 6. Cleanup
        store.cleanup_old_screenshots ();
    });

    enc.cleanup ();
}

/* ─── Benchmark: Sign string ─── */

void bench_sign_string () {
    clean_crypto_dir ();
    var svc = new Vigil.Services.EncryptionService ();
    svc.user_id = "@bench:test";
    svc.device_id = "BENCHDEV";
    svc.initialize ("bench-key");

    var message = "{\"algorithms\":[\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],\"device_id\":\"BENCHDEV\",\"keys\":{\"curve25519:BENCHDEV\":\"abc\",\"ed25519:BENCHDEV\":\"def\"},\"user_id\":\"@bench:test\"}";

    bench ("sign_string (Ed25519)", 2000, () => {
        svc.sign_string (message);
    });

    svc.cleanup ();
}

/* ─── Benchmark: File read (simulating screenshot read for upload) ─── */

void bench_file_read_2mb () {
    // Create a 2MB fake screenshot
    var fake_path = Path.build_filename (bench_data_dir, "fake_2mb.png");
    var buf = new uint8[2 * 1024 * 1024];
    for (int i = 0; i < buf.length; i++) {
        buf[i] = (uint8) (i & 0xFF);
    }
    try { FileUtils.set_data (fake_path, buf); } catch (Error e) { return; }

    bench ("read 2MB file into memory (sync)", 100, () => {
        try {
            uint8[] contents;
            FileUtils.get_data (fake_path, out contents);
        } catch (Error e) {}
    });

    FileUtils.remove (fake_path);
}

public static int main (string[] args) {
    // Set XDG_DATA_HOME before any GLib call
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

    print ("\n═══════════════════════════════════════════════════════════════════════════\n");
    print ("  Vigil Performance Benchmark\n");
    print ("═══════════════════════════════════════════════════════════════════════════\n\n");

    print ("── Random Number Generation ─────────────────────────────────────────────\n");
    bench_urandom_open_read_close ();
    bench_urandom_cached_fd ();

    print ("\n── Encryption ───────────────────────────────────────────────────────────\n");
    bench_sign_string ();
    bench_megolm_encrypt ();
    bench_encrypt_event ();

    print ("\n── Storage Operations ───────────────────────────────────────────────────\n");
    bench_storage_mark_cycle ();
    bench_storage_pending_scan_empty ();
    bench_storage_pending_scan_50 ();
    bench_storage_pending_scan_200 ();
    bench_storage_cleanup_100 ();

    print ("\n── I/O ─────────────────────────────────────────────────────────────────\n");
    bench_file_read_2mb ();
    bench_config_hash ();

    print ("\n── Full Pipeline (no network) ───────────────────────────────────────────\n");
    bench_full_pipeline_no_network ();

    print ("\n═══════════════════════════════════════════════════════════════════════════\n");

    // Cleanup
    delete_directory_recursive (bench_data_dir);

    return 0;
}

void delete_directory_recursive (string path) {
    try {
        var dir = Dir.open (path);
        string? name;
        while ((name = dir.read_name ()) != null) {
            var child_path = Path.build_filename (path, name);
            if (FileUtils.test (child_path, FileTest.IS_DIR)) {
                delete_directory_recursive (child_path);
            } else {
                FileUtils.remove (child_path);
            }
        }
        DirUtils.remove (path);
    } catch (Error e) {
        // Ignore cleanup errors
    }
}
