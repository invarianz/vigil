/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Shared security utilities used across all services.
 *
 * Centralizes cryptographic random number generation, secure file I/O,
 * SHA-256 hashing, and application path construction to eliminate
 * duplication and ensure consistent security practices.
 */
public class Vigil.Services.SecurityUtils : Object {

    /** Maximum screenshot file size (50 MB). */
    public const int64 MAX_SCREENSHOT_SIZE = 50 * 1024 * 1024;

    /** Hex lookup table — avoids printf format parsing per byte. */
    private const string[] HEX_TABLE = {
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
        "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"
    };

    /** Absolute minimum screenshot interval in seconds. */
    public const int ABSOLUTE_MIN_INTERVAL = 1;

    /** Cached application data directory path. */
    private static string? _cached_app_data_dir = null;

    /** Cached crypto directory path. */
    private static string? _cached_crypto_dir = null;

    /**
     * Get the application data directory path.
     *
     * Returns: ~/.local/share/io.github.invarianz.vigil
     * The result is cached after first call since XDG_DATA_HOME never changes.
     */
    public static string get_app_data_dir () {
        if (_cached_app_data_dir == null) {
            _cached_app_data_dir = Path.build_filename (
                Environment.get_user_data_dir (),
                "io.github.invarianz.vigil"
            );
        }
        return _cached_app_data_dir;
    }

    /**
     * Get the cryptographic storage directory path.
     *
     * Returns: ~/.local/share/io.github.invarianz.vigil/crypto
     * The result is cached after first call.
     */
    public static string get_crypto_dir () {
        if (_cached_crypto_dir == null) {
            _cached_crypto_dir = Path.build_filename (get_app_data_dir (), "crypto");
        }
        return _cached_crypto_dir;
    }

    /**
     * Reset cached directory paths.
     *
     * Only needed in tests that override XDG_DATA_HOME between calls.
     */
    public static void reset_cached_paths () {
        _cached_app_data_dir = null;
        _cached_crypto_dir = null;
    }

    /**
     * Read a random uint32 from a cached /dev/urandom fd (CSPRNG).
     *
     * Aborts on failure -- falling back to a weak PRNG would silently
     * compromise scheduling unpredictability and key generation.
     */
    public static uint32 csprng_uint32 () {
        uint8[] buf = new uint8[4];
        csprng_fill (buf);
        return ((uint32) buf[0] << 24) |
               ((uint32) buf[1] << 16) |
               ((uint32) buf[2] << 8) |
               (uint32) buf[3];
    }

    /**
     * Read cryptographic random bytes from a cached /dev/urandom fd.
     *
     * Aborts on failure -- falling back to non-CSPRNG would silently
     * compromise all generated keys, IVs, and Olm randomness.
     */
    public static uint8[] csprng_bytes (size_t length) {
        if (length == 0) {
            return new uint8[0];
        }
        var buf = new uint8[length];
        csprng_fill (buf);
        return buf;
    }

    /**
     * Ensure a directory exists with owner-only (0700) permissions.
     *
     * Creates the directory and all parents if needed, then enforces
     * 0700 even if the directory already existed with wrong permissions.
     */
    public static void ensure_secure_directory (string path) {
        DirUtils.create_with_parents (path, 0700);
        FileUtils.chmod (path, 0700);
    }

    /**
     * Write contents to a file with owner-only read/write (0600) permissions.
     *
     * Creates or overwrites the file atomically, then restricts access.
     */
    public static void write_secure_file (string path, string contents) throws Error {
        FileUtils.set_contents (path, contents);
        FileUtils.chmod (path, 0600);
    }

    /**
     * Compute SHA-256 hex digest using OpenSSL (hardware-accelerated).
     *
     * 5x faster than GLib.Checksum for binary data on the hot path
     * (screenshot hashing, integrity verification).
     */
    public static string compute_sha256_hex (uint8[] data) {
        var hash = new uint8[32];
        uint md_size;
        OpenSSL.digest (data, data.length, hash, out md_size, OpenSSL.sha256 ());
        var sb = new StringBuilder.sized (64);
        for (int i = 0; i < 32; i++) {
            sb.append (HEX_TABLE[hash[i]]);
        }
        return sb.str;
    }

    /**
     * Compute HMAC-SHA256 hex digest using OpenSSL (hardware-accelerated).
     *
     * Replaces GLib.Hmac for consistency and performance on the hot path
     * (marker file authentication runs per-screenshot).
     */
    public static string compute_hmac_sha256_hex (string key, string data) {
        var md = new uint8[32];
        uint md_len;
        OpenSSL.hmac (OpenSSL.sha256 (),
            (void*) key, key.length,
            (void*) data, data.length,
            (void*) md, out md_len);
        var sb = new StringBuilder.sized (64);
        for (int i = 0; i < 32; i++) {
            sb.append (HEX_TABLE[md[i]]);
        }
        return sb.str;
    }

    /**
     * Compute SHA-256 hex digest of a UTF-8 string.
     */
    public static string compute_sha256_hex_string (string data) {
        return compute_sha256_hex (data.data);
    }

    /**
     * Load a secure file from the crypto directory, strip whitespace, return contents.
     *
     * Returns null if the file doesn't exist or is empty.
     */
    public static string? load_secure_file_string (string filename) {
        var path = Path.build_filename (get_crypto_dir (), filename);

        if (!FileUtils.test (path, FileTest.EXISTS)) {
            return null;
        }

        try {
            string contents;
            FileUtils.get_contents (path, out contents);
            var stripped = contents.strip ();
            return stripped != "" ? stripped : null;
        } catch (Error e) {
            warning ("Failed to read %s: %s", filename, e.message);
            return null;
        }
    }

    /**
     * Check whether the process dumpable flag has been re-enabled.
     *
     * If an attacker re-enables PR_SET_DUMPABLE (e.g., via ptrace or
     * /proc/self/attr), this detects it and re-hardens immediately.
     *
     * Returns a description of the violation if dumpable was re-enabled,
     * or null if everything is fine.
     */
    public static string? check_and_reharden_dumpable () {
        int current = Linux.prctl (Linux.PR_GET_DUMPABLE);
        if (current != 0) {
            Linux.prctl (Linux.PR_SET_DUMPABLE, 0);
            return ("Process dumpable flag was re-enabled (was %d)" +
                " -- possible ptrace attack, re-hardened").printf (current);
        }
        return null;
    }

    /**
     * Harden the current process against debugging and injection.
     *
     * 1. Calls prctl(PR_SET_DUMPABLE, 0) to prevent ptrace and core dumps
     * 2. Checks LD_PRELOAD for library injection
     *
     * Returns a list of deferred tamper event descriptions (format:
     * "event_type:details") since TamperDetectionService may not exist yet.
     */
    public static GenericArray<string> harden_process () {
        var events = new GenericArray<string> ();

        // Prevent ptrace attach and core dumps
        int ret = Linux.prctl (Linux.PR_SET_DUMPABLE, 0);
        if (ret != 0) {
            events.add ("prctl_failed:prctl(PR_SET_DUMPABLE, 0) returned %d".printf (ret));
        }

        // Detect LD_PRELOAD injection
        var ld_preload = Environment.get_variable ("LD_PRELOAD");
        if (ld_preload != null && ld_preload.strip () != "") {
            events.add ("ld_preload_detected:LD_PRELOAD is set: %s".printf (ld_preload));
        }

        return events;
    }

    /**
     * Collect startup environment attestation for the first heartbeat.
     *
     * Returns a compact multi-field string describing the runtime
     * environment so the partner can verify where the daemon is running.
     */
    public static string collect_environment_attestation (string binary_path, string binary_hash) {
        var sb = new StringBuilder ();

        // Hostname
        sb.append_printf ("host: %s", Environment.get_host_name ());

        // Session type
        var session = Vigil.Utils.detect_session_type ();
        sb.append_printf (" | session: %s", session.to_string ());

        // Binary path and hash (truncate to 16 chars for readability)
        sb.append_printf (" | binary: %s", binary_path);
        if (binary_hash.length >= 16) {
            sb.append_printf (" | binary_hash: %s\u2026", binary_hash.substring (0, 16));
        } else {
            sb.append_printf (" | binary_hash: %s", binary_hash);
        }

        // Flatpak detection
        bool is_flatpak = FileUtils.test ("/.flatpak-info", FileTest.EXISTS);
        sb.append_printf (" | flatpak: %s", is_flatpak ? "yes" : "no");

        // Container detection (docker/lxc/podman via cgroup)
        string container = "none";
        try {
            string cgroup_contents;
            FileUtils.get_contents ("/proc/self/cgroup", out cgroup_contents);
            var lower = cgroup_contents.down ();
            if (lower.contains ("docker") || lower.contains ("lxc") || lower.contains ("podman")) {
                container = "detected";
            }
        } catch (Error e) {
            // Not available -- leave as "none"
        }
        sb.append_printf (" | container: %s", container);

        // PID namespace detection (NSpid in /proc/self/status)
        string pidns = "unknown";
        try {
            string status_contents;
            FileUtils.get_contents ("/proc/self/status", out status_contents);
            foreach (var line in status_contents.split ("\n")) {
                if (line.has_prefix ("NSpid:")) {
                    var parts = line.substring (6).strip ().split ("\t");
                    pidns = parts.length > 1 ? "nested" : "root";
                    break;
                }
            }
        } catch (Error e) {
            // Not available
        }
        sb.append_printf (" | pidns: %s", pidns);

        // Mount namespace ID
        string mntns = "unknown";
        try {
            mntns = FileUtils.read_link ("/proc/self/ns/mnt");
        } catch (Error e) {
            // Not available
        }
        sb.append_printf (" | mntns: %s", mntns);

        return sb.str;
    }

    /**
     * Compute a jittered interval for unpredictable scheduling.
     *
     * Returns a value in [base_interval * 3/4, base_interval * 5/4]
     * using CSPRNG, so an attacker cannot predict when the next
     * check/action will run.
     */
    public static int jittered_interval (int base_interval) {
        int min_val = base_interval * 3 / 4;
        int max_val = base_interval * 5 / 4;

        if (min_val >= max_val) {
            return base_interval;
        }

        int range = max_val - min_val;
        uint32 rand_val = csprng_uint32 ();

        return min_val + (int) (rand_val % (range + 1));
    }

    /**
     * Fill a buffer with cryptographic random bytes using OpenSSL RAND_bytes.
     *
     * Uses hardware RDRAND/RDSEED when available, falling back to
     * OpenSSL's software CSPRNG (which seeds from /dev/urandom).
     */
    private static void csprng_fill (uint8[] buf) {
        if (OpenSSL.rand_bytes (buf, buf.length) != 1) {
            error ("CRITICAL: OpenSSL RAND_bytes failed. " +
                   "Refusing to generate weak random data.");
        }
    }
}
