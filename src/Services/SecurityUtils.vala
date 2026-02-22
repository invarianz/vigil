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

    /** Hex lookup table -- avoids printf format parsing per byte. */
    public const string[] HEX_TABLE = {
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
     * Encode a byte array as a lowercase hex string.
     */
    public static string bytes_to_hex (uint8[] data) {
        var sb = new StringBuilder.sized (data.length * 2);
        foreach (var b in data) {
            sb.append (HEX_TABLE[b]);
        }
        return sb.str;
    }

    /**
     * Decode a hex string to bytes. Returns null on invalid input.
     */
    public static uint8[]? hex_to_bytes (string hex) {
        if (hex.length % 2 != 0) return null;
        var len = hex.length / 2;
        var result = new uint8[len];
        for (int i = 0; i < len; i++) {
            int high = hex_nibble (hex[i * 2]);
            int low = hex_nibble (hex[i * 2 + 1]);
            if (high < 0 || low < 0) return null;
            result[i] = (uint8) ((high << 4) | low);
        }
        return result;
    }

    private static int hex_nibble (char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
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
        return bytes_to_hex (hash);
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
        return bytes_to_hex (md);
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
