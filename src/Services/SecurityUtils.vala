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

    /** Absolute minimum screenshot interval in seconds. */
    public const int ABSOLUTE_MIN_INTERVAL = 1;

    /** Process-wide cached /dev/urandom stream. */
    private static DataInputStream? _urandom = null;

    /**
     * Get the application data directory path.
     *
     * Returns: ~/.local/share/io.github.invarianz.vigil
     */
    public static string get_app_data_dir () {
        return Path.build_filename (
            Environment.get_user_data_dir (),
            "io.github.invarianz.vigil"
        );
    }

    /**
     * Get the cryptographic storage directory path.
     *
     * Returns: ~/.local/share/io.github.invarianz.vigil/crypto
     */
    public static string get_crypto_dir () {
        return Path.build_filename (get_app_data_dir (), "crypto");
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
            sb.append_printf ("%02x", hash[i]);
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
     * Fill a buffer with cryptographic random bytes from /dev/urandom.
     *
     * The fd is cached process-wide to avoid open/close overhead.
     */
    private static void csprng_fill (uint8[] buf) {
        try {
            if (_urandom == null) {
                var file = File.new_for_path ("/dev/urandom");
                _urandom = new DataInputStream (file.read (null));
            }
            size_t bytes_read;
            _urandom.read_all (buf, out bytes_read, null);
        } catch (Error e) {
            error ("CRITICAL: Failed to read /dev/urandom: %s. " +
                   "Refusing to generate weak random data.", e.message);
        }
    }
}
