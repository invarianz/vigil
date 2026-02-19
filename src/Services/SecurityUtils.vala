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
        sb.append ("host: %s".printf (Environment.get_host_name ()));

        // Session type
        var session = Vigil.Utils.detect_session_type ();
        sb.append (" | session: %s".printf (session.to_string ()));

        // Binary path and hash
        sb.append (" | binary: %s".printf (binary_path));
        sb.append (" | binary_hash: %s".printf (
            binary_hash.length >= 16 ? binary_hash.substring (0, 16) + "\u2026" : binary_hash));

        // Flatpak detection
        bool is_flatpak = FileUtils.test ("/.flatpak-info", FileTest.EXISTS);
        sb.append (" | flatpak: %s".printf (is_flatpak ? "yes" : "no"));

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
        sb.append (" | container: %s".printf (container));

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
        sb.append (" | pidns: %s".printf (pidns));

        // Mount namespace ID
        string mntns = "unknown";
        try {
            mntns = FileUtils.read_link ("/proc/self/ns/mnt");
        } catch (Error e) {
            // Not available
        }
        sb.append (" | mntns: %s".printf (mntns));

        return sb.str;
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
