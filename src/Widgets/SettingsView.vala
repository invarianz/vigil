/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Radically simplified settings view.
 *
 * The user only needs to provide:
 *   1. Homeserver (auto-discovered from server name)
 *   2. Username
 *   3. Password
 *   4. Partner's Matrix ID
 *   5. E2EE password (for encrypting crypto state at rest)
 *
 * One "Setup" button does everything: login, create encrypted room,
 * initialize E2EE, upload device keys, share room keys.
 *
 * After setup, settings are locked. The partner receives an unlock code
 * via Matrix. To change settings, the user must enter this code.
 *
 * Schedule/storage/system settings are in a collapsible "Advanced" section.
 */
public class Vigil.Widgets.SettingsView : Gtk.Box {

    private Gtk.Entry homeserver_entry;
    private Gtk.Entry username_entry;
    private Gtk.PasswordEntry password_entry;
    private Gtk.Entry partner_entry;
    private Gtk.PasswordEntry e2ee_password_entry;
    private Gtk.Button setup_button;
    private Gtk.Label status_label;
    private Gtk.SpinButton min_interval_spin;
    private Gtk.SpinButton max_interval_spin;
    private Gtk.SpinButton retention_spin;
    private Gtk.Switch autostart_switch;

    private Gtk.Box setup_box;
    private Gtk.Box advanced_box;
    private Gtk.Entry unlock_entry;
    private Gtk.Button unlock_button;
    private Gtk.Button lock_button;
    private Gtk.Label lock_status_label;
    private Gtk.Box lock_box;

    private GLib.Settings settings;
    private Vigil.Services.MatrixTransportService _matrix_svc;

    private int _failed_unlock_attempts = 0;
    private int64 _last_unlock_attempt_time = 0;
    private const int PBKDF2_ITERATIONS = 600000;
    private const int PBKDF2_SALT_LEN = 16;
    private const int PBKDF2_KEY_LEN = 32;

    public SettingsView () {
        Object ();
    }

    construct {
        orientation = Gtk.Orientation.VERTICAL;
        spacing = 24;
        margin_top = 24;
        margin_bottom = 24;
        margin_start = 24;
        margin_end = 24;

        settings = new GLib.Settings ("io.github.invarianz.vigil");
        _matrix_svc = new Vigil.Services.MatrixTransportService ();

        // Load existing Matrix credentials so we can send lock/unlock messages
        _matrix_svc.homeserver_url = settings.get_string ("matrix-homeserver-url");
        _matrix_svc.access_token = settings.get_string ("matrix-access-token");
        _matrix_svc.room_id = settings.get_string ("matrix-room-id");

        // --- Settings lock section ---
        var lock_header = new Granite.HeaderLabel ("Settings Lock");

        lock_status_label = new Gtk.Label ("") {
            halign = Gtk.Align.START,
            hexpand = true,
            wrap = true
        };

        unlock_entry = new Gtk.Entry () {
            placeholder_text = "Enter unlock code",
            hexpand = true
        };

        unlock_button = new Gtk.Button.with_label ("Unlock");
        unlock_button.add_css_class (Granite.STYLE_CLASS_DESTRUCTIVE_ACTION);
        unlock_button.clicked.connect (on_unlock_clicked);

        lock_button = new Gtk.Button.with_label ("Lock Settings");
        lock_button.add_css_class (Granite.STYLE_CLASS_SUGGESTED_ACTION);
        lock_button.clicked.connect (on_lock_clicked);

        lock_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 12) {
            margin_top = 16,
            margin_bottom = 16,
            margin_start = 16,
            margin_end = 16
        };

        var unlock_row = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 8);
        unlock_row.append (unlock_entry);
        unlock_row.append (unlock_button);

        lock_box.append (lock_status_label);
        lock_box.append (unlock_row);
        lock_box.append (lock_button);

        // --- Account setup section ---
        var setup_header = new Granite.HeaderLabel ("Account Setup");

        homeserver_entry = new Gtk.Entry () {
            placeholder_text = "matrix.org",
            hexpand = true
        };
        var existing_hs = settings.get_string ("matrix-homeserver-url");
        if (existing_hs != "") {
            homeserver_entry.text = existing_hs;
        }

        username_entry = new Gtk.Entry () {
            placeholder_text = "your_username",
            hexpand = true
        };

        password_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };

        partner_entry = new Gtk.Entry () {
            placeholder_text = "@partner:matrix.org",
            hexpand = true
        };
        var existing_partner = settings.get_string ("partner-matrix-id");
        if (existing_partner != "") {
            partner_entry.text = existing_partner;
        }

        e2ee_password_entry = new Gtk.PasswordEntry () {
            show_peek_icon = true,
            hexpand = true
        };

        setup_button = new Gtk.Button.with_label ("Setup") {
            halign = Gtk.Align.END
        };
        setup_button.add_css_class (Granite.STYLE_CLASS_SUGGESTED_ACTION);
        setup_button.clicked.connect (on_setup_clicked);

        status_label = new Gtk.Label ("") {
            halign = Gtk.Align.START,
            hexpand = true,
            wrap = true
        };

        // Show existing status
        var existing_token = settings.get_string ("matrix-access-token");
        var existing_room = settings.get_string ("matrix-room-id");
        if (existing_token != "" && existing_room != "") {
            set_status ("Connected and ready", true);
        } else if (existing_token != "") {
            set_status ("Logged in (room not yet created)", false);
        }

        setup_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 16) {
            margin_top = 16,
            margin_bottom = 16,
            margin_start = 16,
            margin_end = 16
        };

        setup_box.append (create_form_row ("Homeserver", homeserver_entry));
        setup_box.append (create_form_row ("Username", username_entry));
        setup_box.append (create_form_row ("Password", password_entry));
        setup_box.append (create_form_row ("Partner Matrix ID", partner_entry));
        setup_box.append (create_form_row ("E2EE Password", e2ee_password_entry));
        setup_box.append (setup_button);
        setup_box.append (status_label);

        // --- Advanced section (collapsed) ---
        var advanced_header = new Granite.HeaderLabel ("Advanced");

        min_interval_spin = new Gtk.SpinButton.with_range (10, 120, 5);
        min_interval_spin.value = settings.get_int ("min-interval-seconds");
        min_interval_spin.value_changed.connect (() => {
            settings.set_int ("min-interval-seconds", (int) min_interval_spin.value);
        });

        max_interval_spin = new Gtk.SpinButton.with_range (30, 120, 5);
        max_interval_spin.value = settings.get_int ("max-interval-seconds");
        max_interval_spin.value_changed.connect (() => {
            settings.set_int ("max-interval-seconds", (int) max_interval_spin.value);
        });

        retention_spin = new Gtk.SpinButton.with_range (10, 1000, 10);
        settings.bind ("max-local-screenshots", retention_spin, "value", SettingsBindFlags.DEFAULT);

        autostart_switch = new Gtk.Switch () {
            valign = Gtk.Align.CENTER
        };
        settings.bind ("autostart-enabled", autostart_switch, "active", SettingsBindFlags.DEFAULT);

        advanced_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 16) {
            margin_top = 16,
            margin_bottom = 16,
            margin_start = 16,
            margin_end = 16
        };

        advanced_box.append (create_form_row ("Minimum interval (seconds)", min_interval_spin));
        advanced_box.append (create_form_row ("Maximum interval (seconds)", max_interval_spin));
        advanced_box.append (create_form_row ("Maximum local screenshots", retention_spin));
        advanced_box.append (create_form_row ("Start at login", autostart_switch));

        // Assemble the view
        append (lock_header);
        append (lock_box);
        append (setup_header);
        append (setup_box);
        append (advanced_header);
        append (advanced_box);

        // Apply initial lock state
        update_lock_ui ();
    }

    /**
     * One-button setup: login, create room, initialize E2EE.
     */
    private void on_setup_clicked () {
        var hs_input = homeserver_entry.text.strip ();
        var username = username_entry.text.strip ();
        var password = password_entry.text;
        var partner_id = partner_entry.text.strip ();
        var e2ee_password = e2ee_password_entry.text;

        if (hs_input == "" || username == "" || password == "") {
            set_status ("Please fill in homeserver, username, and password", false);
            return;
        }

        if (partner_id == "" || !partner_id.has_prefix ("@")) {
            set_status ("Please enter the partner's Matrix ID (e.g. @partner:matrix.org)", false);
            return;
        }

        if (e2ee_password == "") {
            set_status ("Please set an E2EE password to protect your encryption keys", false);
            return;
        }

        setup_button.sensitive = false;
        set_status ("Discovering homeserver\u2026", false);

        run_setup.begin (hs_input, username, password, partner_id, e2ee_password);
    }

    private async void run_setup (string hs_input, string username, string password,
                                   string partner_id, string e2ee_password) {
        // Step 1: Discover homeserver
        var hs_url = yield _matrix_svc.discover_homeserver (hs_input);
        if (hs_url == null) {
            set_status ("Failed to discover homeserver", false);
            setup_button.sensitive = true;
            return;
        }
        set_status ("Logging in to %s\u2026".printf (hs_url), false);

        // Step 2: Login
        var token = yield _matrix_svc.login (hs_url, username, password);
        if (token == null) {
            set_status ("Login failed -- check credentials", false);
            setup_button.sensitive = true;
            return;
        }

        // Save credentials
        settings.set_string ("matrix-homeserver-url", hs_url);
        settings.set_string ("matrix-access-token", token);
        settings.set_string ("matrix-user-id", _matrix_svc.last_user_id);
        settings.set_string ("partner-matrix-id", partner_id);
        settings.set_string ("e2ee-pickle-key", e2ee_password);

        // Also save token and pickle key to secure files (crypto dir, 0600 permissions)
        Vigil.Services.MatrixTransportService.save_access_token_to_file (token);
        Vigil.Services.EncryptionService.save_pickle_key_to_file (e2ee_password);
        set_status ("Creating encrypted room\u2026", false);

        // Step 3: Create encrypted room with partner
        var new_room_id = yield _matrix_svc.create_encrypted_room (partner_id);
        if (new_room_id == null) {
            set_status ("Room creation failed -- is the partner ID correct?", false);
            setup_button.sensitive = true;
            return;
        }
        settings.set_string ("matrix-room-id", new_room_id);
        set_status ("Setting up E2EE\u2026", false);

        // Step 4: Initialize E2EE
        var enc_svc = new Vigil.Services.EncryptionService ();
        enc_svc.user_id = _matrix_svc.last_user_id;
        enc_svc.device_id = _matrix_svc.last_device_id;
        settings.set_string ("device-id", _matrix_svc.last_device_id);

        if (!enc_svc.initialize (e2ee_password)) {
            set_status ("E2EE initialization failed", false);
            setup_button.sensitive = true;
            return;
        }

        // Step 5: Full E2EE setup (upload keys, create Megolm session, share)
        bool e2ee_ok = yield _matrix_svc.setup_e2ee (enc_svc, partner_id);

        // Clear password fields
        password_entry.text = "";
        e2ee_password_entry.text = "";

        setup_button.sensitive = true;

        if (e2ee_ok) {
            set_status ("Setup complete -- monitoring ready", true);
        } else {
            // Partial success - login and room created but E2EE had issues
            set_status ("Setup mostly complete -- E2EE key sharing deferred until partner is online", true);
        }

        // Auto-lock settings after successful setup
        yield lock_settings ();
    }

    /**
     * Generate a random 6-character unlock code using unambiguous characters.
     * Characters I/O/0/1 are excluded to avoid visual confusion.
     *
     * Uses /dev/urandom (CSPRNG) rather than GLib's PRNG so the code
     * cannot be predicted from the RNG state.
     */
    private string generate_unlock_code () {
        const string CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        // Rejection limit: floor(256 / 31) * 31 = 248
        const uint8 LIMIT = 248;
        var code = new StringBuilder ();

        try {
            var urandom = File.new_for_path ("/dev/urandom");
            var stream = new DataInputStream (urandom.read (null));
            for (int i = 0; i < 6; i++) {
                uint8 b = stream.read_byte (null);
                while (b >= LIMIT) {
                    b = stream.read_byte (null);
                }
                code.append_c (CHARS[b % CHARS.length]);
            }
            stream.close (null);
        } catch (Error e) {
            warning ("Failed to read /dev/urandom: %s", e.message);
            return "ERRGEN";
        }

        return code.str;
    }

    /**
     * Hash an unlock code with PBKDF2-SHA256 and a random salt.
     *
     * Uses 600K iterations to make offline brute-force impractical.
     * Returns "hex(salt):hex(derived_key)" for storage.
     */
    private string hash_code (string code) {
        uint8[] salt = new uint8[PBKDF2_SALT_LEN];
        try {
            var urandom = File.new_for_path ("/dev/urandom");
            var stream = new DataInputStream (urandom.read (null));
            size_t bytes_read;
            stream.read_all (salt, out bytes_read, null);
            stream.close (null);
        } catch (Error e) {
            warning ("Failed to generate salt: %s", e.message);
            return Checksum.compute_for_string (ChecksumType.SHA256, code);
        }

        return hash_code_with_salt (code, salt);
    }

    private string hash_code_with_salt (string code, uint8[] salt) {
        var derived = new uint8[PBKDF2_KEY_LEN];
        var result = OpenSSL.pbkdf2_hmac (
            code, code.length,
            salt, salt.length,
            PBKDF2_ITERATIONS,
            OpenSSL.sha256 (),
            PBKDF2_KEY_LEN,
            derived
        );

        if (result != 1) {
            // Refuse to silently downgrade -- weak hashing would compromise
            // the unlock code's brute-force resistance.
            error ("PBKDF2 failed: OpenSSL returned %d. " +
                   "Refusing to fall back to weak hashing.", result);
        }

        return "%s:%s".printf (bytes_to_hex (salt), bytes_to_hex (derived));
    }

    /**
     * Verify an unlock code against a stored hash.
     *
     * Supports both PBKDF2 format (salt:hash) and legacy SHA-256.
     * Uses constant-time comparison to prevent timing side-channel attacks.
     */
    private bool verify_code (string code, string stored_hash) {
        if (":" in stored_hash) {
            var parts = stored_hash.split (":");
            if (parts.length != 2) return false;
            var salt = hex_to_bytes (parts[0]);
            if (salt == null) return false;
            var expected = hash_code_with_salt (code, salt);
            return constant_time_equal (expected, stored_hash);
        } else {
            // Legacy SHA-256 format
            var computed = Checksum.compute_for_string (ChecksumType.SHA256, code);
            return constant_time_equal (computed, stored_hash);
        }
    }

    /**
     * Constant-time string comparison to prevent timing side-channel attacks.
     *
     * Always compares all bytes regardless of where mismatches occur,
     * so an attacker cannot infer correct characters from response timing.
     */
    private static bool constant_time_equal (string a, string b) {
        if (a.length != b.length) {
            return false;
        }
        uint8 result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= (uint8) (a[i] ^ b[i]);
        }
        return result == 0;
    }

    private static string bytes_to_hex (uint8[] data) {
        var sb = new StringBuilder.sized (data.length * 2);
        foreach (var b in data) {
            sb.append_printf ("%02x", b);
        }
        return sb.str;
    }

    private static uint8[]? hex_to_bytes (string hex) {
        if (hex.length % 2 != 0) return null;
        var len = hex.length / 2;
        var result = new uint8[len];
        for (int i = 0; i < len; i++) {
            int high = hex_char_val (hex[i * 2]);
            int low = hex_char_val (hex[i * 2 + 1]);
            if (high < 0 || low < 0) return null;
            result[i] = (uint8) ((high << 4) | low);
        }
        return result;
    }

    private static int hex_char_val (char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /**
     * Lock settings and display the unlock code.
     *
     * The code is NOT sent via Matrix (the monitored user can read the
     * room). Instead, it is shown once in the UI for the user to share
     * with their partner out-of-band (in person, phone, or another chat).
     */
    private async void lock_settings () {
        var code = generate_unlock_code ();
        settings.set_string ("unlock-code-hash", hash_code (code));
        settings.set_boolean ("settings-locked", true);

        // Notify the partner that settings are locked (code NOT included)
        yield _matrix_svc.send_text_message (
            "Settings are now locked. The unlock code has been shared " +
            "with the user directly -- please ask them for it " +
            "(in person, phone, or another chat)."
        );

        // Show the code in the UI (displayed once, not persisted anywhere)
        set_status (
            "Settings locked. Unlock code: %s\n".printf (code) +
            "Share this code with your partner now (in person, phone, " +
            "or another chat). It will not be shown again.",
            true
        );

        update_lock_ui ();
    }

    /**
     * Verify the entered unlock code and unlock settings if correct.
     *
     * Rate-limited: after 3 failed attempts, a 30-second cooldown is
     * enforced. The counter is kept in memory so it cannot be reset
     * by editing GSettings/dconf.
     */
    private void on_unlock_clicked () {
        // Rate limiting: after 3 failures, require 30s cooldown
        if (_failed_unlock_attempts >= 3) {
            var now = GLib.get_monotonic_time ();
            var elapsed_sec = (now - _last_unlock_attempt_time) / 1000000;
            if (elapsed_sec < 30) {
                var remaining = 30 - (int) elapsed_sec;
                lock_status_label.label =
                    "Too many failed attempts. Try again in %d seconds.".printf (remaining);
                lock_status_label.add_css_class ("error");
                return;
            }
            _failed_unlock_attempts = 0;
        }

        var entered = unlock_entry.text.strip ().up ();
        var stored_hash = settings.get_string ("unlock-code-hash");

        if (stored_hash == "" || !verify_code (entered, stored_hash)) {
            _failed_unlock_attempts++;
            _last_unlock_attempt_time = GLib.get_monotonic_time ();
            lock_status_label.label =
                "Incorrect unlock code. Ask your accountability partner for the code.";
            lock_status_label.add_css_class ("error");
            return;
        }

        // Correct code -- send notification then unlock
        _failed_unlock_attempts = 0;
        _matrix_svc.send_text_message.begin (
            "Settings unlocked (authorized by partner). Changes may follow."
        );
        settings.set_boolean ("settings-locked", false);
        unlock_entry.text = "";
        update_lock_ui ();
    }

    /**
     * Re-lock settings with a new code.
     */
    private void on_lock_clicked () {
        lock_settings.begin ();
    }

    /**
     * Update the UI based on current lock state.
     */
    private void update_lock_ui () {
        bool locked = settings.get_boolean ("settings-locked");
        bool setup_done = settings.get_string ("matrix-access-token") != "";

        // If setup hasn't been done yet, don't show lock UI
        if (!setup_done) {
            lock_box.visible = false;
            setup_box.sensitive = true;
            advanced_box.sensitive = true;
            return;
        }

        lock_box.visible = true;

        if (locked) {
            lock_status_label.label =
                "Settings are locked. Ask your accountability partner" +
                " for the unlock code to make changes.";
            lock_status_label.remove_css_class ("error");
            unlock_entry.visible = true;
            unlock_button.visible = true;
            lock_button.visible = false;
            setup_box.sensitive = false;
            advanced_box.sensitive = false;
        } else {
            lock_status_label.label = "Settings are unlocked. Make your changes, then lock when done.";
            lock_status_label.remove_css_class ("error");
            unlock_entry.visible = false;
            unlock_button.visible = false;
            lock_button.visible = true;
            setup_box.sensitive = true;
            advanced_box.sensitive = true;
        }
    }

    private static Gtk.Box create_form_row (string label_text, Gtk.Widget widget) {
        var row = new Gtk.Box (Gtk.Orientation.VERTICAL, 4);
        var label = new Gtk.Label (label_text) {
            halign = Gtk.Align.START
        };
        label.add_css_class ("h4");
        row.append (label);
        row.append (widget);
        return row;
    }

    private void set_status (string message, bool success) {
        status_label.label = message;
        status_label.remove_css_class ("success");
        status_label.remove_css_class ("error");
        if (success) {
            status_label.add_css_class ("success");
        } else if (message != "") {
            status_label.add_css_class ("error");
        }
    }
}
