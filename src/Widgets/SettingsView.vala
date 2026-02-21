/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unified settings view with integrated lock flow.
 *
 * The user provides:
 *   1. Homeserver (auto-discovered from server name)
 *   2. Username
 *   3. Password
 *   4. Partner's Matrix ID
 *   5. E2EE password (for encrypting crypto state at rest)
 *
 * One "Lock Settings" button does everything: setup (if needed), then lock.
 * When locked, all fields are greyed out (visible but not editable).
 * The unlock code is shown once in a Granite dialog.
 */
public class Vigil.Widgets.SettingsView : Gtk.Box {

    private Gtk.Entry homeserver_entry;
    private Gtk.Entry username_entry;
    private Gtk.PasswordEntry password_entry;
    private Gtk.Entry partner_entry;
    private Gtk.PasswordEntry e2ee_password_entry;
    private Gtk.Label status_label;
    private Vigil.Widgets.RangeScale interval_range;

    private Gtk.Button lock_button;
    private Gtk.Entry unlock_entry;
    private Gtk.Button unlock_button;
    private Gtk.Box unlock_row;
    private Gtk.Label lock_status_label;

    private GLib.Settings settings;
    private Vigil.Services.MatrixTransportService _matrix_svc;

    private int _failed_unlock_attempts = 0;
    private int64 _last_unlock_attempt_time = 0;
    private const int PBKDF2_ITERATIONS = 600000;
    private const int PBKDF2_SALT_LEN = 16;
    private const int PBKDF2_KEY_LEN = 32;

    /** Path to the authorized unlock marker file. */
    private string _authorized_unlock_path;

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

        _authorized_unlock_path = Path.build_filename (
            Environment.get_user_data_dir (),
            "io.github.invarianz.vigil", "authorized_unlock"
        );

        // Load existing Matrix credentials so we can send lock/unlock messages
        _matrix_svc.homeserver_url = settings.get_string ("matrix-homeserver-url");
        _matrix_svc.access_token = settings.get_string ("matrix-access-token");
        _matrix_svc.room_id = settings.get_string ("matrix-room-id");

        homeserver_entry = new Gtk.Entry () {
            placeholder_text = "matrix.org",
            hexpand = true
        };
        var existing_hs = settings.get_string ("matrix-homeserver-url");
        if (existing_hs != "") {
            homeserver_entry.text = existing_hs;
        }

        username_entry = new Gtk.Entry () {
            placeholder_text = "username (without @user:server)",
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

        // --- Screenshot interval range slider ---
        interval_range = new Vigil.Widgets.RangeScale (
            30, 120, 5, 30,
            settings.get_int ("min-interval-seconds"),
            settings.get_int ("max-interval-seconds")
        );
        interval_range.values_changed.connect (() => {
            settings.set_int ("min-interval-seconds", (int) interval_range.lower_value);
            settings.set_int ("max-interval-seconds", (int) interval_range.upper_value);
        });

        // --- Lock button (does setup-if-needed + lock) ---
        lock_button = new Gtk.Button.with_label ("Lock Settings") {
            halign = Gtk.Align.END
        };
        lock_button.add_css_class ("suggested-action");
        lock_button.clicked.connect (() => {
            do_lock.begin ();
        });

        // --- Unlock row (visible when locked) ---
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
        unlock_button.add_css_class ("destructive-action");
        unlock_button.clicked.connect (on_unlock_clicked);

        unlock_row = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 8);
        unlock_row.append (unlock_entry);
        unlock_row.append (unlock_button);

        // --- Assemble the view (single section, no headers) ---
        var content_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 16) {
            margin_top = 16,
            margin_bottom = 16,
            margin_start = 16,
            margin_end = 16
        };

        content_box.append (create_form_row ("Matrix Server", homeserver_entry));
        content_box.append (create_form_row ("Username", username_entry));
        content_box.append (create_form_row ("Password", password_entry));
        content_box.append (create_form_row ("Partner Matrix ID", partner_entry));
        content_box.append (create_form_row ("E2EE Password", e2ee_password_entry));
        content_box.append (status_label);
        content_box.append (create_form_row ("Screenshot interval", interval_range));
        content_box.append (lock_button);
        content_box.append (lock_status_label);
        content_box.append (unlock_row);

        append (content_box);

        // Apply initial lock state
        update_lock_ui ();
    }

    /**
     * Unified lock flow: setup if needed, then lock and show code in dialog.
     */
    private async void do_lock () {
        var existing_token = settings.get_string ("matrix-access-token");

        if (existing_token == "") {
            // Setup not done yet — validate fields and run setup first
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

            lock_button.sensitive = false;
            set_status ("Discovering homeserver\u2026", false);

            bool setup_ok = yield run_setup (hs_input, username, password, partner_id, e2ee_password);
            if (!setup_ok) {
                lock_button.sensitive = true;
                return;
            }
        }

        // Now lock
        yield lock_settings ();
        lock_button.sensitive = true;
    }

    /**
     * Run the setup pipeline. Returns true on success.
     */
    private async bool run_setup (string hs_input, string username, string password,
                                   string partner_id, string e2ee_password) {
        // Step 1: Discover homeserver
        var hs_url = yield _matrix_svc.discover_homeserver (hs_input);
        if (hs_url == null) {
            set_status ("Failed to discover homeserver", false);
            return false;
        }
        set_status ("Logging in to %s\u2026".printf (hs_url), false);

        // Step 2: Login
        var token = yield _matrix_svc.login (hs_url, username, password);
        if (token == null) {
            set_status ("Login failed -- check credentials", false);
            return false;
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
            return false;
        }
        settings.set_string ("matrix-room-id", new_room_id);
        set_status ("Locking down room permissions\u2026", false);

        // Step 3b: Lock down power levels (separate call so invites
        // aren't blocked by the creator's demotion during createRoom)
        yield _matrix_svc.set_room_power_levels (new_room_id, partner_id);
        set_status ("Setting up E2EE\u2026", false);

        // Step 4: Initialize E2EE
        var enc_svc = new Vigil.Services.EncryptionService ();
        enc_svc.user_id = _matrix_svc.last_user_id;
        enc_svc.device_id = _matrix_svc.last_device_id;
        settings.set_string ("device-id", _matrix_svc.last_device_id);

        if (!enc_svc.initialize (e2ee_password)) {
            set_status ("E2EE initialization failed", false);
            return false;
        }

        // Step 5: Full E2EE setup (upload keys, create Megolm session, share)
        bool e2ee_ok = yield _matrix_svc.setup_e2ee (enc_svc, partner_id);

        // Clear password fields
        password_entry.text = "";
        e2ee_password_entry.text = "";

        // Step 6: Request screenshot permission via Portal.
        // The first portal screenshot call triggers a one-time "Allow" dialog.
        // Do this during setup so the user grants it before monitoring starts,
        // rather than seeing a surprise dialog on the first scheduled capture.
        set_status ("Requesting screenshot permission\u2026", false);
        yield request_screenshot_permission ();

        if (e2ee_ok) {
            set_status ("Setup complete -- locking settings\u2026", true);
        } else {
            set_status ("Setup mostly complete -- E2EE key sharing deferred until partner is online", true);
        }

        return true;
    }

    /**
     * Take a throwaway screenshot to trigger the portal permission dialog.
     *
     * The XDG Desktop Portal shows a one-time "Allow screenshots" dialog
     * on the first non-interactive call. By triggering this during setup,
     * the user sees and grants the permission before monitoring starts.
     */
    private async void request_screenshot_permission () {
        try {
            var portal = new Xdp.Portal ();
            var uri = yield portal.take_screenshot (
                null,
                Xdp.ScreenshotFlags.NONE,
                null
            );
            // Discard the result — we only needed to trigger the permission dialog
            if (uri != null && uri != "") {
                try {
                    var file = File.new_for_uri (uri);
                    yield file.delete_async (Priority.DEFAULT, null);
                } catch (Error e) {
                    // Cleanup failure is fine
                }
            }
            debug ("Screenshot permission granted during setup");
        } catch (Error e) {
            debug ("Screenshot permission request failed: %s", e.message);
        }
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
        uint8[] salt = Vigil.Services.SecurityUtils.csprng_bytes (PBKDF2_SALT_LEN);
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

        return "%s:%s".printf (
            Vigil.Services.SecurityUtils.bytes_to_hex (salt),
            Vigil.Services.SecurityUtils.bytes_to_hex (derived));
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
            var salt = Vigil.Services.SecurityUtils.hex_to_bytes (parts[0]);
            if (salt == null) return false;
            var expected = hash_code_with_salt (code, salt);
            return constant_time_equal (expected, stored_hash);
        } else {
            // Legacy SHA-256 format
            var computed = Vigil.Services.SecurityUtils.compute_sha256_hex_string (code);
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

    /**
     * Lock settings and show the unlock code in a Granite dialog.
     *
     * The code is NOT sent via Matrix (the monitored user can read the
     * room). Instead, it is shown once in a dialog for the user to share
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

        update_lock_ui ();

        // Show the unlock code in a Granite dialog
        var dialog = new Granite.MessageDialog.with_image_from_icon_name (
            "Settings Locked",
            "Your unlock code is: <b>%s</b>\n\n".printf (code) +
                "Share this code with your accountability partner now " +
                "(in person, phone, or another chat). It will not be shown again.",
            "dialog-password",
            Gtk.ButtonsType.NONE
        );
        dialog.transient_for = (Gtk.Window) get_root ();
        dialog.modal = true;
        dialog.secondary_label.use_markup = true;
        var ok_button = (Gtk.Button) dialog.add_button ("OK", Gtk.ResponseType.OK);
        ok_button.add_css_class ("suggested-action");
        ok_button.clicked.connect (() => {
            dialog.destroy ();
        });
        dialog.present ();
    }

    /**
     * Verify the entered unlock code and unlock settings if correct.
     *
     * Rate-limited: after 3 failed attempts, a 30-second cooldown is
     * enforced. The counter is kept in memory so it cannot be reset
     * by editing GSettings/dconf.
     *
     * Writes an authorized_unlock marker file before toggling the
     * GSettings lock, so the daemon can distinguish GUI unlocks from
     * dconf bypass attempts.
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

        // Correct code — write marker, send notification, then unlock
        _failed_unlock_attempts = 0;

        // Write authorized_unlock marker BEFORE toggling settings-locked
        // so the daemon sees it when the GSettings change fires
        try {
            var parent = Path.get_dirname (_authorized_unlock_path);
            DirUtils.create_with_parents (parent, 0700);
            FileUtils.set_contents (_authorized_unlock_path, "authorized");
        } catch (Error e) {
            warning ("Failed to write authorized unlock marker: %s", e.message);
        }

        _matrix_svc.send_text_message.begin (
            "Settings unlocked (authorized by partner). Changes may follow."
        );
        settings.set_boolean ("settings-locked", false);

        // Clean up marker (daemon will have already read it)
        FileUtils.unlink (_authorized_unlock_path);

        unlock_entry.text = "";
        update_lock_ui ();
    }

    /**
     * Update the UI based on current lock state.
     *
     * When locked: all form fields greyed out (visible but insensitive),
     * lock button hidden, unlock row visible.
     * When unlocked: all fields sensitive, lock button visible, unlock row hidden.
     */
    private void update_lock_ui () {
        bool locked = settings.get_boolean ("settings-locked");

        homeserver_entry.sensitive = !locked;
        username_entry.sensitive = !locked;
        password_entry.sensitive = !locked;
        partner_entry.sensitive = !locked;
        e2ee_password_entry.sensitive = !locked;
        interval_range.sensitive = !locked;
        lock_button.visible = !locked;
        unlock_row.visible = locked;

        if (locked) {
            lock_status_label.label =
                "Settings are locked. Ask your accountability partner" +
                " for the unlock code to make changes.";
            lock_status_label.remove_css_class ("error");
            lock_status_label.visible = true;
        } else {
            lock_status_label.label = "";
            lock_status_label.visible = false;
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
