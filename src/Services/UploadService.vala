/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Uploads screenshot images to a configurable HTTPS endpoint.
 *
 * The endpoint receives a multipart/form-data POST with:
 *   - "screenshot": the PNG image file
 *   - "timestamp": ISO 8601 capture timestamp
 *   - "device_id": a stable identifier for this device
 *
 * The accountability partner runs a server (or uses a hosted service)
 * that receives and displays these screenshots.
 */
public class Vigil.Services.UploadService : Object {

    public signal void upload_succeeded (string file_path);
    public signal void upload_failed (string file_path, string error_message);

    /** The HTTPS endpoint URL to POST screenshots to. */
    public string endpoint_url { get; set; default = ""; }

    /** An optional API key / auth token sent as Authorization: Bearer header. */
    public string api_token { get; set; default = ""; }

    /** A stable device identifier (generated once, stored in GSettings). */
    public string device_id { get; set; default = ""; }

    private Soup.Session _session;

    construct {
        _session = new Soup.Session () {
            timeout = 30,
            user_agent = "Vigil/1.0"
        };
    }

    /**
     * Upload a screenshot file to the configured endpoint.
     *
     * @param file_path Absolute path to the screenshot PNG file.
     * @param capture_time The time the screenshot was taken.
     * @return true if the upload succeeded.
     */
    public async bool upload (string file_path, DateTime capture_time) {
        if (endpoint_url == "") {
            var msg = "No upload endpoint configured";
            warning (msg);
            upload_failed (file_path, msg);
            return false;
        }

        try {
            var file = File.new_for_path (file_path);
            if (!file.query_exists ()) {
                throw new IOError.NOT_FOUND ("Screenshot file not found: %s".printf (file_path));
            }

            var file_info = yield file.query_info_async (
                "standard::size",
                FileQueryInfoFlags.NONE,
                Priority.DEFAULT,
                null
            );

            var input_stream = yield file.read_async (Priority.DEFAULT, null);
            var file_size = file_info.get_size ();

            // Read file contents into memory for the multipart body
            var bytes = yield input_stream.read_bytes_async ((size_t) file_size, Priority.DEFAULT, null);
            input_stream.close ();

            // Build multipart request
            var multipart = new Soup.Multipart (Soup.FORM_MIME_TYPE_MULTIPART);
            multipart.append_form_string ("timestamp", capture_time.format_iso8601 ());
            multipart.append_form_string ("device_id", device_id);
            multipart.append_form_file (
                "screenshot",
                Path.get_basename (file_path),
                "image/png",
                bytes
            );

            var message = Soup.Form.request_new_from_multipart (endpoint_url, multipart);
            message.method = "POST";

            if (api_token != "") {
                message.get_request_headers ().append ("Authorization", "Bearer %s".printf (api_token));
            }

            var response_bytes = yield _session.send_and_read_async (message, Priority.DEFAULT, null);
            var status = message.get_status ();

            if (status == Soup.Status.OK || status == Soup.Status.CREATED || status == Soup.Status.ACCEPTED) {
                debug ("Upload succeeded for %s (HTTP %u)", file_path, status);
                upload_succeeded (file_path);
                return true;
            } else {
                var response_text = (string) response_bytes.get_data ();
                var error_msg = "HTTP %u: %s".printf (status, response_text ?? "");
                warning ("Upload failed for %s: %s", file_path, error_msg);
                upload_failed (file_path, error_msg);
                return false;
            }
        } catch (Error e) {
            warning ("Upload error for %s: %s", file_path, e.message);
            upload_failed (file_path, e.message);
            return false;
        }
    }
}
