/*
 * Minimal VAPI bindings for OpenSSL EVP cipher and digest APIs.
 *
 * Binds only the functions needed for:
 *   - AES-256-CTR encryption (Matrix encrypted attachments)
 *   - SHA-256 hashing (ciphertext integrity hash)
 */

[CCode (cheader_filename = "openssl/evp.h")]
namespace OpenSSL {

    /* ───── Cipher (AES-256-CTR) ───── */

    [CCode (cname = "EVP_CIPHER", has_type_id = false)]
    [Compact]
    public class Cipher {
    }

    [CCode (cname = "EVP_aes_256_ctr")]
    public unowned Cipher aes_256_ctr ();

    [CCode (cname = "EVP_CIPHER_CTX", free_function = "EVP_CIPHER_CTX_free", has_type_id = false)]
    [Compact]
    public class CipherCtx {
        [CCode (cname = "EVP_CIPHER_CTX_new")]
        public CipherCtx ();

        [CCode (cname = "EVP_EncryptInit_ex")]
        public int encrypt_init (Cipher? cipher, void* engine,
                                 [CCode (array_length = false)] uint8[]? key,
                                 [CCode (array_length = false)] uint8[]? iv);

        [CCode (cname = "EVP_EncryptUpdate")]
        public int encrypt_update ([CCode (array_length = false)] uint8[] out_buf,
                                   out int out_len,
                                   [CCode (array_length = false)] uint8[] in_buf,
                                   int in_len);

        [CCode (cname = "EVP_EncryptFinal_ex")]
        public int encrypt_final ([CCode (array_length = false)] uint8[] out_buf,
                                  out int out_len);

        [CCode (cname = "EVP_DecryptInit_ex")]
        public int decrypt_init (Cipher? cipher, void* engine,
                                 [CCode (array_length = false)] uint8[]? key,
                                 [CCode (array_length = false)] uint8[]? iv);

        [CCode (cname = "EVP_DecryptUpdate")]
        public int decrypt_update ([CCode (array_length = false)] uint8[] out_buf,
                                   out int out_len,
                                   [CCode (array_length = false)] uint8[] in_buf,
                                   int in_len);

        [CCode (cname = "EVP_DecryptFinal_ex")]
        public int decrypt_final ([CCode (array_length = false)] uint8[] out_buf,
                                  out int out_len);

        [CCode (cname = "EVP_CIPHER_CTX_set_padding")]
        public int set_padding (int pad);
    }

    /* ───── Digest (SHA-256) ───── */

    [CCode (cname = "EVP_MD", has_type_id = false)]
    [Compact]
    public class Md {
    }

    [CCode (cname = "EVP_sha256")]
    public unowned Md sha256 ();

    /**
     * One-shot digest: hash data directly into md (caller-allocated).
     * Returns 1 on success, 0 on failure.
     */
    [CCode (cname = "EVP_Digest")]
    public int digest ([CCode (array_length = false)] uint8[] data,
                       size_t count,
                       [CCode (array_length = false)] uint8[] md,
                       out uint md_size,
                       Md type,
                       void* engine = null);

    /* ───── HMAC ───── */

    /**
     * One-shot HMAC: compute HMAC of data with key.
     * Returns pointer to md (same as md parameter), or null on failure.
     * md must be at least EVP_MAX_MD_SIZE (64) bytes.
     */
    [CCode (cname = "HMAC", cheader_filename = "openssl/hmac.h")]
    public void* hmac (Md evp_md,
                       void* key, int key_len,
                       void* data, size_t data_len,
                       void* md, out uint md_len);

    /* ───── Key Derivation (PBKDF2) ───── */

    /**
     * PBKDF2-HMAC key derivation.
     * Returns 1 on success, 0 on failure.
     */
    [CCode (cname = "PKCS5_PBKDF2_HMAC")]
    public int pbkdf2_hmac (string pass, int passlen,
                            [CCode (array_length = false)] uint8[] salt, int saltlen,
                            int iterations,
                            Md digest,
                            int keylen,
                            [CCode (array_length = false)] uint8[] out_key);
}
