/*
 * Minimal VAPI bindings for OpenSSL EVP cipher API.
 *
 * Only the functions needed for AES-256-CTR (Matrix encrypted
 * attachments) are bound here.
 */

[CCode (cheader_filename = "openssl/evp.h")]
namespace OpenSSL {

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

        [CCode (cname = "EVP_CIPHER_CTX_set_padding")]
        public int set_padding (int pad);
    }
}
