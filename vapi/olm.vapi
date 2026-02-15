/*
 * VAPI bindings for libolm (Olm/Megolm cryptographic library).
 *
 * These bindings expose the raw C API. The EncryptionService wraps
 * them in a safe, high-level Vala interface.
 *
 * libolm uses caller-allocated buffers for all objects. Call
 * *_size() to get the required buffer size, allocate, then call
 * the init function which returns a pointer into that buffer.
 */

[CCode (cheader_filename = "olm/olm.h")]
namespace Olm {

    /* Sentinel value returned on error */
    [CCode (cname = "olm_error")]
    public size_t error_val ();

    /* ────────── OlmAccount ────────── */

    [CCode (cname = "olm_account_size")]
    public size_t account_size ();

    [CCode (cname = "olm_account")]
    public void* account_init (void* memory);

    [CCode (cname = "olm_clear_account")]
    public size_t clear_account (void* account);

    [CCode (cname = "olm_account_last_error")]
    public unowned string account_last_error (void* account);

    [CCode (cname = "olm_create_account_random_length")]
    public size_t create_account_random_length (void* account);

    [CCode (cname = "olm_create_account")]
    public size_t create_account (void* account, void* random, size_t random_len);

    [CCode (cname = "olm_account_identity_keys_length")]
    public size_t account_identity_keys_length (void* account);

    [CCode (cname = "olm_account_identity_keys")]
    public size_t account_identity_keys (void* account, void* keys, size_t keys_len);

    [CCode (cname = "olm_account_signature_length")]
    public size_t account_signature_length (void* account);

    [CCode (cname = "olm_account_sign")]
    public size_t account_sign (void* account, void* message, size_t msg_len,
                                void* signature, size_t sig_len);

    [CCode (cname = "olm_account_one_time_keys_length")]
    public size_t account_one_time_keys_length (void* account);

    [CCode (cname = "olm_account_one_time_keys")]
    public size_t account_one_time_keys (void* account, void* keys, size_t keys_len);

    [CCode (cname = "olm_account_mark_keys_as_published")]
    public size_t account_mark_keys_as_published (void* account);

    [CCode (cname = "olm_account_max_number_of_one_time_keys")]
    public size_t account_max_number_of_one_time_keys (void* account);

    [CCode (cname = "olm_account_generate_one_time_keys_random_length")]
    public size_t account_generate_one_time_keys_random_length (void* account, size_t count);

    [CCode (cname = "olm_account_generate_one_time_keys")]
    public size_t account_generate_one_time_keys (void* account, size_t count,
                                                   void* random, size_t random_len);

    [CCode (cname = "olm_account_generate_fallback_key_random_length")]
    public size_t account_generate_fallback_key_random_length (void* account);

    [CCode (cname = "olm_account_generate_fallback_key")]
    public size_t account_generate_fallback_key (void* account, void* random, size_t random_len);

    /* Pickle / unpickle (persist encrypted state) */
    [CCode (cname = "olm_pickle_account_length")]
    public size_t pickle_account_length (void* account);

    [CCode (cname = "olm_pickle_account")]
    public size_t pickle_account (void* account, void* key, size_t key_len,
                                  void* pickled, size_t pickled_len);

    [CCode (cname = "olm_unpickle_account")]
    public size_t unpickle_account (void* account, void* key, size_t key_len,
                                    void* pickled, size_t pickled_len);

    /* ────────── OlmSession (Olm 1:1 encryption for key sharing) ────────── */

    [CCode (cname = "olm_session_size")]
    public size_t session_size ();

    [CCode (cname = "olm_session")]
    public void* session_init (void* memory);

    [CCode (cname = "olm_clear_session")]
    public size_t clear_session (void* session);

    [CCode (cname = "olm_session_last_error")]
    public unowned string session_last_error (void* session);

    [CCode (cname = "olm_create_outbound_session_random_length")]
    public size_t create_outbound_session_random_length (void* session);

    [CCode (cname = "olm_create_outbound_session")]
    public size_t create_outbound_session (void* session, void* account,
                                           void* id_key, size_t id_key_len,
                                           void* otk, size_t otk_len,
                                           void* random, size_t random_len);

    [CCode (cname = "olm_encrypt_message_type")]
    public size_t encrypt_message_type (void* session);

    [CCode (cname = "olm_encrypt_random_length")]
    public size_t encrypt_random_length (void* session);

    [CCode (cname = "olm_encrypt_message_length")]
    public size_t encrypt_message_length (void* session, size_t plaintext_len);

    [CCode (cname = "olm_encrypt")]
    public size_t encrypt (void* session,
                           void* plaintext, size_t plaintext_len,
                           void* random, size_t random_len,
                           void* message, size_t message_len);

    [CCode (cname = "olm_pickle_session_length")]
    public size_t pickle_session_length (void* session);

    [CCode (cname = "olm_pickle_session")]
    public size_t pickle_session (void* session, void* key, size_t key_len,
                                  void* pickled, size_t pickled_len);

    [CCode (cname = "olm_unpickle_session")]
    public size_t unpickle_session (void* session, void* key, size_t key_len,
                                    void* pickled, size_t pickled_len);

    /* ────────── OlmOutboundGroupSession (Megolm room encryption) ────────── */

    [CCode (cname = "olm_outbound_group_session_size")]
    public size_t outbound_group_session_size ();

    [CCode (cname = "olm_outbound_group_session")]
    public void* outbound_group_session_init (void* memory);

    [CCode (cname = "olm_clear_outbound_group_session")]
    public size_t clear_outbound_group_session (void* session);

    [CCode (cname = "olm_outbound_group_session_last_error")]
    public unowned string outbound_group_session_last_error (void* session);

    [CCode (cname = "olm_init_outbound_group_session_random_length")]
    public size_t init_outbound_group_session_random_length (void* session);

    [CCode (cname = "olm_init_outbound_group_session")]
    public size_t init_outbound_group_session (void* session, uint8* random, size_t random_len);

    [CCode (cname = "olm_group_encrypt_message_length")]
    public size_t group_encrypt_message_length (void* session, size_t plaintext_len);

    [CCode (cname = "olm_group_encrypt")]
    public size_t group_encrypt (void* session,
                                 uint8* plaintext, size_t plaintext_len,
                                 uint8* message, size_t message_len);

    [CCode (cname = "olm_outbound_group_session_id_length")]
    public size_t outbound_group_session_id_length (void* session);

    [CCode (cname = "olm_outbound_group_session_id")]
    public size_t outbound_group_session_id (void* session, uint8* id, size_t id_len);

    [CCode (cname = "olm_outbound_group_session_key_length")]
    public size_t outbound_group_session_key_length (void* session);

    [CCode (cname = "olm_outbound_group_session_key")]
    public size_t outbound_group_session_key (void* session, uint8* key, size_t key_len);

    [CCode (cname = "olm_outbound_group_session_message_index")]
    public uint32 outbound_group_session_message_index (void* session);

    /* Pickle / unpickle outbound group session */
    [CCode (cname = "olm_pickle_outbound_group_session_length")]
    public size_t pickle_outbound_group_session_length (void* session);

    [CCode (cname = "olm_pickle_outbound_group_session")]
    public size_t pickle_outbound_group_session (void* session, void* key, size_t key_len,
                                                  void* pickled, size_t pickled_len);

    [CCode (cname = "olm_unpickle_outbound_group_session")]
    public size_t unpickle_outbound_group_session (void* session, void* key, size_t key_len,
                                                    void* pickled, size_t pickled_len);
}
