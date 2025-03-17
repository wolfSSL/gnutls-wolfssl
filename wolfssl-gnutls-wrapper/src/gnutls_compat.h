/* gnutls_compat.h */

#include <gnutls/crypto.h>

/* replicated definitions from GnuTLS internal headers */

/* From crypto-backend.h */
typedef struct {
    gnutls_cipher_init_func init;
    gnutls_cipher_setkey_func setkey;
    gnutls_cipher_setiv_func setiv;
    gnutls_cipher_getiv_func getiv;
    gnutls_cipher_encrypt_func encrypt;
    gnutls_cipher_decrypt_func decrypt;
    gnutls_cipher_aead_encrypt_func aead_encrypt;
    gnutls_cipher_aead_decrypt_func aead_decrypt;
    gnutls_cipher_deinit_func deinit;
    gnutls_cipher_auth_func auth;
    gnutls_cipher_tag_func tag;

    /* Not needed for registered on run-time. Only included
     * should define it. */
    int (*exists)(gnutls_cipher_algorithm_t); /* true/false */
} gnutls_crypto_cipher_st;

typedef struct {
    gnutls_mac_init_func init;
    gnutls_mac_setkey_func setkey;
    gnutls_mac_setnonce_func setnonce;
    gnutls_mac_hash_func hash;
    gnutls_mac_output_func output;
    gnutls_mac_deinit_func deinit;
    gnutls_mac_fast_func fast;
    gnutls_mac_copy_func copy;

    /* Not needed for registered on run-time. Only included
     * should define it. */
    int (*exists)(gnutls_mac_algorithm_t);
} gnutls_crypto_mac_st;

typedef struct {
    gnutls_digest_init_func init;
    gnutls_digest_hash_func hash;
    gnutls_digest_output_func output;
    gnutls_digest_deinit_func deinit;
    gnutls_digest_fast_func fast;
    gnutls_digest_copy_func copy;

    /* Not needed for registered on run-time. Only included
     * should define it. */
    int (*exists)(gnutls_digest_algorithm_t);
} gnutls_crypto_digest_st;


int gnutls_crypto_single_cipher_register(gnutls_cipher_algorithm_t algorithm,
                                         int priority,
                                         const gnutls_crypto_cipher_st *s,
                                         int free_s);

int gnutls_crypto_single_mac_register(gnutls_mac_algorithm_t algorithm,
                                     int priority,
                                     const gnutls_crypto_mac_st *s,
                                     int free_s);

int gnutls_crypto_single_digest_register(gnutls_digest_algorithm_t algorithm,
                                        int priority,
                                        const gnutls_crypto_digest_st *s,
                                        int free_s);

