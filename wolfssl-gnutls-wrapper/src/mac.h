#ifdef ENABLE_WOLFSSL
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/aes.h>

int wolfssl_mac_register(void);
int get_hash_type(gnutls_mac_algorithm_t algorithm);
/** Context for wolfSSL CMAC. */
struct wolfssl_cmac_ctx {
    /** wolfSSL CMAC object. */
    Cmac cmac_ctx;
    /** Indicates that this context as been initialized. */
    int initialized;
    /** The GnuTLS cipher algorithm ID. */
    gnutls_mac_algorithm_t algorithm;
    /** Cached key. */
    unsigned char key[AES_256_KEY_SIZE];
    /** Size of cached key. */
    size_t key_size;
    /** Setting of the key is required before hashing. */
    unsigned int set_key:1;
};
#endif
