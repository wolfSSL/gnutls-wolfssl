#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "logging.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/kdf.h>

#ifdef ENABLE_WOLFSSL
/**
 * Generate data with TLS PRF.
 *
 * @param [in] mac          Digest algorithm to use with TLS PRF.
 * @param [in] master_size  Size of master secret data in bytes.
 * @param [in] master       Master secret data.
 * @param [in] label_size   Size of label data in bytes.
 * @param [in] label        Label data.
 * @param [in] seed_size    Size of seed data in bytes.
 * @param [in] seed         Seed data.
 * @param [in] outsize      Size of output buffer in bytes.
 * @param [in] out          Output buffer.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL TLS PRF fails.
 */
int wolfssl_tls_prf(gnutls_mac_algorithm_t mac, size_t master_size,
    const void *master, size_t label_size, const char *label, size_t seed_size,
    const uint8_t *seed, size_t outsize, char *out)
{
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("outsize=%d", outsize);

    switch (mac) {
        case GNUTLS_MAC_MD5_SHA1:
            WGW_LOG("MD5+SHA1");
            PRIVATE_KEY_UNLOCK();

            ret = wc_PRF_TLSv1((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, NULL, INVALID_DEVID);

            PRIVATE_KEY_LOCK();

            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_PRF_TLSv1(MD5/SHA-1)", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        case GNUTLS_MAC_SHA256:
            WGW_LOG("SHA256");

            PRIVATE_KEY_UNLOCK();

            ret = wc_PRF_TLS((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, 1, sha256_mac, NULL,
                INVALID_DEVID);

            PRIVATE_KEY_LOCK();
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_PRF_TLSv1(SHA-256)", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        case GNUTLS_MAC_SHA384:
            WGW_LOG("SHA384");

            PRIVATE_KEY_UNLOCK();

            ret = wc_PRF_TLS((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, 1, sha384_mac, NULL,
                INVALID_DEVID);

            PRIVATE_KEY_LOCK();

            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_PRF_TLSv1(SHA-384)", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        default:
            WGW_ERROR("prf mac %d is not supported", mac);
            return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

/** Function pointer for the TLS PRF implementation. */
static const gnutls_crypto_prf_st wolfssl_tls_prf_struct = {
    .raw = wolfssl_tls_prf,
};

/**
 * Return the implementations of the PRF operations.
 *
 * @return  PRF implementation.
 */
const gnutls_crypto_prf_st* gnutls_get_prf_ops(void)
{
    WGW_FUNC_ENTER();

    return &wolfssl_tls_prf_struct;
}
#endif
