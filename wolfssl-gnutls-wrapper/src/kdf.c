#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "logging.h"
#include "mac.h"
#include "digest.h"
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#ifdef ENABLE_WOLFSSL
/***************************** KDF **********************************/

/**
 * HMAC-KDF-Extract operation.
 *
 * @param [in]  mac       MAC algorithm.
 * @param [in]  key       Input key.
 * @param [in]  keysize   Size of input key in bytes.
 * @param [in]  salt      Salt.
 * @param [in]  saltsize  Size of salt in bytes.
 * @param [out] output    Pseuodranodm key with length the same as the hash.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_hkdf_extract(gnutls_mac_algorithm_t mac, const void *key,
    size_t keysize, const void *salt, size_t saltsize, void *output)
{
    int ret;
    int hash_type;

    WGW_FUNC_ENTER();

    /* Get hash algorithm. */
    hash_type = get_hash_type(mac);
    if (hash_type < 0) {
        WGW_ERROR("MAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    PRIVATE_KEY_UNLOCK();

    /* Extract the key. */
    ret = wc_HKDF_Extract(hash_type, salt, saltsize, key, keysize, output);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_HKDF_Extract", ret);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#else
        return GNUTLS_E_INTERNAL_ERROR;
#endif
    }

    return 0;
}

/**
 * HMAC-KDF-Expand operation.
 *
 * @param [in]  mac       MAC algorithm.
 * @param [in]  key       Input key.
 * @param [in]  keysize   Size of input key in bytes.
 * @param [in]  info      Application specific information.
 * @param [in]  infosize  Size of information in bytes.
 * @param [out] output    Output keying material.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_hkdf_expand(gnutls_mac_algorithm_t mac, const void *key,
    size_t keysize, const void *info, size_t infosize, void *output,
    size_t length)
{
    int ret;
    int hash_type;

    WGW_FUNC_ENTER();
    WGW_LOG("length=%ld", length);

    /* Get hash algorithm. */
    hash_type = get_hash_type(mac);
    if (hash_type < 0) {
        WGW_ERROR("MAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    PRIVATE_KEY_UNLOCK();

    /* Expand the key. */
    ret = wc_HKDF_Expand(hash_type, key, keysize, info, infosize, output,
        length);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_HKDF_Expand_ex", ret);
        if (ret == BAD_FUNC_ARG) {
            return GNUTLS_E_INVALID_REQUEST;
        }
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**
 * PBKDF2 - Password Based Key Derivation Function 2.
 *
 * @param [in]  mac         MAC algorithm.
 * @param [in]  key         Input key.
 * @param [in]  keysize     Size of input key in bytes.
 * @param [in]  salt        Salt.
 * @param [in]  saltsize    Size of salt in bytes.
 * @param [in]  iter_count  Number of iterations to perform.
 * @param [out] output      Output keying material.
 * @param [in]  length      Length of output in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_pbkdf2(gnutls_mac_algorithm_t mac, const void *key,
    size_t keysize, const void *salt, size_t saltsize, unsigned iter_count,
    void *output, size_t length)
{
    int ret;
    int hash_type;

    WGW_FUNC_ENTER();

    /* Get hash algorithm. */
    hash_type = get_hash_type(mac);
    if (hash_type < 0) {
        WGW_ERROR("HMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    PRIVATE_KEY_UNLOCK();

    /* Derive the key. */
    ret = wc_PBKDF2_ex(output, key, keysize, salt, saltsize, iter_count, length,
        hash_type, NULL, INVALID_DEVID);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_PBKDF2_ex", ret);
#if defined(HAVE_FIPS)
        if (ret == HMAC_MIN_KEYLEN_E) {
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
        }
#endif
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/** Function pointers for the KDF implementation. */
static const gnutls_crypto_kdf_st wolfssl_kdf_struct = {
        .hkdf_extract = wolfssl_hkdf_extract,
        .hkdf_expand = wolfssl_hkdf_expand,
        .pbkdf2 = wolfssl_pbkdf2,
};

/**
 * Return the implementations of the KDF operations.
 *
 * @return  KDF implementation.
 */
const gnutls_crypto_kdf_st* gnutls_get_kdf_ops(void)
{
    WGW_FUNC_ENTER();

    return &wolfssl_kdf_struct;
}

/***************************** TLS13 HKDF **********************************/

/**
 * Create initial TLS 1.3 secret.
 *
 * @param [in]  mac       MAC algorithm.
 * @param [in]  psk       Input key.
 * @param [in]  psk_size  Size of input key in bytes.
 * @param [out] out       Pseuodranodm key with length the same as the hash.
 * @param [in]  outsize   Size of output in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_tls13_init_secret(gnutls_mac_algorithm_t mac,
    const unsigned char *psk, size_t psk_size, void *out, size_t output_size)
{
    int ret;
    int hash_type;
    unsigned char tmp[WC_MAX_DIGEST_SIZE];

    WGW_FUNC_ENTER();

    (void)output_size;

    /* Get hash algorithm. */
    hash_type = get_hash_type(mac);
    if (hash_type < 0) {
        WGW_ERROR("HMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (psk == NULL && psk_size == 0) {
        psk = tmp;
    }

    PRIVATE_KEY_UNLOCK();

    ret = wc_Tls13_HKDF_Extract(out, NULL, 0, (byte*)psk, psk_size,
        hash_type);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_Tls13_HKDF_Extract_ex", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**
 * TLS 1.3 HKDF extract operation.
 *
 * @param [in]  mac       MAC algorithm.
 * @param [in]  key       Input key.
 * @param [in]  keysize   Size of input key in bytes.
 * @param [in]  salt      Salt.
 * @param [in]  saltsize  Size of salt in bytes.
 * @param [out] output    Pseuodranodm key with length the same as the hash.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_tls13_update_secret(gnutls_mac_algorithm_t mac,
    const unsigned char *key, size_t key_size, const unsigned char *salt,
    size_t salt_size, unsigned char *secret)
{
    int ret;
    int hash_type;

    WGW_FUNC_ENTER();

    /* Get hash algorithm. */
    hash_type = get_hash_type(mac);
    if (hash_type < 0) {
        WGW_ERROR("HMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    PRIVATE_KEY_UNLOCK();

    /* Extract the key. */
    ret = wc_Tls13_HKDF_Extract(secret, salt, salt_size, (byte*)key,
        key_size, hash_type);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_Tls13_HKDF_Extract_ex", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**
 * TLS 1.3 HKDF expand operation.
 *
 * @param [in]  mac        MAC algorithm.
 * @param [in]  label      Label to identify usage.
 * @param [in]  labelsize  Size of label in bytes.
 * @param [in]  msg        Application specific information.
 * @param [in]  msg_size   Size of information in bytes.
 * @param [in]  secret     Input key.
 * @param [in]  outsize    Size of output in bytes.
 * @param [out] output     Output keying material.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_tls13_expand_secret(gnutls_mac_algorithm_t mac,
    const char *label, unsigned label_size, const unsigned char *msg,
    size_t msg_size, const unsigned char* secret, unsigned out_size, void *out)
{
    int ret;
    int hash_type;
    int digest_size;
    /* Protocol is fixed. */
    unsigned char protocol[] = "tls13 ";
    int protocol_len = sizeof(protocol) - 1;

    WGW_FUNC_ENTER();

    /* Get hash algorithm. */
    hash_type = get_hash_type(mac);
    if (hash_type < 0) {
        WGW_ERROR("HMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }
    /* Get the secret size. */
    digest_size = wc_HmacSizeByType(hash_type);


    PRIVATE_KEY_UNLOCK();

    /* Expand the key. */
    ret = wc_Tls13_HKDF_Expand_Label(out, out_size, secret, digest_size,
        protocol, protocol_len, (byte*)label, label_size, msg, msg_size,
        hash_type);

    PRIVATE_KEY_LOCK();


    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_Tls13_HKDF_Expand_Label_ex", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**
 * TLS 1.3 HKDF derive operation that uses expand.
 *
 * @param [in]  mac        MAC algorithm.
 * @param [in]  label      Label to identify usage.
 * @param [in]  labelsize  Size of label in bytes.
 * @param [in]  tbh        Data to be hashed. Digest becomes message.
 * @param [in]  tbh_size   Size of data to be hashed in bytes.
 * @param [in]  secret     Input key.
 * @param [in]  outsize    Size of output in bytes.
 * @param [out] output     Output keying material.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm not supported.
 * @return  GNUTLS_E_INTERNAL_ERROR when wolfSSL operation fails.
 */
static int wolfssl_tls13_derive_secret(gnutls_mac_algorithm_t mac,
    const char *label, unsigned label_size, const unsigned char* tbh,
    size_t tbh_size, const unsigned char* secret, void *out, size_t output_size)
{
    int ret;
    unsigned char digest[WC_MAX_DIGEST_SIZE];

    WGW_FUNC_ENTER();

    /* Hash data. */
    ret = wolfssl_digest_fast((gnutls_digest_algorithm_t)mac, tbh, tbh_size,
        digest);
    if (ret != 0) {
        return ret;
    }

    /* Expand to key. */
    return wolfssl_tls13_expand_secret(mac, label, label_size, digest,
        output_size, secret, output_size, out);
}

/** Function pointer for the TLS13 HKDF implementation. */
static const gnutls_crypto_tls13_hkdf_st wolfssl_tls13_hkdf_struct = {
    .init = wolfssl_tls13_init_secret,
    .update = wolfssl_tls13_update_secret,
    .derive = wolfssl_tls13_derive_secret,
    .expand = wolfssl_tls13_expand_secret
};

/**
 * Return the implementations of the TLS13 HKDF operations.
 *
 * @return  TLS13 HKDF implementation.
 */
const gnutls_crypto_tls13_hkdf_st* gnutls_get_tls13_hkdf_ops(void)
{
    WGW_FUNC_ENTER();

    return &wolfssl_tls13_hkdf_struct;
}
#endif
