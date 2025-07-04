#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "logging.h"
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>

#ifdef ENABLE_WOLFSSL
/** Maximum size of a digest output from a HMAC operation. */
#define MAX_HMAC_DIGEST_SIZE    WC_SHA512_DIGEST_SIZE

/** Context for wolfSSL HMAC. */
struct wolfssl_hmac_ctx {
    /** wolfSSL HMAC object. */
    Hmac hmac_ctx;
    /** Indicates that this context as been initialized. */
    int initialized;
    /** The GnuTLS cipher algorithm ID. */
    gnutls_mac_algorithm_t algorithm;
};

/** Array of supported ciphers. */
static const int wolfssl_mac_supported[] = {
    [GNUTLS_MAC_MD5] = 1,
    [GNUTLS_MAC_SHA1] = 1,
    [GNUTLS_MAC_SHA224] = 1,
    [GNUTLS_MAC_SHA256] = 1,
    [GNUTLS_MAC_SHA384] = 1,
    [GNUTLS_MAC_SHA512] = 1,
    [GNUTLS_MAC_SHA3_224] = 1,
    [GNUTLS_MAC_SHA3_256] = 1,
    [GNUTLS_MAC_SHA3_384] = 1,
    [GNUTLS_MAC_SHA3_512] = 1,
    [GNUTLS_MAC_AES_CMAC_128] = 1,
    [GNUTLS_MAC_AES_CMAC_256] = 1,
    [GNUTLS_MAC_AES_GMAC_128] = 1,
    [GNUTLS_MAC_AES_GMAC_192] = 1,
    [GNUTLS_MAC_AES_GMAC_256] = 1,
};
/** Length of array of supported MACs. */
#define WOLFSSL_MAC_SUPPORTED_LEN (int)(sizeof(wolfssl_mac_supported) / \
                                        sizeof(wolfssl_mac_supported[0]))

/**
 * Convert GnuTLS MAC algorithm to wolfSSL hash type
 *
 * @param [in] algorithm  GnuTLS MAC algorithm.
 * @return  wolfSSL hash type when algorithm supported.
 * @return  -1 when MAC algorithm is not supported.
 */
int get_hash_type(gnutls_mac_algorithm_t algorithm)
{
    switch (algorithm) {
        case GNUTLS_MAC_MD5:
            WGW_LOG("using MD5");
            return WC_MD5;
        case GNUTLS_MAC_SHA1:
            WGW_LOG("using SHA1");
            return WC_SHA;
        case GNUTLS_MAC_MD5_SHA1:
            WGW_LOG("using MD5_SHA1");
            return WC_HASH_TYPE_MD5_SHA;
        case GNUTLS_MAC_SHA224:
            WGW_LOG("using SHA224");
            return WC_SHA224;
        case GNUTLS_MAC_SHA256:
            WGW_LOG("using SHA256");
            return WC_SHA256;
        case GNUTLS_MAC_SHA384:
            WGW_LOG("using SHA384");
            return WC_SHA384;
        case GNUTLS_MAC_SHA512:
            WGW_LOG("using SHA512");
            return WC_SHA512;
        case GNUTLS_MAC_SHA3_224:
            WGW_LOG("using SHA3-224");
            return WC_SHA3_224;
        case GNUTLS_MAC_SHA3_256:
            WGW_LOG("using SHA3-256");
            return WC_SHA3_256;
        case GNUTLS_MAC_SHA3_384:
            WGW_LOG("using SHA3-384");
            return WC_SHA3_384;
        case GNUTLS_MAC_SHA3_512:
            WGW_LOG("using SHA3-512");
            return WC_SHA3_512;
#if defined(WOLFSSL_SHAKE128)
        case GNUTLS_DIG_SHAKE_128:
            WGW_LOG("using SHAKE128");
            return WC_HASH_TYPE_SHAKE128;
#endif
#if defined(WOLFSSL_SHAKE256)
        case GNUTLS_DIG_SHAKE_256:
            WGW_LOG("using SHAKE256");
            return WC_HASH_TYPE_SHAKE256;
#endif
        default:
            return -1;
    }
}

/**
 * Checks if MAC is supported.
 *
 * @param [in] algorithm  GnuTLS MAC algorithm.
 * @return  1 when algorithm is supported.
 * @return  0 otherwise.
 */
static int is_mac_supported(gnutls_mac_algorithm_t algorithm)
{
    return (algorithm >= 0 && algorithm < WOLFSSL_MAC_SUPPORTED_LEN &&
            wolfssl_mac_supported[algorithm]);
}

/**
 * Initialize a MAC context.
 *
 * @param [in]  algorithm  MAC algorithm.
 * @param [out] _ctx       HMAC context.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when initialization of HMAC fails.
 */
static int wolfssl_hmac_init(gnutls_mac_algorithm_t algorithm, void **_ctx)
{
    struct wolfssl_hmac_ctx *ctx;
    int ret = 0;

    WGW_FUNC_ENTER();
    WGW_LOG("HMAC algorithm %d", algorithm);

    /* Check if MAC algorithm is supported. */
    if (!is_mac_supported(algorithm)) {
        WGW_ERROR("mac algorithm %d is not supported", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate context. */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hmac_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize wolfSSL HMAC context. */
    ret = wc_HmacInit(&ctx->hmac_ctx, NULL, INVALID_DEVID);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_HmacInit", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->initialized = 1;
    ctx->algorithm = algorithm;
    *_ctx = ctx;

    WGW_LOG("hmac context initialized successfully");
    return 0;
}

/**
 * Set the MAC key into HMAC context.
 *
 * @param [in, out] _ctx     HMAC context.
 * @param [in]      key      Key data.
 * @param [in]      keysize  Size of key data in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized or algorithm
 *          is not supported.
 * @return  GNUTLS_E_HASH_FAILED when setting the key into wolfSSL object fails.
 */
static int wolfssl_hmac_setkey(void *_ctx, const void *key, size_t keysize)
{
    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;
    int hash_type;

    WGW_FUNC_ENTER();
    WGW_LOG("keysize %zu", keysize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Get wolfSSL hash type. */
    hash_type = get_hash_type(ctx->algorithm);
    if (hash_type < 0) {
        WGW_ERROR("HMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Set the key. */
    ret = wc_HmacSetKey(&ctx->hmac_ctx, hash_type, (const byte*)key,
        (word32)keysize);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_HmacSetKey", ret);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#else
        return GNUTLS_E_HASH_FAILED;
#endif
    }

    WGW_LOG("hmac key set successfully");
    return 0;
}


/**
 * Update the HMAC with data.
 *
 * @param [in, out] _ctx      HMAC context.
 * @param [in]      text      Text to update with.
 * @param [in]      textsize  Size of text in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL HMAC update fails.
 */
static int wolfssl_hmac_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", textsize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Can only do 32-bit sized updates at a time. */
    do {
        /* Use a max that is a multiple of the maximum block size. */
        word32 size = 0xffffffc0;
        if (textsize < (size_t)size) {
            size = textsize;
        }

        /* Update the HMAC. */
        ret = wc_HmacUpdate(&ctx->hmac_ctx, (const byte*)text, size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_HmacUpdate", ret);
            return GNUTLS_E_HASH_FAILED;
        }

        /* Move over processed text. */
        text += size;
        textsize -= size;
    } while (textsize != 0);

    WGW_LOG("hmac updated successfully");
    return 0;
}


/**
 * Output the hmac result.
 *
 * @param [in, out] _ctx        HMAC context.
 * @param [out]     digest      Buffer to hold digest.
 * @param [in]      digestsize  Size of buffer to hold digest in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized or
 *          algorithm not supported.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when digestsize is too small for HMAC
 *          output.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL HMAC operation fails.
 */
static int wolfssl_hmac_output(void *_ctx, void *digest, size_t digestsize)
{
    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;
    int digest_size;

    WGW_FUNC_ENTER();
    WGW_LOG("digestsize %zu", digestsize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Get the digest size based on the hash algorithm. */
    digest_size = wc_HmacSizeByType(get_hash_type(ctx->algorithm));
    if (digest_size <= 0) {
        WGW_ERROR("HMAC not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Make sure the output buffer is large enough. */
    if (digestsize < (size_t)digest_size) {
        WGW_ERROR("digestsize too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* Finalize the HMAC and get the result. */
    ret = wc_HmacFinal(&ctx->hmac_ctx, (byte*)digest);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_HmacFinal", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    WGW_LOG("hmac output successful");
    return 0;
}


/**
 * Clean up HMAC resources.
 *
 * @param [in, out] _ctx  HMAC context.
 */
static void wolfssl_hmac_deinit(void *_ctx)
{
    struct wolfssl_hmac_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();

    if (ctx && ctx->initialized) {
        /* free the wolfSSL HMAC context */
        wc_HmacFree(&ctx->hmac_ctx);
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/**
 * One-shot HMAC function.
 *
 * @param [in]  algorithm  GnuTLS digest algorithm ID.
 * @param [in]  text       Text to update digest with.
 * @param [in]  textsize   Size of text in bytes.
 * @param [out] digest     Buffer to hold digest.
 * @return 0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when digest algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL operation fails.
 */
static int wolfssl_hmac_fast(gnutls_mac_algorithm_t algorithm,
    const void *nonce, size_t nonce_size, const void *key, size_t keysize,
    const void *text, size_t textsize, void *digest)
{
    struct wolfssl_hmac_ctx *ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    (void)nonce;
    (void)nonce_size;

    /* Initialize HMAC context. */
    ret = wolfssl_hmac_init(algorithm, (void**)&ctx);
    if (ret != 0) {
        return ret;
    }

    /* Set key into HMAC context. */
    ret = wolfssl_hmac_setkey(ctx, key, keysize);
    if (ret != 0) {
        return ret;
    }

    /* Hash the text. */
    ret = wolfssl_hmac_hash(ctx, text, textsize);
    if (ret != 0) {
        wolfssl_hmac_deinit(ctx);
        return ret;
    }

    /* Output the MAC - pass in maximum size to ensure length test passes. */
    ret = wolfssl_hmac_output(ctx, digest, MAX_HMAC_DIGEST_SIZE);
    if (ret != 0) {
        wolfssl_hmac_deinit(ctx);
        return ret;
    }

    /* Dispose of HMAC context. */
    wolfssl_hmac_deinit(ctx);

    return 0;
}

/** Function pointers for the MAC implementation using wolfSSL. */
static const gnutls_crypto_mac_st wolfssl_mac_struct = {
    .init = wolfssl_hmac_init,
    .setkey = wolfssl_hmac_setkey,
    .hash = wolfssl_hmac_hash,
    .output = wolfssl_hmac_output,
    .deinit = wolfssl_hmac_deinit,
    .fast = wolfssl_hmac_fast
};

/*************************** MAC algorithms (CMAC) ***************************/

/**
 * Checks if MAC is CMAC.
 *
 * @param [in] algorithm  GnuTLS MAC algorithm.
 * @return  1 when algorithm is CMAC.
 * @return  0 otherwise.
 */
static int is_mac_cmac(gnutls_mac_algorithm_t algorithm)
{
    return (algorithm == GNUTLS_MAC_AES_CMAC_128 ||
            algorithm == GNUTLS_MAC_AES_CMAC_256);
}

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

/**
 * Get CMAC algorithm key sizes.
 *
 * @param [in]  algorithm  MAC algorithm.
 * @return  Keys size for CMAC algorithm on success.
 * @return  -1 when algorithm not a CMAC algorithm.
 */
static size_t cmac_alg_key_size(gnutls_mac_algorithm_t algorithm)
{
    if (algorithm == GNUTLS_MAC_AES_CMAC_128) {
        return AES_128_KEY_SIZE;
    } else if (algorithm == GNUTLS_MAC_AES_CMAC_256) {
        return AES_256_KEY_SIZE;
    } else {
        return (size_t)-1;
    }
}

/**
 * Initialize a MAC context.
 *
 * @param [in]  algorithm  MAC algorithm.
 * @param [out] _ctx       CMAC context.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when initialization of CMAC fails.
 */
static int wolfssl_cmac_init(gnutls_mac_algorithm_t algorithm, void **_ctx)
{
    struct wolfssl_cmac_ctx *ctx;

    WGW_FUNC_ENTER();
    WGW_LOG("CMAC algorithm %d", algorithm);

    /* Check if mac is supported. */
    if (!is_mac_supported(algorithm)) {
        WGW_ERROR("mac algorithm %d is not supported", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if MAC algorithm is a CMAC. */
    if (!is_mac_cmac(algorithm)) {
        WGW_ERROR("Unsupported algorithm: %d\n", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate context. */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_cmac_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ctx->initialized = 1;
    ctx->algorithm = algorithm;
    *_ctx = ctx;

    WGW_LOG("CMAC context initialized successfully");
    return 0;
}

/**
 * Set the MAC key into CMAC context.
 *
 * @param [in, out] _ctx     CMAC context.
 * @param [in]      key      Key data.
 * @param [in]      keysize  Size of key data in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized or algorithm
 *          is not supported.
 * @return  GNUTLS_E_HASH_FAILED when setting the key into wolfSSL object fails.
 */
static int wolfssl_cmac_setkey(void *_ctx, const void *key, size_t keysize)
{
    struct wolfssl_cmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("keysize %zu", keysize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check key size. */
    if (keysize != cmac_alg_key_size(ctx->algorithm)) {
        WGW_ERROR("CMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Initialize and set the key */
    ret = wc_InitCmac(&ctx->cmac_ctx, (const byte*)key, (word32)keysize,
        WC_CMAC_AES, NULL);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitCmac", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    XMEMCPY(ctx->key, key, keysize);
    ctx->key_size = keysize;
    ctx->set_key = 0;

    WGW_LOG("cmac key set successfully");
    return 0;
}

/**
 * Update the CMAC with data.
 *
 * @param [in, out] _ctx      CMAC context.
 * @param [in]      text      Text to update with.
 * @param [in]      textsize  Size of text in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL CMAC update fails.
 */
static int wolfssl_cmac_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_cmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", textsize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (ctx->set_key) {
        /* Initialize and set the key */
        ret = wc_InitCmac(&ctx->cmac_ctx, (const byte*)ctx->key,
            (word32)ctx->key_size, WC_CMAC_AES, NULL);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_InitCmac", ret);
            gnutls_free(ctx);
            return GNUTLS_E_HASH_FAILED;
        }
        ctx->set_key = 0;
    }

    /* Can only do 32-bit sized updates at a time. */
    do {
        /* Use a max that is a multiple of the block size. */
        word32 size = 0xfffffff0;
        if (textsize < (size_t)size) {
            size = textsize;
        }

        /* Update CMAC. */
        ret = wc_CmacUpdate(&ctx->cmac_ctx, (const byte*)text, size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_CmacUpdate", ret);
            return GNUTLS_E_HASH_FAILED;
        }

        /* Move over processed text. */
        text += size;
        textsize -= size;
    } while (textsize != 0);

    WGW_LOG("cmac updated successfully");
    return 0;
}

/**
 * Output the cmac result.
 *
 * @param [in, out] _ctx        CMAC context.
 * @param [out]     digest      Buffer to hold digest.
 * @param [in]      digestsize  Size of buffer to hold digest in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized or
 *          algorithm not supported.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when digestsize is too small for CMAC
 *          output.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL CMAC operation fails.
 */
static int wolfssl_cmac_output(void *_ctx, void *digest, size_t digestsize)
{
    struct wolfssl_cmac_ctx *ctx = _ctx;
    int ret;
    word32 digest_size = digestsize;

    WGW_FUNC_ENTER();
    WGW_LOG("digestsize %zu", digestsize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Make sure output buffer is large enough. */
    if (digestsize < WC_CMAC_TAG_MIN_SZ) {
        WGW_ERROR("digestsize too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    if (ctx->set_key) {
        /* Initialize and set the key */
        ret = wc_InitCmac(&ctx->cmac_ctx, (const byte*)ctx->key,
            (word32)ctx->key_size, WC_CMAC_AES, NULL);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_InitCmac", ret);
            gnutls_free(ctx);
            return GNUTLS_E_HASH_FAILED;
        }
        ctx->set_key = 0;
    }

    /* Finalize CMAC and get the result. */
    ret = wc_CmacFinal(&ctx->cmac_ctx, (byte*)digest, &digest_size);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_CmacFinal", ret);
        return GNUTLS_E_HASH_FAILED;
    }
    ctx->set_key = 1;

    WGW_LOG("cmac output successful");
    return 0;
}

/**
 * Clean up CMAC resources.
 *
 * @param [in, out] _ctx  CMAC context.
 */
static void wolfssl_cmac_deinit(void *_ctx)
{
    struct wolfssl_cmac_ctx *ctx = _ctx;

    WGW_LOG("wolfssl_cmac_deinit");

    if (ctx && ctx->initialized) {
        /* free the wolfSSL CMAC context */
#if !defined(HAVE_FIPS)
        wc_CmacFree(&ctx->cmac_ctx);
#endif
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/**
 * One-shot CMAC function.
 *
 * @param [in]  algorithm  GnuTLS digest algorithm ID.
 * @param [in]  text       Text to update digest with.
 * @param [in]  textsize   Size of text in bytes.
 * @param [out] digest     Buffer to hold digest.
 * @return 0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when digest algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL operation fails.
 */
static int wolfssl_cmac_fast(gnutls_mac_algorithm_t algorithm,
    const void *nonce, size_t nonce_size, const void *key, size_t keysize,
    const void *text, size_t textsize, void *digest)
{
    struct wolfssl_cmac_ctx *ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    (void)nonce;
    (void)nonce_size;

    /* Initialize CMAC context. */
    ret = wolfssl_cmac_init(algorithm, (void**)&ctx);
    if (ret != 0) {
        return ret;
    }

    /* Set key into CMAC context. */
    ret = wolfssl_cmac_setkey(ctx, key, keysize);
    if (ret != 0) {
        return ret;
    }

    /* Hash the text. */
    ret = wolfssl_cmac_hash(ctx, text, textsize);
    if (ret != 0) {
        wolfssl_cmac_deinit(ctx);
        return ret;
    }

    /* Output the MAC. */
    ret = wolfssl_cmac_output(ctx, digest, WC_SHA512_DIGEST_SIZE);
    if (ret != 0) {
        wolfssl_cmac_deinit(ctx);
        return ret;
    }

    /* Dispose of CMAC context. */
    wolfssl_cmac_deinit(ctx);

    return 0;
}

/** Function pointers for the MAC implementation using wolfSSL. */
static const gnutls_crypto_mac_st wolfssl_cmac_struct = {
    .init = wolfssl_cmac_init,
    .setkey = wolfssl_cmac_setkey,
    .hash = wolfssl_cmac_hash,
    .output = wolfssl_cmac_output,
    .deinit = wolfssl_cmac_deinit,
    .fast = wolfssl_cmac_fast
};

/*************************** MAC algorithms (GMAC) ***************************/

/**
 * Checks if MAC is GMAC.
 *
 * @param [in] algorithm  GnuTLS MAC algorithm.
 * @return  1 when algorithm is GMAC.
 * @return  0 otherwise.
 */
static int is_mac_gmac(gnutls_mac_algorithm_t algorithm)
{
    return (algorithm == GNUTLS_MAC_AES_GMAC_128 ||
            algorithm == GNUTLS_MAC_AES_GMAC_192 ||
            algorithm == GNUTLS_MAC_AES_GMAC_256);
}

/** Context for wolfSSL GMAC. */
struct wolfssl_gmac_ctx {
    /** wolfSSL GMAC object. */
    Gmac gmac_ctx;
    /** Indicates that this context as been initialized. */
    unsigned int initialized:1;
    /** The GnuTLS cipher algorithm ID. */
    gnutls_mac_algorithm_t algorithm;
    /** Nonce. */
    unsigned char nonce[GCM_NONCE_MAX_SZ];
    /** Nonce size. */
    int nonce_size;
    /** Cached data. */
    unsigned char* data;
    /** Length of cached data. */
    word32 data_size;
};


/**
 * Get GMAC algorithm key sizes.
 *
 * @param [in]  algorithm  MAC algorithm.
 * @return  Keys size for GMAC algorithm on success.
 * @return  -1 when algorithm not a CMAC algorithm.
 */
static size_t gmac_alg_key_size(gnutls_mac_algorithm_t algorithm)
{
    if (algorithm == GNUTLS_MAC_AES_GMAC_128) {
        return AES_128_KEY_SIZE;
    } else if (algorithm == GNUTLS_MAC_AES_GMAC_192) {
        return AES_192_KEY_SIZE;
    } else if (algorithm == GNUTLS_MAC_AES_GMAC_256) {
        return AES_256_KEY_SIZE;
    }

    return (size_t)-1;
}

/**
 * Initialize a MAC context.
 *
 * @param [in]  algorithm  MAC algorithm.
 * @param [out] _ctx       GMAC context.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when MAC algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when initialization of GMAC fails.
 */
static int wolfssl_gmac_init(gnutls_mac_algorithm_t algorithm, void **_ctx)
{
    struct wolfssl_gmac_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("GMAC algorithm %d", algorithm);

    /* Check if MAC algorithm is supported */
    if (!is_mac_supported(algorithm)) {
        WGW_ERROR("mac algorithm %d is not supported", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if MAC algorithm is a GMAC. */
    if (!is_mac_gmac(algorithm)) {
        WGW_ERROR("mac algorithm %d is not GMAC", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate context. */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_gmac_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize wolfSSL GMAC context. */
    ret = wc_AesInit(&ctx->gmac_ctx.aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_AesInit", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->initialized = 1;
    ctx->algorithm = algorithm;
    *_ctx = ctx;

    WGW_LOG("gmac context initialized successfully");
    return 0;
}

/**
 * Set the MAC key into GMAC context.
 *
 * @param [in, out] _ctx     GMAC context.
 * @param [in]      key      Key data.
 * @param [in]      keysize  Size of key data in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized or algorithm
 *          is not supported.
 * @return  GNUTLS_E_HASH_FAILED when setting the key into wolfSSL object fails.
 */
static int wolfssl_gmac_setkey(void *_ctx, const void *key, size_t keysize)
{
    struct wolfssl_gmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("keysize %zu", keysize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check the key size is valid for algorithm. */
    if (keysize != gmac_alg_key_size(ctx->algorithm)) {
        WGW_ERROR("GMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Initialize and set the key */
    ret = wc_GmacSetKey(&ctx->gmac_ctx, (const byte*)key, (word32)keysize);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_GmacSetKey", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    WGW_LOG("gmac key set successfully");
    return 0;
}

/**
 * Set the nonce into GMAC context.
 *
 * @param [in, out] _ctx        GMAC context.
 * @param [in]      nonce       Key data.
 * @param [in]      nonce_size  Size of key data in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized or algorithm
 *          is not supported.
 * @return  GNUTLS_E_HASH_FAILED when setting the key into wolfSSL object fails.
 */
static int wolfssl_gmac_setnonce(void *_ctx, const void *nonce,
    size_t nonce_size)
{
    struct wolfssl_gmac_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();
    WGW_LOG("nonce_size %zu", nonce_size);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check nonce is valid size. */
    if (nonce_size < GCM_NONCE_MIN_SZ || nonce_size > GCM_NONCE_MAX_SZ) {
        WGW_ERROR("Nonce size not supported: %d", nonce_size);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Keep the nonce */
    XMEMCPY(ctx->nonce, nonce, nonce_size);
    ctx->nonce_size = (int)nonce_size;

    WGW_LOG("gmac nonce set successfully");
    return 0;
}

/**
 * Update the GMAC with data.
 *
 * @param [in, out] _ctx      GMAC context.
 * @param [in]      text      Text to update with.
 * @param [in]      textsize  Size of text in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL GMAC update fails.
 */
static int wolfssl_gmac_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_gmac_ctx *ctx = _ctx;
    unsigned char* ptr;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", textsize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Increase size of cached data. */
    ptr = gnutls_realloc(ctx->data, ctx->data_size + textsize);
    if (ptr == NULL) {
        WGW_ERROR("realloc of gmac data failed");
        return GNUTLS_E_HASH_FAILED;
    }

    /* Replace pointer with new resized one. */
    ctx->data = ptr;
    /* Add to cached data. */
    XMEMCPY(ctx->data + ctx->data_size, text, textsize);
    ctx->data_size += textsize;

    WGW_LOG("gmac updated successfully");
    return 0;
}

/**
 * Output the gmac result.
 *
 * Doesn't support more than 32-bit length.
 *
 * @param [in, out] _ctx        GMAC context.
 * @param [out]     digest      Buffer to hold digest.
 * @param [in]      digestsize  Size of buffer to hold digest in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized or
 *          algorithm not supported.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when digestsize is too small for GMAC
 *          output.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL GMAC operation fails.
 */
static int wolfssl_gmac_output(void *_ctx, void *digest, size_t digestsize)
{
    struct wolfssl_gmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("digestsize %zu", digestsize);

    if (!ctx->initialized) {
        WGW_ERROR("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Make sure the output buffer is large enough. */
    if (digestsize < AES_BLOCK_SIZE) {
        WGW_ERROR("digestsize too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* Update all data at once. */
    ret = wc_GmacUpdate(&ctx->gmac_ctx, ctx->nonce, ctx->nonce_size, ctx->data,
        ctx->data_size, digest, digestsize);
    /* Dispose of data. */
    gnutls_free(ctx->data);
    ctx->data = NULL;
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_GmacUpdate", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    WGW_LOG("gmac output successful");
    return 0;
}

/**
 * Clean up GMAC resources.
 *
 * @param [in, out] _ctx  GMAC context.
 */
static void wolfssl_gmac_deinit(void *_ctx)
{
    struct wolfssl_gmac_ctx *ctx = _ctx;

    WGW_LOG("wolfssl_gmac_deinit");

    if (ctx && ctx->initialized) {
        /* Free the wolfSSL GMAC context. */
        gnutls_free(ctx->data);
        wc_AesFree(&ctx->gmac_ctx.aes);
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/**
 * One-shot GMAC function.
 *
 * @param [in]  algorithm  GnuTLS digest algorithm ID.
 * @param [in]  text       Text to update digest with.
 * @param [in]  textsize   Size of text in bytes.
 * @param [out] digest     Buffer to hold digest.
 * @return 0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when digest algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL operation fails.
 */
static int wolfssl_gmac_fast(gnutls_mac_algorithm_t algorithm,
    const void *nonce, size_t nonce_size, const void *key, size_t keysize,
    const void *text, size_t textsize, void *digest)
{
    struct wolfssl_gmac_ctx *ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    /* Initialize GMAC context. */
    ret = wolfssl_gmac_init(algorithm, (void**)&ctx);
    if (ret != 0) {
        return ret;
    }

    /* Set key into GMAC context. */
    ret = wolfssl_gmac_setkey(ctx, key, keysize);
    if (ret != 0) {
        return ret;
    }

    /* Set key into GMAC context. */
    ret = wolfssl_gmac_setnonce(ctx, nonce, nonce_size);
    if (ret != 0) {
        return ret;
    }

    /* Hash the text. */
    ret = wolfssl_gmac_hash(ctx, text, textsize);
    if (ret != 0) {
        wolfssl_gmac_deinit(ctx);
        return ret;
    }

    /* Output the MAC. */
    ret = wolfssl_gmac_output(ctx, digest, WC_SHA512_DIGEST_SIZE);
    if (ret != 0) {
        wolfssl_gmac_deinit(ctx);
        return ret;
    }

    /* Dispose of GMAC context. */
    wolfssl_gmac_deinit(ctx);

    return 0;
}

/** Function pointers for the MAC implementation using wolfSSL. */
static const gnutls_crypto_mac_st wolfssl_gmac_struct = {
    .init = wolfssl_gmac_init,
    .setkey = wolfssl_gmac_setkey,
    .setnonce = wolfssl_gmac_setnonce,
    .hash = wolfssl_gmac_hash,
    .output = wolfssl_gmac_output,
    .deinit = wolfssl_gmac_deinit,
    .fast = wolfssl_gmac_fast
};

/******************************* MAC algorithms *******************************/

/**
 * Register the MAC algorithms with GnuTLS.
 *
 * @return  0 on success.
 */
int wolfssl_mac_register(void)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    /* Register HMAC-MD5 */
    if (wolfssl_mac_supported[GNUTLS_MAC_MD5]) {
        WGW_LOG("registering HMAC-MD5");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_MD5, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering HMAC-MD5 failed");
            return ret;
        }
    }
    /* Register HMAC-SHA1 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA1]) {
        WGW_LOG("registering HMAC-SHA1");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA1, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering HMAC-SHA1 failed");
            return ret;
        }
    }
    /* Register HMAC-SHA224 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA224]) {
        WGW_LOG("registering HMAC-SHA224");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA224, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering HMAC-SHA224 failed");
            return ret;
        }
    }
    /* Register HMAC-SHA256 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA256]) {
        WGW_LOG("registering HMAC-SHA256");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA256, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering HMAC-SHA256 failed");
            return ret;
        }
    }
    /* Register HMAC-SHA384 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA384]) {
        WGW_LOG("registering HMAC-SHA384");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA384, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering HMAC-SHA384 failed");
            return ret;
        }
    }
    /* Register HMAC-SHA512 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA512]) {
        WGW_LOG("registering HMAC-SHA512");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA512, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering HMAC-SHA512 failed");
            return ret;
        }
    }
    /* Register AES-CMAC-128 */
    if (wolfssl_mac_supported[GNUTLS_MAC_AES_CMAC_128]) {
        WGW_LOG("registering AES_CMAC_128");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_AES_CMAC_128, 80, &wolfssl_cmac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES_CMAC_128 failed");
            return ret;
        }
    }
    /* Register AES-CMAC-256 */
    if (wolfssl_mac_supported[GNUTLS_MAC_AES_CMAC_256]) {
        WGW_LOG("registering AES_CMAC_256");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_AES_CMAC_256, 80, &wolfssl_cmac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES_CMAC_256 failed");
            return ret;
        }
    }
    /* Register AES-GMAC-128 */
    if (wolfssl_mac_supported[GNUTLS_MAC_AES_GMAC_128]) {
        WGW_LOG("registering AES_GMAC_128");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_AES_GMAC_128, 80, &wolfssl_gmac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES_GMAC_128 failed");
            return ret;
        }
    }
    /* Register AES-GMAC-192 */
    if (wolfssl_mac_supported[GNUTLS_MAC_AES_GMAC_192]) {
        WGW_LOG("registering AES_GMAC_192");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_AES_GMAC_192, 80, &wolfssl_gmac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES_GMAC_192 failed");
            return ret;
        }
    }
    /* Register AES-GMAC-256 */
    if (wolfssl_mac_supported[GNUTLS_MAC_AES_GMAC_256]) {
        WGW_LOG("registering AES_GMAC_256");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_AES_GMAC_256, 80, &wolfssl_gmac_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES_GMAC_256 failed");
            return ret;
        }
    }

    return ret;
}

#endif
