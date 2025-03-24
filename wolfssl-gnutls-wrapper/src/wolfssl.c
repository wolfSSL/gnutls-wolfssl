/* Integration of wolfssl crypto with GnuTLS */
#include <gnutls/crypto.h>
#include "gnutls_compat.h"

#include "wolfssl.h"
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>

void __attribute__((constructor)) wolfssl_init(void) {
    _gnutls_wolfssl_init();
}

#ifdef ENABLE_WOLFSSL

/********************* Cipher algorithms (AES) *********************/
enum {
    CBC,
    GCM
};

#define GCM_TAG_SIZE 16
#define GCM_KEY_SIZE 32

/* context structure for wolfssl AES */
struct wolfssl_cipher_ctx {
    Aes enc_aes_ctx;
    Aes dec_aes_ctx;
    int initialized;
    int enc;
    int enc_initialized;
    int dec_initialized;
    gnutls_cipher_algorithm_t algorithm;
    int mode;

    /* store the key and IV */
    unsigned char key[GCM_KEY_SIZE];
    size_t key_size;
    unsigned char iv[AES_IV_SIZE];
    size_t iv_size;

    /* for GCM mode */
    unsigned char auth_data[1024];
    size_t auth_data_size;
    unsigned char tag[GCM_TAG_SIZE];
    size_t tag_size;
    int auth_set;
};

/* mapping of gnutls cipher algorithms to wolfssl ciphers */
static const int wolfssl_cipher_supported[] = {
    [GNUTLS_CIPHER_AES_128_CBC] = 1,
    [GNUTLS_CIPHER_AES_192_CBC] = 1,
    [GNUTLS_CIPHER_AES_256_CBC] = 1,
    [GNUTLS_CIPHER_AES_128_GCM] = 1,
    [GNUTLS_CIPHER_AES_192_GCM] = 1,
    [GNUTLS_CIPHER_AES_256_GCM] = 1,
};

/* check if cipher is supported */
static int
is_cipher_supported(int algorithm) {
    if (algorithm >= 0 &&
        algorithm < (int)(sizeof(wolfssl_cipher_supported)/sizeof(wolfssl_cipher_supported[0])) &&
        wolfssl_cipher_supported[algorithm] == 1) {
        return 0; /* supported */
    }

    printf("wolfssl: cipher %d is not supported\n", algorithm);
    return -1; /* not supported */
}

/* returns the algorithm type based on the cipher */
static int
get_mode(gnutls_cipher_algorithm_t algorithm) {
    if (algorithm == GNUTLS_CIPHER_AES_128_CBC ||
            algorithm == GNUTLS_CIPHER_AES_192_CBC ||
            algorithm == GNUTLS_CIPHER_AES_256_CBC) {
        printf("wolfssl: setting AES mode to CBC (value = %d)\n", CBC);
        return CBC;
    } else if (algorithm == GNUTLS_CIPHER_AES_128_GCM ||
            algorithm == GNUTLS_CIPHER_AES_192_GCM ||
            algorithm == GNUTLS_CIPHER_AES_256_GCM) {
        printf("wolfssl: setting AES mode to GCM (value = %d)\n", GCM);
        return GCM;
    }
    return GNUTLS_E_INVALID_REQUEST;
}

/**
 * initialize a cipher context
 */
    static int
wolfssl_cipher_init(gnutls_cipher_algorithm_t algorithm, void **_ctx, int enc)
{
    printf("wolfssl: wolfssl_cipher_init with enc=%d\n", enc);

    struct wolfssl_cipher_ctx *ctx;
    int mode;

    /* check if cipher is supported */
    if (is_cipher_supported((int)algorithm) < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, 2048);
    if (ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize context with default values */
    ctx->initialized = 0;
    ctx->enc = 0;
    ctx->enc_initialized = 0;
    ctx->dec_initialized = 0;
    ctx->key_size = 0;
    ctx->iv_size = 0;
    ctx->auth_data_size = 0;
    ctx->tag_size = 0;
    ctx->auth_set = 0;
    ctx->algorithm = 0;

    if (enc) {
        /* initialize wolfSSL AES contexts */
        if (wc_AesInit(&ctx->enc_aes_ctx, NULL, INVALID_DEVID) != 0) {
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        ctx->enc = enc;
        ctx->enc_initialized = 1;

        mode = get_mode(algorithm);
        if (mode == GCM) {
            ctx->dec_initialized = 1;
        }
    } else {
        if (wc_AesInit(&ctx->dec_aes_ctx, NULL, INVALID_DEVID) != 0) {
            wc_AesFree(&ctx->enc_aes_ctx);
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        ctx->enc = enc;
        ctx->dec_initialized = 1;
    }

    ctx->tag_size = GCM_TAG_SIZE;
    ctx->algorithm = algorithm;
    ctx->initialized = 1;
    *_ctx = ctx;

    printf("wolfssl: cipher context initialized successfully\n");
    return 0;
}

/**
 * set the encryption/decryption key
 */
    static int
wolfssl_cipher_setkey(void *_ctx, const void *key, size_t keysize)
{
    printf("wolfssl: wolfssl_cipher_setkey with keysize %zu\n", keysize);

    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* store key for later use when setting up IV */
    if (keysize > sizeof(ctx->key)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* save key */
    memcpy(ctx->key, key, keysize);
    ctx->key_size = keysize;

    printf("wolfssl: key stored, waiting for IV\n");
    return 0;
}

/**
 * Set the initialization vector (IV)
 */
    static int
wolfssl_cipher_setiv(void *_ctx, const void *iv, size_t iv_size)
{
    printf("wolfssl: wolfssl_cipher_setiv with iv_size %zu\n", iv_size);

    struct wolfssl_cipher_ctx *ctx = _ctx;
    int ret = -1;
    int mode = -1;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    mode = get_mode(ctx->algorithm);

    /* for GCM, we expect a 16-byte IV */
    if (mode == GCM && iv_size != AES_IV_SIZE) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* for CBC, validate IV size */
    if (mode == CBC && iv_size != AES_BLOCK_SIZE) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* save IV */
    memcpy(ctx->iv, iv, iv_size);
    ctx->iv_size = iv_size;

    /* now we have both key and IV, so we can set the keys in wolfSSL */
    if (ctx->key_size > 0) {
        if (mode == CBC) {
            printf("wolfssl: setting key for CBC mode\n");
            printf("wolfssl: setting key and IV for %s\n",
                    ctx->enc ? "encryption" : "decryption");
            if (ctx->enc && ctx->enc_initialized) {
                ret = wc_AesSetKey(&ctx->enc_aes_ctx, ctx->key, ctx->key_size, ctx->iv, AES_ENCRYPTION);
                if (ret != 0) {
                    printf("wolfssl: wc_AesSetKey failed for encryption with code %d\n", ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
                ctx->enc_initialized = 1;
            } else if (!ctx->enc && ctx->dec_initialized) {
                ret = wc_AesSetKey(&ctx->dec_aes_ctx, ctx->key, ctx->key_size, ctx->iv, AES_DECRYPTION);
                if (ret != 0) {
                    printf("wolfssl: wc_AesSetKey failed for decryption with code %d\n", ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
                ctx->dec_initialized = 1;
            }
            ctx->mode = mode;
        } else if (mode == GCM) {
            printf("wolfssl: setting key for GCM mode\n");
            ret = wc_AesGcmSetKey(&ctx->enc_aes_ctx, ctx->key, ctx->key_size);
            if (ret != 0) {
                printf("wolfssl: wc_AesGcmSetKey failed for encryption with code %d\n", ret);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            ctx->mode = mode;
        } else {
            printf("wolfssl: encryption/decryption struct not correctly initialized\n");
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        printf("wolfssl: no key set yet, deferring key setup\n");
        return GNUTLS_E_INVALID_REQUEST;
    }

    printf("wolfssl: setiv completed successfully\n");
    return 0;
}

/**
 * Process Additional Authenticated Data (AAD) for GCM mode
 */
    static int
wolfssl_cipher_auth(void *_ctx, const void *auth_data, size_t auth_size)
{
    printf("wolfssl: wolfssl_cipher_auth with auth_size %zu\n", auth_size);

    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (auth_size > sizeof(ctx->auth_data)) {
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* store AAD for later use in encrypt/decrypt operations */
    memcpy(ctx->auth_data, auth_data, auth_size);
    ctx->auth_data_size = auth_size;
    ctx->auth_set = 1;

    printf("wolfssl: AAD added successfully\n");
    return 0;
}

static
int is_buffer_zero(const void *buffer, size_t size) {
    const unsigned char *bytes = (const unsigned char *)buffer;
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/**
 * Get or store the tag;
 */
    static void
wolfssl_cipher_tag(void *_ctx, void *tag, size_t tag_size)
{
    printf("wolfssl: wolfssl_cipher_tag with tag_size %zu\n", tag_size);

    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (!ctx->initialized) {
        return;
    }

    if (tag_size > ctx->tag_size) {
        tag_size = ctx->tag_size;
    }

    if (is_buffer_zero(tag, tag_size)) {
        memcpy(tag, ctx->tag, tag_size);
        printf("wolfssl: tag stored successfully\n");
    } else {
        memcpy(ctx->tag, tag, tag_size);
        printf("wolfssl: tag provided successfully\n");
    }
}


/**
 * encrypt data
 */
    static int
wolfssl_cipher_encrypt(void *_ctx, const void *src, size_t src_size, void *dst, size_t dst_size)
{
    printf("wolfssl: wolfssl_cipher_encrypt with data size %zu\n", src_size);

    struct wolfssl_cipher_ctx *ctx = _ctx;
    int ret = -1;

    if (!ctx->initialized) {
        printf("wolfssl: encryption failed - context not initialized\n");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* check if encryption context is initialized */
    if (!ctx->enc_initialized) {
        printf("wolfssl: encryption context not initialized\n");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (dst_size < src_size) {
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* always use the encryption context for encryption operations */
    if (ctx->mode == CBC) {
        printf("wolfssl: wc_AesCbcEncrypt\n");

        /* check block alignment for CBC mode */
        if (src_size % AES_BLOCK_SIZE != 0) {
            return GNUTLS_E_INVALID_REQUEST;
        }

        ret = wc_AesCbcEncrypt(&ctx->enc_aes_ctx, dst, src, src_size);
        if (ret != 0) {
            printf("wolfssl: wc_AesCbcEncrypt failed with code %d\n", ret);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        printf("wolfssl: wc_AesGcmEncrypt\n");

        /* for GCM mode, we need to use the GCM encrypt function with AAD */
        ret = wc_AesGcmEncrypt(
                &ctx->enc_aes_ctx,
                dst,
                src,
                src_size,
                ctx->iv,
                sizeof(ctx->iv),
                ctx->tag,
                sizeof(ctx->tag),
                ctx->auth_data,
                sizeof(ctx->auth_data)
                );

        if (ret != 0) {
            printf("wolfssl: wc_AesGcmEncrypt failed with code %d\n", ret);
            return GNUTLS_E_ENCRYPTION_FAILED;
        } else {
        }
    } else {
        printf("wolfssl: AES mode not set\n");
        return GNUTLS_E_INVALID_REQUEST;
    }

    printf("wolfssl: encryption completed successfully\n");
    return 0;
}

/**
 * Decrypt data
 */
    static int
wolfssl_cipher_decrypt(void *_ctx, const void *src, size_t src_size, void *dst, size_t dst_size)
{
    printf("wolfssl: wolfssl_cipher_decrypt with data size %zu\n", src_size);

    struct wolfssl_cipher_ctx *ctx = _ctx;
    int ret = -1;

    if (!ctx->initialized) {
        printf("wolfssl: decryption failed - context not initialized\n");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* check if decryption context is initialized */
    if (!ctx->dec_initialized) {
        printf("wolfssl: decryption context not initialized\n");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (dst_size < src_size) {
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* always use the decryption context for decryption operations */
    if (ctx->mode == CBC) {
        printf("wolfssl: wc_AesCbcDecrypt\n");
        /* check block alignment for CBC mode */
        if (src_size % AES_BLOCK_SIZE != 0) {
            return GNUTLS_E_INVALID_REQUEST;
        }

        ret = wc_AesCbcDecrypt(&ctx->dec_aes_ctx, dst, src, src_size);
        if (ret != 0) {
            printf("wolfssl: wc_AesCbcDecrypt failed with code %d\n", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        printf("wolfssl: wc_AesGcmDecrypt\n");

        ret = wc_AesGcmDecrypt(
                &ctx->enc_aes_ctx,
                dst,
                src,
                src_size,
                ctx->iv,
                sizeof(ctx->iv),
                ctx->tag,
                sizeof(ctx->tag),
                ctx->auth_data,
                sizeof(ctx->auth_data)
                );

        if (ret != 0) {
            printf("wolfssl: wc_AesGcmDecrypt failed with code %d\n", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
    } else {
        return GNUTLS_E_INVALID_REQUEST;
    }
    printf("wolfssl: decryption completed successfully\n");
    return 0;
}

/**
 * clean up cipher resources
 */
    static void
wolfssl_cipher_deinit(void *_ctx)
{
    printf("wolfssl: wolfssl_cipher_deinit\n");

    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (ctx && ctx->initialized) {
        /* free the wolfSSL AES contexts */
        wc_AesFree(&ctx->enc_aes_ctx);
        wc_AesFree(&ctx->dec_aes_ctx);
        ctx->initialized = 0;
        ctx->enc_initialized = 0;
        ctx->dec_initialized = 0;
    }

    gnutls_free(ctx);
}

/* structure containing function pointers for the cipher implementation */
static const gnutls_crypto_cipher_st wolfssl_cipher_struct = {
    .init = wolfssl_cipher_init,
    .setkey = wolfssl_cipher_setkey,
    .setiv = wolfssl_cipher_setiv,
    .encrypt = wolfssl_cipher_encrypt,
    .decrypt = wolfssl_cipher_decrypt,
    .auth = wolfssl_cipher_auth,
    .tag = wolfssl_cipher_tag,
    .deinit = wolfssl_cipher_deinit,
};

/* register the cipher algorithm with GnuTLS */
static int wolfssl_cipher_register(void)
{
    int ret = 0;

    printf("wolfssl: wolfssl_cipher_register\n");

    /* Register AES-128-CBC */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_CBC]) {
        printf("wolfssl: registering AES-128-CBC\n");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_128_CBC, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register AES-192-CBC */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_192_CBC]) {
        printf("wolfssl: registering AES-192-CBC\n");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_192_CBC, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register AES-256-CBC */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_CBC]) {
        printf("wolfssl: registering AES-256-CBC\n");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_CBC, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register AES-128-GCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_GCM]) {
        printf("wolfssl: registering AES-128-GCM\n");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_128_GCM, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register AES-192-GCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_192_GCM]) {
        printf("wolfssl: registering AES-192-GCM\n");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_192_GCM, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register AES-256-GCM*/
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_GCM]) {
        printf("wolfssl: registering AES-256-GCM\n");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_GCM, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    return ret;
}

/*************************** MAC algorithms (HMAC) ***************************/

/* context structure for wolfssl HMAC */
struct wolfssl_hmac_ctx {
    Hmac hmac_ctx;
    int initialized;
    gnutls_mac_algorithm_t algorithm;
};

/* mapping of gnutls mac algorithms to wolfssl macs */
static const int wolfssl_mac_supported[] = {
    [GNUTLS_MAC_MD5] = 1,
    [GNUTLS_MAC_SHA1] = 1,
    [GNUTLS_MAC_SHA256] = 1,
    [GNUTLS_MAC_SHA384] = 1,
    [GNUTLS_MAC_SHA512] = 1,
};

/* convert gnutls mac algorithm to wolfssl hash type */
static int
get_hash_type(gnutls_mac_algorithm_t algorithm) {
    switch (algorithm) {
        case GNUTLS_MAC_MD5:
            printf("wolfssl: using MD5 for HMAC\n");
            return WC_MD5;
        case GNUTLS_MAC_SHA1:
            printf("wolfssl: using SHA1 for HMAC\n");
            return WC_SHA;
        case GNUTLS_MAC_SHA256:
            printf("wolfssl: using SHA256 for HMAC\n");
            return WC_SHA256;
        case GNUTLS_MAC_SHA384:
            printf("wolfssl: using SHA384 for HMAC\n");
            return WC_SHA384;
        case GNUTLS_MAC_SHA512:
            printf("wolfssl: using SHA512 for HMAC\n");
            return WC_SHA512;
        default:
            return -1;
    }
}

/* check if mac is supported */
static int
is_mac_supported(gnutls_mac_algorithm_t algorithm) {
    if (algorithm >= 0 && algorithm < sizeof(wolfssl_mac_supported) &&
            wolfssl_mac_supported[algorithm]) {
        return 0;
    }
    printf("wolfssl: mac algorithm %d is not supported\n", algorithm);
    return -1;
}


/* initialize an hmac context*/

    static int
wolfssl_mac_init(gnutls_mac_algorithm_t algorithm, void **_ctx)
{
    printf("wolfssl: wolfssl_mac_init for algorithm %d\n", algorithm);

    struct wolfssl_hmac_ctx *ctx;
    int ret = 0;

    /* check if mac is supported */
    if (is_mac_supported(algorithm) < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hmac_ctx));
    if (ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize wolfSSL HMAC context */
    ret = wc_HmacInit(&ctx->hmac_ctx, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("wolfssl: wc_HmacInit has failed with code %d\n", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->initialized = 1;
    ctx->algorithm = algorithm;
    *_ctx = ctx;

    printf("wolfssl: hmac context initialized successfully\n");
    return 0;
}

/**
 * set the hmac key
 */
    static int
wolfssl_mac_setkey(void *_ctx, const void *key, size_t keysize)
{
    printf("wolfssl: wolfssl_mac_setkey with keysize %zu\n", keysize);

    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;
    int hash_type;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* get wolfssl hash type */
    hash_type = get_hash_type(ctx->algorithm);
    if (hash_type < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* set the key */
    ret = wc_HmacSetKey(&ctx->hmac_ctx, hash_type, (const byte*)key, (word32)keysize);
    if (ret != 0) {
        printf("wolfssl: wc_HmacSetKey failed with code %d\n", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    printf("wolfssl: hmac key set successfully\n");
    return 0;
}


/* update the hmac with data */

    static int
wolfssl_mac_hash(void *_ctx, const void *text, size_t textsize)
{
    printf("wolfssl: wolfssl_mac_hash with data size %zu\n", textsize);

    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* update the hmac */
    ret = wc_HmacUpdate(&ctx->hmac_ctx, (const byte*)text, (word32)textsize);
    if (ret != 0) {
        printf("wolfssl: wc_HmacUpdate failed with code %d\n", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    printf("wolfssl: hmac updated successfully\n");
    return 0;
}


/* output the hmac result */

    static int
wolfssl_mac_output(void *_ctx, void *digest, size_t digestsize)
{
    printf("wolfssl: wolfssl_mac_output with digestsize %zu\n", digestsize);

    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;
    int digest_size;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* get the digest size based on the hash algorithm */
    digest_size = wc_HmacSizeByType(get_hash_type(ctx->algorithm));
    if (digest_size <= 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* make sure the output buffer is large enough */
    if (digestsize < (size_t)digest_size) {
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* finalize the hmac and get the result */
    ret = wc_HmacFinal(&ctx->hmac_ctx, (byte*)digest);
    if (ret != 0) {
        printf("wolfssl: wc_HmacFinal failed with code %d\n", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    printf("wolfssl: hmac output successful\n");
    return 0;
}


/* clean up hmac resources */

    static void
wolfssl_mac_deinit(void *_ctx)
{
    printf("wolfssl: wolfssl_mac_deinit\n");

    struct wolfssl_hmac_ctx *ctx = _ctx;

    if (ctx && ctx->initialized) {
        /* free the wolfSSL HMAC context */
        wc_HmacFree(&ctx->hmac_ctx);
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/* structure containing function pointers for the mac implementation */
static const gnutls_crypto_mac_st wolfssl_mac_struct = {
    .init = wolfssl_mac_init,
    .setkey = wolfssl_mac_setkey,
    .hash = wolfssl_mac_hash,
    .output = wolfssl_mac_output,
    .deinit = wolfssl_mac_deinit,
};


/* register the mac algorithm with GnuTLS */

static int wolfssl_mac_register(void)
{
    int ret = 0;

    printf("wolfssl: wolfssl_mac_register\n");

    /* Register HMAC-MD5 */
    if (wolfssl_mac_supported[GNUTLS_MAC_MD5]) {
        printf("wolfssl: registering HMAC-MD5\n");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_MD5, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register HMAC-SHA1 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA1]) {
        printf("wolfssl: registering HMAC-SHA1\n");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA1, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register HMAC-SHA256 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA256]) {
        printf("wolfssl: registering HMAC-SHA256\n");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA256, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register HMAC-SHA384 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA384]) {
        printf("wolfssl: registering HMAC-SHA384\n");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA384, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    /* Register HMAC-SHA512 */
    if (wolfssl_mac_supported[GNUTLS_MAC_SHA512]) {
        printf("wolfssl: registering HMAC-SHA512\n");
        ret = gnutls_crypto_single_mac_register(
                GNUTLS_MAC_SHA512, 80, &wolfssl_mac_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    return ret;
}

/************************ Digest algorithms *****************************/

/* context structure for wolfssl SHA256 */
struct wolfssl_hash_ctx {
    wc_Sha256 sha256_ctx;
    int initialized;
};

/* mapping of gnutls digest algorithms to wolfssl digests */
static const int wolfssl_digest_supported[] = {
    [GNUTLS_DIG_SHA256] = 1,
};

/**
 * initialize a digest context
 */
static int wolfssl_digest_init(gnutls_digest_algorithm_t algorithm, void **_ctx)
{
    printf("wolfssl: wolfssl_digest_init\n");

    struct wolfssl_hash_ctx *ctx;
    int ret;

    /* return error if it's not sha256 */
    if (algorithm != GNUTLS_DIG_SHA256 || !wolfssl_digest_supported[algorithm]) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate gnutls context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hash_ctx));
    if (ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize the wolfssl sha256 context */
    ret = wc_InitSha256(&ctx->sha256_ctx);
    if (ret != 0) {
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->initialized = 1;
    *_ctx = ctx;

    return 0;
}

/**
 * update the digest with data
 */
static int wolfssl_digest_hash(void *_ctx, const void *text, size_t textsize)
{
    printf("wolfssl: wolfssl_digest_hash\n");

    struct wolfssl_hash_ctx *ctx = _ctx;
    int ret;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* update the wolfssl sha256 context with data */
    ret = wc_Sha256Update(&ctx->sha256_ctx, (const byte*)text, (word32)textsize);
    if (ret != 0) {
        printf("wolfssl: wc_Sh256Update with ret code: %d\n", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    return 0;
}

/**
 * output the digest result
 */
static int wolfssl_digest_output(void *_ctx, void *digest, size_t digestsize)
{
    printf("wolfssl: wolfssl_digest_output\n");

    struct wolfssl_hash_ctx *ctx = _ctx;
    int ret;

    if (!ctx->initialized) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* make sure the output buffer is large enough */
    if (digestsize < WC_SHA256_DIGEST_SIZE) {
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* finalize the digest and get the result */
    ret = wc_Sha256Final(&ctx->sha256_ctx, (byte*)digest);
    if (ret != 0) {
        return GNUTLS_E_HASH_FAILED;
    }

    return 0;
}

/*
 * one-shot hash function.
 * */
static int wolfssl_digest_fast(gnutls_digest_algorithm_t algorithm,
                             const void *text, size_t textsize,
                             void *digest)
{
    printf("wolfssl: wolfssl_digest_fast\n");
    struct wolfssl_hash_ctx *ctx;
    int ret;

    /* return error if it's not sha256 */
    if (algorithm != GNUTLS_DIG_SHA256 || !wolfssl_digest_supported[algorithm]) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate gnutls context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hash_ctx));
    if (ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize the wolfssl sha256 context */
    ret = wc_InitSha256(&ctx->sha256_ctx);
    if (ret != 0) {
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->initialized = 1;

    /* update the wolfssl sha256 context with data */
    ret = wc_Sha256Update(&ctx->sha256_ctx, (const byte*)text, (word32)textsize);
    if (ret != 0) {
        return GNUTLS_E_HASH_FAILED;
    }

    /* finalize the digest and get the result */
    ret = wc_Sha256Final(&ctx->sha256_ctx, (byte*)digest);
    if (ret != 0) {
        return GNUTLS_E_HASH_FAILED;
    }

    return 0;
}


/**
 * clean up digest resources
 */
static void wolfssl_digest_deinit(void *_ctx)
{
    printf("wolfssl: wolfssl_digest_deinit\n");
    struct wolfssl_hash_ctx *ctx = _ctx;

    if (ctx && ctx->initialized) {
        /* free the wolfssl sha256 context */
        wc_Sha256Free(&ctx->sha256_ctx);
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/* structure containing function pointers for the digest implementation */
static const gnutls_crypto_digest_st wolfssl_digest_struct = {
    .init = wolfssl_digest_init,
    .hash = wolfssl_digest_hash,
    .output = wolfssl_digest_output,
    .deinit = wolfssl_digest_deinit,
    .fast = wolfssl_digest_fast
};

/**
 * register the digest algorithm with GnuTLS
 */
static int wolfssl_digest_register(void)
{
    int ret = 0;

    printf("wolfssl: wolfssl_digest_register\n");

    /* register sha256 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA256]) {
        printf("wolfssl: registering sha256\n");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA256, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

    return ret;
}

/**
 * module initialization
 */
int _gnutls_wolfssl_init(void)
{
    int ret;

    printf("wolfssl: _gnutls_wolfssl_init\n");

    /* register digest algorithms */
    ret = wolfssl_digest_register();
    if (ret < 0) {
        return ret;
    }

    /* register mac algorithms */
    ret = wolfssl_mac_register();
    if (ret < 0) {
        return ret;
    }

    /* register cipher algorithms */
    ret = wolfssl_cipher_register();
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/**
 * module deinitialization
 */
void _gnutls_wolfssl_deinit(void)
{
    printf("wolfssl: _gnutls_wolfssl_deinit\n");
    return;
}

#else /* ENABLE_WOLFSSL */

int _gnutls_wolfssl_init(void)
{
    printf("wolfssl: empty _gnutls_wolfssl_init called, no algo registered\n");
    return 0;
}

void _gnutls_wolfssl_deinit(void)
{
    printf("wolfssl: empty _gnutls_wolfssl_deinit called, no algo registered\n");
    return;
}

#endif /* ENABLE_WOLFSSL */
