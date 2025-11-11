#include <wolfssl/options.h>
#include "gnutls_compat.h"
#include "logging.h"
#include "mac.h"
#include <wolfssl/wolfcrypt/aes.h>

#ifdef WOLFSSL_AES_COUNTER
#include <wolfssl/wolfcrypt/cmac.h>
#endif

#ifdef ENABLE_WOLFSSL
/** List of supported AES cipher modes. */
enum {
    NONE,
    CBC,
    GCM,
    CCM,
    CFB8,
    XTS,
    SIV
};

#if defined(HAVE_FIPS)
/* List of operation for signing schemes */
enum {
    SIGN_OP,
    VERIFY_OP
};
#endif

/** Size of GCM tag. */
#define GCM_TAG_SIZE        WC_AES_BLOCK_SIZE
/** Size of CCM tag. */
#define CCM_TAG_SIZE        WC_AES_BLOCK_SIZE
/** Size of CCM-8 tag. */
#define CCM_8_TAG_SIZE      8
/** Maximum AES key size. */
#define MAX_AES_KEY_SIZE    AES_256_KEY_SIZE
/** Maximum authentication data. */
#define MAX_AUTH_DATA       4096
/** Maximum plaintext to encrypt for GCM  */
#define MAX_AES_GCM_PLAINTEXT ((1ULL << 36) - 32)
/** Maximum RSA-PSS signature size */
#define RSA_PSS_SIG_SIZE 512

/** Encrypted data locations. */
struct cache_dec_loc {
    /** Pointer to copy encrypted data to. */
    unsigned char* data;
    /** Amount of encrypted data to copy. */
    size_t size;
};

/** Context structure for wolfSSL AES. */
struct wolfssl_cipher_ctx {
    union {
        struct {
            /** AES encryption context. */
            Aes aes_enc;
            /** AES decryption context. */
            Aes aes_dec;
        } pair;
        /** AES context. */
        Aes aes_ctx;
    #ifdef WOLFSSL_AES_XTS
        /** wolfSSL context for AES-XTS */
        XtsAes aes_xts;
    #endif
    } cipher;

#ifdef WOLFSSL_AES_COUNTER
    byte *siv_synth;
    byte *original_key;
    word32 original_key_sz;
#endif

    /** Indicates that this context as been initialized. */
    unsigned int initialized:1;
    /** Indicates that we have been initialized for encryption. */
    unsigned int enc_initialized:1;
    /** Indicates that we have been initialized for decryption. */
    unsigned int dec_initialized:1;
    /** Indicates whether we are doing encryption or decryption.  */
    unsigned int enc:1;

    /** The GnuTLS cipher algorithm ID. */
    gnutls_cipher_algorithm_t algorithm;
    /** Mode of AES to use. */
    int mode;

    /** IV/nonce to use.  */
    unsigned char iv[AES_IV_SIZE];
    /** Size of IV/nonce to use.  */
    size_t iv_size;

    /* For GCM mode. */
    /** Authentication data to use (static, maximum 4096 bytes). */
    unsigned char auth_data_static[MAX_AUTH_DATA];
    /** Authentication data to use (allocated dynamically). */
    unsigned char *auth_data_heap;
    /** Size of authentication data to use (static). */
    size_t auth_data_size;
    /** Size of authentication data to use (heap). */
    size_t auth_alloc;
    /** Calculated authentication tag. */
    unsigned char tag[GCM_TAG_SIZE];
    /** Size of calculated authentication tag. */
    size_t tag_size;
    /** Data to encrypt/decrypt. */
    unsigned char* data;
    /** Data size. */
    size_t data_size;
    /** Tag has been set. */
    unsigned int tag_set:1;
    /** Tag has been set from external source. */
    unsigned int tag_set_ext:1;
};

/** Array of supported ciphers. */
const int wolfssl_cipher_supported[] = {
    [GNUTLS_CIPHER_AES_128_CBC] = 1,
    [GNUTLS_CIPHER_AES_192_CBC] = 1,
    [GNUTLS_CIPHER_AES_256_CBC] = 1,
    [GNUTLS_CIPHER_AES_128_GCM] = 1,
    [GNUTLS_CIPHER_AES_192_GCM] = 1,
    [GNUTLS_CIPHER_AES_256_GCM] = 1,
    [GNUTLS_CIPHER_AES_128_CCM] = 1,
    [GNUTLS_CIPHER_AES_256_CCM] = 1,
    [GNUTLS_CIPHER_AES_128_CCM_8] = 1,
    [GNUTLS_CIPHER_AES_256_CCM_8] = 1,
#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
    [GNUTLS_CIPHER_AES_128_CFB8] = 1,
    [GNUTLS_CIPHER_AES_192_CFB8] = 1,
    [GNUTLS_CIPHER_AES_256_CFB8] = 1,
#endif
#ifdef WOLFSSL_AES_XTS
    [GNUTLS_CIPHER_AES_128_XTS] = 1,
    [GNUTLS_CIPHER_AES_256_XTS] = 1,
#endif

/* AES-SIV is implemented with a composition of CMAC and AES-CTR. */
#ifdef WOLFSSL_AES_COUNTER
    [GNUTLS_CIPHER_AES_128_SIV] = 1,
    [GNUTLS_CIPHER_AES_256_SIV] = 1,
#endif
};
/** Length of array of supported ciphers. */
#define WOLFSSL_CIPHER_SUPPORTED_LEN (int)(sizeof(wolfssl_cipher_supported) / \
                                           sizeof(wolfssl_cipher_supported[0]))

/**
 * Check if cipher is supported.
 *
 * @param [in] algorithm   GnuTLS cipher algorithm ID.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
int is_cipher_supported(int algorithm)
{
    return (algorithm >= 0 && algorithm < WOLFSSL_CIPHER_SUPPORTED_LEN &&
            wolfssl_cipher_supported[algorithm] == 1);
}

/**
 * Get the cipher mode from GnuTLS cipher algorithm ID.
 *
 * @param [in] algorithm   GnuTLS cipher algorithm ID.
 * @return  CBC for AES-CBC algorithms.
 * @return  GCM for AES-GCM algorithms.
 * @return  GNUTLS_E_INVALID_REQUEST when algorithm not supported.
 */
int get_cipher_mode(gnutls_cipher_algorithm_t algorithm)
{
    if (algorithm == GNUTLS_CIPHER_AES_128_CBC ||
            algorithm == GNUTLS_CIPHER_AES_192_CBC ||
            algorithm == GNUTLS_CIPHER_AES_256_CBC) {
        WGW_LOG("setting AES mode to CBC (value = %d)", CBC);
        return CBC;
    } else if (algorithm == GNUTLS_CIPHER_AES_128_GCM ||
            algorithm == GNUTLS_CIPHER_AES_192_GCM ||
            algorithm == GNUTLS_CIPHER_AES_256_GCM) {
        WGW_LOG("setting AES mode to GCM (value = %d)", GCM);
        return GCM;
    } else if (algorithm == GNUTLS_CIPHER_AES_128_CCM ||
            algorithm == GNUTLS_CIPHER_AES_256_CCM) {
        WGW_LOG("setting AES mode to CCM (value = %d)", CCM);
        return CCM;
    } else if (algorithm == GNUTLS_CIPHER_AES_128_CCM_8 ||
            algorithm == GNUTLS_CIPHER_AES_256_CCM_8) {
        WGW_LOG("setting AES mode to CCM (value = %d)", CCM);
        return CCM;
#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
    } else if (algorithm == GNUTLS_CIPHER_AES_128_CFB8 ||
            algorithm == GNUTLS_CIPHER_AES_192_CFB8 ||
            algorithm == GNUTLS_CIPHER_AES_256_CFB8) {
        WGW_LOG("setting AES mode to CFB8 (value = %d)", CFB8);
        return CFB8;
#endif
#ifdef WOLFSSL_AES_XTS
    } else if (algorithm == GNUTLS_CIPHER_AES_128_XTS ||
            algorithm == GNUTLS_CIPHER_AES_256_XTS) {
        WGW_LOG("setting AES mode to XTS (value = %d)", XTS);
        return XTS;
#endif
#ifdef WOLFSSL_AES_COUNTER
    } else if (algorithm == GNUTLS_CIPHER_AES_128_SIV ||
            algorithm == GNUTLS_CIPHER_AES_256_SIV) {
        WGW_LOG("setting AES mode to SIV (value = %d)", SIV);
        return SIV;
#endif
    }

    WGW_LOG("Cipher not supported: %d", algorithm);

    return NONE;
}

/**
 * Initialize a cipher context.
 *
 * @param [in]  algorithm  GnuTLS cipher algorithm ID.
 * @param [out] _ctx       Cipher context.
 * @param [in]  enc        Whether cipher is to be used for encryption or
 *                         decryption.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when wolfSSL cipher initialization fails.
 */
int wolfssl_cipher_init(gnutls_cipher_algorithm_t algorithm, void **_ctx,
    int enc)
{
    struct wolfssl_cipher_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("enc=%d", enc);

    /* check if cipher is supported */
    if (!is_cipher_supported((int)algorithm)) {
        WGW_ERROR("cipher %d is not supported", algorithm);
#if defined(HAVE_FIPS)
        WGW_LOG("returning GNUTLS_E_UNWANTED_ALGORITHM");
        return GNUTLS_E_UNWANTED_ALGORITHM;
#else
        return GNUTLS_E_INVALID_REQUEST;
#endif
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_cipher_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ctx->auth_data_heap = NULL;
    ctx->algorithm = algorithm;
    ctx->mode = get_cipher_mode(algorithm);

#ifdef WOLFSSL_AES_XTS
    if (ctx->mode == XTS) {
        ret = wc_AesXtsInit(&ctx->cipher.aes_xts, NULL, INVALID_DEVID);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesXtsInit", ret);
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        ctx->enc = enc;
        ctx->enc_initialized = 1;
        ctx->dec_initialized = 1;
    } else
#endif
    if (ctx->mode == GCM || ctx->mode == CCM || ctx->mode == SIV) {
        /* initialize wolfSSL AES contexts */
        ret = wc_AesInit(&ctx->cipher.aes_ctx, NULL, INVALID_DEVID);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesInit", ret);
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
        ctx->enc = enc;
        ctx->enc_initialized = 1;
        ctx->dec_initialized = 1;

        if (ctx->mode == SIV) {
            ctx->siv_synth = gnutls_malloc(WC_AES_BLOCK_SIZE);
            if (!ctx->siv_synth) {
                gnutls_free(ctx);
                return GNUTLS_E_MEMORY_ERROR;
            }
        }
        WGW_LOG("AES context initialized successfully");
    } else if (enc) {
        /* initialize wolfSSL AES contexts */
        ret = wc_AesInit(&ctx->cipher.pair.aes_enc, NULL, INVALID_DEVID);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesInit", ret);
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        ctx->enc = enc;
        ctx->enc_initialized = 1;
    } else {
        ret = wc_AesInit(&ctx->cipher.pair.aes_dec, NULL, INVALID_DEVID);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesInit", ret);
            wc_AesFree(&ctx->cipher.pair.aes_enc);
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        ctx->enc = enc;
        ctx->dec_initialized = 1;

        WGW_LOG("decryption context initialized successfully");
    }

    /* Set tag size for AEAD ciphers. */
    if (ctx->mode == GCM) {
        WGW_LOG("cipher-init: GCM – tag size set to 16 bytes");
        ctx->tag_size = GCM_TAG_SIZE;

    } else if (ctx->mode == CCM) {
        WGW_LOG("cipher-init: CCM – tag size set to 16 bytes");
        ctx->tag_size = CCM_TAG_SIZE;

    } else if (algorithm == GNUTLS_CIPHER_AES_128_CCM_8 ||
            algorithm == GNUTLS_CIPHER_AES_256_CCM_8) {
        WGW_LOG("cipher-init: CCM-8 – tag size set to 8 bytes");
        ctx->tag_size = CCM_8_TAG_SIZE;
    } else if (algorithm == GNUTLS_CIPHER_AES_128_SIV ||
            algorithm == GNUTLS_CIPHER_AES_256_SIV) {
        WGW_LOG("cipher-init: SIV – tag size set to 16 bytes");
        ctx->tag_size = WC_AES_BLOCK_SIZE;
    } else {
        WGW_LOG("cipher-init: non-AEAD – tag size set to 0");
        ctx->tag_size = 0;
    }

    ctx->initialized = 1;
    *_ctx = ctx;

    WGW_LOG("cipher context initialized successfully");
    return 0;
}

/**
 * Get the key size for the cipher algorithm.
 *
 * @param [in] algorithm   GnuTLS cipher algorithm ID.
 * @return  Key size in bytes on success.
 * @return  0 when algorithm not supported.
 */
int get_cipher_key_size(gnutls_cipher_algorithm_t algorithm)
{
    WGW_FUNC_ENTER();
    switch (algorithm) {
        case GNUTLS_CIPHER_AES_128_CBC:
        case GNUTLS_CIPHER_AES_128_GCM:
        case GNUTLS_CIPHER_AES_128_CCM:
        case GNUTLS_CIPHER_AES_128_CCM_8:
    #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
        case GNUTLS_CIPHER_AES_128_CFB8:
    #endif
            return AES_128_KEY_SIZE;
        case GNUTLS_CIPHER_AES_192_CBC:
        case GNUTLS_CIPHER_AES_192_GCM:
    #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
        case GNUTLS_CIPHER_AES_192_CFB8:
    #endif
            return AES_192_KEY_SIZE;
        case GNUTLS_CIPHER_AES_256_CBC:
        case GNUTLS_CIPHER_AES_256_GCM:
        case GNUTLS_CIPHER_AES_256_CCM:
        case GNUTLS_CIPHER_AES_256_CCM_8:
    #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
        case GNUTLS_CIPHER_AES_256_CFB8:
    #endif
            return AES_256_KEY_SIZE;
    #ifdef WOLFSSL_AES_XTS
        case GNUTLS_CIPHER_AES_128_XTS:
            return 2 * AES_128_KEY_SIZE;
        case GNUTLS_CIPHER_AES_256_XTS:
            return 2 * AES_256_KEY_SIZE;
    #endif
    #ifdef WOLFSSL_AES_COUNTER
       case GNUTLS_CIPHER_AES_128_SIV:
            return AES_128_KEY_SIZE * 2;
       case GNUTLS_CIPHER_AES_256_SIV:
            return AES_256_KEY_SIZE * 2;
    #endif
        default:
            return 0;
    }
}

/**
 * Set the encryption or decryption key.
 *
 * Key is cached and set when the IV is set.
 *
 * @param [in, out] ctx      Cipher context.
 * @param [in]      key      Key data. Assumed not NULL.
 * @param [in]      keysize  Size of key in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context hasn't been initialized or
 *          key size is invalid.
 */
int wolfssl_cipher_setkey(void *_ctx, const void *key, size_t keysize)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;
    size_t exp_key_size;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("keysize %zu", keysize);

    if (!ctx->initialized) {
        WGW_ERROR("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Get expected key size for cipoher algorithm. */
    exp_key_size = get_cipher_key_size(ctx->algorithm);
    /* Check if key size was found. */
    if (exp_key_size == 0) {
        WGW_ERROR("Key size not supported for algorithm: %d", ctx->algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }
    /* Check key size is the expected length. */
    if (keysize != exp_key_size) {
        WGW_ERROR("Key size is not the expected length: %d != %d (%d)", keysize,
            exp_key_size, ctx->algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

#ifdef WOLFSSL_AES_XTS
    if (ctx->mode == XTS && gnutls_fips140_mode_enabled()) {
        /* XTS has two AES keys that are no allowed to be the same. */
        if (XMEMCMP(key, key + exp_key_size / 2, exp_key_size / 2) == 0) {
            WGW_ERROR("XTS keys are the same");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
#endif

    switch (ctx->mode) {
        case CBC:
    #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
        case CFB8:
    #endif
            if (ctx->enc && ctx->enc_initialized) {
                /* Set the key for AES encrypt. */
                ret = wc_AesSetKey(&ctx->cipher.pair.aes_enc, key, keysize,
                    NULL, AES_ENCRYPTION);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_AesSetKey(ENC)", ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
                ctx->enc_initialized = 1;
            } else if (!ctx->enc && ctx->dec_initialized) {
                int enc_mode = AES_DECRYPTION;
            #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
                if (ctx->mode == CFB8) {
                    enc_mode = AES_ENCRYPTION;
                }
            #endif
                /* Set the key for AES decrypt. */
                ret = wc_AesSetKey(&ctx->cipher.pair.aes_dec, key, keysize,
                    NULL, enc_mode);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_AesSetKey(DEC)", ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
                ctx->dec_initialized = 1;
            }
            break;
        case GCM:
            WGW_LOG("wc_AesGcmSetKey");
            /* Set the key now for AEAD calls. */
            ret = wc_AesGcmSetKey(&ctx->cipher.aes_ctx, key, keysize);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesGcmSetKey", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
            break;
        case CCM:
            WGW_LOG("wc_AesCcmSetKey");
            /* Set the key now for AEAD calls. */
            ret = wc_AesCcmSetKey(&ctx->cipher.aes_ctx, key, keysize);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesCcmSetKey", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
            break;

#if defined(WOLFSSL_AES_XTS)
        case XTS:
            WGW_LOG("setting key for XTS mode");
            ret = wc_AesXtsSetKeyNoInit(&ctx->cipher.aes_xts, key, keysize,
                ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesXtsSetKeyNoInit", ret);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            break;
#endif
#if defined(WOLFSSL_AES_COUNTER)
        case SIV:
            WGW_LOG("wc_AesSIVSetKey");
            if (keysize != 32 && keysize != 48 && keysize != 64) {
                WGW_LOG("Bad key size. Must be 256, 384, or 512 bits.");
                return GNUTLS_E_INVALID_REQUEST;
            }

            /* The key splitting and setting for S2V and
             * CTR will happen later on during
             * the encryption/decryption operations.
             * So we only save the key for now. */
            ctx->original_key = gnutls_malloc(keysize);
            if (!ctx->original_key) {
                return GNUTLS_E_MEMORY_ERROR;
            }
            XMEMCPY(ctx->original_key, key, keysize);
            ctx->original_key_sz = keysize;
            break;
#endif
        default:
            WGW_ERROR("AES mode not supported: %d", ctx->mode);
            return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("key stored");
    return 0;
}

/**
 * Get the IV range for the cipher mode.
 *
 * @param [in]  mode  Cipher mode.
 * @param [out] min   Minimum IV size.
 * @param [out] max   Maximum IV size.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when mode not supported.
 */
int get_iv_range(int mode, size_t* min, size_t* max)
{
    switch (mode) {
        case CBC:
    #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
        case CFB8:
    #endif
    #ifdef WOLFSSL_AES_XTS
        case XTS:
    #endif
            *min = AES_IV_SIZE;
            *max = AES_IV_SIZE;
            return 0;
        case GCM:
            *min = GCM_NONCE_MIN_SZ;
            *max = GCM_NONCE_MAX_SZ;
            return 0;
        case CCM:
            *min = CCM_NONCE_MIN_SZ;
            *max = CCM_NONCE_MAX_SZ;
            return 0;
#if defined(WOLFSSL_AES_COUNTER)
        case SIV:
            *min = AES_BLOCK_SIZE;
            *max = AES_BLOCK_SIZE;
            return 0;
#endif
        default:
            return GNUTLS_E_INVALID_REQUEST;
    }
}

/**
 * Set the Initialization Vector (IV) into the cipher context.
 *
 * @param [in, out] ctx      Cipher context.
 * @param [in]      iv       IV data. Assumed not NULL.
 * @param [in]      iv_size  Size of IV in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context hasn't been initialized,
 *          IV size is invalid or mode not supported.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when setting key/IV against wolfSSL
 *          cipher fails.
 */
int wolfssl_cipher_setiv(void *_ctx, const void *iv, size_t iv_size)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;
    int ret = -1;
    size_t min_size;
    size_t max_size;

    WGW_FUNC_ENTER();
    WGW_LOG("iv_size %zu", iv_size);

    if (!ctx->initialized) {
        WGW_LOG("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (ctx->mode == SIV) {
        /* if we are in SIV mode, the IV is derived later on during
         * encryption/decryption operation sytnhetically using AES-CMAC. */
        WGW_LOG("SIV mode is used, skipping setting of IV");
        return 0;
    }

    /* Get valid size range for IV for mode. */
    if (get_iv_range(ctx->mode, &min_size, &max_size) != 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check IV size range. */
    if (iv_size < min_size || iv_size > max_size) {
        WGW_ERROR("IV out of range: %d <= %d <= %d (%d)", min_size, iv_size,
            max_size, ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Save IV for use later. */
    XMEMCPY(ctx->iv, iv, iv_size);
    ctx->iv_size = iv_size;

    switch (ctx->mode) {
        case CBC:
    #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
        case CFB8:
    #endif
            WGW_LOG("setting key for CBC/CFB8 mode");
            WGW_LOG("setting key and IV for %s",
                    ctx->enc ? "encryption" : "decryption");
            if (ctx->enc && ctx->enc_initialized) {
                    ret = wc_AesSetIV(&ctx->cipher.pair.aes_enc, ctx->iv);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_AesSetIV(ENC)", ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
            } else if (!ctx->enc && ctx->dec_initialized) {
                ret = wc_AesSetIV(&ctx->cipher.pair.aes_dec, ctx->iv);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_AesSetIV(DEC)", ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
            }
            break;
        case GCM:
            /* IV stored and used in encrypt/decrypt/tag. */
            /* No tag set, auth data or plaintext now we have a new IV. */
            ctx->tag_set = 0;
            ctx->tag_set_ext = 0;
            ctx->auth_data_size = 0;
            ctx->data_size = 0;
            break;
    #ifdef WOLFSSL_AES_XTS
        case XTS:
            /* IV stored and used in encrypt/decrypt. */
            break;
    #endif
    #ifdef WOLFSSL_AES_COUNTER
        case SIV:
            /* IV computed synthetically during the encryption/decryption process. */
            break;
    #endif
        default:
            WGW_ERROR("encryption/decryption struct not correctly initialized");
            return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("setiv completed successfully");
    return 0;
}

#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
/**
 * Get the IV after encryption or decryptiom.
 *
 * @param [in, out] ctx      Cipher context.
 * @param [out]     iv       IV data. Assumed not NULL.
 * @param [in]      iv_size  Size of IV buffer in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when when context hasn't been initialized,
 *          mode is not CFB8.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when IV buffer too small.
 */
int wolfssl_cipher_getiv(void *_ctx, void *iv, size_t iv_size)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (!ctx->initialized) {
        WGW_ERROR("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Only CFB8 supported. */
    if (ctx->mode != CFB8) {
        WGW_ERROR("Mode not supported: ", ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check buffer is big enough. */
    if (iv_size < ctx->iv_size) {
        WGW_ERROR("IV buffer too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* Get current IV. */
    XMEMCPY(iv, ctx->cipher.pair.aes_enc.reg, ctx->iv_size);

    return (int)ctx->iv_size;
}
#endif

/**
 * Process Additional Authenticated Data (AAD) for GCM mode
 *
 * @param [in, out] _ctx        Cipher context.
 * @param [in]       auth_data  Authentication data.
 * @param [in]       auth_size  Size of authentication data in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when too much data to store.
 */
int wolfssl_cipher_auth(void *_ctx, const void *auth_data,
    size_t auth_size)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();
    WGW_LOG("auth_size %zu", auth_size);

    if (!ctx->initialized) {
        WGW_ERROR("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check authentication data will fit in the static cache,
     * switch to heap if it doesn't. */
    if (ctx->auth_data_heap == NULL &&
            ctx->auth_data_size + auth_size > sizeof(ctx->auth_data_static)) {
        WGW_LOG("Auth data too big: %ld + %ld > %ld", ctx->auth_data_size,
                auth_size, sizeof(ctx->auth_data_static));
        WGW_LOG("Switching to dynamic allocation");

        size_t new_sz = sizeof(ctx->auth_data_static);
        while (new_sz < ctx->auth_data_size + auth_size)
            new_sz *= 2;

        ctx->auth_data_heap = gnutls_malloc(new_sz);
        if (!ctx->auth_data_heap) {
            WGW_ERROR("gnutls_malloc failed for auth_data_heap");
            return GNUTLS_E_MEMORY_ERROR;
        }
        ctx->auth_alloc = new_sz;
        XMEMCPY(ctx->auth_data_heap, ctx->auth_data_static,
                ctx->auth_data_size);
        WGW_LOG("Spilled AAD to heap (%zu bytes)", new_sz);
    }

    /* We are already storing in the heap, we check
     * if we need to grow it. */
    if (ctx->auth_data_heap &&
            ctx->auth_data_size + auth_size > ctx->auth_alloc) {
        WGW_LOG("New auth data too big, reallocating");
        size_t new_sz = ctx->auth_alloc;
        while (new_sz < ctx->auth_data_size + auth_size)
            new_sz *= 2;

        unsigned char *p = gnutls_realloc(ctx->auth_data_heap, new_sz);
        if (!p) {
            WGW_ERROR("gnutls_realloc failed for auth_data_heap");
            return GNUTLS_E_MEMORY_ERROR;
        }
        ctx->auth_data_heap = p;
        ctx->auth_alloc     = new_sz;
        WGW_LOG("Grew AAD heap to %zu bytes", new_sz);
    }

    /* Streaming must be a multiple of block size except for last. */
    if ((ctx->auth_data_size % AES_BLOCK_SIZE) != 0) {
        WGW_ERROR("Can only do multiple updates if multiple of block size");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Store AAD for later use in encrypt/decrypt operations. */
    unsigned char *dst = ctx->auth_data_heap ?
        ctx->auth_data_heap : ctx->auth_data_static;

    XMEMCPY(dst + ctx->auth_data_size, auth_data, auth_size);
    ctx->auth_data_size += auth_size;

    WGW_LOG("AAD added successfully");
    return 0;
}

/**
 * Encrypt data with cipher.
 *
 * @param [in]  _ctx      Cipher context.
 * @param [in]  src       Data to be encrypted.
 * @param [in]  src_size  Size of data to be encrypted in bytes.
 * @param [in]  dst       Buffer to hold encrypted data.
 * @param [in]  dst_size  Size of buffer to hold encrypted data.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized,
 *          context is not initialized for encryption, src_size is not valid
 *          for cipher, or mode not supported.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when wolfSSL encryption fails.
 */
int wolfssl_cipher_encrypt(void *_ctx, const void *src, size_t src_size,
    void *dst, size_t dst_size)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;
    int ret = -1;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", src_size);

    if (!ctx->initialized) {
        WGW_ERROR("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if encryption context is initialized. */
    if (!ctx->enc_initialized) {
        WGW_ERROR("encryption context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check destination is big enough for encrypted data. */
    if (dst_size < src_size) {
        WGW_ERROR("Destination size is too small for source size");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    if (ctx->mode == CBC) {
        WGW_LOG("wc_AesCbcEncrypt");

        /* Check block alignment for CBC mode. */
        if (src_size % AES_BLOCK_SIZE != 0) {
            WGW_ERROR("Source size not a multiple of the block size");
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Always use the encryption context for encryption operations. */
        ret = wc_AesCbcEncrypt(&ctx->cipher.pair.aes_enc, dst, src, src_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCbcEncrypt", ret);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        unsigned char* ptr;
        unsigned char* encr;

        WGW_LOG("Caching plaintext");

        ctx->enc = 1;

        /* Streaming must be a multiple of block size except for last. */
        if ((ctx->data_size % AES_BLOCK_SIZE) != 0) {
            WGW_ERROR("Can only do multiple updates if multiple of block size");
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (ctx->data_size + src_size > MAX_AES_GCM_PLAINTEXT) {
            WGW_ERROR("too much data for one request");
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Add the new plaintext on to the existing buffer. */
        ptr = gnutls_realloc(ctx->data, ctx->data_size + src_size);
        if (ptr == NULL) {
            WGW_ERROR("realloc of gmac data failed");
            return GNUTLS_E_INVALID_REQUEST;
        }
        ctx->data = ptr;
        XMEMCPY(ctx->data + ctx->data_size, src, src_size);
        ctx->data_size += src_size;

        /* Allocate an encrypted data buffer to encrypt all plaintext into. */
        encr = gnutls_malloc(ctx->data_size + src_size);
        if (ptr == NULL) {
            WGW_ERROR("realloc of gmac data failed");
            return GNUTLS_E_INVALID_REQUEST;
        }
    unsigned char *aad = ctx->auth_data_heap ?
      ctx->auth_data_heap : ctx->auth_data_static;

        /* Do encryption with the data we have. */
        ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, encr,
            ctx->data, ctx->data_size, ctx->iv, ctx->iv_size,
            ctx->tag, ctx->tag_size, aad, ctx->auth_data_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            gnutls_free(encr);
            return GNUTLS_E_ENCRYPTION_FAILED;
        } else {
            /* Copy out the last encrypted bytes. */
            XMEMCPY(dst, encr + ctx->data_size - src_size, src_size);
            gnutls_free(encr);
            /* A tag was created. */
            ctx->tag_set =1;
        }
#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
    } else if (ctx->mode == CFB8) {
        WGW_LOG("wc_AesCfb8Encrypt");

        /* Always use the encryption context for encryption operations. */
        ret = wc_AesCfb8Encrypt(&ctx->cipher.pair.aes_enc, dst, src, src_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCfb8Encrypt", ret);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
#endif
#ifdef WOLFSSL_AES_XTS
    } else if (ctx->mode == XTS) {
        WGW_LOG("wc_AesXtsEncrypt");

        /* Encrypt the data with the IV. */
        ret = wc_AesXtsEncrypt(&ctx->cipher.aes_xts, dst, src, src_size,
            ctx->iv, ctx->iv_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesXtsEncrypt", ret);
            if (ret == BAD_FUNC_ARG) {
                /* If the plaintext size is invalid then return invalid
                 * request. */
                return GNUTLS_E_INVALID_REQUEST;
            }
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
#endif
    } else {
        WGW_ERROR("AES mode not supported: %d", ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("encryption completed successfully");
    return 0;
}

/**
 * Decrypt data with cipher.
 *
 * @param [in]  _ctx      Cipher context.
 * @param [in]  src       Data to be decrypted.
 * @param [in]  src_size  Size of data to be decrypted in bytes.
 * @param [in]  dst       Buffer to hold decrypted data.
 * @param [in]  dst_size  Size of buffer to hold decrypted data.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized,
 *          context is not initialized for decryption, src_size is not valid
 *          for cipher, or mode not supported.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when wolfSSL decryption fails.
 */
int wolfssl_cipher_decrypt(void *_ctx, const void *src, size_t src_size,
    void *dst, size_t dst_size)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;
    int ret = -1;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", src_size);

    if (!ctx->initialized) {
        WGW_ERROR("decryption failed - context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if decryption context is initialized. */
    if (!ctx->dec_initialized) {
        WGW_ERROR("decryption context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check destination is big enough for encrypted data. */
    if (dst_size < src_size) {
        WGW_ERROR("Destination size is too small for source size");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    if (ctx->mode == CBC) {
        WGW_LOG("wc_AesCbcDecrypt");

        /* Check block alignment for CBC mode. */
        if (src_size % AES_BLOCK_SIZE != 0) {
            WGW_ERROR("Source size not a multiple of the block size");
            return GNUTLS_E_INVALID_REQUEST;
        }

	/* Handle 0-byte finalization call, common in cipher APIs for flushing/padding */
	if (src_size == 0) {
	   WGW_LOG("Zero-byte decrypt call (finalization), returning success");
	   return 0;
	}


        /* Always use the decryption context for decryption operations */
        ret = wc_AesCbcDecrypt(&ctx->cipher.pair.aes_dec, dst, src, src_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCbcDecrypt", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        unsigned char* ptr;
        unsigned char* decr;

        WGW_LOG("Caching plaintext");

        ctx->enc = 1;

        /* Streaming must be a multiple of block size except for last. */
        if ((ctx->data_size % AES_BLOCK_SIZE) != 0) {
            WGW_ERROR("Can only do multiple updates if multiple of block size");
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Add the new ciphertext on to the existing buffer. */
        ptr = gnutls_realloc(ctx->data, ctx->data_size + src_size);
        if (ptr == NULL) {
            WGW_ERROR("realloc of encrypted data failed");
            return GNUTLS_E_INVALID_REQUEST;
        }
        ctx->data = ptr;
        XMEMCPY(ctx->data + ctx->data_size, src, src_size);
        ctx->data_size += src_size;

        /* Allocate a decrypted data buffer to decrypt all ciphertext into. */
        decr = gnutls_malloc(ctx->data_size + src_size);
        if (ptr == NULL) {
            WGW_ERROR("realloc of decrypted data failed");
            return GNUTLS_E_INVALID_REQUEST;
        }

        WGW_LOG("wc_AesGcmDecrypt");

        unsigned char *aad = ctx->auth_data_heap ?
            ctx->auth_data_heap : ctx->auth_data_static;

        /* If caller hasn't set tag then we are creating it. */
        if (!ctx->tag_set_ext) {
            /* Encrypt the ciphertext to get the plaintext.
             * Tag will have been created on plaintext which is of no use.
             */
            ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, decr, ctx->data,
                ctx->data_size, ctx->iv, ctx->iv_size,
                ctx->tag, ctx->tag_size, aad, ctx->auth_data_size);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
                gnutls_free(decr);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            /* Encrypt the plaintext to create the tag. */
            ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, decr, decr,
                ctx->data_size, ctx->iv, ctx->iv_size,
                ctx->tag, ctx->tag_size, aad, ctx->auth_data_size);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
                gnutls_free(decr);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            /* A tag is now available. */
            ctx->tag_set = 1;
        }
        /* Do decryption with cipehtext, IV, authentication data and tag. */
        ret = wc_AesGcmDecrypt(&ctx->cipher.aes_ctx, decr,
            ctx->data, ctx->data_size, ctx->iv, ctx->iv_size,
            ctx->tag, ctx->tag_size, aad, ctx->auth_data_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            gnutls_free(decr);
            return GNUTLS_E_ENCRYPTION_FAILED;
        } else {
            /* Copy out the last decrypted data. */
            XMEMCPY(dst, decr + ctx->data_size - src_size, src_size);
            gnutls_free(decr);
        }
#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
    } else if (ctx->mode == CFB8) {
        WGW_LOG("wc_AesCfb8Decrypt");

        /* Always use the decryption context for decryption operations. */
        ret = wc_AesCfb8Decrypt(&ctx->cipher.pair.aes_dec, dst, src, src_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCfb8Decrypt", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
#endif
#ifdef WOLFSSL_AES_XTS
    } else if (ctx->mode == XTS) {
        WGW_LOG("wc_AesXtsDecrypt");

        /* Decrypt the data with the IV. */
        ret = wc_AesXtsDecrypt(&ctx->cipher.aes_xts, dst, src, src_size,
            ctx->iv, ctx->iv_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesXtsDecrypt", ret);
            if (ret == BAD_FUNC_ARG) {
                /* If the plaintext size is invalid then return invalid
                 * request. */
                return GNUTLS_E_INVALID_REQUEST;
            }
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
#endif
    } else {
        WGW_ERROR("AES mode not supported: %d", ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("decryption completed successfully");
    return 0;
}

/**
 * Get or store the tag;
 *
 * When tag is all zeros then copy out the stored authentication tag.
 *
 * @param [in]      _ctx      Cipher context.
 * @param [in, out] tag       Authentication tag.
 * @param [in]      tag_size  Size of authentication tag in bytes.
 */
void wolfssl_cipher_tag(void *_ctx, void *tag, size_t tag_size)
{
    WGW_FUNC_ENTER();
    WGW_LOG("tag_size %zu", tag_size);

    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (!ctx->initialized) {
        WGW_LOG("cipher context not initialized");
        return;
    }

    /* Make sure copied tag size is no larger than that generated. */
    if (tag_size > ctx->tag_size) {
        tag_size = ctx->tag_size;
    }

    /* Check if tag available. */
    if (ctx->tag_set) {
        if (ctx->mode == GCM) {
            XMEMCPY(tag, ctx->tag, tag_size);
            /* Authentication data used - reset count. */
            ctx->auth_data_size = 0;
            /* Dispose of cached data. */
            gnutls_free(ctx->data);
            ctx->data = NULL;
            ctx->data_size = 0;
            WGW_LOG("tag returned successfully");
        } else {
            WGW_LOG("AES mode not supported: %d", ctx->mode);
        }
    } else if (ctx->enc) {
        int ret = -1;

        /* Encrypting and no tag set means we don't have plaintext. */
        if (ctx->mode == GCM) {
            WGW_LOG("wc_AesGcmEncrypt");

            unsigned char *aad = ctx->auth_data_heap ?
                ctx->auth_data_heap : ctx->auth_data_static;

            /* Do authentication with no plaintext. */
            ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, NULL, NULL, 0, ctx->iv,
                ctx->iv_size, ctx->tag, ctx->tag_size, aad,
                ctx->auth_data_size);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            } else {
                /* Copy out tag. */
                ctx->tag_set = 1;
                XMEMCPY(tag, ctx->tag, tag_size);
                WGW_LOG("tag stored successfully");
            }
            /* Authentication data used - reset count. */
            ctx->auth_data_size = 0;
            /* Dispose of cached plaintext. */
            gnutls_free(ctx->data);
            ctx->data = NULL;
            ctx->data_size = 0;
        } else {
            WGW_LOG("AES mode not supported: %d", ctx->mode);
        }
    } else {
        /* Decrypting and we need to set tag for decrypt operation. */
        XMEMCPY(ctx->tag, tag, tag_size);
        ctx->tag_set = 1;
        ctx->tag_set_ext = 1;
        WGW_LOG("tag provided successfully");
    }
}

/* Routine that does a shift and xor of the input buffer
 * and stores the result inside the output buffer.
 * Routine copied from the wolfcrypt/src/cmac.c source code*/
void ShiftAndXorRb(byte* out, byte* in)
{
    int i, j, xorRb;
    int mask = 0, last = 0;
    byte Rb = 0x87;

    xorRb = (in[0] & 0x80) != 0;

    for (i = 1, j = WC_AES_BLOCK_SIZE - 1; i <= WC_AES_BLOCK_SIZE; i++, j--) {
        last = (in[j] & 0x80) ? 1 : 0;
        out[j] = (byte)((in[j] << 1) | mask);
        mask = last;
        if (xorRb) {
            out[j] ^= Rb;
            Rb = 0;
        }
    }
}

/* This routine performs a bitwise XOR operation of <*r> and <*a> for <n> number
of wolfssl_words, placing the result in <*r>.
Routine copied from the wolfcrypt/src/misc.c source code. */
static void XorWords(wolfssl_word** r, const wolfssl_word** a,
                                       word32 n)
{
    const wolfssl_word *e = *a + n;

    while (*a < e)
        *((*r)++) ^= *((*a)++);
}

/* This routine performs a bitwise XOR operation of <*buf> and <*mask> of n
counts, placing the result in <*buf>.
* Routine copied from the wolfcrypt/src/misc.c source code. */
void xorbuf(void* buf, const void* mask, word32 count)
{
    byte*       b = (byte*)buf;
    const byte* m = (const byte*)mask;

    /* type-punning helpers */
    union {
        byte* bp;
        wolfssl_word* wp;
    } tpb;
    union {
        const byte* bp;
        const wolfssl_word* wp;
    } tpm;

    if ((((wc_ptr_t)buf & (WOLFSSL_WORD_SIZE - 1)) == 0) &&
        (((wc_ptr_t)mask & (WOLFSSL_WORD_SIZE - 1)) == 0))
    {
        /* Both buffers are already aligned.  Possible to XOR by words without
         * fixup.
         */

        tpb.bp = b;
        tpm.bp = m;
        /* Work around false positives from linuxkm CONFIG_FORTIFY_SOURCE. */
        #if defined(WOLFSSL_LINUXKM) && defined(CONFIG_FORTIFY_SOURCE)
            PRAGMA_GCC_DIAG_PUSH;
            PRAGMA_GCC("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
        #endif
        XorWords(&tpb.wp, &tpm.wp, count >> WOLFSSL_WORD_SIZE_LOG2);
        #if defined(WOLFSSL_LINUXKM) && defined(CONFIG_FORTIFY_SOURCE)
            PRAGMA_GCC_DIAG_POP;
        #endif
        b = tpb.bp;
        m = tpm.bp;
        count &= (WOLFSSL_WORD_SIZE - 1);
    }
    else if (((wc_ptr_t)buf & (WOLFSSL_WORD_SIZE - 1)) ==
             ((wc_ptr_t)mask & (WOLFSSL_WORD_SIZE - 1)))
    {
        /* Alignment can be fixed up to allow XOR by words. */

        /* Perform bytewise xor until pointers are aligned to
         * WOLFSSL_WORD_SIZE.
         */
        while ((((wc_ptr_t)b & (WOLFSSL_WORD_SIZE - 1)) != 0) && (count > 0))
        {
            *(b++) ^= *(m++);
            count--;
        }

        tpb.bp = b;
        tpm.bp = m;
        /* Work around false positives from linuxkm CONFIG_FORTIFY_SOURCE. */
        #if defined(WOLFSSL_LINUXKM) && defined(CONFIG_FORTIFY_SOURCE)
            PRAGMA_GCC_DIAG_PUSH;
            PRAGMA_GCC("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
        #endif
        XorWords(&tpb.wp, &tpm.wp, count >> WOLFSSL_WORD_SIZE_LOG2);
        #if defined(WOLFSSL_LINUXKM) && defined(CONFIG_FORTIFY_SOURCE)
            PRAGMA_GCC_DIAG_POP;
        #endif
        b = tpb.bp;
        m = tpm.bp;
        count &= (WOLFSSL_WORD_SIZE - 1);
    }

    while (count > 0) {
        *b++ ^= *m++;
        count--;
    }
}

typedef struct AesSivAssoc {
    const byte* assoc;
    word32 assocSz;
} AesSivAssoc;

/* section 2.4 of RFC 5297 */
static WARN_UNUSED_RESULT int S2V(
    const byte* key, word32 keySz, const AesSivAssoc* assoc, word32 numAssoc,
    const byte* nonce, word32 nonceSz, const byte* data,
    word32 dataSz, byte* out)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* tmp[3] = {NULL, NULL, NULL};
    int i;
    Cmac* cmac;
#else
    byte tmp[3][WC_AES_BLOCK_SIZE];
    Cmac cmac[1];
#endif
    word32 macSz = WC_AES_BLOCK_SIZE;
    int ret = 0;
    byte tmpi = 0;
    word32 ai;
    word32 zeroBytes;

#ifdef WOLFSSL_SMALL_STACK
    for (i = 0; i < 3; ++i) {
        tmp[i] = (byte*)XMALLOC(WC_AES_BLOCK_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp[i] == NULL) {
            ret = MEMORY_E;
            break;
        }
    }
    if (ret == 0)
#endif

    if ((numAssoc > 126) || ((nonceSz > 0) && (numAssoc > 125))) {
        /* See RFC 5297 Section 7. */
        WGW_LOG("Maximum number of ADs (including the nonce) for AES SIV is"
                    " 126.");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        XMEMSET(tmp[1], 0, WC_AES_BLOCK_SIZE);
        XMEMSET(tmp[2], 0, WC_AES_BLOCK_SIZE);

        ret = wc_AesCmacGenerate(tmp[0], &macSz, tmp[1], WC_AES_BLOCK_SIZE,
                                 key, keySz);
    }

    if (ret == 0) {
        for (ai = 0; ai < numAssoc; ++ai) {
            ShiftAndXorRb(tmp[1-tmpi], tmp[tmpi]);
            ret = wc_AesCmacGenerate(tmp[tmpi], &macSz, assoc[ai].assoc,
                                     assoc[ai].assocSz, key, keySz);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesCmacGenerate", ret);
                break;
            }
            xorbuf(tmp[1-tmpi], tmp[tmpi], WC_AES_BLOCK_SIZE);
            tmpi = (byte)(1 - tmpi);
        }

        /* Add nonce as final AD. See RFC 5297 Section 3. */
        if ((ret == 0) && (nonceSz > 0)) {
            ShiftAndXorRb(tmp[1-tmpi], tmp[tmpi]);
            ret = wc_AesCmacGenerate(tmp[tmpi], &macSz, nonce,
                                     nonceSz, key, keySz);
            if (ret == 0) {
                xorbuf(tmp[1-tmpi], tmp[tmpi], WC_AES_BLOCK_SIZE);
            }
            tmpi = (byte)(1U - tmpi);
        }

        /* For simplicity of the remaining code, make sure the "final" result
           is always in tmp[0]. */
        if (tmpi == 1) {
            XMEMCPY(tmp[0], tmp[1], WC_AES_BLOCK_SIZE);
        }
    }

    if (ret == 0) {
        if (dataSz >= WC_AES_BLOCK_SIZE) {

        #ifdef WOLFSSL_SMALL_STACK
            cmac = (Cmac*)XMALLOC(sizeof(Cmac), NULL, DYNAMIC_TYPE_CMAC);
            if (cmac == NULL) {
                ret = MEMORY_E;
            }
            if (ret == 0)
        #endif
            {
            #ifdef WOLFSSL_CHECK_MEM_ZERO
                /* Aes part is checked by wc_AesFree. */
                wc_MemZero_Add("wc_AesCmacGenerate cmac",
                    ((unsigned char *)cmac) + sizeof(Aes),
                    sizeof(Cmac) - sizeof(Aes));
            #endif
                xorbuf(tmp[0], data + (dataSz - WC_AES_BLOCK_SIZE),
                       WC_AES_BLOCK_SIZE);
                ret = wc_InitCmac(cmac, key, keySz, WC_CMAC_AES, NULL);
                if (ret == 0) {
                    ret = wc_CmacUpdate(cmac, data, dataSz - WC_AES_BLOCK_SIZE);
                }
                if (ret == 0) {
                    ret = wc_CmacUpdate(cmac, tmp[0], WC_AES_BLOCK_SIZE);
                }
                if (ret == 0) {
                    ret = wc_CmacFinal(cmac, out, &macSz);
                }
            }
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(cmac, NULL, DYNAMIC_TYPE_CMAC);
        #elif defined(WOLFSSL_CHECK_MEM_ZERO)
            wc_MemZero_Check(cmac, sizeof(Cmac));
        #endif
        }
        else {
            XMEMCPY(tmp[2], data, dataSz);
            tmp[2][dataSz] |= 0x80;
            zeroBytes = WC_AES_BLOCK_SIZE - (dataSz + 1);
            if (zeroBytes != 0) {
                XMEMSET(tmp[2] + dataSz + 1, 0, zeroBytes);
            }
            ShiftAndXorRb(tmp[1], tmp[0]);
            xorbuf(tmp[1], tmp[2], WC_AES_BLOCK_SIZE);
            ret = wc_AesCmacGenerate(out, &macSz, tmp[1], WC_AES_BLOCK_SIZE, key,
                                     keySz);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    for (i = 0; i < 3; ++i) {
        if (tmp[i] != NULL) {
            XFREE(tmp[i], NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
#endif

    return ret;
}

/**
 * Authenticated Encryption with Authutenticated Data (AEAD) encrypt.
 *
 * @param [in, out] _ctx        Cipher context.
 * @param [in]      nonce       Nonce for encryption.
 * @param [in]      nonce_size  Size of nonce in bytes.
 * @param [in]      auth        Authentication data.
 * @param [in]      auth_size   Size of authentication data in bytes.
 * @param [in]      tag_size    Size of tag to store.
 * @param [in]      plain       Plaintext to encrypt.
 * @param [in]      plain_size  Size of plaintext.
 * @param [out]     encr        Encrypted data.
 * @param [in]      encr_size   Size, in bytes, of buffer to hold encrypted
 *                              data.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context hasn't been initialized,
 *          nonce size is invalid or mode not supported.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when setting key/nonce against wolfSSL
 *          cipher fails or wolfSSL encryption fails.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when too much auth data to store or
 *          encrypted buffer size won't fit plain text and tag.
 */
int wolfssl_cipher_aead_encrypt(void *_ctx, const void *nonce,
     size_t nonce_size, const void *auth, size_t auth_size, size_t tag_size,
     const void *plain, size_t plain_size, void *encr, size_t encr_size)
{
    int ret;
    struct wolfssl_cipher_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();

    if (!ctx->initialized) {
        WGW_ERROR("aead encrypt failed - context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check encrypted data is big enough for ciphertext and tag. */
    if (encr_size < plain_size + tag_size) {
        WGW_ERROR("encrypted size too small: %d < %d + %d", encr_size,
            plain_size, tag_size);
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    ctx->enc = 1;

    if (ctx->mode == GCM) {
        WGW_LOG("wc_AesGcmEncrypt");
        /* Encrypt with AES-GCM. */
        ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, encr, plain, plain_size,
            nonce, nonce_size, encr + plain_size, tag_size, auth, auth_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
    } else if (ctx->mode == CCM) {
        WGW_LOG("wc_AesCcmEncrypt");
        /* Encrypt with AES-CCM. */
        ret = wc_AesCcmEncrypt(&ctx->cipher.aes_ctx, encr, plain, plain_size,
            nonce, nonce_size, encr + plain_size, tag_size, auth, auth_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCcmEncrypt", ret);
#if defined(HAVE_FIPS)
            if (ret == BAD_FUNC_ARG)
                return GNUTLS_E_INVALID_REQUEST;
#endif
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
    }
#if defined(WOLFSSL_AES_COUNTER)
    else if (ctx->mode == SIV) {
        WGW_LOG("wc_AesSivEncrypt");
        WGW_LOG("encr_size: %d", encr_size);
        /*sinthetic iv that gets computed during s2v via cmac */
        unsigned char siv_tmp[WC_AES_BLOCK_SIZE];
        int ret = 0;
        size_t keySz = ctx->original_key_sz;
        unsigned char tmp_encr[plain_size];
        AesSivAssoc ad;
        word32 numAssoc;

        ad.assoc = auth;
        ad.assocSz = auth_size;
        numAssoc = 1U;

        if (keySz != 32 && keySz != 48 && keySz != 64) {
            WGW_LOG("Bad key size. Must be 256, 384, or 512 bits.");
            WGW_LOG("keySz: %d", keySz);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* from RFC 5297, section 2.6
         * in this case we use the first half of the key for the S2V for CMAC
         * which is the encryption side of things.
         * */
        ret = S2V(ctx->original_key, keySz / 2,
                &ad, numAssoc, nonce,
                nonce_size, plain, plain_size, siv_tmp);
        if (ret != 0) {
            WGW_LOG("Error during S2V compute for AES-SIV");
            return GNUTLS_E_ENCRYPTION_FAILED;
        } else {
            XMEMCPY(ctx->siv_synth, siv_tmp, WC_AES_BLOCK_SIZE);
        }

        if (ret == 0 && plain_size > 0) {
            siv_tmp[12] &= 0x7f;
            siv_tmp[8] &= 0x7f;
            ret = wc_AesSetKey(&ctx->cipher.aes_ctx,
                    ctx->original_key + keySz / 2,
                    keySz / 2, siv_tmp,
                    AES_ENCRYPTION);
            if (ret != 0) {
                WGW_LOG("Failed to set key for AES-CTR.");
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            else {
                ret = wc_AesCtrEncrypt(&ctx->cipher.aes_ctx, tmp_encr,
                        plain, plain_size);
                if (ret != 0) {
                    WGW_LOG("AES-CTR encryption failed.");
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
            }
        }

        /* gnutls expects the final cipher text to be siv followed by the
         * cipher text, while wolfssl separates these two and puts siv into a
         * separate buffer pointer, we need to merge them for compatibility. */
        XMEMCPY(encr, ctx->siv_synth, WC_AES_BLOCK_SIZE);
        XMEMCPY(encr + WC_AES_BLOCK_SIZE, tmp_encr, plain_size);
    }
#endif
    else {
        WGW_ERROR("AES mode not supported: %d", ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

/**
 * Authenticated Encryption with Authutenticated Data (AEAD) decrypt.
 *
 * @param [in, out] _ctx        Cipher context.
 * @param [in]      nonce       Nonce for encryption.
 * @param [in]      nonce_size  Size of nonce in bytes.
 * @param [in]      auth        Authentication data.
 * @param [in]      auth_size   Size of authentication data in bytes.
 * @param [in]      tag_size    Size of tag in encrypted data.
 * @param [in]      encr        Encrypted data.
 * @param [in]      encr_size   Size of encrypted data in bytes.
 * @param [out]     plain       Plaintext to encrypt.
 * @param [in]      plain_size  Size, in bytes, of buffer to hold plaintext.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context hasn't been initialized,
 *          nonce size is invalid or mode not supported.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when setting key/nonce against wolfSSL
 *          cipher fails or wolfSSL encryption fails.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when too much auth data to store or
 *          encrypted buffer size is less than tag size.
 */
int wolfssl_cipher_aead_decrypt(void *_ctx, const void *nonce,
     size_t nonce_size, const void *auth, size_t auth_size, size_t tag_size,
     const void *encr, size_t encr_size, void *plain, size_t plain_size)
{
    int ret;
    struct wolfssl_cipher_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();

    if (!ctx->initialized) {
        WGW_ERROR("aead decrypt failed - context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check decrypted data is big enough for ciphertext. */
    if (plain_size + tag_size < encr_size) {
        WGW_ERROR("plain size too small: %d + %d < %d ", plain_size, tag_size,
            encr_size);
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    ctx->enc = 0;

    /* Encrypted size includes tag. */
    encr_size -= tag_size;

    if (ctx->mode == GCM) {
        WGW_LOG("wc_AesGcmDncrypt");
        /* Decrypt with AES-GCM. */
        ret = wc_AesGcmDecrypt(&ctx->cipher.aes_ctx, plain, encr, encr_size,
            nonce, nonce_size, encr + encr_size, tag_size, auth, auth_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesGcmDecrypt", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        return 0;
    } else if (ctx->mode == CCM) {
        WGW_LOG("wc_AesCcmDncrypt");
        /* Decrypt with AES-CCM. */
        ret = wc_AesCcmDecrypt(&ctx->cipher.aes_ctx, plain, encr, encr_size,
            nonce, nonce_size, encr + encr_size, tag_size, auth, auth_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCcmDecrypt", ret);
#if defined(HAVE_FIPS)
            if (ret == BAD_FUNC_ARG)
                return GNUTLS_E_INVALID_REQUEST;
#endif
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        return 0;
    }
#if defined(WOLFSSL_AES_COUNTER)
    else if (ctx->mode == SIV) {
        /* sinthetic iv that gets computed during s2v via cmac
         * during the encryption/decryption operations operations. */
        unsigned char siv_tmp[WC_AES_BLOCK_SIZE];
        int ret = 0;
        size_t keySz = ctx->original_key_sz;
        AesSivAssoc assoc;
        word32 numAssoc;

        assoc.assoc = auth;
        assoc.assocSz = auth_size;
        numAssoc = 1U;

        if (ret == 0 && keySz != 32 && keySz != 48 && keySz != 64) {
            WGW_LOG("Bad key size. Must be 256, 384, or 512 bits.");
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* gnutls expects the final cipher text to be siv followed by the
         * cipher text, while wolfssl separates these two and puts siv into a
         * separate buffer pointer, we need to split them for compatibility. */
        XMEMCPY(ctx->siv_synth, encr, WC_AES_BLOCK_SIZE);
        XMEMCPY(siv_tmp, ctx->siv_synth, WC_AES_BLOCK_SIZE);

        if (ret == 0 && encr_size > 0) {
            siv_tmp[12] &= 0x7f;
            siv_tmp[8] &= 0x7f;
            ret = wc_AesSetKey(&ctx->cipher.aes_ctx,
                    ctx->original_key + keySz / 2,
                    keySz / 2, siv_tmp,
                    AES_ENCRYPTION);
            if (ret != 0) {
                WGW_LOG("Failed to set key for AES-CTR.");
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            else {
                ret = wc_AesCtrEncrypt(&ctx->cipher.aes_ctx, plain,
                        encr + WC_AES_BLOCK_SIZE, encr_size);
                if (ret != 0) {
                    WGW_LOG("AES-CTR decryption failed.");
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
            }
        }

        /* from RFC 5297, section 2.6
         * in this case we use the first half of the key for the S2V for CMAC
         * which is the encryption/decryption side of things.
         * */
        ret = S2V(ctx->original_key, keySz / 2,
                &assoc, numAssoc, nonce,
                nonce_size, plain, plain_size, siv_tmp);
        if (ret != 0) {
            WGW_LOG("Error during S2V compute for AES-SIV");
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        if (XMEMCMP(ctx->siv_synth, siv_tmp, WC_AES_BLOCK_SIZE) != 0) {
            WGW_LOG("Computed SIV doesn't match received SIV.");
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        return 0;
    }
#endif
    else {
        WGW_ERROR("AES mode not supported: %d", ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }
}


/**
 * Clean up cipher resources.
 *
 * @param [in, out] _ctx  Cipher context.
 */
void wolfssl_cipher_deinit(void *_ctx)
{
    WGW_LOG("wolfssl_cipher_deinit");

    struct wolfssl_cipher_ctx *ctx = _ctx;

    if (ctx && ctx->initialized) {
        gnutls_free(ctx->data);
        /* Free the wolfSSL AES contexts */
        switch (ctx->mode) {
        #ifdef WOLFSSL_AES_XTS
            case XTS:
                wc_AesXtsFree(&ctx->cipher.aes_xts);
                break;
        #endif
            case GCM:
            case CCM:
        #ifdef WOLFSSL_AES_COUNTER
            case SIV:
                wc_AesFree(&ctx->cipher.aes_ctx);
                if (ctx->original_key) {
                    gnutls_free(ctx->original_key);
                }
                break;
        #endif
            case CBC:
        #if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
            case CFB8:
        #endif
                wc_AesFree(&ctx->cipher.pair.aes_enc);
                wc_AesFree(&ctx->cipher.pair.aes_dec);
                break;
            default:
                break;
        }
        ctx->initialized = 0;
        ctx->enc_initialized = 0;
        ctx->dec_initialized = 0;
        if (ctx->auth_data_heap) {
            gnutls_free(ctx->auth_data_heap);
        }
    }

    gnutls_free(ctx);
}

/** Function pointers for the wolfSSL implementation of ciphers. */
const gnutls_crypto_cipher_st wolfssl_cipher_struct = {
    .init = wolfssl_cipher_init,
    .setkey = wolfssl_cipher_setkey,
    .setiv = wolfssl_cipher_setiv,
    .encrypt = wolfssl_cipher_encrypt,
    .decrypt = wolfssl_cipher_decrypt,
    .auth = wolfssl_cipher_auth,
    .tag = wolfssl_cipher_tag,
    .deinit = wolfssl_cipher_deinit,
};

/** Function pointers for the wolfSSL implementation of AEAD ciphers. */
const gnutls_crypto_cipher_st wolfssl_cipher_aead_struct = {
    .init = wolfssl_cipher_init,
    .setkey = wolfssl_cipher_setkey,
    .setiv = wolfssl_cipher_setiv,
    .encrypt = wolfssl_cipher_encrypt,
    .decrypt = wolfssl_cipher_decrypt,
    .aead_encrypt = wolfssl_cipher_aead_encrypt,
    .aead_decrypt = wolfssl_cipher_aead_decrypt,
    .auth = wolfssl_cipher_auth,
    .tag = wolfssl_cipher_tag,
    .deinit = wolfssl_cipher_deinit,
};

/** Function pointers for the wolfSSL implementation of AEAD only ciphers. */
const gnutls_crypto_cipher_st wolfssl_cipher_aead_only_struct = {
    .init = wolfssl_cipher_init,
    .setkey = wolfssl_cipher_setkey,
    .aead_encrypt = wolfssl_cipher_aead_encrypt,
    .aead_decrypt = wolfssl_cipher_aead_decrypt,
    .deinit = wolfssl_cipher_deinit,
};

#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
/** Function pointers for the wolfSSL implementation of ciphers. */
const gnutls_crypto_cipher_st wolfssl_cipher_getiv_struct = {
    .init = wolfssl_cipher_init,
    .setkey = wolfssl_cipher_setkey,
    .setiv = wolfssl_cipher_setiv,
    .getiv = wolfssl_cipher_getiv,
    .encrypt = wolfssl_cipher_encrypt,
    .decrypt = wolfssl_cipher_decrypt,
    .auth = wolfssl_cipher_auth,
    .tag = wolfssl_cipher_tag,
    .deinit = wolfssl_cipher_deinit,
};
#endif

/**
 * Register the cipher algorithms with GnuTLS.
 *
 * TODO: consider having the GnuTLS code get a list of algorithms to register.
 *       That way the gnutls functions don't need to be prototyped here.
 *
 * @return  0 on success.
 */
int wolfssl_cipher_register(void)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    /* Register AES-128-CBC */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_CBC]) {
        WGW_LOG("registering AES-128-CBC");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_128_CBC, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-CBC failed");
            return ret;
        }
    }

    /* Register AES-192-CBC */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_192_CBC]) {
        WGW_LOG("registering AES-192-CBC");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_192_CBC, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-192-CBC failed");
            return ret;
        }
    }

    /* Register AES-256-CBC */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_CBC]) {
        WGW_LOG("registering AES-256-CBC");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_CBC, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-CBC failed");
            return ret;
        }
    }

    /* Register AES-128-GCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_GCM]) {
        WGW_LOG("registering AES-128-GCM");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_128_GCM, 80, &wolfssl_cipher_aead_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-GCM failed");
            return ret;
        }
    }

    /* Register AES-192-GCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_192_GCM]) {
        WGW_LOG("registering AES-192-GCM");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_192_GCM, 80, &wolfssl_cipher_aead_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-192-GCM failed");
            return ret;
        }
    }

    /* Register AES-256-GCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_GCM]) {
        WGW_LOG("registering AES-256-GCM");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_GCM, 80, &wolfssl_cipher_aead_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-GCM failed");
            return ret;
        }
    }

    /* Register AES-128-CCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_CCM]) {
        WGW_LOG("registering AES-128-CCM");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_128_CCM,
            80, &wolfssl_cipher_aead_only_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-CCM failed");
            return ret;
        }
    }

    /* Register AES-256-CCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_CCM]) {
        WGW_LOG("registering AES-256-CCM");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_256_CCM,
            80, &wolfssl_cipher_aead_only_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-CCM failed");
            return ret;
        }
    }

    /* Register AES-128-CCM-8 */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_CCM_8]) {
        WGW_LOG("registering AES-128-CCM-8");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_128_CCM_8,
            80, &wolfssl_cipher_aead_only_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-CCM-8 failed");
            return ret;
        }
    }

    /* Register AES-256-CCM-8 */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_CCM_8]) {
        WGW_LOG("registering AES-256-CCM-8");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_256_CCM_8,
            80, &wolfssl_cipher_aead_only_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-CCM-8 failed");
            return ret;
        }
    }

#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
    /* Register AES-128-CFB8 */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_CFB8]) {
        WGW_LOG("registering AES-128-CFB8");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_128_CFB8,
            80, &wolfssl_cipher_getiv_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-CFB8 failed");
            return ret;
        }
    }

    /* Register AES-192-CFB8 */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_192_CFB8]) {
        WGW_LOG("registering AES-192-CFB8");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_192_CFB8,
            80, &wolfssl_cipher_getiv_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-192-CFB8 failed");
            return ret;
        }
    }

    /* Register AES-256-CFB8 */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_CFB8]) {
        WGW_LOG("registering AES-256-CFB8");
        ret = gnutls_crypto_single_cipher_register(GNUTLS_CIPHER_AES_256_CFB8,
             80, &wolfssl_cipher_getiv_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-CFB8 failed");
            return ret;
        }
    }
#endif

#ifdef WOLFSSL_AES_XTS
    /* Register AES-128-XTS */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_XTS]) {
        WGW_LOG("registering AES-128-XTS");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_128_XTS, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-XTS failed");
            return ret;
        }
    }

    /* Register AES-256-XTS */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_XTS]) {
        WGW_LOG("registering AES-256-XTS");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_XTS, 80, &wolfssl_cipher_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-XTS failed");
            return ret;
        }
    }
#endif
#ifdef WOLFSSL_AES_COUNTER
    /* Register AES-128-SIV */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_128_SIV]) {
        WGW_LOG("registering AES-128-SIV");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_128_SIV, 80, &wolfssl_cipher_aead_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-SIV failed");
            return ret;
        }
    }

    /* Register AES-256-SIV */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_SIV]) {
        WGW_LOG("registering AES-256-SIV");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_SIV, 80, &wolfssl_cipher_aead_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-SIV failed");
            return ret;
        }
    }
#endif

    return ret;
}
#endif
