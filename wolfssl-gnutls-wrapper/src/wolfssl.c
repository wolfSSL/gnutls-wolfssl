/* Integration of wolfssl crypto with GnuTLS */
#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "wolfssl.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * Constructor for shared library.
 *
 * Initializes the library.
 */
void __attribute__((constructor)) wolfssl_init(void) {
    _gnutls_wolfssl_init();
}

#ifdef ENABLE_WOLFSSL

/********************************** Logging **********************************/

/**
 * Log function entry.
 */
#define WGW_FUNC_ENTER()    wgw_log(__LINE__, "ENTER: %s", __func__)

#ifndef NO_ERROR_STRINGS
/**
 * Log a wolfSSL error message.
 *
 * @param [in] func  wolfSSL function that failed.
 * @param [in] ret   Return value form wolfSSL function.
 */
#define WGW_WOLFSSL_ERROR(func, ret) \
    wgw_log(__LINE__, "%s failed : %s (%d)", func, wc_GetErrorString(ret), ret)
#else
/**
 * Log a wolfSSL error message.
 *
 * @param [in] func  wolfSSL function that failed.
 * @param [in] ret   Return value form wolfSSL function.
 */
#define WGW_WOLFSSL_ERROR(func, ret) \
    wgw_log(__LINE__, "%s failed : %d", func, ret)
#endif

/**
 * Log an error message that can be printed with printf formating.
 *
 * @param [in] fmt   Format of string to print.
 * @param [in] args  Arguments to use when printing.
 */
#define WGW_ERROR(fmt, args...)    wgw_log(__LINE__, "ERROR: " fmt, ## args)

/**
 * Log a message that can be printed with printf formating.
 *
 * @param [in] fmt   Format of string to print.
 * @param [in] args  Arguments to use when printing.
 */
#define WGW_LOG(fmt, args...)    wgw_log(__LINE__, fmt, ## args)

/** Wether logging output will be written. */
static int loggingEnabled = 0;

/** File descriptor to log to. Set in _gnutls_wolfssl_init. */
static FILE* loggingFd = NULL;

/**
 * Log a message.
 *
 * @param [in] line  Line number of log message.
 * @param [in] fmt   Format of string to print.
 */
static void wgw_log(int line, const char* fmt, ...)
{
    if (loggingEnabled) {
        va_list args;
        va_start(args, fmt);
        /* TODO: use a file when required. */
        fprintf(loggingFd, "wgw [%4d]: ", line);
        vfprintf(loggingFd, fmt, args);
        fprintf(loggingFd, "\n");
        va_end(args);
    }
}

/********************* Cipher algorithms (AES) *********************/

/** List of supported AES cipher modes. */
enum {
    NONE,
    CBC,
    GCM,
    CCM,
    CFB8,
    XTS,
};

/** Size of GCM tag. */
#define GCM_TAG_SIZE        WC_AES_BLOCK_SIZE
/** Size of CCM tag. */
#define CCM_TAG_SIZE        WC_AES_BLOCK_SIZE
/** Size of CCM-8 tag. */
#define CCM_8_TAG_SIZE      8
/** Maximum AES key size. */
#define MAX_AES_KEY_SIZE    AES_256_KEY_SIZE
/** Maximum authentication data. */
#define MAX_AUTH_DATA       1024
/** Maxium plaintext to encrypt for GCM  */
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

    /** Indicates that this context as been initialized. */
    int initialized:1;
    /** Indicates that we have been initialized for encryption. */
    int enc_initialized:1;
    /** Indicates that we have been initialized for decryption. */
    int dec_initialized:1;
    /** Indicates whether we are doing encryption or decryption.  */
    int enc:1;

    /** The GnuTLS cipher algorithm ID. */
    gnutls_cipher_algorithm_t algorithm;
    /** Mode of AES to use. */
    int mode;

    /** IV/nonce to use.  */
    unsigned char iv[AES_IV_SIZE];
    /** Size of IV/nonce to use.  */
    size_t iv_size;

    /* For GCM mode. */
    /** Authentication data to use. */
    unsigned char auth_data[MAX_AUTH_DATA];
    /** Size of authentication data to use. */
    size_t auth_data_size;
    /** Calculated authentication tag. */
    unsigned char tag[GCM_TAG_SIZE];
    /** Size of calculated authentication tag. */
    size_t tag_size;
    /** Data to encrypt/decrypt. */
    unsigned char* data;
    /** Data size. */
    size_t data_size;
    /** Tag has been set. */
    int tag_set:1;
    /** Tag has been set from external source. */
    int tag_set_ext:1;
};

/** Array of supported ciphers. */
static const int wolfssl_cipher_supported[] = {
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
static int is_cipher_supported(int algorithm)
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
static int get_cipher_mode(gnutls_cipher_algorithm_t algorithm)
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
static int wolfssl_cipher_init(gnutls_cipher_algorithm_t algorithm, void **_ctx,
    int enc)
{
    struct wolfssl_cipher_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("enc=%d", enc);

    /* check if cipher is supported */
    if (!is_cipher_supported((int)algorithm)) {
        WGW_ERROR("cipher %d is not supported", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_cipher_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize context with default values */
    /* TODO: context was set to all zeros on allocation - no needd for this? */
    ctx->initialized = 0;
    ctx->enc_initialized = 0;
    ctx->dec_initialized = 0;
    ctx->enc = 0;
    ctx->mode = NONE;
    ctx->iv_size = 0;
    ctx->auth_data_size = 0;
    ctx->tag_size = 0;
    ctx->tag_set = 0;
    ctx->tag_set_ext = 0;
    ctx->algorithm = 0;
    ctx->data_size = 0;

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
    if (ctx->mode == GCM || ctx->mode == CCM) {
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

        WGW_LOG("encryption context initialized successfully");
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
        ctx->tag_size = GCM_TAG_SIZE;
    } else if (algorithm == GNUTLS_CIPHER_AES_128_CCM_8 ||
               algorithm == GNUTLS_CIPHER_AES_256_CCM_8) {
        ctx->tag_size = CCM_8_TAG_SIZE;
    } else if (ctx->mode == CCM) {
        ctx->tag_size = CCM_TAG_SIZE;
    } else {
        ctx->tag_size = 0;
    }

    ctx->initialized = 1;
    *_ctx = ctx;

    WGW_LOG("cipher context initialized successfully");
    return 0;
}

/**
 * Get the key size for the cipher algorith,
 *
 * @param [in] algorithm   GnuTLS cipher algorithm ID.
 * @return  Key size in bytes on success.
 * @return  0 when algorithm not supported.
 */
static int get_cipher_key_size(gnutls_cipher_algorithm_t algorithm)
{
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
static int wolfssl_cipher_setkey(void *_ctx, const void *key, size_t keysize)
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
    if (ctx->mode == XTS) {
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
        case XTS:
            WGW_LOG("setting key for XTS mode");
            ret = wc_AesXtsSetKeyNoInit(&ctx->cipher.aes_xts, key, keysize,
                ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesXtsSetKeyNoInit", ret);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            break;
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
static int get_iv_range(int mode, size_t* min, size_t* max)
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
static int wolfssl_cipher_setiv(void *_ctx, const void *iv, size_t iv_size)
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
static int wolfssl_cipher_getiv(void *_ctx, void *iv, size_t iv_size)
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
static int wolfssl_cipher_auth(void *_ctx, const void *auth_data,
    size_t auth_size)
{
    struct wolfssl_cipher_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();
    WGW_LOG("auth_size %zu", auth_size);

    if (!ctx->initialized) {
        WGW_ERROR("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check authentication data will fit in cache. */
    if (ctx->auth_data_size + auth_size > sizeof(ctx->auth_data)) {
        WGW_ERROR("Auth data too big: %ld + %ld > %ld", ctx->auth_data_size,
            auth_size, sizeof(ctx->auth_data));
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* Streaming must be a multiple of block size except for last. */
    if ((ctx->auth_data_size % AES_BLOCK_SIZE) != 0) {
        WGW_ERROR("Can only do multiple updates if multiple of block size");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Store AAD for later use in encrypt/decrypt operations. */
    XMEMCPY(ctx->auth_data + ctx->auth_data_size, auth_data, auth_size);
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
static int wolfssl_cipher_encrypt(void *_ctx, const void *src, size_t src_size,
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

        WGW_LOG("Caching platintext");

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

        /* Do encryption with the data we have. */
        ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, encr,
            ctx->data, ctx->data_size, ctx->iv, ctx->iv_size,
            ctx->tag, ctx->tag_size, ctx->auth_data, ctx->auth_data_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            gnutls_free(encr);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
        else {
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
static int wolfssl_cipher_decrypt(void *_ctx, const void *src, size_t src_size,
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

        /* Always use the decryption context for decryption operations */
        ret = wc_AesCbcDecrypt(&ctx->cipher.pair.aes_dec, dst, src, src_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesCbcDecrypt", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        unsigned char* ptr;
        unsigned char* decr;

        WGW_LOG("Caching platintext");

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
        /* If caller hasn't set tag then we are creating it. */
        if (!ctx->tag_set_ext) {
            /* Encrypt the ciphertext to get the plaintext.
             * Tag will ahve been created on plaintext which is of no use.
             */
            ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, decr, ctx->data,
                ctx->data_size, ctx->iv, ctx->iv_size,
                ctx->tag, ctx->tag_size, ctx->auth_data, ctx->auth_data_size);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
                gnutls_free(decr);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            /* Encrypt the plaintext to create the tag. */
            ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, decr, decr,
                ctx->data_size, ctx->iv, ctx->iv_size,
                ctx->tag, ctx->tag_size, ctx->auth_data, ctx->auth_data_size);
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
            ctx->tag, ctx->tag_size, ctx->auth_data, ctx->auth_data_size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            gnutls_free(decr);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
        else {
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
static void wolfssl_cipher_tag(void *_ctx, void *tag, size_t tag_size)
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

            /* Do authentication with no plaintext. */
            ret = wc_AesGcmEncrypt(&ctx->cipher.aes_ctx, NULL, NULL, 0, ctx->iv,
                ctx->iv_size, ctx->tag, ctx->tag_size, ctx->auth_data,
                ctx->auth_data_size);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_AesGcmEncrypt", ret);
            }
            else {
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
static int wolfssl_cipher_aead_encrypt(void *_ctx, const void *nonce,
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
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
    } else {
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
static int wolfssl_cipher_aead_decrypt(void *_ctx, const void *nonce,
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
            WGW_WOLFSSL_ERROR("wc_AesCcmEncrypt", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        return 0;
    } else {
        WGW_ERROR("AES mode not supported: %d", ctx->mode);
        return GNUTLS_E_INVALID_REQUEST;
    }
}


/**
 * Clean up cipher resources.
 *
 * @param [in, out] _ctx  Cipher context.
 */
static void wolfssl_cipher_deinit(void *_ctx)
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
                wc_AesFree(&ctx->cipher.aes_ctx);
                break;
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
    }

    gnutls_free(ctx);
}

/** Function pointers for the wolfSSL implementation of ciphers. */
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

/** Function pointers for the wolfSSL implementation of AEAD ciphers. */
static const gnutls_crypto_cipher_st wolfssl_cipher_aead_struct = {
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
static const gnutls_crypto_cipher_st wolfssl_cipher_aead_only_struct = {
    .init = wolfssl_cipher_init,
    .setkey = wolfssl_cipher_setkey,
    .aead_encrypt = wolfssl_cipher_aead_encrypt,
    .aead_decrypt = wolfssl_cipher_aead_decrypt,
    .deinit = wolfssl_cipher_deinit,
};

#if defined(WOLFSSL_AES_CFB) && !defined(WOLFSSL_NO_AES_CFB_1_8)
/** Function pointers for the wolfSSL implementation of ciphers. */
static const gnutls_crypto_cipher_st wolfssl_cipher_getiv_struct = {
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
static int wolfssl_cipher_register(void)
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

    return ret;
}

/*************************** MAC algorithms (HMAC) ***************************/

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
static int get_hash_type(gnutls_mac_algorithm_t algorithm)
{
    switch (algorithm) {
        case GNUTLS_MAC_MD5:
            WGW_LOG("using MD5 for HMAC");
            return WC_MD5;
        case GNUTLS_MAC_SHA1:
            WGW_LOG("using SHA1 for HMAC");
            return WC_SHA;
        case GNUTLS_MAC_SHA224:
            WGW_LOG("using SHA224 for HMAC");
            return WC_SHA224;
        case GNUTLS_MAC_SHA256:
            WGW_LOG("using SHA256 for HMAC");
            return WC_SHA256;
        case GNUTLS_MAC_SHA384:
            WGW_LOG("using SHA384 for HMAC");
            return WC_SHA384;
        case GNUTLS_MAC_SHA512:
            WGW_LOG("using SHA512 for HMAC");
            return WC_SHA512;
        case GNUTLS_MAC_MD5_SHA1:
            WGW_LOG("using MD5_SHA1 for HMAC");
            return WC_HASH_TYPE_MD5_SHA;
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
        return GNUTLS_E_HASH_FAILED;
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

    /* Finalize CMAC and get the result. */
    ret = wc_CmacFinal(&ctx->cmac_ctx, (byte*)digest, &digest_size);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_CmacFinal", ret);
        return GNUTLS_E_HASH_FAILED;
    }

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
        wc_CmacFree(&ctx->cmac_ctx);
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
    int initialized:1;
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
static int wolfssl_mac_register(void)
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

/************************ Digest algorithms *****************************/

/** Context structure for digest operations with wolfssl. */
struct wolfssl_hash_ctx {
    /** All supported hash algorithm wolfSSL objects. */
    union {
        /** wolfSSL MD5 object.  */
        wc_Md5    md5;
        /** wolfSSL SHA-1 object.  */
        wc_Sha    sha;
        /** wolfSSL SHA-224 object.  */
        wc_Sha224 sha224;
        /** wolfSSL SHA-256 object.  */
        wc_Sha256 sha256;
        /** wolfSSL SHA-384 object.  */
        wc_Sha384 sha384;
        /** wolfSSL SHA-512 object.  */
        wc_Sha512 sha512;
        /** wolfSSL SHA-512 object.  */
        wc_Sha3   sha3;
    } obj;
    /** The GnuTLS digest algorithm ID. */
    gnutls_digest_algorithm_t algorithm;
    /** Indicates that this context as been initialized. */
    int initialized:1;
};

/** Array of supported digests. */
static const int wolfssl_digest_supported[] = {
    [GNUTLS_DIG_MD5] = 1,
    [GNUTLS_DIG_SHA1] = 1,
    [GNUTLS_DIG_SHA224] = 1,
    [GNUTLS_DIG_SHA256] = 1,
    [GNUTLS_DIG_SHA384] = 1,
    [GNUTLS_DIG_SHA512] = 1,
    [GNUTLS_DIG_SHA3_224] = 1,
    [GNUTLS_DIG_SHA3_256] = 1,
    [GNUTLS_DIG_SHA3_384] = 1,
    [GNUTLS_DIG_SHA3_512] = 1,
};
/** Length of array of supported digests. */
#define WOLFSSL_DIGEST_SUPPORTED_LEN (int)(sizeof(wolfssl_digest_supported) / \
                                           sizeof(wolfssl_digest_supported[0]))

/**
 * Check if GnuTLS digest algorithm ID is supported.
 *
 * @param [in] algorithm  GnuTLS digest algorithm ID.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int is_digest_supported(int algorithm)
{
    return (algorithm >= 0 && algorithm < WOLFSSL_DIGEST_SUPPORTED_LEN &&
            wolfssl_digest_supported[algorithm] == 1);
}

/**
 * Initialize the wolfSSL digest.
 *
 * @param [in, out] ctx  Hash context.
 * @return  0 on success.
 * @return  Other value on failure.
 */
static int wolfssl_digest_init_alg(struct wolfssl_hash_ctx *ctx)
{
    int ret = -1;
    gnutls_digest_algorithm_t algorithm = ctx->algorithm;

    /* initialize the wolfSSL digest object */
    if (algorithm == GNUTLS_DIG_MD5) {
        ret = wc_InitMd5(&ctx->obj.md5);
    } else if (algorithm == GNUTLS_DIG_SHA1) {
        ret = wc_InitSha(&ctx->obj.sha);
    } else if (algorithm == GNUTLS_DIG_SHA224) {
        ret = wc_InitSha224(&ctx->obj.sha224);
    } else if (algorithm == GNUTLS_DIG_SHA256) {
        ret = wc_InitSha256(&ctx->obj.sha256);
    } else if (algorithm == GNUTLS_DIG_SHA384) {
        ret = wc_InitSha384(&ctx->obj.sha384);
    } else if (algorithm == GNUTLS_DIG_SHA512) {
        ret = wc_InitSha512(&ctx->obj.sha512);
    } else if (algorithm == GNUTLS_DIG_SHA3_224) {
        ret = wc_InitSha3_224(&ctx->obj.sha3, NULL, INVALID_DEVID);
    } else if (algorithm == GNUTLS_DIG_SHA3_256) {
        ret = wc_InitSha3_256(&ctx->obj.sha3, NULL, INVALID_DEVID);
    } else if (algorithm == GNUTLS_DIG_SHA3_384) {
        ret = wc_InitSha3_384(&ctx->obj.sha3, NULL, INVALID_DEVID);
    } else if (algorithm == GNUTLS_DIG_SHA3_512) {
        ret = wc_InitSha3_512(&ctx->obj.sha3, NULL, INVALID_DEVID);
    }

    return ret;
}
/**
 * Initialize a digest context.
 *
 * @param [in]  algorithm  GnuTLS digest algorithm ID.
 * @param [out] _ctx       Digest context.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when digest algorithm is not supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when initialization of digest fails.
 */
static int wolfssl_digest_init(gnutls_digest_algorithm_t algorithm, void **_ctx)
{
    struct wolfssl_hash_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("Digest algorithm %d", algorithm);

    /* Return error if digest's not supported */
    if (!is_digest_supported(algorithm)) {
        WGW_ERROR("digest %d is not supported", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate context. */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hash_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Set algorithm. */
    ctx->algorithm = algorithm;

    /* Initialize digest. */
    ret = wolfssl_digest_init_alg(ctx);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wolfSSL digest init", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->initialized = 1;
    *_ctx = ctx;

    return 0;
}

/**
 * Update the digest with data.
 *
 * @param [in, out] _ctx      Digest context.
 * @param [in]      text      Text to update digest with.
 * @param [in]      textsize  Size of text in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL update operation fails.
 */
static int wolfssl_digest_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_hash_ctx *ctx = _ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    if (!ctx->initialized) {
        WGW_ERROR("Digest context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Can only do 32-bit sized updates at a time. */
    do {
        /* Use a max that is a multiple of the block size. */
        word32 size = 0xfffffff0;
        if (textsize < (size_t)size) {
            size = textsize;
        }

        /* Update the wolfSSL digest object with data */
        if (ctx->algorithm == GNUTLS_DIG_MD5) {
            ret = wc_Md5Update(&ctx->obj.md5, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA1) {
            ret = wc_ShaUpdate(&ctx->obj.sha, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA224) {
            ret = wc_Sha224Update(&ctx->obj.sha224, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA256) {
            ret = wc_Sha256Update(&ctx->obj.sha256, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA384) {
            ret = wc_Sha384Update(&ctx->obj.sha384, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA512) {
            ret = wc_Sha512Update(&ctx->obj.sha512, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_224) {
            ret = wc_Sha3_224_Update(&ctx->obj.sha3, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_256) {
            ret = wc_Sha3_256_Update(&ctx->obj.sha3, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_384) {
            ret = wc_Sha3_384_Update(&ctx->obj.sha3, (const byte*)text, size);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_512) {
            ret = wc_Sha3_512_Update(&ctx->obj.sha3, (const byte*)text, size);
        }
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wolfSSL digest update", ret);
            return GNUTLS_E_HASH_FAILED;
        }

        /* Move over processed text. */
        text += size;
        textsize -= size;
    } while (textsize > 0);

    return 0;
}

/**
 * Output the digest result.
 *
 * @param [in, out]  _ctx         Digest context.
 * @param [out]      digest      Buffer to hold digest.
 * @param [in]       digestsize  Size of buffer in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when digestsize is too small for HMAC
 *          output.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL HMAC operation fails.
 */
static int wolfssl_digest_output(void *_ctx, void *digest, size_t digestsize)
{
    struct wolfssl_hash_ctx *ctx = _ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    if (!ctx->initialized) {
        WGW_ERROR("Digest context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (digest == NULL) {
        /* No output buffer means to discard result and re-initialize. */
        ret = wolfssl_digest_init_alg(ctx);
        if (ret != 0) {
            return GNUTLS_E_HASH_FAILED;
        }
        return 0;
    }

    /* Finalize the digest and get the result. */
    if (ctx->algorithm == GNUTLS_DIG_MD5) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_MD5_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for MD5 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Md5Final(&ctx->obj.md5, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA1) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-1 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_ShaFinal(&ctx->obj.sha, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA224) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA224_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-224 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha224Final(&ctx->obj.sha224, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA256) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA256_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-256 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha256Final(&ctx->obj.sha256, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA384) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA384_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-384 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha384Final(&ctx->obj.sha384, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA512) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA512_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-512 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha512Final(&ctx->obj.sha512, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_224) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_224_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-224 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_224_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_256) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_256_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-256 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_256_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_384) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_384_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-384 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_384_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_512) {
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_512_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-512 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_512_Final(&ctx->obj.sha3, (byte*)digest);
    }
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wolfSSL digest final", ret);
        return GNUTLS_E_HASH_FAILED;
    }

    return 0;
}

/**
 * Clean up digest resources.
 *
 * @param [in, out]  _ctx  Digest context.
 */
static void wolfssl_digest_deinit(void *_ctx)
{
    struct wolfssl_hash_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();

    if (ctx && ctx->initialized) {
        /* Free the wolfSSL digest object. */
        if (ctx->algorithm == GNUTLS_DIG_MD5) {
            wc_Md5Free(&ctx->obj.md5);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA1) {
            wc_ShaFree(&ctx->obj.sha);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA224) {
            wc_Sha224Free(&ctx->obj.sha224);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA256) {
            wc_Sha256Free(&ctx->obj.sha256);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA384) {
            wc_Sha384Free(&ctx->obj.sha384);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA512) {
            wc_Sha512Free(&ctx->obj.sha512);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_224) {
            wc_Sha3_224_Free(&ctx->obj.sha3);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_256) {
            wc_Sha3_256_Free(&ctx->obj.sha3);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_384) {
            wc_Sha3_384_Free(&ctx->obj.sha3);
        } else if (ctx->algorithm == GNUTLS_DIG_SHA3_512) {
            wc_Sha3_512_Free(&ctx->obj.sha3);
        }
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/**
 * One-shot hash function.
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
static int wolfssl_digest_fast(gnutls_digest_algorithm_t algorithm,
    const void *text, size_t textsize, void *digest)
{
    struct wolfssl_hash_ctx *ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    /* Initialize digest context. */
    ret = wolfssl_digest_init(algorithm, (void**)&ctx);
    if (ret != 0) {
        return ret;
    }

    /* Hash the text. */
    ret = wolfssl_digest_hash(ctx, text, textsize);
    if (ret != 0) {
        wolfssl_digest_deinit(ctx);
        return ret;
    }

    /* Output the digest. */
    ret = wolfssl_digest_output(ctx, digest, WC_SHA512_DIGEST_SIZE);
    if (ret != 0) {
        wolfssl_digest_deinit(ctx);
        return ret;
    }

    /* Dispose of digest context. */
    wolfssl_digest_deinit(ctx);

    return 0;
}


/** Function pointers for the digest implementation. */
static const gnutls_crypto_digest_st wolfssl_digest_struct = {
    .init = wolfssl_digest_init,
    .hash = wolfssl_digest_hash,
    .output = wolfssl_digest_output,
    .deinit = wolfssl_digest_deinit,
    .fast = wolfssl_digest_fast
};

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
#ifdef WOLFSSL_SHAKE128
/** Max block size. */
#define MAX_SHAKE_BLOCK_SIZE    WC_SHA3_128_BLOCK_SIZE
#else
/** Max block size. */
#define MAX_SHAKE_BLOCK_SIZE    WC_SHA3_256_BLOCK_SIZE
#endif

/** Context structure for Shake operations with wolfSSL. */
struct wolfssl_shake_ctx {
    wc_Shake  shake;
    /** The GnuTLS digest algorithm ID. */
    gnutls_digest_algorithm_t algorithm;
    /** Indicates that this context as been initialized. */
    int initialized:1;
    /** Started squeezing - no more absorb calls allowed. */
    int squeezing:1;
    /** Output block. */
    byte block[MAX_SHAKE_BLOCK_SIZE];
    /** Number of bytes of block already returned. */
    int used;
};

/** Array of supported Shakes. */
static const int wolfssl_shake_supported[] = {
#ifdef WOLFSSL_SHAKE128
    [GNUTLS_DIG_SHAKE_128] = 1,
#endif
#ifdef WOLFSSL_SHAKE256
    [GNUTLS_DIG_SHAKE_256] = 1,
#endif
};
/** Length of array of supported digests. */
#define WOLFSSL_SHAKE_SUPPORTED_LEN (int)(sizeof(wolfssl_shake_supported) / \
                                          sizeof(wolfssl_shake_supported[0]))

/**
 * Check if GnuTLS Shake digest algorithm ID is supported.
 *
 * @param [in] algorithm  GnuTLS digest algorithm ID.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int is_shake_supported(int algorithm)
{
    return (algorithm >= 0 && algorithm < WOLFSSL_SHAKE_SUPPORTED_LEN &&
            wolfssl_shake_supported[algorithm] == 1);
}

/**
 * Initialize the wolfSSL Shake.
 *
 * @param [in, out] ctx  Hash context.
 * @return  0 on success.
 * @return  Other value on failure.
 */
static int wolfssl_shake_init_alg(struct wolfssl_shake_ctx *ctx)
{
    int ret = -1;
    gnutls_digest_algorithm_t algorithm = ctx->algorithm;

    /* initialize the wolfSSL digest object */
#ifdef WOLFSSL_SHAKE128
    if (algorithm == GNUTLS_DIG_SHAKE_128) {
        ret = wc_InitShake128(&ctx->shake, NULL, INVALID_DEVID);
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (algorithm == GNUTLS_DIG_SHAKE_256) {
        ret = wc_InitShake256(&ctx->shake, NULL, INVALID_DEVID);
    }
#endif

    return ret;
}
/**
 * Initialize a Shake digest context.
 *
 * @param [in]  algorithm  GnuTLS Shake digest algorithm ID.
 * @param [out] _ctx       Digest context.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when Shake digest algorithm is not
 *           supported.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_HASH_FAILED when initialization of Shake digest fails.
 */
static int wolfssl_shake_init(gnutls_digest_algorithm_t algorithm, void **_ctx)
{
    struct wolfssl_shake_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("Digest algorithm %d", algorithm);

    /* Return error if Shake digest is not supported */
    if (!is_shake_supported(algorithm)) {
        WGW_ERROR("Shake digest %d is not supported", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate context. */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_shake_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize digest. */
    ret = wolfssl_shake_init_alg(ctx);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wolfSSL digest init", ret);
        gnutls_free(ctx);
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->algorithm = algorithm;
    ctx->initialized = 1;
    *_ctx = ctx;

    return 0;
}

/**
 * Update the Shake digest with data.
 *
 * @param [in, out] _ctx      Digest context.
 * @param [in]      text      Text to update digest with.
 * @param [in]      textsize  Size of text in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context not initialized.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL update operation fails.
 */
static int wolfssl_shake_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_shake_ctx *ctx = _ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    if (!ctx->initialized) {
        WGW_ERROR("Digest context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
    if (ctx->squeezing) {
        WGW_ERROR("SHAKE is already aqueezing");
        return GNUTLS_E_INVALID_REQUEST;
    }
#endif

    /* Can only do 32-bit sized updates at a time. */
    do {
        /* Use a max that is a multiple of the block size. */
        word32 size = 0xfffffff0;
        if (textsize < (size_t)size) {
            size = textsize;
        }

        /* Update the wolfSSL Shake digest object with data */
    #ifdef WOLFSSL_SHAKE128
        if (ctx->algorithm == GNUTLS_DIG_SHAKE_128) {
            ret = wc_Shake128_Absorb(&ctx->shake, (const byte*)text, size);
        }
    #endif
    #ifdef WOLFSSL_SHAKE256
        if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
            ret = wc_Shake256_Absorb(&ctx->shake, (const byte*)text, size);
        }
    #endif
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wolfSSL digest update", ret);
            return GNUTLS_E_HASH_FAILED;
        }

        /* Move over processed text. */
        text += size;
        textsize -= size;
    } while (textsize > 0);

    return 0;
}

/**
 * Output the Shake digest data.
 *
 * @param [in, out]  _ctx         Digest context.
 * @param [out]      digest      Buffer to hold digest.
 * @param [in]       digestsize  Size of buffer in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context is not initialized.
 * @return  GNUTLS_E_SHORT_MEMORY_BUFFER when digestsize is too small for HMAC
 *          output.
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL HMAC operation fails.
 */
static int wolfssl_shake_output(void *_ctx, void *digest, size_t digestsize)
{
    struct wolfssl_shake_ctx *ctx = _ctx;
    int ret = -1;
    size_t size;

    WGW_FUNC_ENTER();

    if (!ctx->initialized) {
        WGW_ERROR("Digest context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (digest == NULL) {
        /* No output buffer means to discard result and re-initialize. */
        ret = wolfssl_shake_init_alg(ctx);
        if (ret != 0) {
            return GNUTLS_E_HASH_FAILED;
        }
        return 0;
    }

#ifdef WOLFSSL_SHAKE128
    if (ctx->algorithm == GNUTLS_DIG_SHAKE_128) {
        /* Take from cache if not any and not all used. */
	if (ctx->used > 0 && ctx->used < WC_SHA3_128_BLOCK_SIZE) {
            size = MIN(digestsize, WC_SHA3_128_BLOCK_SIZE);
            XMEMCPY(digest, ctx->block + ctx->used, size);
            digest += size;
            digestsize -= size;
            ctx->used += size;
        }

        /* Generate more blocks if more output needed. */
        while (digestsize > 0) {
            size = MIN(digestsize, WC_SHA3_128_BLOCK_SIZE);

            /* Put straight into output if all bytes needed for output. */
            if (size == WC_SHA3_128_BLOCK_SIZE) {
                ret = wc_Shake128_SqueezeBlocks(&ctx->shake, (byte*)digest,
                    size);
            /* Put into cache and copy out needed bytes. */
            } else {
                ret = wc_Shake128_SqueezeBlocks(&ctx->shake, ctx->block,
                    size);
                if (ret == 0) {
                    XMEMCPY(digest, ctx->block, size);
                    ctx->used = size;
                }
            }
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_Shake128_SqueezeBlocks", ret);
                return GNUTLS_E_HASH_FAILED;
            }

            /* Skip over output generated. */
            digest += size;
            digestsize -= size;
        }
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
        /* Take from cache if not any and not all used. */
        if (ctx->used > 0 && ctx->used < WC_SHA3_256_BLOCK_SIZE) {
            size = MIN(digestsize, WC_SHA3_256_BLOCK_SIZE);
            XMEMCPY(digest, ctx->block + ctx->used, size);
            digest += size;
            digestsize -= size;
            ctx->used += size;
        }

        /* Generate more blocks if more output needed. */
        while (digestsize > 0) {
            size = MIN(digestsize, WC_SHA3_256_BLOCK_SIZE);

            /* Put straight into output if all bytes needed for output. */
            if (size == WC_SHA3_256_BLOCK_SIZE) {
                ret = wc_Shake256_SqueezeBlocks(&ctx->shake, (byte*)digest,
                    size);
            /* Put into cache and copy out needed bytes. */
            } else {
                ret = wc_Shake256_SqueezeBlocks(&ctx->shake, ctx->block,
                    size);
                if (ret == 0) {
                    XMEMCPY(digest, ctx->block, size);
                    ctx->used = size;
                }
            }
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_Shake256_SqueezeBlocks", ret);
                return GNUTLS_E_HASH_FAILED;
            }

            /* Skip over output generated. */
            digest += size;
            digestsize -= size;
        }
    }
#endif

    /* When squeezing, can no longer add data. */
    ctx->squeezing = 1;

    return 0;
}

/**
 * Clean up digest resources.
 *
 * @param [in, out]  _ctx  Digest context.
 */
static void wolfssl_shake_deinit(void *_ctx)
{
    struct wolfssl_shake_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();

    if (ctx && ctx->initialized) {
        /* Free the wolfSSL Shake digest object. */
    #ifdef WOLFSSL_SHAKE128
        if (ctx->algorithm == GNUTLS_DIG_SHAKE_128) {
            wc_Shake128_Free(&ctx->shake);
        }
    #endif
    #ifdef WOLFSSL_SHAKE256
        if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
            wc_Shake256_Free(&ctx->shake);
        }
    #endif
        ctx->initialized = 0;
    }

    gnutls_free(ctx);
}

/**
 * One-shot Shake hash function.
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
static int wolfssl_shake_fast(gnutls_digest_algorithm_t algorithm,
    const void *text, size_t textsize, void *digest)
{
    struct wolfssl_shake_ctx *ctx;
    int ret = -1;

    WGW_FUNC_ENTER();

    /* Initialize Shake digest context. */
    ret = wolfssl_shake_init(algorithm, (void**)&ctx);
    if (ret != 0) {
        return ret;
    }

    /* Absorb the text. */
    ret = wolfssl_shake_hash(ctx, text, textsize);
    if (ret != 0) {
        wolfssl_shake_deinit(ctx);
        return ret;
    }

    /* Output the Shake data. */
    ret = wolfssl_shake_output(ctx, digest, WC_SHA512_DIGEST_SIZE);
    if (ret != 0) {
        wolfssl_shake_deinit(ctx);
        return ret;
    }

    /* Dispose of Shake digest context. */
    wolfssl_shake_deinit(ctx);

    return 0;
}

/** Function pointers for the Shake digest implementation. */
static const gnutls_crypto_digest_st wolfssl_shake_struct = {
    .init = wolfssl_shake_init,
    .hash = wolfssl_shake_hash,
    .output = wolfssl_shake_output,
    .deinit = wolfssl_shake_deinit,
    .fast = wolfssl_shake_fast
};
#endif /* WOLFSSL_SHAKE128 || WOLFSSL_SHAKE256 */

/**
 * Register the digest algorithms with GnuTLS.
 *
 * @return  0 on success.
 */
static int wolfssl_digest_register(void)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    /* register md5 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_MD5]) {
        WGW_LOG("registering md5");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_MD5, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering md5 failed");
            return ret;
        }
    }
    /* register sha1 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA1]) {
        WGW_LOG("registering sha1");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA1, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha1 failed");
            return ret;
        }
    }
    /* register sha224 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA224]) {
        WGW_LOG("registering sha224");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA224, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha224 failed");
            return ret;
        }
    }
    /* register sha256 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA256]) {
        WGW_LOG("registering sha256");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA256, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha256 failed");
            return ret;
        }
    }
    /* register sha384 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA384]) {
        WGW_LOG("registering sha384");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA384, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha384 failed");
            return ret;
        }
    }
    /* register sha512 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA512]) {
        WGW_LOG("registering sha512");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA512, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha512 failed");
            return ret;
        }
    }
    /* register sha3-224 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA3_224]) {
        WGW_LOG("registering sha3-224");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA3_224, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha3-224 failed");
            return ret;
        }
    }
    /* register sha3-256 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA3_256]) {
        WGW_LOG("registering sha3-256");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA3_256, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha3-256 failed");
            return ret;
        }
    }
    /* register sha3-384 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA3_384]) {
        WGW_LOG("registering sha3-384");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA3_384, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha3-384 failed");
            return ret;
        }
    }
    /* register sha3-512 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHA3_512]) {
        WGW_LOG("registering sha3-512");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHA3_512, 80, &wolfssl_digest_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering sha3-512 failed");
            return ret;
        }
    }
#ifdef WOLFSSL_SHAKE128
    /* register shake-128 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHAKE_128]) {
        WGW_LOG("registering shake-128");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHAKE_128, 80, &wolfssl_shake_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering shake-128 failed");
            return ret;
        }
    }
#endif
#ifdef WOLFSSL_SHAKE256
    /* register shake-256 if it's supported */
    if (wolfssl_digest_supported[GNUTLS_DIG_SHAKE_256]) {
        WGW_LOG("registering shake-256");
        ret = gnutls_crypto_single_digest_register(
                GNUTLS_DIG_SHAKE_256, 80, &wolfssl_shake_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering shake-256 failed");
            return ret;
        }
    }
#endif

    return ret;
}

/************************ Public key algorithms *****************************/

/* context structure for wolfssl pk */
struct wolfssl_pk_ctx {
    union {
        ecc_key ecc;
        ed25519_key ed25519;
        ed448_key ed448;
        curve25519_key x25519;
        curve448_key x448;
        RsaKey rsa;
    } key;
    int initialized;
    /** The GnuTLS public key algorithm ID.  */
    gnutls_pk_algorithm_t algo;
    WC_RNG rng;
    int rng_initialized;

    byte pub_data[1024];
    word32 pub_data_len;
};

/* mapping of gnutls pk algorithms to wolfssl pk */
static const int wolfssl_pk_supported[] = {
        [GNUTLS_PK_UNKNOWN] = 1,
        [GNUTLS_PK_ECDSA] = 1,
        [GNUTLS_PK_EDDSA_ED25519] = 1,
        [GNUTLS_PK_EDDSA_ED448] = 1,
        [GNUTLS_PK_ECDH_X25519] = 1,
        [GNUTLS_PK_ECDH_X448] = 1,
        [GNUTLS_PK_RSA] = 1,
        [GNUTLS_PK_RSA_PSS] = 1,
};

static const int wolfssl_pk_sign_supported[] = {
        [GNUTLS_PK_UNKNOWN] = 1,
        [GNUTLS_SIGN_RSA_SHA256] = 1,
        [GNUTLS_SIGN_RSA_SHA384] = 1,
        [GNUTLS_SIGN_RSA_SHA512] = 1,
        [GNUTLS_SIGN_RSA_PSS_SHA256] = 1,
        [GNUTLS_SIGN_RSA_PSS_SHA384] = 1,
        [GNUTLS_SIGN_RSA_PSS_SHA512] = 1,
        [GNUTLS_SIGN_ECDSA_SHA256] = 1,
        [GNUTLS_SIGN_ECDSA_SECP256R1_SHA256] = 1,
        [GNUTLS_SIGN_ECDSA_SHA384] = 1,
        [GNUTLS_SIGN_ECDSA_SECP384R1_SHA384] = 1,
        [GNUTLS_SIGN_ECDSA_SHA512] = 1,
        [GNUTLS_SIGN_ECDSA_SECP521R1_SHA512] = 1,
        [GNUTLS_SIGN_EDDSA_ED25519] = 1,
        [GNUTLS_SIGN_EDDSA_ED448] = 1,
        [GNUTLS_SIGN_RSA_PSS_RSAE_SHA256] = 1,
        [GNUTLS_SIGN_RSA_PSS_RSAE_SHA384] = 1,
        [GNUTLS_SIGN_RSA_PSS_RSAE_SHA512] = 1,
};

/* import a private key from raw X.509 data using trial-and-error approach */
/* TODO: Refactor this to use ToTraditional_ex to get the algID instead of using
 * the trial-and-error approach */
static int
wolfssl_pk_import_privkey_x509(void **_ctx, gnutls_pk_algorithm_t **privkey_algo,
        const gnutls_datum_t *data, gnutls_x509_crt_fmt_t format)
{
    WGW_LOG("wolfssl: wolfssl_pk_import_privkey_x509");

    struct wolfssl_pk_ctx *ctx;
    int ret = GNUTLS_E_INVALID_REQUEST; /* Default error if all imports fail */
    int key_found = 0;
    byte* keyData = data->data;
    word32 keySize = data->size;
    DerBuffer* derBuf = NULL;

    /* Validate input parameters */
    if (!_ctx) {
        WGW_LOG("wolfssl: invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate a new context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize RNG */
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        WGW_LOG("wolfssl: wc_InitRng failed with code %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    ctx->rng_initialized = 1;

    /* Only support PEM and DER formats */
    if (format != GNUTLS_X509_FMT_PEM && format != GNUTLS_X509_FMT_DER) {
        WGW_LOG("wolfssl: unsupported format for private key import");
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Empty data check */
    if (!data || !data->data || data->size == 0) {
        WGW_LOG("wolfssl: empty data for private key import");
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Convert PEM to DER if needed */
    if (format == GNUTLS_X509_FMT_PEM) {
        WGW_LOG("wolfssl: converting PEM to DER");
        ret = wc_PemToDer(keyData, keySize, PRIVATEKEY_TYPE, &derBuf, NULL, NULL, NULL);
        if (ret != 0 || derBuf == NULL) {
            WGW_LOG("wolfssl: PEM to DER conversion failed with code %d\n", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_ASN1_DER_ERROR;
        }
        WGW_LOG("wolfssl: wc_PemToder ret: %d", ret);
        WGW_LOG("wolfssl: derBuf length: %d", derBuf->length);
        /* Update key data and size to use DER data */
        keyData = derBuf->buffer;
        keySize = derBuf->length;
    }

    WGW_LOG("Converted correctly from PEM to der");

    /* Try each key type until one works */
    /* Try ECDSA */
    if (!key_found) {
        WGW_LOG("wolfssl: trying ECDSA private key import");
        ret = wc_ecc_init(&ctx->key.ecc);
        if (ret == 0) {
            ret = wc_EccPrivateKeyDecode(keyData, &(word32){0}, &ctx->key.ecc, keySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: ECDSA private key import succeeded");
                ctx->algo = GNUTLS_PK_ECDSA;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: ECDSA private key import failed with code %d", ret);
                wc_ecc_free(&ctx->key.ecc);
            }
        }
    }

    /* Try Ed25519 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying Ed25519 private key import");
        ret = wc_ed25519_init(&ctx->key.ed25519);
        if (ret == 0) {
            ret = wc_Ed25519PrivateKeyDecode(keyData, &(word32){0},
                    &ctx->key.ed25519, keySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: Ed25519 private key import succeeded");
                ctx->algo = GNUTLS_PK_EDDSA_ED25519;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: Ed25519 private key import failed with code %d", ret);
                wc_ed25519_free(&ctx->key.ed25519);
            }
        }
    }

    /* Try Ed448 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying Ed448 private key import");
        ret = wc_ed448_init(&ctx->key.ed448);
        if (ret == 0) {
            ret = wc_Ed448PrivateKeyDecode(keyData, &(word32){0}, &ctx->key.ed448, keySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: Ed448 private key import succeeded");
                ctx->algo = GNUTLS_PK_EDDSA_ED448;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: Ed448 private key import failed with code %d", ret);
                wc_ed448_free(&ctx->key.ed448);
            }
        }
    }

    /* Try X25519 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying X25519 private key import");
        ret = wc_curve25519_init(&ctx->key.x25519);
        if (ret == 0) {
            ret = wc_Curve25519PrivateKeyDecode(keyData, &(word32){0}, 
                    &ctx->key.x25519, keySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: X25519 private key import succeeded");
                ctx->algo = GNUTLS_PK_ECDH_X25519;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: X25519 private key import failed with code %d", ret);
                wc_curve25519_free(&ctx->key.x25519);
            }
        }
    }

    /* Try X448 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying X448 private key import");
        ret = wc_curve448_init(&ctx->key.x448);
        if (ret == 0) {
            ret = wc_Curve448PrivateKeyDecode(keyData, &(word32){0}, 
                    &ctx->key.x448, keySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: X448 private key import succeeded\n");
                ctx->algo = GNUTLS_PK_ECDH_X448;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: X448 private key import failed with code %d", ret);
                wc_curve448_free(&ctx->key.x448);
            }
        }
    }

    /* Try RSA */
    if (!key_found) {
        WGW_LOG("wolfssl: trying RSA private key import");
        ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
        if (ret == 0) {
            ret = wc_RsaPrivateKeyDecode(keyData, &(word32){0}, &ctx->key.rsa, keySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: RSA private key import succeeded");
                ctx->algo = GNUTLS_PK_RSA;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: RSA private key import failed with code %d", ret);
                wc_FreeRsaKey(&ctx->key.rsa);
            }
        }
    }


    /* Free the DER buffer if we created one */
    if (derBuf) {
        wc_FreeDer(&derBuf);
        WGW_LOG("wolfssl: der freed");
    }

    if (!key_found) {
        /* No supported key type was found */
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        WGW_LOG("wolfssl: could not determine private key type, using fallback");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    *privkey_algo = &ctx->algo;

    ctx->initialized = 1;
    *_ctx = ctx;

    WGW_LOG("wolfssl: private key imported successfully");
    return 0;
}

static int
wolfssl_pk_copy(void **_dst, void *src, gnutls_pk_algorithm_t algo) {
    WGW_FUNC_ENTER();
    struct wolfssl_pk_ctx *ctx_src;
    struct wolfssl_pk_ctx *ctx_dst;

    /* Validate input parameters */
    if (!src) {
        WGW_LOG("wolfssl: context not initialized");
        if (wolfssl_pk_supported[algo]) {
            WGW_LOG("wolfssl: algo supported, initializing context");
            /* Allocate a new context */
            ctx_src = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
            if (ctx_src == NULL) {
                return GNUTLS_E_MEMORY_ERROR;
            }
            ctx_src->algo = algo;
            ctx_src->initialized = 1;
        } else {
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
        }
    } else {
        ctx_src = src;
    }

    ctx_dst = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx_dst == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    memcpy(ctx_dst, ctx_src, sizeof(struct wolfssl_pk_ctx));
    WGW_LOG("wolfssl: copied context from x509 struct to priv key struct");

    *_dst = ctx_dst;

    return 0;
}

/* import a public key from raw X.509 data using trial-and-error approach */
/* TODO: Refactor this to use ToTraditional_ex to get the algID instead of using
 * the trial-and-error approach */
static int
wolfssl_pk_import_pubkey_x509(void **_ctx, gnutls_pk_algorithm_t **pubkey_algo,
        gnutls_datum_t *data,
        unsigned int flags)
{
    WGW_LOG("wolfssl: wolfssl_pk_import_pubkey_x509");

    (void)flags;
    struct wolfssl_pk_ctx *ctx;
    int ret = GNUTLS_E_INVALID_REQUEST; /* Default error if all imports fail */
    int key_found = 0;
    DecodedCert cert;
    byte *publicKeyDer = NULL;
    word32 publicKeySize = 0;

    /* Validate input parameters */
    if (!_ctx) {
        WGW_LOG("wolfssl: invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate a new context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Empty data check */
    if (!data->data || data->size == 0) {
        WGW_LOG("wolfssl: empty data for public key import");
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("Public key data size: %d bytes", data->size);

    /* Initialize the decoded cert structure */
    wc_InitDecodedCert(&cert, data->data, data->size, NULL);

    /* Parse the certificate */
    ret = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        WGW_LOG("wolfssl: Failed to parse X.509 certificate: %d", ret);
        wc_FreeDecodedCert(&cert);
        gnutls_free(ctx);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    /* Extract just the public key from the certificate */
    publicKeySize = cert.pubKeySize;
    publicKeyDer = gnutls_malloc(publicKeySize);
    if (publicKeyDer == NULL) {
        wc_FreeDecodedCert(&cert);
        gnutls_free(ctx);
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(publicKeyDer, cert.publicKey, publicKeySize);

    /* Now we're done with the cert structure */
    wc_FreeDecodedCert(&cert);

    /* Try ECDSA key first */
    if (!key_found) {
        WGW_LOG("wolfssl: trying ECDSA public key import");
        ret = wc_ecc_init(&ctx->key.ecc);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_EccPublicKeyDecode(publicKeyDer, &idx, &ctx->key.ecc, publicKeySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: ECDSA public key import succeeded");
                ctx->algo = GNUTLS_PK_ECDSA;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: ECDSA public key import failed with code %d", ret);
                wc_ecc_free(&ctx->key.ecc);
            }
        }
    }

    /* Try Ed25519 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying Ed25519 public key import");
        ret = wc_ed25519_init(&ctx->key.ed25519);
        if (ret == 0) {
            ret = wc_ed25519_import_public(publicKeyDer, publicKeySize, &ctx->key.ed25519);

            if (ret == 0) {
                WGW_LOG("wolfssl: Ed25519 public key import succeeded");
                ctx->pub_data_len = ED25519_PUB_KEY_SIZE;
                ret = wc_ed25519_export_public(&ctx->key.ed25519, ctx->pub_data, &ctx->pub_data_len);
                if (ret != 0) {
                    WGW_LOG("wolfssl: Ed25519 public key export failed with code: %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                } else {
                    WGW_LOG("wolfssl: Ed25519 public key export succeeded");
                }
                ctx->algo = GNUTLS_PK_EDDSA_ED25519;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: Ed25519 public key import failed with code %d", ret);
                wc_ed25519_free(&ctx->key.ed25519);
            }

        } else {
            WGW_LOG("wolfssl: Ed25519 public key already imported - derived from private previously");
        }
    }

    /* Try Ed448 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying Ed448 public key import");
        ret = wc_ed448_init(&ctx->key.ed448);
        if (ret == 0) {
            ret = wc_ed448_import_public(publicKeyDer, publicKeySize, &ctx->key.ed448);

            if (ret == 0) {
                WGW_LOG("wolfssl: Ed448 public key import succeeded");
                ctx->pub_data_len = ED448_PUB_KEY_SIZE;
                ret = wc_ed448_export_public(&ctx->key.ed448, ctx->pub_data, &ctx->pub_data_len);
                if (ret != 0) {
                    WGW_LOG("wolfssl: Ed448 public key export failed with code: %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                } else {
                    WGW_LOG("wolfssl: Ed448 public key export succeeded");
                }
                ctx->algo = GNUTLS_PK_EDDSA_ED448;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: Ed448 public key import failed with code %d", ret);
                wc_ed448_free(&ctx->key.ed448);
            }

        } else {
            WGW_LOG("wolfssl: Ed448 public key already imported - derived from private previously");
        }
    }

    /* Try X25519 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying X25519 public key import");
        ret = wc_curve25519_init(&ctx->key.x25519);
        if (ret == 0) {
            ret = wc_curve25519_import_public(publicKeyDer, publicKeySize, &ctx->key.x25519);

            if (ret == 0) {
                WGW_LOG("wolfssl: x25519 public key import succeeded");
                ctx->pub_data_len = CURVE25519_PUB_KEY_SIZE;
                ret = wc_curve25519_export_public(&ctx->key.x25519, ctx->pub_data, &ctx->pub_data_len);
                if (ret != 0) {
                    WGW_LOG("wolfssl: x25519 public key export failed with code: %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                } else {
                    WGW_LOG("wolfssl: x25519 public key export succeeded");
                }
                ctx->algo = GNUTLS_PK_ECDH_X25519;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: X25519 public key import failed with code %d", ret);
                wc_curve25519_free(&ctx->key.x25519);
            }
        }
    }

    /* Try X448 */
    if (!key_found) {
        WGW_LOG("wolfssl: trying X448 public key import");
        ret = wc_curve448_init(&ctx->key.x448);
        if (ret == 0) {
            ret = wc_curve448_import_public(publicKeyDer, publicKeySize, &ctx->key.x448);

            if (ret == 0) {
                WGW_LOG("wolfssl: x448 public key import succeeded");
                ctx->pub_data_len = CURVE448_PUB_KEY_SIZE;
                ret = wc_curve448_export_public(&ctx->key.x448, ctx->pub_data, &ctx->pub_data_len);
                if (ret != 0) {
                    WGW_LOG("wolfssl: x448 public key export failed with code: %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                } else {
                    WGW_LOG("wolfssl: x448 public key export succeeded");
                }
                ctx->algo = GNUTLS_PK_ECDH_X448;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: X448 public key import failed with code %d", ret);
                wc_curve448_free(&ctx->key.x448);
            }
        }
    }

    /* Try RSA */
    if (!key_found) {
        WGW_LOG("wolfssl: trying RSA public key import");
        ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_RsaPublicKeyDecode(publicKeyDer, &idx, &ctx->key.rsa, publicKeySize);

            if (ret == 0) {
                WGW_LOG("wolfssl: RSA public key import succeeded");

                XMEMCPY(ctx->pub_data, publicKeyDer, publicKeySize);
                ctx->pub_data_len = publicKeySize;
                WGW_LOG("wolfssl: RSA public key stored in context, size: %d", ctx->pub_data_len);

                ctx->algo = GNUTLS_PK_RSA;
                key_found = 1;
            } else {
                WGW_LOG("wolfssl: RSA public key import failed with code %d", ret);
                wc_FreeRsaKey(&ctx->key.rsa);
            }
        }
    }

    /* Free the extracted public key buffer */
    gnutls_free(publicKeyDer);

    if (!key_found) {
        /* No supported key type was found */
        gnutls_free(ctx);
        WGW_LOG("wolfssl: could not determine public key type, using fallback");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (ret != 0) {
        WGW_LOG("wolfssl: wc_InitRng failed with code %d", ret);

        /* Free the key we found */
        if (ctx->algo == GNUTLS_PK_ECDSA) {
            wc_ecc_free(&ctx->key.ecc);
        } else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
            wc_ed25519_free(&ctx->key.ed25519);
        } else if (ctx->algo == GNUTLS_PK_ECDH_X25519) {
            wc_curve25519_free(&ctx->key.x25519);
        } else if (ctx->algo == GNUTLS_PK_ECDH_X448) {
            wc_curve448_free(&ctx->key.x448);
        } else if (ctx->algo == GNUTLS_PK_RSA) {
            wc_FreeRsaKey(&ctx->key.rsa);
        }

        gnutls_free(ctx);
    }

    *pubkey_algo = &ctx->algo;

    ctx->rng_initialized = 1;
    ctx->initialized = 1;
    *_ctx = ctx;

    WGW_LOG("wolfssl: public key imported successfully");
    return 0;
}

/* sign a hash with a private key */
    static int
wolfssl_pk_sign_hash(void *_ctx, const void *signer,
        gnutls_digest_algorithm_t hash_algo,
        const gnutls_datum_t *hash_data,
        gnutls_datum_t *signature,
        unsigned int flags,
        gnutls_sign_algorithm_t algo)
{
    WGW_LOG("wolfssl: wolfssl_pk_sign_hash with hash algorithm %d", hash_algo);

    (void)signer;
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret = 0;
    int hash_type;

    if (ctx == NULL) {
        WGW_LOG("Context is NULL!");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!ctx || !ctx->initialized) {
        WGW_LOG("Context not initialized: %d", ctx->initialized);
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!hash_data || !hash_data->data || hash_data->size == 0 || !signature) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    hash_type = get_hash_type((gnutls_mac_algorithm_t)hash_algo);
    if (hash_type < 0 && hash_algo != 0) {
        WGW_LOG("hash algo not supported: %d", hash_algo);
        return GNUTLS_E_INVALID_REQUEST;
    } else if (hash_algo == 0) {
        WGW_LOG("hash algo unknown, defaulting to sha256");
        hash_type = WC_HASH_TYPE_SHA256;
    }

    /* check if any RSA-PSS flags/arguments were provided, and if so, update the algo */
    if ((flags & GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS) || algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("setting to rsa-pss");
        ctx->algo = GNUTLS_PK_RSA_PSS;
    }

    if (ctx->algo == GNUTLS_PK_ECDSA) {
        /* Get signature size for allocation */
        word32 sig_size = wc_ecc_sig_size(&ctx->key.ecc);
        byte *sig_buf = gnutls_malloc(sig_size);

        if (!sig_buf) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Sign the hash data */
        ret = wc_ecc_sign_hash(hash_data->data, hash_data->size,
                sig_buf, &sig_size, &ctx->rng, &ctx->key.ecc);

        if (ret != 0) {
            WGW_LOG("wolfssl: ECDSA hash signing failed with code %d", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Copy the signature to output */
        signature->data = gnutls_malloc(sig_size);
        if (!signature->data) {
            gnutls_free(sig_buf);
            return GNUTLS_E_MEMORY_ERROR;
        }

        memcpy(signature->data, sig_buf, sig_size);
        signature->size = sig_size;
        gnutls_free(sig_buf);

    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        /* For Ed25519, the hash is actually the message to sign */
        word32 sig_size = ED25519_SIG_SIZE;
        byte sig_buf[ED25519_SIG_SIZE];

        /* Sign the hash data */
        ret = wc_ed25519ph_sign_hash(hash_data->data, hash_data->size,
                sig_buf, &sig_size, &ctx->key.ed25519, NULL, 0);

        if (ret != 0) {
            WGW_LOG("wolfssl: Ed25519 hash signing failed with code %d", ret);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Copy the signature to output */
        signature->data = gnutls_malloc(sig_size);
        if (!signature->data) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        memcpy(signature->data, sig_buf, sig_size);
        signature->size = sig_size;

    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        /* For Ed448, the hash is actually the message to sign */
        word32 sig_size = ED448_SIG_SIZE;
        byte sig_buf[ED448_SIG_SIZE];

        /* Sign the hash data */
        ret = wc_ed448ph_sign_hash(hash_data->data, hash_data->size,
                sig_buf, &sig_size, &ctx->key.ed448, NULL, 0);

        if (ret != 0) {
            WGW_LOG("wolfssl: Ed448 hash signing failed with code %d", ret);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Copy the signature to output */
        signature->data = gnutls_malloc(sig_size);
        if (!signature->data) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        memcpy(signature->data, sig_buf, sig_size);
        signature->size = sig_size;

    } else if (ctx->algo == GNUTLS_PK_RSA) {
        WGW_LOG("signing hash with RSA");
        /* Get the maximum signature size - typically the key size */
        word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
        word32 actual_sig_size = sig_buf_len;

        byte *sig_buf = gnutls_malloc(sig_buf_len);
        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("sig_buf_len: %d", sig_buf_len);

        WGW_LOG("using RSA PKCS#1 v1.5 padding");
        /* Use wc_SignatureGenerate for PKCS#1 v1.5 */
        ret = wc_SignatureGenerateHash(
                hash_type,                       /* Hash algorithm type */
                WC_SIGNATURE_TYPE_RSA,           /* Signature type (RSA) */
                hash_data->data, hash_data->size,  /* Data hash to sign */
                sig_buf, &actual_sig_size,       /* Output signature buffer and resulting length */
                &ctx->key.rsa, sizeof(ctx->key.rsa), /* RSA key and size */
                &ctx->rng                        /* RNG */
                );

        if (ret != 0) {
            WGW_LOG("RSA PKCS#1 v1.5 signing failed with code %d", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Allocate space for the final signature and copy it */
        signature->data = gnutls_malloc(actual_sig_size);
        if (!signature->data) {
            gnutls_free(sig_buf);
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("RSA sig_size: %u", actual_sig_size);
        XMEMCPY(signature->data, sig_buf, actual_sig_size);
        signature->size = actual_sig_size;
        gnutls_free(sig_buf);
    } else if (ctx->algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("signing with RSA-PSS");
        /* Get the maximum signature size - typically the key size */
        word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
        word32 actual_sig_size = sig_buf_len;

        byte *sig_buf = gnutls_malloc(sig_buf_len);
        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("using RSA-PSS padding");
        int mgf = 0;

        /* Map GnuTLS hash algorithm to WolfSSL hash type */
        switch (hash_type) {
            case WC_HASH_TYPE_SHA256:
                mgf = WC_MGF1SHA256;
                WGW_LOG("using MGF1SHA256");
                break;
            case WC_HASH_TYPE_SHA384:
                mgf = WC_MGF1SHA384;
                WGW_LOG("using MGF1SHA384");
                break;
            case WC_HASH_TYPE_SHA512:
                mgf = WC_MGF1SHA512;
                WGW_LOG("using MGF1SHA512");
                break;
            case WC_HASH_TYPE_MD5_SHA:
                mgf = WC_MGF1SHA1;
                WGW_LOG("using MGF1SHA1 as fallback for MD5_SHA1");
                break;
            default:
                WGW_LOG("Unsupported hash algorithm: %d", hash_type);
                return GNUTLS_E_INVALID_REQUEST;
        }

        ret = wc_RsaPSS_Sign(
                hash_data->data, hash_data->size, /* Hash digest and length */
                sig_buf, sig_buf_len,           /* Output buffer and length */
                hash_type,                      /* Hash type */
                mgf,                            /* Mask Generation Function */
                &ctx->key.rsa,                  /* RSA key */
                &ctx->rng                      /* RNG */
                );

        if (ret < 0) {
            WGW_LOG("RSA-PSS signing failed with code %d", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        actual_sig_size = ret;
        /* Allocate space for the final signature and copy it */
        signature->data = gnutls_malloc(actual_sig_size);
        if (!signature->data) {
            gnutls_free(sig_buf);
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("RSA sig_size: %u", actual_sig_size);
        XMEMCPY(signature->data, sig_buf, actual_sig_size);
        signature->size = actual_sig_size;
        gnutls_free(sig_buf);
    } else {
        WGW_LOG("wolfssl: unsupported algorithm for hash signing: %d\n", ctx->algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("wolfssl: hash signed successfully");
    return 0;
}

/**
 * Helper function to determine the MGF type and hash length based on hash type
 *
 * @param hash_type The hash type to get MGF and length for
 * @param mgf Pointer to store the resulting MGF value
 * @param hash_len Pointer to store the resulting hash length
 * @return 0 on success, -1 on error
 */
static int get_mgf_and_hash_len(int hash_type, int *mgf, int *hash_len)
{
    switch (hash_type) {
        case WC_HASH_TYPE_SHA256:
            *mgf = WC_MGF1SHA256;
            *hash_len = WC_SHA256_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA256");
            return 0;
        case WC_HASH_TYPE_SHA384:
            *mgf = WC_MGF1SHA384;
            *hash_len = WC_SHA384_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA384");
            return 0;
        case WC_HASH_TYPE_SHA512:
            *mgf = WC_MGF1SHA512;
            *hash_len = WC_SHA512_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA512");
            return 0;
        default:
            WGW_LOG("Unsupported hash algorithm: %d", hash_type);
            return -1;
    }
}


/**
 * Verify using rsa-pss.
 *
 * @param hash_type The Wolf hash type
 * @param msg_data The message data
 * @param sig The signature to verify
 * @param hash The GnuTLS hash algorithm
 * @param rsa_key The RSA key
 * @return GNUTLS status code (0 on success)
 */
static int verify_rsa_pss(
        int hash_type,
        const gnutls_datum_t *msg_data,
        const gnutls_datum_t *sig,
        gnutls_digest_algorithm_t hash,
        RsaKey *rsa_key,
        int hash_flag)
{
    int ret;
    int mgf = 0;
    int hash_len = 0;
    byte *digest = NULL;
    byte *verify_buf = NULL;

    WGW_LOG("Using RSA-PSS verification");

    /* Get MGF type and hash length */
    if (get_mgf_and_hash_len(hash_type, &mgf, &hash_len) != 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (hash_flag) {
        /* Allocate memory for the digest */
        digest = gnutls_malloc(hash_len);
        if (!digest) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Hash the message */
        ret = wolfssl_digest_fast(hash, msg_data->data, msg_data->size, digest);
        if (ret != 0) {
            WGW_LOG("Hashing of the message before verification failed with ret: %d", ret);
            gnutls_free(digest);
            return GNUTLS_E_PK_SIGN_FAILED;
        }
    }

    /* Allocate memory for verification buffer */
    verify_buf = gnutls_malloc(RSA_PSS_SIG_SIZE);
    if (!verify_buf) {
        gnutls_free(digest);
        return GNUTLS_E_MEMORY_ERROR;
    }

    if (hash_flag) {
        /* Verify using RSA-PSS */
        ret = wc_RsaPSS_VerifyCheck(
                sig->data, sig->size,
                verify_buf, RSA_PSS_SIG_SIZE,
                digest, hash_len,
                hash_type,
                mgf,
                rsa_key
                );
        gnutls_free(digest);
    } else {
        /* Verify using RSA-PSS */
        ret = wc_RsaPSS_VerifyCheck(
                sig->data, sig->size,
                verify_buf, RSA_PSS_SIG_SIZE,
                msg_data->data, msg_data->size,
                hash_type,
                mgf,
                rsa_key
                );
    }

    /* Free resources */
    gnutls_free(verify_buf);

    WGW_LOG("ret: %d", ret);

    return (ret < 0) ? GNUTLS_E_PK_SIG_VERIFY_FAILED : 0;
}

/**
 * Helper function to verify using RSA PKCS#1 v1.5
 *
 * @param hash_type The Wolf hash type
 * @param msg_data The message data
 * @param sig The signature to verify
 * @param rsa_key The RSA key
 * @return GNUTLS status code (0 on success)
 */
static int verify_rsa_pkcs1(
        int hash_type,
        const gnutls_datum_t *msg_data,
        const gnutls_datum_t *sig,
        RsaKey *rsa_key,
        int hash_flag)
{
    int ret;

    WGW_LOG("Using RSA PKCS#1 v1.5 verification");

    if (!hash_flag) {
        WGW_LOG("data not already hashed");
    /* Use SignatureVerify for PKCS#1 v1.5 */
    ret = wc_SignatureVerify(
            hash_type,                     /* Hash algorithm type */
            WC_SIGNATURE_TYPE_RSA,         /* Signature type (RSA) */
            msg_data->data, msg_data->size, /* Message buffer and length */
            sig->data, sig->size,          /* Signature buffer and length */
            rsa_key, sizeof(*rsa_key)      /* RSA key and size */
            );
    } else {
        WGW_LOG("already hashed data");
        /* Use SignatureVerify for PKCS#1 v1.5 */
        ret = wc_SignatureVerifyHash(
                hash_type,                     /* Hash algorithm type */
                WC_SIGNATURE_TYPE_RSA,         /* Signature type (RSA) */
                msg_data->data, msg_data->size, /* Message buffer and length */
                sig->data, sig->size,          /* Signature buffer and length */
                rsa_key, sizeof(*rsa_key)      /* RSA key and size */
                );
    }

    if (ret != 0) {
        WGW_LOG("RSA PKCS#1 v1.5 verification failed with code %d", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

/* verify a hash signature with a public key */
static int
wolfssl_pk_verify_hash(void *_ctx, const void *key,
        gnutls_sign_algorithm_t algo,
        const gnutls_datum_t *hash,
        const gnutls_datum_t *signature)
{
    WGW_LOG("wolfssl: wolfssl_pk_verify_hash with sign algorithm %d", algo);

    (void)key;

    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    int verify_result = 0;

    if (!ctx || !ctx->initialized) {
        WGW_LOG("wolfssl: ctx not initialized, returning not supported");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!hash || !hash->data || hash->size == 0 ||
            !signature || !signature->data || signature->size == 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Handle based on signature algorithm */
    if (algo == GNUTLS_SIGN_ECDSA_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SHA512 ||
            algo == GNUTLS_SIGN_ECDSA_SECP256R1_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SECP384R1_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SECP521R1_SHA512 ||
            ctx->algo == GNUTLS_PK_ECDSA
            ) {

        /* Verify ECDSA signature */
        ret = wc_ecc_verify_hash(signature->data, signature->size,
                hash->data, hash->size,
                &verify_result, &ctx->key.ecc);

        if (ret != 0) {
            WGW_LOG("wolfssl: ECDSA hash verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_result != 1) {
            WGW_LOG("wolfssl: ECDSA hash signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    } else if (algo == GNUTLS_SIGN_EDDSA_ED25519 ||
               ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        int verify_status = 0;

        /* Verify Ed25519 signature */
        ret = wc_ed25519_verify_msg(signature->data, signature->size,
                hash->data, hash->size,
                &verify_status, &ctx->key.ed25519);

        if (ret != 0) {
            WGW_LOG("wolfssl: Ed25519 hash verification failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        if (verify_status != 1) {
            WGW_LOG("wolfssl: Ed25519 hash signature verification failed\n");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    } else if (algo == GNUTLS_SIGN_EDDSA_ED448 ||
               ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        int verify_status = 0;

        /* Verify Ed448 signature */
        ret = wc_ed448_verify_msg(signature->data, signature->size,
                hash->data, hash->size,
                &verify_status, &ctx->key.ed448, NULL, 0);

        if (ret != 0) {
            WGW_LOG("wolfssl: Ed448 hash verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_status != 1) {
            WGW_LOG("wolfssl: Ed448 hash signature verification failed\n");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else if (algo == GNUTLS_SIGN_RSA_SHA256 ||
               algo == GNUTLS_SIGN_RSA_SHA384 ||
               algo == GNUTLS_SIGN_RSA_SHA512 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA256 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA384 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA512 ||
               ctx->algo == GNUTLS_PK_RSA) {
        WGW_LOG("verifying with RSA");
        enum wc_HashType hash_type;
        gnutls_digest_algorithm_t hash_gnutls;

        /* Determine hash algorithm and if using PSS */
        switch (algo) {
            case GNUTLS_SIGN_RSA_SHA256:
                hash_type = WC_HASH_TYPE_SHA256;
                hash_gnutls = GNUTLS_DIG_SHA256;
                WGW_LOG("hash detected SHA256 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA384:
                hash_type = WC_HASH_TYPE_SHA384;
                hash_gnutls = GNUTLS_DIG_SHA384;
                WGW_LOG("hash detected SHA384 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA512:
                hash_type = WC_HASH_TYPE_SHA512;
                hash_gnutls = GNUTLS_DIG_SHA512;
                WGW_LOG("hash detected SHA512 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA256:
                hash_type = WC_HASH_TYPE_SHA256;
                hash_gnutls = GNUTLS_DIG_SHA256;
                WGW_LOG("hash detected SHA256 (PSS)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA384:
                hash_type = WC_HASH_TYPE_SHA384;
                hash_gnutls = GNUTLS_DIG_SHA384;
                WGW_LOG("hash detected SHA384 (PSS)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA512:
                hash_type = WC_HASH_TYPE_SHA512;
                hash_gnutls = GNUTLS_DIG_SHA512;
                WGW_LOG("hash detected SHA512 (PSS)");
                break;
            default:
                /* If no specific algorithm was provided but ctx->algo is RSA,
                 * default to SHA256 */
                hash_type = WC_HASH_TYPE_SHA256;
                WGW_LOG("defaulting to SHA256 for RSA, algo: %d", algo);
                break;
        }

        /* Import the public key if needed */
        if (mp_iszero(&ctx->key.rsa.n) || mp_iszero(&ctx->key.rsa.e)) {
            WGW_LOG("public key is not set, importing now");

            /* Import the public key from DER */
            ret = wc_RsaPublicKeyDecode(ctx->pub_data, &(word32){0}, &ctx->key.rsa, ctx->pub_data_len);
            if (ret != 0) {
                WGW_LOG("RSA public key import failed with code %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
        }

        /* First try RSA-PSS verification */
        WGW_LOG("Trying RSA-PSS verification for unknown algorithm");
        ret = verify_rsa_pss(hash_type, hash, signature, hash_gnutls, &ctx->key.rsa, 0);

        /* If RSA-PSS fails, fall back to PKCS#1 v1.5 */
        if (ret < 0) {
            WGW_LOG("RSA-PSS verification failed, trying PKCS#1 v1.5, ret: %d", ret);
            ret = verify_rsa_pkcs1(hash_type, hash, signature, &ctx->key.rsa, 1);
        }

        if (ret < 0) {
            WGW_LOG("RSA signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else {
        WGW_LOG("wolfssl: unsupported algorithm for hash verification: %d\n", algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("wolfssl: hash signature verified successfully");
    return 0;
}

/* generate a pk key pair */
static int wolfssl_pk_generate(void **_ctx, const void *privkey,
    gnutls_pk_algorithm_t algo, unsigned int bits)
{
    struct wolfssl_pk_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("algo %d with %d bits", algo, bits);

    (void)privkey;

    /* Allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize RNG */
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        WGW_LOG("wc_InitRng failed with code %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    ctx->rng_initialized = 1;
    ctx->algo = algo;

    /* Handle different key types */
    if (algo == GNUTLS_PK_EC) {
        WGW_LOG("EC");
        int curve_id;
        int curve_size;

        /* Initialize ECC key */
        ret = wc_ecc_init(&ctx->key.ecc);
        if (ret != 0) {
            WGW_LOG("wc_ecc_init failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        /* Map GnuTLS curve to wolfSSL */
        switch (bits) {
            case 224: /* SECP224R1 */
                WGW_LOG("SECP224R1");
                curve_id = ECC_SECP224R1;
                break;
            case 256: /* SECP256R1 */
                WGW_LOG("SECP256R1");
                curve_id = ECC_SECP256R1;
                break;
            case 384: /* SECP384R1 */
                WGW_LOG("SECP384R1");
                curve_id = ECC_SECP384R1;
                break;
            case 521: /* SECP521R1 */
                WGW_LOG("SECP521R1");
                curve_id = ECC_SECP521R1;
                break;
            default:
                WGW_LOG("unsupported curve bits: %d", bits);
                wc_ecc_free(&ctx->key.ecc);
                wc_FreeRng(&ctx->rng);
                gnutls_free(ctx);
                return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
        }

        curve_size = wc_ecc_get_curve_size_from_id(curve_id);
        WGW_LOG("curve size: %d", curve_size);

        /* Generate ECC key */
        ret = wc_ecc_make_key_ex(&ctx->rng, curve_size, &ctx->key.ecc, curve_id);
        if (ret != 0) {
            WGW_LOG("key generation failed with code %d", ret);
            wc_ecc_free(&ctx->key.ecc);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_PK_GENERATION_ERROR;
        }

    } else if (algo == GNUTLS_PK_EDDSA_ED25519) {
        WGW_LOG("ED25519");
        /* Initialize Ed25519 key */
        ret = wc_ed25519_init(&ctx->key.ed25519);
        if (ret != 0) {
            WGW_LOG("wc_ed25519_init failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        /* Generate Ed25519 key */
        ret = wc_ed25519_make_key(&ctx->rng, ED25519_KEY_SIZE, &ctx->key.ed25519);
        if (ret != 0) {
            WGW_LOG("Ed25519 key generation failed with code %d", ret);
            wc_ed25519_free(&ctx->key.ed25519);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_PK_GENERATION_ERROR;
        }

    } else if (algo == GNUTLS_PK_EDDSA_ED448) {
        WGW_LOG("ED448");
        /* Initialize Ed448 key */
        ret = wc_ed448_init(&ctx->key.ed448);
        if (ret != 0) {
            WGW_LOG("wc_ed448_init failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        /* Generate Ed448 key */
        ret = wc_ed448_make_key(&ctx->rng, ED448_KEY_SIZE, &ctx->key.ed448);
        if (ret != 0) {
            WGW_LOG("Ed448 key generation failed with code %d", ret);
            wc_ed448_free(&ctx->key.ed448);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_PK_GENERATION_ERROR;
        }

    } else if (algo == GNUTLS_PK_ECDH_X25519) {
        WGW_LOG("X25519");
        /* Initialize X25519 key */
        ret = wc_curve25519_init(&ctx->key.x25519);
        if (ret != 0) {
            WGW_LOG("wc_curve25519_init failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        /* Generate X25519 key */
        ret = wc_curve25519_make_key(&ctx->rng, CURVE25519_KEYSIZE, &ctx->key.x25519);
        if (ret != 0) {
            WGW_LOG("X25519 key generation failed with code %d", ret);
            wc_curve25519_free(&ctx->key.x25519);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_PK_GENERATION_ERROR;
        }
    } else if (algo == GNUTLS_PK_ECDH_X448) {
        WGW_LOG("X448");
        /* Initialize X448 key */
        ret = wc_curve448_init(&ctx->key.x448);
        if (ret != 0) {
            WGW_LOG("wc_curve448_init failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        /* Generate X448 key */
        ret = wc_curve448_make_key(&ctx->rng, CURVE448_KEY_SIZE, &ctx->key.x448);
        if (ret != 0) {
            WGW_LOG("X448 key generation failed with code %d", ret);
            wc_curve448_free(&ctx->key.x448);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_PK_GENERATION_ERROR;
        }
    } else if (algo == GNUTLS_PK_RSA ||
               algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("RSA");
        /* Initialize RSA key */
        ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
        if (ret != 0) {
            WGW_LOG("wc_InitRsaKey failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        ret = wc_RsaSetRNG(&ctx->key.rsa, &ctx->rng);
        if (ret != 0) {
            WGW_LOG("wc_RsaSetRNG failed with code %d", ret);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_CRYPTO_INIT_FAILED;
        }

        /* Generate RSA key */
        ret = wc_MakeRsaKey(&ctx->key.rsa, bits, WC_RSA_EXPONENT, &ctx->rng);
        if (ret != 0) {
            WGW_LOG("RSA key generation failed with code %d", ret);
            wc_FreeRsaKey(&ctx->key.rsa);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_PK_GENERATION_ERROR;
        }
    } else {
        WGW_LOG("unsupported algorithm: %d", algo);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    ctx->initialized = 1;
    WGW_LOG("pk generated successfully");

    *_ctx = ctx;
    return 0;
}

/* export pub from the key pair */
static int wolfssl_pk_export_pub(void **_pub_ctx, void *_priv_ctx, const void *pubkey)
{
    struct wolfssl_pk_ctx *priv_ctx = _priv_ctx;
    struct wolfssl_pk_ctx *pub_ctx;
    int ret;

    WGW_FUNC_ENTER();

    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_LOG("PK context not initialized");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    /* Check if pubkey parameter is provided */
    if (!pubkey) {
        WGW_LOG("pubkey parameter is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!_pub_ctx) {
        WGW_LOG("wolfssl: invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (pub_ctx == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize pub_ctx with the same algorithm as priv_ctx */
    pub_ctx->algo = priv_ctx->algo;

    gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;

    if (priv_ctx->algo == GNUTLS_PK_ECDSA) {
        /* Get the size needed for X9.63 formatted public key */
        word32 pubSz = 0;
        ret = wc_ecc_export_x963(&priv_ctx->key.ecc, NULL, &pubSz);
        if (ret == BUFFER_E) {
            WGW_LOG("public key size calculation failed with code %d, and size: %d", ret, pubSz);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Allocate memory for the public key */
        pub->data = gnutls_malloc(pubSz);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Export the key in X9.63 format (0x04 | X | Y) */
        ret = wc_ecc_export_x963(&priv_ctx->key.ecc, pub->data, &pubSz);
        if (ret != 0) {
            WGW_LOG("public key export failed with code %d", ret);
            gnutls_free(pub->data);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        pub->size = pubSz;

        WGW_LOG("pub->size: %d", pub->size);

        pub_ctx->pub_data_len = pubSz;
        XMEMCPY(pub_ctx->pub_data, pub->data, pub_ctx->pub_data_len);
    } else if (priv_ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        if (!priv_ctx->key.ed25519.pubKeySet) {
            WGW_LOG("pub key was not set, can't exported");
            return GNUTLS_E_INVALID_REQUEST;
        }

        word32 pub_size = ED25519_PUB_KEY_SIZE;

        /* Export Ed25519 public key directly to pub_ctx->pub_data */
        ret = wc_ed25519_export_public(&priv_ctx->key.ed25519, pub_ctx->pub_data, &pub_size);
        if (ret != 0) {
            WGW_LOG("Ed25519 public key export failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        pub_ctx->pub_data_len = pub_size;

        /* Allocate and copy public key to the external pubkey datum */
        pub->data = gnutls_malloc(pub_size);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
        pub->size = pub_size;

    } else if (priv_ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        if (!priv_ctx->key.ed448.pubKeySet) {
            WGW_LOG("pub key was not set, can't be exported");
            return GNUTLS_E_INVALID_REQUEST;
        }

        word32 pub_size = ED448_PUB_KEY_SIZE;

        /* Export Ed448 public key directly to pub_ctx->pub_data */
        ret = wc_ed448_export_public(&priv_ctx->key.ed448, pub_ctx->pub_data, &pub_size);
        if (ret != 0) {
            WGW_LOG("Ed448 public key export failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        pub_ctx->pub_data_len = pub_size;

        /* Allocate and copy public key to the external pubkey datum */
        pub->data = gnutls_malloc(pub_size);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
        pub->size = pub_size;
    } else if (priv_ctx->algo == GNUTLS_PK_ECDH_X25519) {
        word32 pub_size = CURVE25519_KEYSIZE;

        /* Export X25519 public key directly to pub_ctx->pub_data */
        ret = wc_curve25519_export_public_ex(&priv_ctx->key.x25519, pub_ctx->pub_data,
                &pub_size, EC25519_LITTLE_ENDIAN);
        if (ret != 0) {
            WGW_LOG("X25519 public key export failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        pub_ctx->pub_data_len = pub_size;

        /* Allocate and copy public key to the external pubkey datum */
        pub->data = gnutls_malloc(pub_size);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
        pub->size = pub_size;
    } else if (priv_ctx->algo == GNUTLS_PK_ECDH_X448) {
        word32 pub_size = CURVE448_KEY_SIZE;

        /* Export X448 public key directly to pub_ctx->pub_data */
        ret = wc_curve448_export_public_ex(&priv_ctx->key.x448, pub_ctx->pub_data,
                &pub_size, EC448_LITTLE_ENDIAN);
        if (ret != 0) {
            WGW_LOG("X448 public key export failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        pub_ctx->pub_data_len = pub_size;

        /* Allocate and copy public key to the external pubkey datum */
        pub->data = gnutls_malloc(pub_size);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
        pub->size = pub_size;
    } else if (priv_ctx->algo == GNUTLS_PK_RSA ||
               priv_ctx->algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("RSA");
        word32 pubSz = 0;

        /* Get size required for DER formatted public key */
        ret = wc_RsaPublicKeyDerSize(&priv_ctx->key.rsa, 1);
        if (ret < 0) { /* Note: wc_RsaPublicKeyDerSize returns size on success, negative on error */
            WGW_LOG("RSA public key DER size calculation failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST; /* Or a more specific error */
        }

        pubSz = ret;

        WGW_LOG("RSA public key DER size: %u", pubSz);

        /* Allocate memory for the public key */
        pub->data = gnutls_malloc(pubSz);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Export the public key in DER format */
        ret = wc_RsaKeyToPublicDer(&priv_ctx->key.rsa, pub->data, pubSz);
        if (ret < 0) {
            WGW_LOG("RSA public key DER export failed with code %d", ret);
            gnutls_free(pub->data);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST; /* Or a more specific error */
        }

        pub->size = ret; /* The actual size written */

        pub_ctx->pub_data_len = pub->size;
        XMEMCPY(pub_ctx->pub_data, pub->data, pub_ctx->pub_data_len);
    } else {
        WGW_LOG("unsupported algorithm for exporting public key: %d", priv_ctx->algo);
        gnutls_free(pub_ctx);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    pub_ctx->initialized = 1;
    *_pub_ctx = pub_ctx;

    WGW_LOG("public key exported successfully");
    return 0;
}

/* sign message */
static int wolfssl_pk_sign(void *_ctx, const void *privkey,
    gnutls_digest_algorithm_t hash, const void *data, const void *signature, unsigned int flags, gnutls_sign_algorithm_t algo)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    enum wc_HashType hash_type;

    WGW_FUNC_ENTER();
    WGW_LOG("hash %d", hash);

    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized, using fallback");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    const gnutls_datum_t *msg_data = (const gnutls_datum_t *)data;
    gnutls_datum_t *sig = (gnutls_datum_t *)signature;

    if (!msg_data || !msg_data->data || msg_data->size == 0 || !sig) {
        WGW_LOG("Bad message data or signature");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Map GnuTLS hash algorithm to WolfSSL hash type */
    switch (hash) {
        case GNUTLS_DIG_SHA256:
            hash_type = WC_HASH_TYPE_SHA256;
            WGW_LOG("hash detected SHA256");
            break;
        case GNUTLS_DIG_SHA384:
            hash_type = WC_HASH_TYPE_SHA384;
            WGW_LOG("hash detected SHA384");
            break;
        case GNUTLS_DIG_SHA512:
            hash_type = WC_HASH_TYPE_SHA512;
            WGW_LOG("hash detected SHA512");
            break;
        default:
            WGW_LOG("Unsupported hash algorithm: %d", hash);
            return GNUTLS_E_INVALID_REQUEST;
    }

    /* check if any RSA-PSS flags/arguments were provided, and if so, update the algo */
    if ((flags & GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS) || algo == GNUTLS_PK_RSA_PSS) {
        ctx->algo = GNUTLS_PK_RSA_PSS;
    }

    if (ctx->algo == GNUTLS_PK_ECDSA) {
        WGW_LOG("signing with ECDSA");
        /* Get the maximum signature size */
        word32 sig_size = wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC,
                &ctx->key.ecc, sizeof(ctx->key.ecc));
        byte *sig_buf = gnutls_malloc(sig_size);

        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Sign the message with ECDSA using SignatureGenerate */
        ret = wc_SignatureGenerate(
                hash_type,                       /* Hash algorithm type */
                WC_SIGNATURE_TYPE_ECC,           /* Signature type (ECC) */
                msg_data->data, msg_data->size,  /* Data to sign */
                sig_buf, &sig_size,              /* Output signature buffer and length */
                &ctx->key.ecc, sizeof(ctx->key.ecc), /* ECC key and size */
                &ctx->rng                        /* RNG */
                );

        if (ret != 0) {
            WGW_LOG("ECDSA signing failed with code %d", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Allocate space for the signature and copy it */
        sig->data = gnutls_malloc(sig_size);
        if (!sig->data) {
            gnutls_free(sig_buf);
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("sig_size: %d", sig_size);
        XMEMCPY(sig->data, sig_buf, sig_size);
        sig->size = sig_size;
        gnutls_free(sig_buf);
    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        WGW_LOG("signing with EDDSA ed25519");
        /* Allocate buffer for Ed25519 signature */
        word32 sig_size = ED25519_SIG_SIZE;
        byte *sig_buf = gnutls_malloc(sig_size);

        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        if (!ctx->key.ed25519.privKeySet) {
            WGW_LOG("private key not imported, importing it now");

            const gnutls_datum_t *private_key_raw = (const gnutls_datum_t *)privkey;
            WGW_LOG("size of private key: %d", private_key_raw->size);

            ret = wc_ed25519_import_private_only(private_key_raw->data, private_key_raw->size, &ctx->key.ed25519);
            if (ret != 0) {
                 WGW_LOG("Error while importing the private key, ret = %d", ret);
                 return GNUTLS_E_INVALID_REQUEST;
            } else {
                 WGW_LOG("Private key imported successfully.");
            }
        }

        if (!ctx->key.ed25519.pubKeySet) {
            WGW_LOG("Deriving public key from private key before signing");
            ctx->pub_data_len = ED25519_PUB_KEY_SIZE;

            ret = wc_ed25519_make_public(&ctx->key.ed25519, ctx->pub_data, ctx->pub_data_len);

            if (ret != 0) {
                WGW_LOG("Failed to derive public key before signing, ret = %d", ret);
                return GNUTLS_E_PK_SIGN_FAILED;
            } else {
                WGW_LOG("Succeess to derive public key before signing");

                ret = wc_ed25519_import_public(ctx->pub_data, ctx->pub_data_len, &ctx->key.ed25519);
                if (ret != 0) {
                    WGW_LOG("Error while importing the public key");
                    return GNUTLS_E_INVALID_REQUEST;
                }
            }
        } else {
             WGW_LOG("Public key already set in signing context");
        }

        ret = wc_ed25519_check_key(&ctx->key.ed25519);
        if (ret != 0) {
            WGW_LOG("wolfssl: Ed25519 check key failed (pub and priv set), with ret = %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Sign the message with Ed25519 */
        ret = wc_ed25519_sign_msg(msg_data->data, msg_data->size,
                sig_buf, &sig_size, &ctx->key.ed25519);

        if (ret != 0) {
            WGW_LOG("Ed25519 signing failed with code %d", ret);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Allocate space for the signature and copy it */
        sig->data = gnutls_malloc(sig_size);
        if (!sig->data) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(sig->data, sig_buf, sig_size);
        sig->size = sig_size;
        gnutls_free(sig_buf);
    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        WGW_LOG("signing with EDDSA ed448");
        /* Allocate buffer for Ed448 signature */
        word32 sig_size = ED448_SIG_SIZE;
        byte *sig_buf = gnutls_malloc(sig_size);

        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        if (!ctx->key.ed448.privKeySet) {
            WGW_LOG("private key not imported, importing it now");

            const gnutls_datum_t *private_key_raw = (const gnutls_datum_t *)privkey;
            WGW_LOG("size of private key: %d", private_key_raw->size);

            ret = wc_ed448_import_private_only(private_key_raw->data, private_key_raw->size, &ctx->key.ed448);
            if (ret != 0) {
                 WGW_LOG("Error while importing the private key, ret = %d", ret);
                 return GNUTLS_E_INVALID_REQUEST;
            } else {
                 WGW_LOG("Private key imported successfully.");
            }
        }

        if (!ctx->key.ed448.pubKeySet) {
            WGW_LOG("Deriving public key from private key before signing");
            ctx->pub_data_len = ED448_PUB_KEY_SIZE;

            ret = wc_ed448_make_public(&ctx->key.ed448, ctx->pub_data, ctx->pub_data_len);

            if (ret != 0) {
                WGW_LOG("Failed to derive public key before signing, ret = %d", ret);
                return GNUTLS_E_PK_SIGN_FAILED;
            } else {
                WGW_LOG("Succeess to derive public key before signing");

                ret = wc_ed448_import_public(ctx->pub_data, ctx->pub_data_len, &ctx->key.ed448);
                if (ret != 0) {
                    WGW_LOG("Error while importing the public key");
                    return GNUTLS_E_INVALID_REQUEST;
                }
            }
        } else {
             WGW_LOG("Public key already set in signing context");
        }

        ret = wc_ed448_check_key(&ctx->key.ed448);
        if (ret != 0) {
            WGW_LOG("wolfssl: Ed448 check key failed (pub and priv set), with ret = %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Sign the message with Ed448 */
        ret = wc_ed448_sign_msg(msg_data->data, msg_data->size,
                sig_buf, &sig_size, &ctx->key.ed448, NULL, 0);

        if (ret != 0) {
            WGW_LOG("Ed448 signing failed with code %d", ret);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Allocate space for the signature and copy it */
        sig->data = gnutls_malloc(sig_size);
        if (!sig->data) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(sig->data, sig_buf, sig_size);
        sig->size = sig_size;
        gnutls_free(sig_buf);
    } else if (ctx->algo == GNUTLS_PK_RSA) {
        WGW_LOG("signing with RSA");
        /* Get the maximum signature size - typically the key size */
        word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
        word32 actual_sig_size = sig_buf_len;

        byte *sig_buf = gnutls_malloc(sig_buf_len);
        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("using RSA PKCS#1 v1.5 padding");
        /* Use wc_SignatureGenerate for PKCS#1 v1.5 */
        ret = wc_SignatureGenerate(
                hash_type,                       /* Hash algorithm type */
                WC_SIGNATURE_TYPE_RSA,           /* Signature type (RSA) */
                msg_data->data, msg_data->size,  /* Data hash to sign */
                sig_buf, &actual_sig_size,       /* Output signature buffer and resulting length */
                &ctx->key.rsa, sizeof(ctx->key.rsa), /* RSA key and size */
                &ctx->rng                        /* RNG */
                );

        if (ret != 0) {
            WGW_LOG("RSA PKCS#1 v1.5 signing failed with code %d", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        /* Allocate space for the final signature and copy it */
        sig->data = gnutls_malloc(actual_sig_size);
        if (!sig->data) {
            gnutls_free(sig_buf);
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("RSA sig_size: %u", actual_sig_size);
        XMEMCPY(sig->data, sig_buf, actual_sig_size);
        sig->size = actual_sig_size;
        gnutls_free(sig_buf);
    } else if (ctx->algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("signing with RSA-PSS");
        /* Get the maximum signature size - typically the key size */
        word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
        word32 actual_sig_size = sig_buf_len;

        byte *sig_buf = gnutls_malloc(sig_buf_len);
        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("using RSA-PSS padding");
        int mgf = 0;
        int hash_len = 0;

        /* Map GnuTLS hash algorithm to WolfSSL hash type */
        switch (hash_type) {
            case WC_HASH_TYPE_SHA256:
                mgf = WC_MGF1SHA256;
                hash_len = WC_SHA256_DIGEST_SIZE;
                WGW_LOG("using MGF1SHA256");
                break;
            case WC_HASH_TYPE_SHA384:
                mgf = WC_MGF1SHA384;
                hash_len = WC_SHA384_DIGEST_SIZE;
                WGW_LOG("using MGF1SHA384");
                break;
            case WC_HASH_TYPE_SHA512:
                mgf = WC_MGF1SHA512;
                hash_len = WC_SHA512_DIGEST_SIZE;
                WGW_LOG("using MGF1SHA512");
                break;
            default:
                WGW_LOG("Unsupported hash algorithm: %d", hash);
                return GNUTLS_E_INVALID_REQUEST;
        }
        byte *digest = gnutls_malloc(hash_len);
        ret = wolfssl_digest_fast(hash, msg_data->data, msg_data->size, digest);
        if (ret != 0) {
            WGW_LOG("Hashing of the message before signing failed with ret: %d\n", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        ret = wc_RsaPSS_Sign(
                digest, hash_len, /* Hash digest and length */
                sig_buf, sig_buf_len,           /* Output buffer and length */
                hash_type,                      /* Hash type */
                mgf,                            /* Mask Generation Function */
                &ctx->key.rsa,                  /* RSA key */
                &ctx->rng                      /* RNG */
                );

        if (ret < 0) {
            WGW_LOG("RSA-PSS signing failed with code %d", ret);
            gnutls_free(sig_buf);
            return GNUTLS_E_PK_SIGN_FAILED;
        }

        actual_sig_size = ret;
        /* Allocate space for the final signature and copy it */
        sig->data = gnutls_malloc(actual_sig_size);
        if (!sig->data) {
            gnutls_free(sig_buf);
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        WGW_LOG("RSA sig_size: %u", actual_sig_size);
        XMEMCPY(sig->data, sig_buf, actual_sig_size);
        sig->size = actual_sig_size;
        gnutls_free(sig_buf);
    } else {
        WGW_LOG("unsupported algorithm for signing: %d", ctx->algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    WGW_LOG("signed message successfully");
    return 0;
}


/* verify message */
static int wolfssl_pk_verify(void *_ctx, const void *pubkey,
    gnutls_sign_algorithm_t algo, const void *data, const void *signature)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();

    if (!wolfssl_pk_sign_supported[algo]) {
        WGW_LOG("Algo not supported, using fallback, algo: %d", algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized, initializing");

        ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
        if (ctx == NULL) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        ctx->initialized = 1;
    }

    const gnutls_datum_t *msg_data = (const gnutls_datum_t *)data;
    const gnutls_datum_t *sig = (const gnutls_datum_t *)signature;

    if (!msg_data || !msg_data->data || msg_data->size == 0 ||
            !sig || !sig->data || sig->size == 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (algo == GNUTLS_SIGN_ECDSA_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SECP256R1_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SECP384R1_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SHA512||
            algo == GNUTLS_SIGN_ECDSA_SECP521R1_SHA512 ||
            ctx->algo == GNUTLS_PK_ECDSA) {
        WGW_LOG("verifying with ECDSA");

        if (!(ctx->key.ecc.type == ECC_PUBLICKEY)) {
            WGW_LOG("public key is not set, importing now, size: %d", ctx->pub_data_len);
            ret = wc_ecc_import_x963(ctx->pub_data, ctx->pub_data_len, &ctx->key.ecc);
            if (ret != 0) {
                WGW_LOG("ECDSA public key import failed with code %d", ret);
                wc_ecc_free(&ctx->key.ecc);
                return GNUTLS_E_INVALID_REQUEST;
            }
        }

        enum wc_HashType hash_type;
        switch (algo) {
            case GNUTLS_SIGN_ECDSA_SHA256:
            case GNUTLS_SIGN_ECDSA_SECP256R1_SHA256:
                hash_type = WC_HASH_TYPE_SHA256;
                WGW_LOG("hash detected SHA256");
                break;
            case GNUTLS_SIGN_ECDSA_SHA384:
            case GNUTLS_SIGN_ECDSA_SECP384R1_SHA384:
                hash_type = WC_HASH_TYPE_SHA384;
                WGW_LOG("hash detected SHA384");
                break;
            case GNUTLS_SIGN_ECDSA_SHA512:
            case GNUTLS_SIGN_ECDSA_SECP521R1_SHA512:
                hash_type = WC_HASH_TYPE_SHA512;
                WGW_LOG("hash detected SHA512");
                break;
            default:
                WGW_LOG("Unsupported algorithm: %d", algo);
                return GNUTLS_E_INVALID_REQUEST;
        }

        /* Verify the message with ECDSA using SignatureVerify */
        ret = wc_SignatureVerify(
                hash_type,
                WC_SIGNATURE_TYPE_ECC,
                msg_data->data, msg_data->size,
                sig->data, sig->size,
                &ctx->key.ecc, sizeof(ctx->key.ecc)
                );

        if (ret != 0) {
            WGW_LOG("ECDSA verifying failed with code %d", ret);
			return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else if (algo == GNUTLS_SIGN_EDDSA_ED25519 ||
               ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        int verify_status = 0;
        if (!ctx->key.ed25519.pubKeySet) {
            WGW_LOG("pub key was not set");
            ret = wc_ed25519_import_public(ctx->pub_data, ctx->pub_data_len, &ctx->key.ed25519);
            if (ret != 0) {
                WGW_LOG("Error while importing the public key, trying from arguments");
                gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;
                ret = wc_ed25519_import_public(pub->data, pub->size, &ctx->key.ed25519);
                if (ret != 0) {
                    WGW_LOG("Error while importing the public key");
                    return GNUTLS_E_INVALID_REQUEST;
                }
            } else {
                WGW_LOG("pub key was correctly set and imported");
            }
        }
        ret = wc_ed25519_verify_msg(sig->data, sig->size,
                msg_data->data, msg_data->size,
                &verify_status, &ctx->key.ed25519);

        if (ret != 0) {
            WGW_LOG("Ed25519 verification failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        if (verify_status != 1) {
            WGW_LOG("Ed25519 signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    } else if (algo == GNUTLS_SIGN_EDDSA_ED448) {
        int verify_status = 0;
        if (!ctx->key.ed448.pubKeySet) {
            WGW_LOG("pub key was not set");
            ret = wc_ed448_import_public(ctx->pub_data, ctx->pub_data_len, &ctx->key.ed448);
            if (ret != 0) {
                WGW_LOG("Error while importing the public key, trying from arguments");
                gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;
                ret = wc_ed448_import_public(pub->data, pub->size, &ctx->key.ed448);
                if (ret != 0) {
                    WGW_LOG("Error while importing the public key");
                    WGW_LOG("pub->size: %d", pub->size);
                    return GNUTLS_E_INVALID_REQUEST;
                }
            } else {
                WGW_LOG("pub key was correctly set and imported");
            }
        }
        ret = wc_ed448_verify_msg(sig->data, sig->size,
                msg_data->data, msg_data->size,
                &verify_status, &ctx->key.ed448, NULL, 0);

        if (ret != 0) {
            WGW_LOG("Ed448 verification failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        if (verify_status != 1) {
            WGW_LOG("Ed448 signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else if (algo == GNUTLS_SIGN_RSA_SHA256 ||
               algo == GNUTLS_SIGN_RSA_SHA384 ||
               algo == GNUTLS_SIGN_RSA_SHA512 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA256 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA384 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA512 ||
               ctx->algo == GNUTLS_PK_RSA) {
        WGW_LOG("verifying with RSA");
        enum wc_HashType hash_type;
        gnutls_digest_algorithm_t hash;

        /* Determine hash algorithm and if using PSS */
        switch (algo) {
            case GNUTLS_SIGN_RSA_SHA256:
                hash_type = WC_HASH_TYPE_SHA256;
                hash = GNUTLS_DIG_SHA256;
                WGW_LOG("hash detected SHA256 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA384:
                hash_type = WC_HASH_TYPE_SHA384;
                hash = GNUTLS_DIG_SHA384;
                WGW_LOG("hash detected SHA384 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA512:
                hash_type = WC_HASH_TYPE_SHA512;
                hash = GNUTLS_DIG_SHA512;
                WGW_LOG("hash detected SHA512 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA256:
            case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
                hash_type = WC_HASH_TYPE_SHA256;
                hash = GNUTLS_DIG_SHA256;
                WGW_LOG("hash detected SHA256 (PSS)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA384:
            case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
                hash_type = WC_HASH_TYPE_SHA384;
                hash = GNUTLS_DIG_SHA384;
                WGW_LOG("hash detected SHA384 (PSS)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA512:
            case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:
                hash_type = WC_HASH_TYPE_SHA512;
                hash = GNUTLS_DIG_SHA512;
                WGW_LOG("hash detected SHA512 (PSS)");
                break;
            default:
                /* If no specific algorithm was provided but ctx->algo is RSA,
                 * default to SHA256 */
                hash_type = WC_HASH_TYPE_SHA256;
                hash = GNUTLS_DIG_SHA256;
                WGW_LOG("defaulting to SHA256 for RSA, algo: %d", algo);
                break;
        }

        /* Import the public key if needed */
        if (mp_iszero(&ctx->key.rsa.n) || mp_iszero(&ctx->key.rsa.e)) {
            WGW_LOG("public key is not set, importing now");

            /* Import the public key from DER */
            ret = wc_RsaPublicKeyDecode(ctx->pub_data, &(word32){0}, &ctx->key.rsa, ctx->pub_data_len);
            if (ret != 0) {
                WGW_LOG("RSA public key import failed with code %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
        }

        /* First try RSA-PSS verification */
        ret = verify_rsa_pss(hash_type, msg_data, sig, hash, &ctx->key.rsa, 1);

        /* If RSA-PSS fails, fall back to PKCS#1 v1.5 */
        if (ret < 0) {
            WGW_LOG("RSA-PSS verification failed, trying PKCS#1 v1.5");
            ret = verify_rsa_pkcs1(hash_type, msg_data, sig, &ctx->key.rsa, 0);
        }

        if (ret < 0) {
            WGW_LOG("RSA signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else {
        WGW_LOG("unsupported algorithm for verification: %d", algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    WGW_LOG("verified message successfully");
    return 0;
}

/**
 * clean up pk resources
 */
static void wolfssl_pk_deinit(void *_ctx)
{
    struct wolfssl_pk_ctx *ctx = _ctx;

    WGW_FUNC_ENTER();

    if (ctx && ctx->initialized) {
        /* Free key based on algorithm */
        if (ctx->algo == GNUTLS_PK_ECDSA) {
            wc_ecc_free(&ctx->key.ecc);
        } else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
            wc_ed25519_free(&ctx->key.ed25519);
        } else if (ctx->algo == GNUTLS_PK_EDDSA_ED448) {
            wc_ed448_free(&ctx->key.ed448);
        } else if (ctx->algo == GNUTLS_PK_ECDH_X25519) {
            wc_curve25519_free(&ctx->key.x25519);
        } else if (ctx->algo == GNUTLS_PK_ECDH_X448) {
            wc_curve448_free(&ctx->key.x448);
        }

        /* Free the RNG if initialized */
        if (ctx->rng_initialized) {
            wc_FreeRng(&ctx->rng);
        }

        ctx->initialized = 0;
        gnutls_free(ctx);
    }

    WGW_LOG("freeing resources");
}
/* derive shared secret between our private key and another's public key */
static int wolfssl_pk_derive_shared_secret(void *_pub_ctx, void *_priv_ctx, const void *privkey,
    const void *pubkey, const gnutls_datum_t *nonce, gnutls_datum_t *secret)
{
    struct wolfssl_pk_ctx *priv_ctx = _priv_ctx;
    struct wolfssl_pk_ctx *pub_ctx = _pub_ctx;
    int ret;
    gnutls_datum_t local_pub = {0};

    WGW_FUNC_ENTER();

    (void)nonce;

    /* Parameters sanity checks */
    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_LOG("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!secret) {
        WGW_LOG("missing required parameters");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Cast pubkey to the expected type */
    const gnutls_datum_t *pub = (const gnutls_datum_t *)pubkey;
    if (!pub->data || pub->size == 0) {
        WGW_LOG("invalid public key data in arguments, checking in ctx");

        /* Use the public key data from the context if available */
        if (pub_ctx->pub_data_len > 0) {
            local_pub.data = pub_ctx->pub_data;
            local_pub.size = pub_ctx->pub_data_len;
            pub = &local_pub;
            WGW_LOG("Using public key from context (size: %d bytes)", local_pub.size);
        } else {
            WGW_LOG("No public key available in context either");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }

    /* Handle based on algorithm type */
    switch (priv_ctx->algo) {
        case GNUTLS_PK_EC:
            {
                ecc_key peer_key;

                /* Initialize the peer's public key */
                ret = wc_ecc_init(&peer_key);
                if (ret != 0) {
                    WGW_LOG("wc_ecc_init failed with code %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Import the peer's public key from X963 format (0x04 | X | Y) */
                ret = wc_ecc_import_x963(pub->data, pub->size, &peer_key);
                if (ret != 0) {
                    WGW_LOG("ECDSA public key import failed with code %d", ret);
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Determine how much space we need for the shared secret */
                word32 secret_size = wc_ecc_size(&priv_ctx->key.ecc);
                if (secret_size == 0) {
                    WGW_LOG("error getting key size");
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_INTERNAL_ERROR;
                }

                /* Allocate buffer for the shared secret */
                byte *shared_secret = gnutls_malloc(secret_size);
                if (!shared_secret) {
                    WGW_LOG("Memory allocation failed");
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_MEMORY_ERROR;
                }

                priv_ctx->key.ecc.rng = &priv_ctx->rng;

                mp_int* priv_mp = wc_ecc_key_get_priv(&priv_ctx->key.ecc);
                if (!(priv_mp != NULL && !mp_iszero(priv_mp))) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv = (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_LOG("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }

                    ret = wc_ecc_import_private_key(priv->data, priv->size, NULL, 0, &priv_ctx->key.ecc);
                    if (ret != 0) {
                        WGW_LOG("Error while importing key, failed with code %d", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }

                /* Generate the shared secret */
                ret = wc_ecc_shared_secret(&priv_ctx->key.ecc, &peer_key, shared_secret, &secret_size);
                if (ret != 0) {
                    WGW_LOG("EC shared secret generation failed with code %d", ret);
                    gnutls_free(shared_secret);
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Free the peer's public key */
                wc_ecc_free(&peer_key);

                /* Set result data */
                secret->data = shared_secret;
                secret->size = secret_size;

                WGW_LOG("EC shared secret derived successfully (size: %d bytes)", secret_size);
                return 0;
            }
        case GNUTLS_PK_ECDH_X25519:
            {
                curve25519_key peer_key;
                byte shared_secret_buf[CURVE25519_KEYSIZE];
                word32 secret_size = sizeof(shared_secret_buf);

                /* Initialize the peer's public key */
                ret = wc_curve25519_init(&peer_key);
                if (ret != 0) {
                    WGW_LOG("wc_curve25519_init failed with code %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Import the peer's public key */
                ret = wc_curve25519_import_public_ex(pub->data, pub->size, &peer_key, EC25519_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_LOG("X25519 public key import failed with code %d", ret);
                    wc_curve25519_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                if (!priv_ctx->key.x25519.privSet) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv = (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_LOG("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }

                    ret = wc_curve25519_import_private_ex(priv->data, priv->size, &priv_ctx->key.x25519, EC25519_LITTLE_ENDIAN);
                    if (ret != 0) {
                        WGW_LOG("Error while importing key, failed with code %d", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }

                /* Generate the shared secret */
                ret = wc_curve25519_shared_secret_ex(&priv_ctx->key.x25519, &peer_key,
                        shared_secret_buf, &secret_size, EC25519_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_LOG("X25519 shared secret generation failed with code %d", ret);
                    wc_curve25519_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Free the peer's public key */
                wc_curve25519_free(&peer_key);

                /* Allocate and set result data */
                secret->data = gnutls_malloc(secret_size);
                if (!secret->data) {
                    return GNUTLS_E_MEMORY_ERROR;
                }

                memcpy(secret->data, shared_secret_buf, secret_size);
                secret->size = secret_size;

                WGW_LOG("X25519 shared secret derived successfully (size: %d bytes)", secret_size);
                return 0;
            }

        case GNUTLS_PK_ECDH_X448:
            {
                curve448_key peer_key;
                byte shared_secret_buf[CURVE448_KEY_SIZE];
                word32 secret_size = sizeof(shared_secret_buf);

                /* Initialize the peer's public key */
                ret = wc_curve448_init(&peer_key);
                if (ret != 0) {
                    WGW_LOG("wc_curve448_init failed with code %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Import the peer's public key */
                ret = wc_curve448_import_public_ex(pub->data, pub->size, &peer_key, EC448_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_LOG("X448 public key import failed with code %d", ret);
                    wc_curve448_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                if (!priv_ctx->key.x448.privSet) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv = (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_LOG("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                    ret = wc_curve448_import_private_ex(priv->data, priv->size, &priv_ctx->key.x448, EC448_LITTLE_ENDIAN);
                    if (ret != 0) {
                        WGW_LOG("Error while importing key, failed with code %d", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }

                /* Generate the shared secret */
                ret = wc_curve448_shared_secret_ex(&priv_ctx->key.x448, &peer_key,
                        shared_secret_buf, &secret_size, EC448_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_LOG("X448 shared secret generation failed with code %d", ret);
                    wc_curve448_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Free the peer's public key */
                wc_curve448_free(&peer_key);

                /* Allocate and set result data */
                secret->data = gnutls_malloc(secret_size);
                if (!secret->data) {
                    return GNUTLS_E_MEMORY_ERROR;
                }

                memcpy(secret->data, shared_secret_buf, secret_size);
                secret->size = secret_size;

                WGW_LOG("X448 shared secret derived successfully (size: %d bytes)", secret_size);
                return 0;
            }

        default:
            WGW_LOG("PK algorithm not supported for key exchange: %d", priv_ctx->algo);
            return GNUTLS_E_INVALID_REQUEST;
    }
}

/* structure containing function pointers for the pk implementation */
static const gnutls_crypto_pk_st wolfssl_pk_struct = {
    /* the init function is not needed, since the init functions of gnutls
     * default to just allocate the key's structs using gnutls_calloc.
     * so we do the init and the generate of the key pair directly in the
     * wolfssl_pk_generate function. */
    .generate_backend = wolfssl_pk_generate,
    .export_pubkey_backend = wolfssl_pk_export_pub,
    .sign_backend = wolfssl_pk_sign,
    .verify_backend = wolfssl_pk_verify,
    .import_privkey_x509_backend = wolfssl_pk_import_privkey_x509,
    .import_pubkey_x509_backend = wolfssl_pk_import_pubkey_x509,
    .sign_hash_backend = wolfssl_pk_sign_hash,
    .verify_hash_backend = wolfssl_pk_verify_hash,
    .derive_shared_secret_backend = wolfssl_pk_derive_shared_secret,
    .copy_backend = wolfssl_pk_copy,
    .deinit_backend = wolfssl_pk_deinit,
};

/* register the pk algorithm with GnuTLS */
static int wolfssl_pk_register(void)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    /* Register ECDSA */
    if (wolfssl_pk_supported[GNUTLS_PK_ECDSA]) {
        WGW_LOG("registering EC-ALL-CURVES");
        ret = gnutls_crypto_single_pk_register(
                GNUTLS_PK_ECDSA, 80, &wolfssl_pk_struct, 0);
        /* this is needed for the import functions to work properly */
        ret = gnutls_crypto_single_pk_register(
                GNUTLS_PK_UNKNOWN, 80, &wolfssl_pk_struct, 0);
        if (ret < 0) {
            return ret;
        }
    }

   /* Register Ed25519 */
   if (wolfssl_pk_supported[GNUTLS_PK_EDDSA_ED25519]) {
        WGW_LOG("registering EdDSA-ED25519");
        ret = gnutls_crypto_single_pk_register(
                GNUTLS_PK_EDDSA_ED25519, 80, &wolfssl_pk_struct, 0);
        if (ret < 0) {
            return ret;
        }
   }

  /* Register Ed448 */
  if (wolfssl_pk_supported[GNUTLS_PK_EDDSA_ED448]) {
      WGW_LOG("registering EdDSA-ED448");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_EDDSA_ED448, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }

  /* Register X25519 */
  if (wolfssl_pk_supported[GNUTLS_PK_ECDH_X25519]) {
      WGW_LOG("registering X25519");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_ECDH_X25519, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }

  /* Register X448 */
  if (wolfssl_pk_supported[GNUTLS_PK_ECDH_X448]) {
      WGW_LOG("registering X448");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_ECDH_X448, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }

  /* Register RSA */
  if (wolfssl_pk_supported[GNUTLS_PK_RSA]) {
      WGW_LOG("registering RSA");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_RSA, 80, &wolfssl_pk_struct, 0);
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_RSA_PSS, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }

    return ret;
}

/***************************** RNG functions **********************************/

/** Context structure for wolfSSL RNG. */
struct wolfssl_rng_ctx {
    /** wolfSSL RNG object for private data. */
    WC_RNG priv_rng;
    /** wolfSSL RNG object for public data. */
    WC_RNG pub_rng;
    /** Indicates that this context as been initialized. */
    int initialized;
    /** Process id to detect forking. */
    pid_t pid;
};

/**
 * Initialize random.
 *
 * @param [out]  _ctx  Random context.
 * @return  0 on success.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_RANDOM_FAILED when initializing a wolfSSL random fails.
 */
static int wolfssl_rnd_init(void **_ctx)
{
    struct wolfssl_rng_ctx* ctx;
    int ret;

    WGW_FUNC_ENTER();

    ctx = gnutls_calloc(1, sizeof(struct wolfssl_rng_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize private random. */
    ret = wc_InitRng(&ctx->priv_rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize public random. */
    ret = wc_InitRng(&ctx->pub_rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        wc_FreeRng(&ctx->priv_rng);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Get current process ID for fork detection. */
    ctx->pid = getpid();

    ctx->initialized = 1;
    *_ctx = (void*)ctx;

    return 0;
}

/**
 * Generate random data.
 *
 * @param [in, out] _ctx      Random context.
 * @param [in]      level     Type of random to generate.
 * @param [out]     data      Buffer to hold generated data.
 * @param [in]      datasize  Size of data to generate in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when context hasn't been initialized.
 * @return  GNUTLS_E_RANDOM_FAILED when level not supported, initializing
 *          wolfSSL random or generating bytes with wolfSSL ranodm fails.
 */
static int wolfssl_rnd(void *_ctx, int level, void *data, size_t datasize)
{
    struct wolfssl_rng_ctx* ctx = (struct wolfssl_rng_ctx*)_ctx;
    WC_RNG* rng = NULL;
    int ret;
    pid_t curr_pid;

    // WGW_FUNC_ENTER();

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("random context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Get the random corresponding the level requested. */
    if (level == GNUTLS_RND_RANDOM || level == GNUTLS_RND_KEY) {
        // WGW_LOG("using private random");
        rng = &ctx->priv_rng;
    } else if (level == GNUTLS_RND_NONCE) {
        // WGW_LOG("using public random");
        rng = &ctx->pub_rng;
    } else {
        WGW_ERROR("level not supported: %d", level);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Ensure data is cleared. */
    XMEMSET(data, 0, datasize);

    /* Get current process ID - if different then this is a fork. */
    curr_pid = getpid();
    if (curr_pid != ctx->pid) {
        WGW_LOG("Forked - reseed randoms");
        ctx->pid = curr_pid;
        /* Reseed the public random with the current process ID. */
        (void)wc_RNG_DRBG_Reseed(&ctx->pub_rng, (unsigned char*)&curr_pid,
            sizeof(curr_pid));

        /* Restart the private random. */
        wc_FreeRng(&ctx->priv_rng);
        ret = wc_InitRng(&ctx->priv_rng);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_InitRng", ret);
            gnutls_free(ctx);
            return GNUTLS_E_RANDOM_FAILED;
        }
    }

    /* Generate up to a block at a time. */
    do {
        size_t size = MIN(RNG_MAX_BLOCK_LEN, datasize);

        ret = wc_RNG_GenerateBlock(rng, data, size);
        if (ret != 0) {
            WGW_ERROR("Requested %d bytes", size);
            WGW_WOLFSSL_ERROR("wc_RNG_GenerateBlock", ret);
            return GNUTLS_E_RANDOM_FAILED;
        }

        /* Move over generated data. */
        data += size;
        datasize -= size;
    } while (datasize > 0);

    return 0;
}

/**
 * Refresh the random number generators.
 *
 * @param [in, out] _ctx  Random context.
 */
static void wolfssl_rnd_refresh(void *_ctx)
{
    struct wolfssl_rng_ctx* ctx = (struct wolfssl_rng_ctx*)_ctx;
    int ret;

    WGW_FUNC_ENTER();

    if (ctx && ctx->initialized) {
        /* Dispose of both wolfSSL randoms. */
        wc_FreeRng(&ctx->priv_rng);
        wc_FreeRng(&ctx->pub_rng);

        /* Initialize private wolfSSL random for use again. */
        ret = wc_InitRng(&ctx->priv_rng);
        if (ret != 0) {
            WGW_LOG("wolfSSL initialize of private random failed: %d", ret);
            WGW_WOLFSSL_ERROR("wc_InitRng", ret);
            /* Set context initialized to 0 to indicate it isn't avaialble. */
            ctx->initialized = 0;
        }

        /* Initialize public wolfSSL random for use again. */
        ret = wc_InitRng(&ctx->pub_rng);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_InitRng", ret);
            wc_FreeRng(&ctx->priv_rng);
            /* Set context initialized to 0 to indicate it isn't avaialble. */
            ctx->initialized = 0;
        }
    }
}

/**
 * Clean up random resources.
 *
 * @param [in, out]  _ctx  Random context.
 */
static void wolfssl_rnd_deinit(void *_ctx)
{
    struct wolfssl_rng_ctx* ctx = (struct wolfssl_rng_ctx*)_ctx;

    WGW_FUNC_ENTER();

    if (ctx && ctx->initialized) {
        /* Dispose of wolfSSL randoms. */
        wc_FreeRng(&ctx->pub_rng);
        wc_FreeRng(&ctx->priv_rng);
    }
    gnutls_free(_ctx);
}

/** Function pointers for the random implementation. */
static const gnutls_crypto_rnd_st wolfssl_rnd_struct = {
    .init = wolfssl_rnd_init,
    .deinit = wolfssl_rnd_deinit,
    .rnd = wolfssl_rnd,
    .rnd_refresh = wolfssl_rnd_refresh,
    .self_test = NULL,
};

/**
 * Return the implementations of the random operations.
 *
 * @return  Random implementation.
 */
const gnutls_crypto_rnd_st* gnutls_get_rnd_ops(void)
{
    WGW_FUNC_ENTER();

    return &wolfssl_rnd_struct;
}

/***************************** TLS PRF **********************************/

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

    switch (mac) {
        case GNUTLS_MAC_MD5_SHA1:
            ret = wc_PRF_TLSv1((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, NULL, INVALID_DEVID);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_PRF_TLSv1(MD5/SHA-1)", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        case GNUTLS_MAC_SHA256:
            ret = wc_PRF_TLS((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, 1, sha256_mac, NULL,
                INVALID_DEVID);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_PRF_TLSv1(SHA-256)", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        case GNUTLS_MAC_SHA384:
            ret = wc_PRF_TLS((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, 1, sha384_mac, NULL,
                INVALID_DEVID);
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

    /* Extract the key. */
    ret = wc_HKDF_Extract_ex(hash_type, salt, saltsize, key, keysize, output,
        NULL, INVALID_DEVID);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_HKDF_Extract_ex", ret);
        return GNUTLS_E_INTERNAL_ERROR;
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

    /* Expand the key. */
    ret = wc_HKDF_Expand_ex(hash_type, key, keysize, info, infosize, output,
        length, NULL, INVALID_DEVID);
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

    /* Derive the key. */
    ret = wc_PBKDF2_ex(output, key, keysize, salt, saltsize, iter_count, length,
        hash_type, NULL, INVALID_DEVID);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_PBKDF2_ex", ret);
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
    unsigned char tmp[WC_MAX_DIGEST_SIZE];

    WGW_FUNC_ENTER();

    /* When no key supplied, use an all zero key. */
    if (psk == NULL) {
        psk_size = output_size;
        XMEMSET(tmp, 0, psk_size);
        psk = tmp;
    }

    ret = wolfssl_hmac_fast(mac, NULL, 0, "", 0, psk, psk_size, out);
    if (ret != 0) {
        return ret;
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

    /* Extract the key. */
    ret = wc_Tls13_HKDF_Extract_ex(secret, salt, salt_size, (byte*)key,
        key_size, hash_type, NULL, INVALID_DEVID);
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

    /* Expand the key. */
    ret = wc_Tls13_HKDF_Expand_Label_ex(out, out_size, secret, digest_size,
        protocol, protocol_len, (byte*)label, label_size, msg, msg_size,
        hash_type, NULL, INVALID_DEVID);
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

/************************ Module functions *****************************/
/**
 * Module initialization
 *
 * @return  0 on success.
 * @return  Other value on failure.
 */
int _gnutls_wolfssl_init(void)
{
    int ret;
    char* str;

    /* Set logging to be enabled. */
    loggingEnabled = 1;
    /* Set default logging file descriptor. */
    loggingFd = stderr;
#if defined(XGETENV) && !defined(NO_GETENV)
    /* Get the environment variable for logging level. */
    if ((str = XGETENV("WGW_LOGGING")) != NULL) {
        loggingEnabled = atoi(str);
    }
    /* Get the environment variable for logging filename. */
    if ((str = XGETENV("WGW_LOGFILE")) != NULL) {
        /* Use stdout if string is says so. */
        if ((XSTRCMP(str, "STDOUT") == 0) ||
               (XSTRCMP(str, "stdout") == 0)) {
            loggingFd = stdout;
        /* Use stderr if string is says so. */
        } else if ((XSTRCMP(str, "STDERR") == 0) ||
                   (XSTRCMP(str, "stderr") == 0)) {
            loggingFd = stderr;
        } else {
            /* Try openning file for writing. */
            FILE* fd = XFOPEN(str, "w");
            if (fd == XBADFILE) {
                fprintf(stderr, "Failed to open log file: %s\n", str);
                fprintf(stderr, "Using default output file descriptor\n");
            } else {
                /* Use the file. */
                loggingFd = fd;
            }
        }
    }
#endif

    WGW_FUNC_ENTER();

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

    /* register pk algorithms */
    ret = wolfssl_pk_register();
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/**
 * Module deinitialization
 *
 * TODO: close logging file descriptor if not stdout/stderr.
 */
void _gnutls_wolfssl_deinit(void)
{
    WGW_FUNC_ENTER();
    return;
}

#else /* ENABLE_WOLFSSL */

int _gnutls_wolfssl_init(void)
{
    WGW_FUNC_ENTER();
    return 0;
}

void _gnutls_wolfssl_deinit(void)
{
    WGW_FUNC_ENTER();
    return;
}

#endif /* ENABLE_WOLFSSL */
