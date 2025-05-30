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
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_DH_BITS       4096
#define MAX_DH_Q_SIZE     256


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
 * Log an error message that can be printed with printf formatting.
 *
 * @param [in] fmt   Format of string to print.
 * @param [in] args  Arguments to use when printing.
 */
#define WGW_ERROR(fmt, args...)    wgw_log(__LINE__, "ERROR: " fmt, ## args)

/**
 * Log a message that can be printed with printf formatting.
 *
 * @param [in] fmt   Format of string to print.
 * @param [in] args  Arguments to use when printing.
 */
#define WGW_LOG(fmt, args...)    wgw_log(__LINE__, fmt, ## args)

#define WGW_DUMP(name, data, len)                                   \
    do {                                                            \
        int _i;                                                     \
        fprintf(stderr, "%s\n", name);                              \
        for (_i = 0; _i < (int)len; _i++) {                         \
            fprintf(stderr, "%02x ", ((unsigned char *)data)[_i]);  \
            if ((_i % 16) == 15) fprintf(stderr, "\n");             \
        }                                                           \
        if (_i % 16 != 0) fprintf(stderr, "\n");                    \
    } while (0)

/** Whether logging output will be written. */
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
#define MAX_AUTH_DATA       1024
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
    unsigned int tag_set:1;
    /** Tag has been set from external source. */
    unsigned int tag_set_ext:1;
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
#if defined(HAVE_FIPS)
        WGW_LOG("returning GNUTLS_E_UNWANTED_ALGORITHM");
        return GNUTLS_E_UNWANTED_ALGORITHM;
#endif
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
 * Get the key size for the cipher algorithm.
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
             * Tag will have been created on plaintext which is of no use.
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
#if defined(HAVE_FIPS)
            if (ret == BAD_FUNC_ARG)
                return GNUTLS_E_INVALID_REQUEST;
#endif
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
            WGW_WOLFSSL_ERROR("wc_AesCcmDecrypt", ret);
#if defined(HAVE_FIPS)
            if (ret == BAD_FUNC_ARG)
                return GNUTLS_E_INVALID_REQUEST;
#endif
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
static int get_hash_type(gnutls_mac_algorithm_t algorithm)
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

/* checks if the provided operation and hash_type are fips approved */
#if defined(HAVE_FIPS)
static int is_hash_type_fips(int hash_type, int operation) {
    switch(hash_type) {
        case WC_SHA:
            if (operation == VERIFY_OP)
                return 1;
            else
                return 0;
        case WC_SHA224:
        case WC_SHA256:
        case WC_SHA384:
        case WC_SHA512:
        case WC_SHA3_224:
        case WC_SHA3_256:
        case WC_SHA3_384:
        case WC_SHA3_512:
            return 1;
        default:
            return 0;
    }
}
#endif

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
#endif
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
        /** wolfSSL SHA3 object.  */
        wc_Sha3   sha3;
    } obj;
    /** The GnuTLS digest algorithm ID. */
    gnutls_digest_algorithm_t algorithm;
    /** Indicates that this context as been initialized. */
    unsigned int initialized:1;
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
    [GNUTLS_DIG_SHAKE_128] = 1,
    [GNUTLS_DIG_SHAKE_256] = 1,
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

    if (textsize == 0) {
        return 0;
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
    unsigned int initialized:1;
    /** Started squeezing - no more absorb calls allowed. */
    unsigned int squeezing:1;
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

    ctx->algorithm = algorithm;

    /* Initialize digest. */
    ret = wolfssl_shake_init_alg(ctx);
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
            size = MIN(digestsize,
                       ((size_t)WC_SHA3_128_BLOCK_SIZE - ctx->used));
            XMEMCPY(digest, ctx->block + ctx->used, size);
            digest = (byte*)digest + size;
            digestsize -= size;
            ctx->used += size;
        }

        /* Generate more blocks if more output needed. */
        while (digestsize > 0) {
            /* Generate a new block if we need one */
            if (ctx->used == 0 || ctx->used >= WC_SHA3_128_BLOCK_SIZE) {
                ret = wc_Shake128_SqueezeBlocks(&ctx->shake, ctx->block, 1);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_Shake128_SqueezeBlocks", ret);
                    return GNUTLS_E_HASH_FAILED;
                }
                ctx->used = 0;
            }

            /* Copy out bytes from current block */
            size = MIN(digestsize,
                       (size_t)(WC_SHA3_128_BLOCK_SIZE - ctx->used));
            XMEMCPY(digest, ctx->block + ctx->used, size);

            /* Update pointers */
            digest = (byte*)digest + size;
            digestsize -= size;
            ctx->used += size;
        }
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
        /* Take from cache if not any and not all used. */
        if (ctx->used > 0 && ctx->used < WC_SHA3_256_BLOCK_SIZE) {
            size = MIN(digestsize,
                       (size_t)(WC_SHA3_256_BLOCK_SIZE - ctx->used));
            XMEMCPY(digest, ctx->block + ctx->used, size);
            digest = (byte*)digest + size;
            digestsize -= size;
            ctx->used += size;
        }

        /* Generate more blocks if more output needed. */
        while (digestsize > 0) {
            /* Generate a new block if we need one */
            if (ctx->used == 0 || ctx->used >= WC_SHA3_256_BLOCK_SIZE) {
                ret = wc_Shake256_SqueezeBlocks(&ctx->shake, ctx->block, 1);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_Shake256_SqueezeBlocks", ret);
                    return GNUTLS_E_HASH_FAILED;
                }
                ctx->used = 0;
            }

            /* Copy out bytes from current block */
            size = MIN(digestsize,
                       (size_t)(WC_SHA3_256_BLOCK_SIZE - ctx->used));
            XMEMCPY(digest, ctx->block + ctx->used, size);

            /* Update pointers */
            digest = (byte*)digest + size;
            digestsize -= size;
            ctx->used += size;
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
#if defined(HAVE_ED25519)
        ed25519_key ed25519;
#endif
#if defined(HAVE_ED448)
        ed448_key ed448;
#endif
#if defined(HAVE_CURVE25519)
        curve25519_key x25519;
#endif
#if defined(HAVE_CURVE448)
        curve448_key x448;
#endif
        RsaKey rsa;
        DhKey dh;
    } key;
    int initialized;
    /** The GnuTLS public key algorithm ID.  */
    gnutls_pk_algorithm_t algo;
    gnutls_ecc_curve_t curve;
    gnutls_x509_spki_st spki;
    WC_RNG rng;
    int rng_initialized;

    byte priv_data[1024];
    word32 priv_data_len;
    byte pub_data[1024];
    word32 pub_data_len;
    int pub_key_der_encoded;
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
        [GNUTLS_PK_DH] = 1,
};
/** Length of array of supported PK algorithms. */
#define WOLFSSL_PK_SUPPORTED_LEN            \
    (int)(sizeof(wolfssl_pk_supported) /    \
          sizeof(wolfssl_pk_supported[0]))

static int wolfssl_der_get_length(const unsigned char *der, word32 *idx,
   word32 size, word32 *len)
{
    byte b;
    word32 i = *idx;
    word32 l;

    if ((i + 1) > size)
        return GNUTLS_E_INVALID_REQUEST;

    b = der[i++];
    if (b == 0x80)
        return GNUTLS_E_INVALID_REQUEST;
    if (b  < 0x80) {
        *len = b;
        *idx = i;
        return 0;
    }

    b &= 0x7f;
    if ((i + b) > size)
        return GNUTLS_E_INVALID_REQUEST;
    if (b > sizeof(*len))
        return GNUTLS_E_INVALID_REQUEST;

    l = 0;
    while (b--) {
        l = (l << 8) | der[i++];
    }
    if ((i + l) > size)
        return GNUTLS_E_INVALID_REQUEST;

    *len = l;
    *idx = i;
    return 0;
}

/**
 * Check if PK algorithm is supported.
 *
 * @param [in] algorithm   GnuTLS PK algorithm ID.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int is_pk_supported(int algorithm)
{
    return (algorithm >= 0 && algorithm < WOLFSSL_PK_SUPPORTED_LEN &&
            wolfssl_pk_supported[algorithm] == 1);
}

static const int wolfssl_pk_sign_supported[] = {
        [GNUTLS_PK_UNKNOWN] = 1,
        [GNUTLS_SIGN_RSA_MD5] = 1,
        [GNUTLS_SIGN_RSA_SHA1] = 1,
        [GNUTLS_SIGN_RSA_SHA224] = 1,
        [GNUTLS_SIGN_RSA_SHA256] = 1,
        [GNUTLS_SIGN_RSA_SHA384] = 1,
        [GNUTLS_SIGN_RSA_SHA512] = 1,
        [GNUTLS_SIGN_RSA_SHA3_224] = 1,
        [GNUTLS_SIGN_RSA_SHA3_256] = 1,
        [GNUTLS_SIGN_RSA_SHA3_384] = 1,
        [GNUTLS_SIGN_RSA_SHA3_512] = 1,
        [GNUTLS_SIGN_RSA_PSS_SHA256] = 1,
        [GNUTLS_SIGN_RSA_PSS_SHA384] = 1,
        [GNUTLS_SIGN_RSA_PSS_SHA512] = 1,
        [GNUTLS_SIGN_ECDSA_SHA256] = 1,
        [GNUTLS_SIGN_ECDSA_SECP256R1_SHA256] = 1,
        [GNUTLS_SIGN_ECDSA_SHA384] = 1,
        [GNUTLS_SIGN_ECDSA_SECP384R1_SHA384] = 1,
        [GNUTLS_SIGN_ECDSA_SHA512] = 1,
        [GNUTLS_SIGN_ECDSA_SECP521R1_SHA512] = 1,
        [GNUTLS_SIGN_ECDSA_SHA1] = 1,
        [GNUTLS_SIGN_ECDSA_SHA224] = 1,
        [GNUTLS_SIGN_ECDSA_SHA3_224] = 1,
        [GNUTLS_SIGN_ECDSA_SHA3_256] = 1,
        [GNUTLS_SIGN_ECDSA_SHA3_384] = 1,
        [GNUTLS_SIGN_ECDSA_SHA3_512] = 1,
        [GNUTLS_SIGN_EDDSA_ED25519] = 1,
        [GNUTLS_SIGN_EDDSA_ED448] = 1,
        [GNUTLS_SIGN_RSA_PSS_RSAE_SHA256] = 1,
        [GNUTLS_SIGN_RSA_PSS_RSAE_SHA384] = 1,
        [GNUTLS_SIGN_RSA_PSS_RSAE_SHA512] = 1,
};
/** Length of array of supported PK signature algorithms. */
#define WOLFSSL_PK_SIGN_SUPPORTED_LEN           \
    (int)(sizeof(wolfssl_pk_sign_supported) /   \
          sizeof(wolfssl_pk_sign_supported[0]))

/**
 * Check if PK signature is supported.
 *
 * @param [in] algorithm   GnuTLS PK signature algorithm ID.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int is_pk_sign_supported(int algorithm)
{
    return (algorithm >= 0 && algorithm < WOLFSSL_PK_SIGN_SUPPORTED_LEN &&
            wolfssl_pk_sign_supported[algorithm] == 1);
}

static int wolfssl_pk_get_bits(void *_ctx, unsigned int* bits)
{
    struct wolfssl_pk_ctx *ctx = (struct wolfssl_pk_ctx *)_ctx;

    WGW_FUNC_ENTER();

	if (!ctx || !ctx->initialized) {
		WGW_LOG("ctx not initialized");
		return GNUTLS_E_ALGO_NOT_SUPPORTED;
	}

	if (!wolfssl_pk_supported[ctx->algo]) {
		WGW_LOG("algorithm not supported");
		return GNUTLS_E_ALGO_NOT_SUPPORTED;
	}

    switch (ctx->algo) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
            *bits = wc_RsaEncryptSize(&ctx->key.rsa) * 8;
            break;
        case GNUTLS_PK_DH:
            {
                word32 pSz, qSz, gSz;
                if (wc_DhExportParamsRaw(&ctx->key.dh, NULL, &pSz, NULL, &qSz,
                        NULL, &gSz) != 0) {
                    return GNUTLS_E_INVALID_REQUEST;
                }
                *bits = pSz * 8;
            }
            break;
        case GNUTLS_PK_ECDSA:
            *bits = wc_ecc_size(&ctx->key.ecc);
            break;
        case GNUTLS_PK_ECDH_X25519:
        case GNUTLS_PK_EDDSA_ED25519:
            *bits = 256;
            break;
        case GNUTLS_PK_ECDH_X448:
        case GNUTLS_PK_EDDSA_ED448:
            *bits = 448;
            break;
        default:
#if defined(HAVE_FIPS)
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
#else
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
#endif
    }

    return 0;
}

static int wolfssl_pk_get_spki(void *_ctx, void *spki)
{
    struct wolfssl_pk_ctx *ctx = (struct wolfssl_pk_ctx *)_ctx;

    /* Validate input parameters */
    if (!spki) {
        WGW_ERROR("invalid pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }
    if (!_ctx) {
        WGW_LOG("NULL ctx");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    XMEMCPY(spki, &ctx->spki, sizeof(gnutls_x509_spki_st));

    return 0;
}

static int wolfssl_pk_set_spki(void *_ctx, void *spki)
{
    struct wolfssl_pk_ctx *ctx = (struct wolfssl_pk_ctx *)_ctx;

    /* Validate input parameters */
    if (!_ctx || !spki) {
        WGW_ERROR("invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    XMEMCPY(&ctx->spki, spki, sizeof(gnutls_x509_spki_st));

    return 0;
}

static int wolfssl_pk_import_privkey_x509_dh(struct wolfssl_pk_ctx *ctx,
    const gnutls_datum_t *priv_datum, const gnutls_datum_t *pub_datum,
    int *key_found)
{
    int ret;

    WGW_LOG("importing DH private key from x/y parameters");

    ret = wc_InitDhKey(&ctx->key.dh);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitDhKey", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_DhImportKeyPair(&ctx->key.dh, priv_datum->data, priv_datum->size,
            (pub_datum ? pub_datum->data : NULL),
            (pub_datum ? pub_datum->size : 0));
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_DhImportKeyPair", ret);
        wc_FreeDhKey(&ctx->key.dh);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("DH key pair imported successfully into DhKey struct");
    WGW_LOG("size: %u", priv_datum->size);

    if (priv_datum->size > sizeof(ctx->priv_data)) {
        WGW_ERROR("insufficient space in ctx->priv_data (%u vs %zu)",
            priv_datum->size, sizeof(ctx->priv_data));
        wc_FreeDhKey(&ctx->key.dh);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    XMEMCPY(ctx->priv_data, priv_datum->data, priv_datum->size);
    ctx->priv_data_len = priv_datum->size;

    if (pub_datum && pub_datum->data && pub_datum->size > 0) {
        if (pub_datum->size > sizeof(ctx->pub_data)) {
            WGW_ERROR("insufficient space in ctx->pub_data (%u vs %zu)",
                pub_datum->size, sizeof(ctx->pub_data));
            wc_FreeDhKey(&ctx->key.dh);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_INTERNAL_ERROR;
        }
        XMEMCPY(ctx->pub_data, pub_datum->data, pub_datum->size);
        ctx->pub_data_len = pub_datum->size;
    } else {
        ctx->pub_data_len = 0;
    }

    ctx->algo = GNUTLS_PK_DH;
    *key_found = 1;

    return 0;
}

static gnutls_digest_algorithm_t rsa_hash_from_bits(int bits)
{
    if (bits <= 2048) {
        return GNUTLS_DIG_SHA256;
    } else if (bits <= 3072) {
        return GNUTLS_DIG_SHA384;
    }
    return GNUTLS_DIG_SHA512;
}

static void wolfssl_pk_import_privkey_x509_rsa(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying RSA private key import");
    ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyData, &idx, &ctx->key.rsa, keySize);
        if (ret == 0) {
            WGW_LOG("RSA private key import succeeded");
            ctx->algo = GNUTLS_PK_RSA;
            *key_found = 1;
        } else {
            WGW_LOG("wc_RsaPrivateKeyDecodeu: %d", ret);
            wc_FreeRsaKey(&ctx->key.rsa);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
    }
}

/** SHA-256 Algorithm ID DER encoding in PSS parameters. */
static const byte sha256AlgId[] = {
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
/** SHA-256 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte sha256AlgIdNull[] = {
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00
};
/** SHA-384 Algorithm ID DER encoding in PSS parameters. */
static const byte sha384AlgId[] = {
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
/** SHA-384 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte sha384AlgIdNull[] = {
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00
};
/** SHA-512 Algorithm ID DER encoding in PSS parameters. */
static const byte sha512AlgId[] = {
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};
/** SHA-512 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte sha512AlgIdNull[] = {
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00
};

/** MGF1 SHA-256 Algorithm ID DER encoding in PSS parameters. */
static const byte mgf1Sha256AlgId[] = {
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01
};
/** MGF1 SHA-256 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte mgf1Sha256AlgIdNull[] = {
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00
};
/** MGF1 SHA-384 Algorithm ID DER encoding in PSS parameters. */
static const byte mgf1Sha384AlgId[] = {
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02
};
/** MGF1 SHA-384 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte mgf1Sha384AlgIdNull[] = {
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02, 0x05, 0x00
};
/** MGF1 SHA-512 Algorithm ID DER encoding in PSS parameters. */
static const byte mgf1Sha512AlgId[] = {
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x03
};
/** MGF1 SHA-512 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte mgf1Sha512AlgIdNull[] = {
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x03, 0x05, 0x00
};

static int wolfssl_pk_import_rsa_pss_spki(gnutls_x509_spki_st *spki,
    byte* keyData, word32 keySize, int params_vers)
{
    word32 i = 0;
    word32 len;

    WGW_LOG("trying RSA private key import");

    if ((i + 1) > keySize)
        return 0;
    if (keyData[i++] != 0x30)
        return 0;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return 0;

    if (params_vers) {
        if ((i + 1) > keySize)
            return 0;
        if (keyData[i++] != 0x02)
            return 0;
        if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
            return 0;
        /* Skip integer value. */
        i += len;
    }

    if ((i + 1) > keySize)
        return 0;
    if (keyData[i++] != 0x30)
        return 0;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return 0;

    if ((i + 1) > keySize)
        return 0;
    if (keyData[i++] != 0x06)
        return 0;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return 0;
    /* Skip OBJECT ID value. */
    i += len;

    if ((i + 1) > keySize)
        return 0;
    if (keyData[i++] != 0x30)
        return 0;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return 0;

    if ((i + 1) < keySize && keyData[i] == 0xa0) {
        if (XMEMCMP(keyData + i, sha256AlgId, sizeof(sha256AlgId)) == 0) {
            spki->rsa_pss_dig = GNUTLS_DIG_SHA256;
            i += sizeof(sha256AlgId);
        } else if (XMEMCMP(keyData + i, sha384AlgId,
                           sizeof(sha384AlgId)) == 0) {
            spki->rsa_pss_dig = GNUTLS_DIG_SHA384;
            i += sizeof(sha256AlgId);
        } else if (XMEMCMP(keyData + i, sha512AlgId,
                           sizeof(sha512AlgId)) == 0) {
            spki->rsa_pss_dig = GNUTLS_DIG_SHA512;
            i += sizeof(sha256AlgId);
        } else if (XMEMCMP(keyData + i, sha256AlgIdNull,
                           sizeof(sha256AlgIdNull)) == 0) {
            spki->rsa_pss_dig = GNUTLS_DIG_SHA256;
            i += sizeof(sha256AlgIdNull);
        } else if (XMEMCMP(keyData + i, sha384AlgIdNull,
                           sizeof(sha384AlgIdNull)) == 0) {
            spki->rsa_pss_dig = GNUTLS_DIG_SHA384;
            i += sizeof(sha256AlgIdNull);
        } else if (XMEMCMP(keyData + i, sha512AlgIdNull,
                           sizeof(sha512AlgIdNull)) == 0) {
            spki->rsa_pss_dig = GNUTLS_DIG_SHA512;
            i += sizeof(sha256AlgIdNull);
        } else {
            return 0;
        }
    }

    if ((i + 1) < keySize && keyData[i] == 0xa1) {
        if (XMEMCMP(keyData + i, mgf1Sha256AlgId,
                    sizeof(mgf1Sha256AlgId)) == 0) {
            if (spki->rsa_pss_dig != GNUTLS_DIG_SHA256)
                return 0;
            i += sizeof(mgf1Sha256AlgId);
        } else if (XMEMCMP(keyData + i, mgf1Sha384AlgId,
                           sizeof(mgf1Sha384AlgId)) == 0) {
            if (spki->rsa_pss_dig != GNUTLS_DIG_SHA384)
                return 0;
            i += sizeof(mgf1Sha256AlgId);
        } else if (XMEMCMP(keyData + i, mgf1Sha512AlgId,
                           sizeof(mgf1Sha512AlgId)) == 0) {
            if (spki->rsa_pss_dig != GNUTLS_DIG_SHA512)
                return 0;
            i += sizeof(mgf1Sha256AlgId);
        } else if (XMEMCMP(keyData + i, mgf1Sha256AlgIdNull,
                           sizeof(mgf1Sha256AlgIdNull)) == 0) {
            if (spki->rsa_pss_dig != GNUTLS_DIG_SHA256)
                return 0;
            i += sizeof(mgf1Sha256AlgIdNull);
        } else if (XMEMCMP(keyData + i, mgf1Sha384AlgIdNull,
                           sizeof(mgf1Sha384AlgIdNull)) == 0) {
            if (spki->rsa_pss_dig != GNUTLS_DIG_SHA384)
                return 0;
            i += sizeof(mgf1Sha256AlgIdNull);
        } else if (XMEMCMP(keyData + i, mgf1Sha512AlgIdNull,
                           sizeof(mgf1Sha512AlgIdNull)) == 0) {
            if (spki->rsa_pss_dig != GNUTLS_DIG_SHA512)
                return 0;
            i += sizeof(mgf1Sha256AlgIdNull);
        } else {
            return 0;
        }
    }

    if ((i + 1) < keySize && keyData[i] == 0xa2) {
        i++;
        if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
            return 0;

        if ((i + 1) > keySize)
            return 0;
        if (keyData[i++] != 0x02)
            return 0;
        if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
            return 0;
        spki->salt_size = 0;
        while (len-- > 0) {
             spki->salt_size <<= 8;
             spki->salt_size += keyData[i++];
        }
    }

    spki->pk = GNUTLS_PK_RSA_PSS;
    return 1;
}

static void wolfssl_pk_import_privkey_x509_rsa_pss(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying RSA private key import");

    if (!wolfssl_pk_import_rsa_pss_spki(&ctx->spki, keyData, keySize, 1))
        return;

    ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(keyData, &idx, &ctx->key.rsa, keySize);
        if (ret == 0) {
            WGW_LOG("RSA private key import succeeded");
            ctx->algo = GNUTLS_PK_RSA_PSS;
            *key_found = 1;
        } else {
            WGW_LOG("wc_RsaPrivateKeyDecodeu: %d", ret);
            wc_FreeRsaKey(&ctx->key.rsa);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
    }
}

static int wolfssl_ecc_curve_id_to_curve_type(int curve_id)
{
    switch (curve_id) {
        case ECC_SECP224R1:
            return GNUTLS_ECC_CURVE_SECP224R1;
        case ECC_SECP256R1:
            return GNUTLS_ECC_CURVE_SECP256R1;
        case ECC_SECP384R1:
            return GNUTLS_ECC_CURVE_SECP384R1;
        case ECC_SECP521R1:
            return GNUTLS_ECC_CURVE_SECP521R1;
        default:
    }
    return 0;
}

static void wolfssl_pk_import_privkey_x509_ecdsa(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying ECDSA private key import");
    ret = wc_ecc_init(&ctx->key.ecc);
    if (ret == 0) {
        ret = wc_EccPrivateKeyDecode(keyData, &idx, &ctx->key.ecc, keySize);
        if (ret == 0) {
            WGW_LOG("ECDSA private key import succeeded");
            ctx->algo = GNUTLS_PK_ECDSA;
            ctx->curve = wolfssl_ecc_curve_id_to_curve_type(
                ctx->key.ecc.dp->id);
            *key_found = 1;
        } else {
            WGW_LOG("wc_EccPrivateKeyDecode: %d", ret);
            wc_ecc_free(&ctx->key.ecc);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_ecc_init", ret);
    }
}

#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
static void wolfssl_pk_import_privkey_x509_ed25519(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying Ed25519 private key import");
    ret = wc_ed25519_init(&ctx->key.ed25519);
    if (ret == 0) {
        ret = wc_Ed25519PrivateKeyDecode(keyData, &idx, &ctx->key.ed25519,
            keySize);
        if (ret == 0) {
            WGW_LOG("Ed25519 private key import succeeded");
            ctx->algo = GNUTLS_PK_EDDSA_ED25519;
            *key_found = 1;
        } else {
            WGW_LOG("wc_Ed25519PrivateKeyDecode: %d", ret);
            wc_ed25519_free(&ctx->key.ed25519);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
    }
}
#endif

#if defined(HAVE_ED448)
static void wolfssl_pk_import_privkey_x509_ed448(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying Ed448 private key import");
    ret = wc_ed448_init(&ctx->key.ed448);
    if (ret == 0) {
        ret = wc_Ed448PrivateKeyDecode(keyData, &idx, &ctx->key.ed448, keySize);
        if (ret == 0) {
            WGW_LOG("Ed448 private key import succeeded");
            ctx->algo = GNUTLS_PK_EDDSA_ED448;
            *key_found = 1;
        } else {
            WGW_LOG("wc_Ed448PrivateKeyDecode: %d", ret);
            wc_ed448_free(&ctx->key.ed448);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
    }
}
#endif

#if defined(HAVE_CURVE25519)
static void wolfssl_pk_import_privkey_x509_x25519(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying X25519 private key import");
    ret = wc_curve25519_init(&ctx->key.x25519);
    if (ret == 0) {
        ret = wc_Curve25519PrivateKeyDecode(keyData, &idx, &ctx->key.x25519,
            keySize);
        if (ret == 0) {
            WGW_LOG("X25519 private key import succeeded");
            ctx->algo = GNUTLS_PK_ECDH_X25519;
            *key_found = 1;
        } else {
            WGW_LOG("wc_Curve25519PrivateKeyDecode: %d", ret);
            wc_curve25519_free(&ctx->key.x25519);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
    }
}
#endif

#if defined(HAVE_CURVE448)
static void wolfssl_pk_import_privkey_x509_x448(struct wolfssl_pk_ctx *ctx,
    byte* keyData, word32 keySize, int *key_found)
{
    int ret;
    word32 idx = 0;

    WGW_LOG("trying X448 private key import");
    ret = wc_curve448_init(&ctx->key.x448);
    if (ret == 0) {
        ret = wc_Curve448PrivateKeyDecode(keyData, &idx, &ctx->key.x448,
            keySize);
        if (ret == 0) {
            WGW_LOG("X448 private key import succeeded\n");
            ctx->algo = GNUTLS_PK_ECDH_X448;
            *key_found = 1;
        } else {
            WGW_LOG("wc_Curve448PrivateKeyDecode: %d", ret);
            wc_curve448_free(&ctx->key.x448);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
    }
}
#endif
#endif

int wolfssl_get_alg_from_der(const unsigned char *keyData, word32 keySize,
    int *algId, word32 *params)
{
    word32 i = 0;
    word32 len;
    static const unsigned char derRsa[] = {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
    };
    static const unsigned char derRsaPss[] = {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a
    };
    static const unsigned char derEcc[] = {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
    };
#if defined(HAVE_ED448)
    static const unsigned char derEd25519[] = {
        0x2b, 0x65, 0x70
    };
#endif
#if defined(HAVE_ED25519)
    static const unsigned char derEd448[] = {
        0x2b, 0x65, 0x71
    };
#endif
#if defined(HAVE_CURVE25519)
    static const unsigned char derX25519[] = {
        0x2b, 0x65, 0x6e
    };
#endif
#if defined(HAVE_CURVE448)
    static const unsigned char derX448[] = {
        0x2b, 0x65, 0x6f
    };
#endif

    if ((i + 1) > keySize)
        return GNUTLS_E_INVALID_REQUEST;
    if (keyData[i++] != 0x30)
        return GNUTLS_E_INVALID_REQUEST;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return GNUTLS_E_INVALID_REQUEST;

    if ((i + 1) > keySize)
        return GNUTLS_E_INVALID_REQUEST;
    if (keyData[i] == 0x30) {
    } else {
        if (keyData[i++] != 0x02)
            return GNUTLS_E_INVALID_REQUEST;
        if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
            return GNUTLS_E_INVALID_REQUEST;
        /* Skip integer value. */
        i += len;
    }

    if ((i + 1) > keySize)
        return GNUTLS_E_INVALID_REQUEST;
    if (keyData[i] == 0x02) {
        *algId = RSAk;
        return 0;
    }
    if (keyData[i] == 0x04) {
        *algId = ECDSAk;
        return 0;
    }
    if (keyData[i++] != 0x30)
        return GNUTLS_E_INVALID_REQUEST;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return GNUTLS_E_INVALID_REQUEST;

    if ((i + 1) > keySize)
        return GNUTLS_E_INVALID_REQUEST;
    if (keyData[i++] != 0x06)
        return GNUTLS_E_INVALID_REQUEST;
    if (wolfssl_der_get_length(keyData, &i, keySize, &len) < 0)
        return GNUTLS_E_INVALID_REQUEST;

    if (len == (word32)sizeof(derRsa) && XMEMCMP(keyData + i, derRsa,
            len) == 0) {
        *algId = RSAk;
    } else if (len == (word32)sizeof(derRsaPss) && XMEMCMP(keyData + i,
            derRsaPss, len) == 0) {
        *algId = RSAPSSk;
        *params = i + len;
    } else if (len == (word32)sizeof(derEcc) && XMEMCMP(keyData + i, derEcc,
            len) == 0) {
        *algId = ECDSAk;
    }
#if defined(HAVE_ED25519)
    else if (len == (word32)sizeof(derEd25519) && XMEMCMP(keyData + i,
            derEd25519, len) == 0) {
        *algId = ED25519k;
    }
#endif
#if defined(HAVE_ED448)
    else if (len == (word32)sizeof(derEd448) && XMEMCMP(keyData + i, derEd448,
            len) == 0) {
        *algId = ED448k;
    }
#endif
#if defined(HAVE_CURVE25519)
    else if (len == (word32)sizeof(derX25519) && XMEMCMP(keyData + i,
            derX25519, len) == 0) {
        *algId = X25519k;
    }
#endif
#if defined(HAVE_CURVE448)
    else if (len == (word32)sizeof(derX448) && XMEMCMP(keyData + i, derX448,
            len) == 0) {
        *algId = X448k;
    }
#endif

    return 0;
}

/* import a private key from raw X.509 data using trial-and-error approach */
static int wolfssl_pk_import_privkey_x509(void **_ctx,
    gnutls_pk_algorithm_t *privkey_algo, gnutls_ecc_curve_t *curve,
    const gnutls_datum_t *data, gnutls_x509_crt_fmt_t format, const void *y,
    const void *x)
{
    struct wolfssl_pk_ctx *ctx;
    int ret = GNUTLS_E_INVALID_REQUEST; /* Default error if all imports fail */
    int key_found = 0;
    byte* keyData = NULL;
    word32 keySize = 0;
    int isDH = 0;
    const gnutls_datum_t *priv_datum = (const gnutls_datum_t *)x;
    const gnutls_datum_t *pub_datum = (const gnutls_datum_t *)y;
    int algId = 0;

    WGW_FUNC_ENTER();

    /* Validate input parameters */
    if (!_ctx) {
        WGW_ERROR("invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate a new context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        WGW_ERROR("wc_InitRng failed with code %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    ctx->rng_initialized = 1;

    /* Only support PEM and DER formats */
    if (format != GNUTLS_X509_FMT_DER) {
        WGW_ERROR("unsupported format for private key import");
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Empty data check */
    if (!data || !data->data || data->size == 0) {
        WGW_LOG("empty data for private key import");

        if (!priv_datum || !priv_datum->data || priv_datum->size == 0) {
            WGW_ERROR("no key data provided in main data or x/y parameters");
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_INVALID_REQUEST;
        } else {
            WGW_LOG("using DH keys from x/y parameters");
            isDH = 1;
        }
    } else {
        keyData = data->data;
        keySize = data->size;
    }

    if (isDH) {
        ret = wolfssl_pk_import_privkey_x509_dh(ctx, priv_datum, pub_datum,
            &key_found);
        if (ret != 0) {
            return ret;
        }
    } else {
	word32 params = 0;

        /* Figure out the algorithm from the DER. */
        ret = wolfssl_get_alg_from_der(keyData, keySize, &algId, &params);
        if (ret == 0) {
            switch (algId) {
                case RSAk:
                    WGW_LOG("RSA private key");
                    wolfssl_pk_import_privkey_x509_rsa(ctx, keyData, keySize,
                        &key_found);
                    if (key_found) {
                        ret = wc_CheckRsaKey(&ctx->key.rsa);
                        if (ret != 0) {
                            WGW_WOLFSSL_ERROR("wc_CheckRsaKey", ret);
                            wc_FreeRng(&ctx->rng);
                            gnutls_free(ctx);
                            return GNUTLS_E_PK_INVALID_PRIVKEY;
                        }
                    }
                    break;
                case RSAPSSk:
                    WGW_LOG("RSA-PSS private key");
                    wolfssl_pk_import_privkey_x509_rsa_pss(ctx, keyData,
                        keySize, &key_found);
                    break;
                case ECDSAk:
                    WGW_LOG("ECDSA private key");
                    wolfssl_pk_import_privkey_x509_ecdsa(ctx, keyData, keySize,
                        &key_found);
                    break;
#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
                case ED25519k:
                    WGW_LOG("Ed25519 private key");
                    wolfssl_pk_import_privkey_x509_ed25519(ctx, keyData,
                        keySize, &key_found);
                    ctx->curve = GNUTLS_ECC_CURVE_ED25519;
                    break;
#endif
#if defined(HAVE_ED448)
                case ED448k:
                    WGW_LOG("Ed448 private key");
                    wolfssl_pk_import_privkey_x509_ed448(ctx, keyData, keySize,
                        &key_found);
                    ctx->curve = GNUTLS_ECC_CURVE_ED448;
                    break;
#endif
#if defined(HAVE_CURVE25519)
                case X25519k:
                    WGW_LOG("X25519 private key");
                    wolfssl_pk_import_privkey_x509_x25519(ctx, keyData, keySize,
                        &key_found);
                    ctx->curve = GNUTLS_ECC_CURVE_X25519;
                    break;
#endif
#if defined(HAVE_CURVE448)
                case X448k:
                    WGW_LOG("X448 private key");
                    wolfssl_pk_import_privkey_x509_x448(ctx, keyData, keySize,
                        &key_found);
                    ctx->curve = GNUTLS_ECC_CURVE_X448;
                    break;
#endif
#endif
                default:
                    ret = GNUTLS_E_ALGO_NOT_SUPPORTED;
            }
        }
    }

    if (!key_found) {
        /* No supported key type was found */
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        WGW_ERROR("could not determine private key type, using fallback");
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }
    *privkey_algo = ctx->algo;
    *curve = ctx->curve;

    ctx->initialized = 1;
    ctx->spki.pk = ctx->algo;
    *_ctx = ctx;

    WGW_LOG("private key imported successfully");
    return 0;
}

static int wolfssl_pk_copy(void **_dst, void *src, gnutls_pk_algorithm_t algo)
{
    struct wolfssl_pk_ctx *ctx_src;
    struct wolfssl_pk_ctx *ctx_dst;
    int ret;

    WGW_FUNC_ENTER();

    /* Validate input parameters */
    if (!src) {
        WGW_LOG("context not initialized");
        if (wolfssl_pk_supported[algo]) {
            WGW_LOG("algo supported, initializing context");
            /* Allocate a new context */
            ctx_src = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
            if (ctx_src == NULL) {
                WGW_ERROR("Memory allocation failed");
                return GNUTLS_E_MEMORY_ERROR;
            }
            ctx_src->algo = algo;
            ctx_src->initialized = 1;
        } else {
            WGW_ERROR("algorithm not supported");
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
        }
    } else {
        ctx_src = src;
    }

    ctx_dst = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx_dst == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    memcpy(ctx_dst, ctx_src, sizeof(struct wolfssl_pk_ctx));
    WGW_LOG("copied context from x509 struct to priv key struct");

    if (ctx_src->rng_initialized) {
#ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
#endif
        /* Initialize RNG */
        ret = wc_InitRng(&ctx_dst->rng);
        if (ret != 0) {
            WGW_ERROR("wc_InitRng failed with code %d", ret);
            return GNUTLS_E_RANDOM_FAILED;
        }
        ctx_dst->rng_initialized = 1;
    }

    *_dst = ctx_dst;
    return 0;
}

static int wolfssl_rsa_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
    if (ret == 0) {
        word32 idx = 0;

        ret = wc_RsaPublicKeyDecode(publicKeyDer, &idx, &ctx->key.rsa,
            publicKeySize);
        if (ret == 0) {
            WGW_LOG("RSA public key import succeeded");
            if (publicKeySize <= sizeof(ctx->pub_data)) {
                 XMEMCPY(ctx->pub_data, publicKeyDer, publicKeySize);
                 ctx->pub_data_len = publicKeySize;
                 WGW_LOG("RSA public key stored in context, size: %u",
                     ctx->pub_data_len);
            } else {
                 WGW_LOG("RSA public key size (%u) too large for buffer (%zu)",
                     publicKeySize, sizeof(ctx->pub_data));
            }

            ctx->algo = GNUTLS_PK_RSA;
            *key_found = 1;
        } else {
            WGW_LOG("RSA public key import failed with code %d", ret);
            wc_FreeRsaKey(&ctx->key.rsa);
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}


static int wolfssl_rsa_pss_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
    if (ret == 0) {
        word32 idx = 0;

        ret = wc_RsaPublicKeyDecode(publicKeyDer, &idx, &ctx->key.rsa,
            publicKeySize);
        if (ret == 0) {
            WGW_LOG("RSA public key import succeeded");
            if (publicKeySize <= sizeof(ctx->pub_data)) {
                 XMEMCPY(ctx->pub_data, publicKeyDer, publicKeySize);
                 ctx->pub_data_len = publicKeySize;
                 WGW_LOG("RSA public key stored in context, size: %u",
                     ctx->pub_data_len);
            } else {
                 WGW_LOG("RSA public key size (%u) too large for buffer (%zu)",
                     publicKeySize, sizeof(ctx->pub_data));
            }

            ctx->algo = GNUTLS_PK_RSA_PSS;
            *key_found = 1;
        } else {
            WGW_LOG("RSA public key import failed with code %d", ret);
            wc_FreeRsaKey(&ctx->key.rsa);
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    if (!wolfssl_pk_import_rsa_pss_spki(&ctx->spki, publicKeyDer,
            publicKeySize, 0)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

static int wolfssl_ecc_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_ecc_init(&ctx->key.ecc);
    if (ret == 0) {
        word32 idx = 0;
        ret = wc_EccPublicKeyDecode(publicKeyDer, &idx, &ctx->key.ecc,
            publicKeySize);
        if (ret == 0) {
            WGW_LOG("ECDSA public key import succeeded");
            ctx->algo = GNUTLS_PK_ECDSA;
            ctx->curve = wolfssl_ecc_curve_id_to_curve_type(
                ctx->key.ecc.dp->id);
            *key_found = 1;
            if (publicKeySize <= sizeof(ctx->pub_data)) {
                XMEMCPY(ctx->pub_data, publicKeyDer, publicKeySize);
                ctx->pub_data_len = publicKeySize;
            }
        } else {
            WGW_LOG("ECDSA public key import failed with code %d", ret);
            wc_ecc_free(&ctx->key.ecc);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_ecc_init", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}

#if defined(HAVE_ED25519)
static int wolfssl_ed25519_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_ed25519_init(&ctx->key.ed25519);
    if (ret == 0) {
        ret = wc_ed25519_import_public(publicKeyDer, publicKeySize,
            &ctx->key.ed25519);
        if (ret == BAD_FUNC_ARG) {
            word32 idx = 0;
            ret = wc_Ed25519PublicKeyDecode(publicKeyDer, &idx,
                &ctx->key.ed25519, publicKeySize);
            if (ret == 0) {
                ctx->pub_key_der_encoded = 1;
            }
        }
        if (ret == 0) {
            WGW_LOG("Ed25519 public key import succeeded");
            if (ctx->pub_key_der_encoded) {
                ret = wc_Ed25519PublicKeyToDer(&ctx->key.ed25519, ctx->pub_data,
                        sizeof(ctx->pub_data), 1);
                if (ret > 0) {
                    ctx->pub_data_len = (word32)ret;
                }
            } else {
                ctx->pub_data_len = ED25519_PUB_KEY_SIZE;
                ret = wc_ed25519_export_public(&ctx->key.ed25519, ctx->pub_data,
                        &ctx->pub_data_len);
            }
            if (ret < 0) {
                WGW_WOLFSSL_ERROR("wc_ed25519_export_public", ret);
                wc_ed25519_free(&ctx->key.ed25519);
                gnutls_free(publicKeyDer);
                return GNUTLS_E_INVALID_REQUEST;
            } else {
                WGW_LOG("Ed25519 public key export succeeded");
                ctx->algo = GNUTLS_PK_EDDSA_ED25519;
                *key_found = 1;
            }
        } else {
            WGW_LOG("Ed25519 public key import failed with code %d", ret);
            wc_ed25519_free(&ctx->key.ed25519);
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}
#endif

#if defined(HAVE_ED448)
static int wolfssl_ed448_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_ed448_init(&ctx->key.ed448);
    if (ret == 0) {
        ret = wc_ed448_import_public(publicKeyDer, publicKeySize,
            &ctx->key.ed448);
        if (ret == BAD_FUNC_ARG) {
            word32 idx = 0;
            ret = wc_Ed448PublicKeyDecode(publicKeyDer, &idx, &ctx->key.ed448,
                publicKeySize);
            if (ret == 0) {
                ctx->pub_data_len = (word32)ret;
                ctx->pub_key_der_encoded = 1;
            }
        }
        if (ret == 0) {
            WGW_LOG("Ed448 public key import succeeded");
            if (ctx->pub_key_der_encoded) {
                ret = wc_Ed448PublicKeyToDer(&ctx->key.ed448, ctx->pub_data,
                        sizeof(ctx->pub_data), 1);
                if (ret > 0) {
                    ctx->pub_data_len = (word32)ret;
                }
            } else {
                ctx->pub_data_len = ED448_PUB_KEY_SIZE;
                ret = wc_ed448_export_public(&ctx->key.ed448, ctx->pub_data,
                        &ctx->pub_data_len);
            }
            if (ret < 0) {
                WGW_WOLFSSL_ERROR("wc_ed448_export_public", ret);
                wc_ed448_free(&ctx->key.ed448);
                gnutls_free(publicKeyDer);
                return GNUTLS_E_INVALID_REQUEST;
            } else {
                WGW_LOG("Ed448 public key export succeeded");
                ctx->algo = GNUTLS_PK_EDDSA_ED448;
                *key_found = 1;
            }
        } else {
            WGW_LOG("Ed448 public key import failed with code %d", ret);
            wc_ed448_free(&ctx->key.ed448);
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}
#endif

#if defined(HAVE_CURVE25519)
static int wolfssl_x25519_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_curve25519_init(&ctx->key.x25519);
    if (ret == 0) {
        ret = wc_curve25519_import_public_ex(publicKeyDer, publicKeySize,
            &ctx->key.x25519, EC25519_LITTLE_ENDIAN);
        if (ret == BAD_FUNC_ARG) {
            word32 idx = 0;
            ret = wc_Curve25519PublicKeyDecode(publicKeyDer, &idx,
                &ctx->key.x25519, publicKeySize);
        }
        if (ret == 0) {
            WGW_LOG("x25519 public key import succeeded");
            ctx->pub_data_len = CURVE25519_PUB_KEY_SIZE;
            ret = wc_curve25519_export_public_ex(&ctx->key.x25519,
                ctx->pub_data, &ctx->pub_data_len, EC25519_LITTLE_ENDIAN);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_curve25519_export_public", ret);
                wc_curve25519_free(&ctx->key.x25519);
                gnutls_free(publicKeyDer);
                return GNUTLS_E_INVALID_REQUEST;
            } else {
                WGW_LOG("x25519 public key export succeeded");
                ctx->algo = GNUTLS_PK_ECDH_X25519;
                *key_found = 1;
            }
        } else {
            WGW_LOG("X25519 public key import failed with code %d", ret);
            wc_curve25519_free(&ctx->key.x25519);
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}
#endif

#if defined(HAVE_CURVE448)
static int wolfssl_x448_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_curve448_init(&ctx->key.x448);
    if (ret == 0) {
        ret = wc_curve448_import_public_ex(publicKeyDer, publicKeySize,
            &ctx->key.x448, EC448_LITTLE_ENDIAN);
        if (ret == BAD_FUNC_ARG) {
            word32 idx = 0;
            ret = wc_Curve448PublicKeyDecode(publicKeyDer, &idx, &ctx->key.x448,
                publicKeySize);
        }
        if (ret == 0) {
            WGW_LOG("x448 public key import succeeded");
            ctx->pub_data_len = CURVE448_PUB_KEY_SIZE;
            ret = wc_curve448_export_public_ex(&ctx->key.x448, ctx->pub_data,
                &ctx->pub_data_len, EC448_LITTLE_ENDIAN);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_curve448_export_public", ret);
                wc_curve448_free(&ctx->key.x448);
                gnutls_free(publicKeyDer);
                return GNUTLS_E_INVALID_REQUEST;
            } else {
                WGW_LOG("x448 public key export succeeded");
                ctx->algo = GNUTLS_PK_ECDH_X448;
                *key_found = 1;
            }
        } else {
            WGW_LOG("X448 public key import failed with code %d", ret);
            wc_curve448_free(&ctx->key.x448);
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}
#endif

static int wolfssl_dh_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;

    WGW_FUNC_ENTER();

    ret = wc_InitDhKey(&ctx->key.dh);
    if (ret == 0) {
        ret = wc_DhImportKeyPair(&ctx->key.dh, NULL, 0, publicKeyDer,
            publicKeySize);
        if (ret == 0) {
            WGW_LOG("RSA public key import succeeded");
            if (publicKeySize <= sizeof(ctx->pub_data)) {
                 XMEMCPY(ctx->pub_data, publicKeyDer, publicKeySize);
                 ctx->pub_data_len = publicKeySize;
                 WGW_LOG("DH public key stored in context, size: %u",
                     ctx->pub_data_len);
            } else {
                 WGW_LOG("DH public key size (%u) too large for buffer (%zu)",
                     publicKeySize, sizeof(ctx->pub_data));
            }

            ctx->algo = GNUTLS_PK_DH;
            *key_found = 1;
        } else {
            WGW_LOG("DH public key import failed with code %d", ret);
            wc_FreeDhKey(&ctx->key.dh);
        }
    } else {
        WGW_WOLFSSL_ERROR("wc_InitDhKey", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    return 0;
}

static int pk_algo_to_alg_id(gnutls_pk_algorithm_t algo)
{
    switch (algo) {
        case GNUTLS_PK_RSA:
            return RSAk;
        case GNUTLS_PK_RSA_PSS:
            return RSAPSSk;
        case GNUTLS_PK_DH:
            return DHk;
        case GNUTLS_PK_ECDSA:
            return ECDSAk;
#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
        case GNUTLS_PK_EDDSA_ED25519:
            return ED25519k;
#endif
#if defined(HAVE_ED448)
        case GNUTLS_PK_EDDSA_ED448:
            return ED448k;
#endif
#if defined(HAVE_CURVE25519)
        case GNUTLS_PK_ECDH_X25519:
            return X25519k;
#endif
#if defined(HAVE_CURVE448)
        case GNUTLS_PK_ECDH_X448:
            return X448k;
#endif
#endif
        default:
            return ANONk;
    }
}

static int wolfssl_pk_import_public(struct wolfssl_pk_ctx *ctx,
    unsigned char* publicKeyDer, word32 publicKeySize, int* key_found)
{
    int ret;
    int algId = pk_algo_to_alg_id(ctx->algo);
    int derAlgId = ANONk;
    word32 params = 0;

    WGW_FUNC_ENTER();

    *key_found = 0;

    ret = wolfssl_get_alg_from_der(publicKeyDer, publicKeySize, &derAlgId,
        &params);
    if (ret != 0 && algId == ANONk) {
        if (publicKeySize == 32) {
            derAlgId = ED25519k;
        }
        else if (publicKeySize == 57) {
            derAlgId = ED448k;
        }
        else {
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            WGW_ERROR("could not determine public key type from certificate");
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
        }
    }
    if (algId == ANONk) {
        algId = derAlgId;
    }
    else if ((derAlgId == RSAPSSk && algId == RSAk) ||
             (derAlgId == RSAk && algId == RSAPSSk)) {
        ; /* Keep algId */
    }
    else if (derAlgId != ANONk && derAlgId != algId) {
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        WGW_ERROR("algorithm found (%d) doesn't match context algorithm (%d)",
            derAlgId, algId);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    switch (algId) {
        case RSAk:
            WGW_LOG("RSA public key");
            ret = wolfssl_rsa_import_public(ctx, publicKeyDer, publicKeySize,
                key_found);
            break;
        case RSAPSSk:
            WGW_LOG("RSA-PSS public key");
            ret = wolfssl_rsa_pss_import_public(ctx, publicKeyDer,
                publicKeySize, key_found);
            if (ret < 0) {
                ret = wolfssl_rsa_import_public(ctx, publicKeyDer,
                    publicKeySize, key_found);
                ctx->algo = GNUTLS_PK_RSA_PSS;
            }
            break;
        case ECDSAk:
            WGW_LOG("ECDSA public key");
            ret = wolfssl_ecc_import_public(ctx, publicKeyDer, publicKeySize,
                key_found);
            break;
#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
        case ED25519k:
            WGW_LOG("Ed25519 public key");
            ret = wolfssl_ed25519_import_public(ctx, publicKeyDer,
                publicKeySize, key_found);
            break;
#endif
#if defined(HAVE_ED448)
        case ED448k:
            WGW_LOG("Ed448 public key");
            ret = wolfssl_ed448_import_public(ctx, publicKeyDer, publicKeySize,
                key_found);
            break;
#endif
#if defined(HAVE_CURVE25519)
        case X25519k:
            WGW_LOG("X25519 public key");
            ret = wolfssl_x25519_import_public(ctx, publicKeyDer, publicKeySize,
                key_found);
            break;
#endif
#if defined(HAVE_CURVE448)
        case X448k:
            WGW_LOG("X448 public key");
            ret = wolfssl_x448_import_public(ctx, publicKeyDer, publicKeySize,
                key_found);
            break;
#endif
#endif
        case DHk:
            WGW_LOG("DH public key");
            ret = wolfssl_dh_import_public(ctx, publicKeyDer, publicKeySize,
                key_found);
            break;
        default:
            ret = GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (ret != 0) {
        WGW_ERROR("Key import failed ret=%d.", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return ret;
    }

    return 0;
}


/* import a public key from raw DER using trial-and-error approach */
static int wolfssl_pk_import_pub(void **_ctx,
    gnutls_pk_algorithm_t *pubkey_algo, gnutls_ecc_curve_t *curve,
    const gnutls_datum_t *data)
{
    int ret;
    int key_found;
    struct wolfssl_pk_ctx *ctx;

    /* Allocate a new context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        WGW_ERROR("wc_InitRng failed with code %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    ctx->rng_initialized = 1;

    ret = wolfssl_pk_import_public(ctx, data->data, data->size, &key_found);
    if (ret != 0) {
        return ret;
    }

    if (key_found) {
        *pubkey_algo = ctx->algo;
        *curve = ctx->curve;
        ctx->initialized = 1;
        *_ctx = ctx;
        WGW_LOG("public key imported successfully (algo: %d)", ctx->algo);
        return 0;
    } else {
        WGW_ERROR("internal error - key not found but finalization reached");
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INTERNAL_ERROR;
    }
}

static int wolfssl_pk_import_pubkey_x509_dh(struct wolfssl_pk_ctx *ctx,
    const gnutls_datum_t *pub_datum, const gnutls_datum_t *priv_datum,
    int *key_found)
{
    int ret;

    ret = wc_InitDhKey(&ctx->key.dh);
    if (ret != 0) {
        WGW_ERROR("wc_InitDhKey failed: %d", ret);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_DhImportKeyPair(&ctx->key.dh,
            (priv_datum ? priv_datum->data : NULL),
            (priv_datum ? priv_datum->size : 0),
            pub_datum->data, pub_datum->size);
    if (ret != 0) {
        WGW_ERROR("wc_DhImportKeyPair failed: %d", ret);
        wc_FreeDhKey(&ctx->key.dh);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("DH public key imported successfully into DhKey struct");
    WGW_LOG("size: %u", pub_datum->size);

    if (pub_datum->size > sizeof(ctx->pub_data)) {
        WGW_ERROR("insufficient space in ctx->pub_data (%u vs %zu)",
            pub_datum->size, sizeof(ctx->pub_data));
        wc_FreeDhKey(&ctx->key.dh);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    XMEMCPY(ctx->pub_data, pub_datum->data, pub_datum->size);
    ctx->pub_data_len = pub_datum->size;

    if (priv_datum && priv_datum->data && priv_datum->size > 0) {
        if (priv_datum->size > sizeof(ctx->priv_data)) {
            WGW_ERROR("insufficient space in ctx->priv_data (%u vs %zu)",
                priv_datum->size, sizeof(ctx->priv_data));
            wc_FreeDhKey(&ctx->key.dh);
            return GNUTLS_E_INTERNAL_ERROR;
        }
        XMEMCPY(ctx->priv_data, priv_datum->data, priv_datum->size);
        ctx->priv_data_len = priv_datum->size;
    } else {
        ctx->priv_data_len = 0;
    }

    ctx->algo = GNUTLS_PK_DH;
    *key_found = 1;

    return 0;
}

/* import a public key from raw X.509 data using trial-and-error approach */
static int wolfssl_pk_import_pubkey_x509(void **_ctx,
    gnutls_pk_algorithm_t *pubkey_algo, gnutls_datum_t *data,
    unsigned int flags, const void *y, const void *x)
{
    (void)flags;
    (void)x;
    struct wolfssl_pk_ctx *ctx;
    int ret = GNUTLS_E_INVALID_REQUEST;
    int key_found = 0;
    DecodedCert cert;
    byte *publicKeyDer = NULL;
    word32 publicKeySize = 0;
    const gnutls_datum_t *pub_datum = (const gnutls_datum_t *)y;
    const gnutls_datum_t *priv_datum = (const gnutls_datum_t *)x;
    int isDH = 0;

    WGW_FUNC_ENTER();

    /* Validate input parameters */
    if (!_ctx) {
        WGW_ERROR("invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate a new context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        WGW_ERROR("wc_InitRng failed with code %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    ctx->rng_initialized = 1;

    /* Check if data is empty, indicating potential raw DH key import */
    if (!data || !data->data || data->size == 0) {
        WGW_LOG("empty data for public key import");
        WGW_LOG("checking if y (public key) is set for raw DH import");

        if (!pub_datum || !pub_datum->data || pub_datum->size == 0) {
             WGW_ERROR("no public key data was provided via y");
             wc_FreeRng(&ctx->rng);
             gnutls_free(ctx);
             return GNUTLS_E_INVALID_REQUEST;
        } else {
            WGW_LOG("attempting raw DH public key import via y");
            isDH = 1;
        }
    } else {
         WGW_LOG("Public key data size provided: %lu bytes", data->size);
         /* Proceed with certificate-based import */
    }

    if (isDH) {
        WGW_LOG("importing DH public key from x/y parameters");
        ret = wolfssl_pk_import_pubkey_x509_dh(ctx, pub_datum, priv_datum,
            &key_found);
    } else {
        WGW_LOG("attempting public key import from X.509 certificate data");
        wc_InitDecodedCert(&cert, data->data, data->size, NULL);

        ret = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
        if (ret != 0) {
            WGW_ERROR("Failed to parse X.509 certificate: %d", ret);
            wc_FreeDecodedCert(&cert);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return (ret == ASN_PARSE_E) ? GNUTLS_E_ASN1_DER_ERROR :
                                          GNUTLS_E_ALGO_NOT_SUPPORTED;
        }

        publicKeySize = cert.pubKeySize;
        publicKeyDer = gnutls_malloc(publicKeySize);
        if (publicKeyDer == NULL) {
            WGW_ERROR("Memory allocation failed");
            wc_FreeDecodedCert(&cert);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }
        XMEMCPY(publicKeyDer, cert.publicKey, publicKeySize);
        wc_FreeDecodedCert(&cert);

        ret = wolfssl_pk_import_public(ctx, publicKeyDer, publicKeySize,
            &key_found);
        gnutls_free(publicKeyDer);
        if (ret != 0) {
            return ret;
        }
    }

    if (key_found) {
        *pubkey_algo = ctx->algo;
        ctx->initialized = 1;
        *_ctx = ctx;
        WGW_LOG("public key imported successfully (algo: %d)", ctx->algo);
        return 0;

    } else {
        WGW_ERROR("internal error - key not found but finalization reached");
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INTERNAL_ERROR;
    }
}

static int wolfssl_pk_verify_privkey_params(void *_ctx)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret = 0;

    WGW_FUNC_ENTER();

    if (!ctx || !ctx->initialized) {
        WGW_LOG("ctx not initialized");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!wolfssl_pk_supported[ctx->algo]) {
        WGW_LOG("algorithm not supported");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    switch (ctx->algo) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_RSA_PSS:
            /* Function not available. */
            /* ret = wc_CheckRsaKey(&ctx->key.rsa); */
            break;
        case GNUTLS_PK_DH:
            ret = wc_DhCheckPrivKey(&ctx->key.dh, ctx->priv_data,
                ctx->priv_data_len);
            break;
        case GNUTLS_PK_ECDSA:
            ret = wc_ecc_check_key(&ctx->key.ecc);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            if (!ctx->key.ed25519.pubKeySet) {
                WGW_LOG("Deriving public key from private key before signing");
                ctx->pub_data_len = ED25519_PUB_KEY_SIZE;

                ret = wc_ed25519_make_public(&ctx->key.ed25519, ctx->pub_data,
                    ctx->pub_data_len);
                if (ret == 0) {
                    ret = wc_ed25519_import_public(ctx->pub_data,
                        ctx->pub_data_len, &ctx->key.ed25519);
                }
            }
            if (ret == 0) {
                ret = wc_ed25519_check_key(&ctx->key.ed25519);
            }
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            if (!ctx->key.ed448.pubKeySet) {
                WGW_LOG("Deriving public key from private key before signing");
                ctx->pub_data_len = ED448_PUB_KEY_SIZE;

                ret = wc_ed448_make_public(&ctx->key.ed448, ctx->pub_data,
                    ctx->pub_data_len);
                if (ret == 0) {
                    ret = wc_ed448_import_public(ctx->pub_data,
                        ctx->pub_data_len, &ctx->key.ed448);
                }
            }
            if (ret == 0) {
                ret = wc_ed448_check_key(&ctx->key.ed448);
            }
            break;
#endif
#ifdef HAVE_X25519
        case GNUTLS_PK_ECDH_X25519:
            /* Checked on import. */
            break;
#endif
#ifdef HAVE_X448
        case GNUTLS_PK_ECDH_X448:
            /* Checked on import. */
            break;
#endif
        default:
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (ret != 0) {
        ret = GNUTLS_E_ILLEGAL_PARAMETER;
    }

    return ret;
}

static int wolfssl_pk_verify_pubkey_params(void *_ctx)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret = 0;

    switch (ctx->algo) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_RSA_PSS:
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
#endif
            break;
        case GNUTLS_PK_ECDSA:
            ret = wc_ecc_check_key(&ctx->key.ecc);
            break;
        default:
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (ret != 0) {
        ret = GNUTLS_E_ILLEGAL_PARAMETER;
    }

    return ret;
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
        case WC_HASH_TYPE_SHA:
            *mgf = WC_MGF1SHA1;
            if (hash_len != NULL)
                *hash_len = WC_SHA_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA224");
            return 0;
        case WC_HASH_TYPE_SHA224:
            *mgf = WC_MGF1SHA224;
            if (hash_len != NULL)
                *hash_len = WC_SHA224_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA224");
            return 0;
        case WC_HASH_TYPE_SHA256:
            *mgf = WC_MGF1SHA256;
            if (hash_len != NULL)
                *hash_len = WC_SHA256_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA256");
            return 0;
        case WC_HASH_TYPE_SHA384:
            *mgf = WC_MGF1SHA384;
            if (hash_len != NULL)
                *hash_len = WC_SHA384_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA384");
            return 0;
        case WC_HASH_TYPE_SHA512:
            *mgf = WC_MGF1SHA512;
            if (hash_len != NULL)
                *hash_len = WC_SHA512_DIGEST_SIZE;
            WGW_LOG("using MGF1SHA512");
            return 0;
        default:
            WGW_ERROR("Unsupported hash algorithm: %d", hash_type);
            return -1;
    }
}

static int wolfssl_pk_sign_hash_rsa(struct wolfssl_pk_ctx *ctx, int hash_type,
    const gnutls_datum_t *hash_data, gnutls_datum_t *signature)
{
    int ret;
    /* Get the maximum signature size - typically the key size */
    word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
    word32 actual_sig_size = sig_buf_len;

    WGW_LOG("signing hash with RSA");

    byte *sig_buf = gnutls_malloc(sig_buf_len);
    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("sig_buf_len: %d", sig_buf_len);

    WGW_LOG("using RSA PKCS#1 v1.5 padding");
    /* Use wc_SignatureGenerate for PKCS#1 v1.5 */
    ret = wc_SignatureGenerateHash(hash_type, WC_SIGNATURE_TYPE_RSA,
            hash_data->data, hash_data->size, sig_buf, &actual_sig_size,
            &ctx->key.rsa, sizeof(ctx->key.rsa), &ctx->rng);

    if (ret != 0) {
        WGW_ERROR("RSA PKCS#1 v1.5 signing failed with code %d", ret);
        gnutls_free(sig_buf);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Allocate space for the final signature and copy it */
    signature->data = gnutls_malloc(actual_sig_size);
    if (!signature->data) {
        gnutls_free(sig_buf);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("RSA sig_size: %u", actual_sig_size);
    XMEMCPY(signature->data, sig_buf, actual_sig_size);
    signature->size = actual_sig_size;
    gnutls_free(sig_buf);

    return 0;
}

static int wolfssl_pk_sign_hash_rsa_pss(struct wolfssl_pk_ctx *ctx,
    int hash_type, const gnutls_datum_t *hash_data, gnutls_datum_t *signature)
{
    int ret;
    /* Get the maximum signature size - typically the key size */
    word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
    word32 actual_sig_size = sig_buf_len;
    int mgf = 0;
    byte *sig_buf;

    WGW_LOG("signing with RSA-PSS");

    sig_buf = gnutls_malloc(sig_buf_len);
    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("using RSA-PSS padding");

    /* Map GnuTLS hash algorithm to WolfSSL hash type */
    ret = get_mgf_and_hash_len(hash_type, &mgf, NULL);
    if (ret != 0) {
        WGW_ERROR("Unsupported hash algorithm: %d", hash_type);
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = wc_RsaPSS_Sign(hash_data->data, hash_data->size, sig_buf, sig_buf_len,
            hash_type, mgf, &ctx->key.rsa, &ctx->rng);

    if (ret < 0) {
        WGW_ERROR("RSA-PSS signing failed with code %d", ret);
        gnutls_free(sig_buf);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    actual_sig_size = ret;
    /* Allocate space for the final signature and copy it */
    signature->data = gnutls_malloc(actual_sig_size);
    if (!signature->data) {
        gnutls_free(sig_buf);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("RSA sig_size: %u", actual_sig_size);
    XMEMCPY(signature->data, sig_buf, actual_sig_size);
    signature->size = actual_sig_size;
    gnutls_free(sig_buf);

    return 0;
}

static int wolfssl_pk_sign_hash_ecdsa(struct wolfssl_pk_ctx *ctx,
    const gnutls_datum_t *hash_data, gnutls_datum_t *signature)
{
    int ret;
    /* Get signature size for allocation */
    word32 sig_size = wc_ecc_sig_size(&ctx->key.ecc);
    byte *sig_buf = gnutls_malloc(sig_size);

    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Sign the hash data */
    ret = wc_ecc_sign_hash(hash_data->data, hash_data->size,
            sig_buf, &sig_size, &ctx->rng, &ctx->key.ecc);
    if (ret != 0) {
        WGW_ERROR("ECDSA hash signing failed with code %d", ret);
        gnutls_free(sig_buf);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Copy the signature to output */
    signature->data = gnutls_malloc(sig_size);
    if (!signature->data) {
        WGW_ERROR("Memory allocation failed");
        gnutls_free(sig_buf);
        return GNUTLS_E_MEMORY_ERROR;
    }

    memcpy(signature->data, sig_buf, sig_size);
    signature->size = sig_size;
    gnutls_free(sig_buf);

    return 0;
}

#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
static int wolfssl_pk_sign_hash_ed25519(struct wolfssl_pk_ctx *ctx,
    const gnutls_datum_t *hash_data, gnutls_datum_t *signature)
{
    int ret;
    /* For Ed25519, the hash is actually the message to sign */
    word32 sig_size = ED25519_SIG_SIZE;
    byte sig_buf[ED25519_SIG_SIZE];

    /* Sign the hash data */
    ret = wc_ed25519ph_sign_hash(hash_data->data, hash_data->size,
            sig_buf, &sig_size, &ctx->key.ed25519, NULL, 0);

    if (ret != 0) {
        WGW_ERROR("Ed25519 hash signing failed with code %d", ret);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Copy the signature to output */
    signature->data = gnutls_malloc(sig_size);
    if (!signature->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    memcpy(signature->data, sig_buf, sig_size);
    signature->size = sig_size;

    return 0;
}
#endif

#if defined(HAVE_ED448)
static int wolfssl_pk_sign_hash_ed448(struct wolfssl_pk_ctx *ctx,
    const gnutls_datum_t *hash_data, gnutls_datum_t *signature)
{
    int ret;
    /* For Ed448, the hash is actually the message to sign */
    word32 sig_size = ED448_SIG_SIZE;
    byte sig_buf[ED448_SIG_SIZE];

    /* Sign the hash data */
    ret = wc_ed448ph_sign_hash(hash_data->data, hash_data->size,
            sig_buf, &sig_size, &ctx->key.ed448, NULL, 0);

    if (ret != 0) {
        WGW_ERROR("Ed448 hash signing failed with code %d", ret);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Copy the signature to output */
    signature->data = gnutls_malloc(sig_size);
    if (!signature->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    memcpy(signature->data, sig_buf, sig_size);
    signature->size = sig_size;

    return 0;
}
#endif
#endif

/* checks if the bits meet the minimum requirements in FIPS mode */
#if defined(HAVE_FIPS)
static int wolfssl_check_rsa_bits(int bits, int operation) {
    switch(bits) {
        case 1024:
            if (operation == VERIFY)
                return 1;
            else
                return 0;
        case 2048:
        case 3072:
        case 4096:
            return 1;
    }
    return 0;
}
#endif

/* sign a hash with a private key */
static int wolfssl_pk_sign_hash(void *_ctx, const void *signer,
    gnutls_digest_algorithm_t hash_algo, const gnutls_datum_t *hash_data,
    gnutls_datum_t *signature, unsigned int flags, gnutls_sign_algorithm_t algo,
    void *params)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret = 0;
    int hash_type;
    gnutls_pk_algorithm_t pk_algo;
    gnutls_x509_spki_st *spki = (gnutls_x509_spki_st *)params;

    (void)signer;
    (void)spki;

    WGW_FUNC_ENTER();
    WGW_LOG("hash algorithm %d", hash_algo);

    if (ctx == NULL) {
        WGW_ERROR("Context is NULL!");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("Context not initialized: %d", ctx->initialized);
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!hash_data || !hash_data->data || hash_data->size == 0 || !signature) {
        WGW_ERROR("bad hash data or signature");
        return GNUTLS_E_INVALID_REQUEST;
    }

    hash_type = get_hash_type((gnutls_mac_algorithm_t)hash_algo);
    if (hash_type < 0 && hash_algo != 0) {
        WGW_ERROR("hash algo not supported: %d", hash_algo);
        return GNUTLS_E_INVALID_REQUEST;
    } else if (hash_algo == 0) {
        WGW_LOG("hash algo unknown, defaulting to sha256");
        hash_type = WC_HASH_TYPE_SHA256;
    }

#if defined(HAVE_FIPS)
    if (hash_type == WC_SHA) {
        WGW_ERROR("hash algo not supported for signing");
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
    }
#endif

    pk_algo = ctx->algo;
    /* check if any RSA-PSS flags/arguments were provided, and if so, update the
     * algo */
    if ((flags & GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS) ||
        algo == GNUTLS_SIGN_RSA_PSS_SHA256 ||
        algo == GNUTLS_SIGN_RSA_PSS_SHA384 ||
        algo == GNUTLS_SIGN_RSA_PSS_SHA512 ||
        algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA256 ||
        algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA384 ||
        algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA512) {
        WGW_LOG("setting to rsa-pss");
        pk_algo = GNUTLS_PK_RSA_PSS;
    }

    if (pk_algo == GNUTLS_PK_RSA) {
#if defined(HAVE_FIPS)
        int bits = (wc_RsaEncryptSize(&ctx->key.rsa) * 8);
        WGW_LOG("bits: %d", bits);
        /* we check if the bits meet the minimum requirement */
        if (!wolfssl_check_rsa_bits(bits, SIGN_OP)) {
            WGW_ERROR("unusual bits size: %d", bits);
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
        }
#endif
        ret = wolfssl_pk_sign_hash_rsa(ctx, hash_type, hash_data, signature);
        if (ret != 0) {
            return ret;
        }
    } else if (pk_algo == GNUTLS_PK_RSA_PSS) {
        int bits = (wc_RsaEncryptSize(&ctx->key.rsa) * 8);
        WGW_LOG("bits: %d", bits);
#if defined(HAVE_FIPS)
        /* we check if the bits meet the minimum requirement */
        if (!wolfssl_check_rsa_bits(bits, SIGN_OP)) {
            WGW_LOG("unusual bits size: %d", bits);
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
        }
#endif
        ret = wolfssl_pk_sign_hash_rsa_pss(ctx, hash_type, hash_data,
            signature);
        if (ret != 0) {
            return ret;
        }
    } else if (pk_algo == GNUTLS_PK_ECDSA) {
#if defined(HAVE_FIPS)
        if (!is_hash_type_fips(hash_type, SIGN_OP)) {
            WGW_ERROR("hash type not approved for signing");
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
        }
#endif

        ret = wolfssl_pk_sign_hash_ecdsa(ctx, hash_data, signature);
        if (ret != 0) {
            return ret;
        }
#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
    } else if (pk_algo == GNUTLS_PK_EDDSA_ED25519) {
        ret = wolfssl_pk_sign_hash_ed25519(ctx, hash_data, signature);
        if (ret != 0) {
            return ret;
        }
#endif
#if defined(HAVE_ED448)
    } else if (pk_algo == GNUTLS_PK_EDDSA_ED448) {
        ret = wolfssl_pk_sign_hash_ed448(ctx, hash_data, signature);
        if (ret != 0) {
            return ret;
        }
#endif
#endif
    } else {
        WGW_ERROR("unsupported algorithm for hash signing: %d\n", algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("hash signed successfully");
    return 0;
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
static int verify_rsa_pss(int hash_type, const gnutls_datum_t *msg_data,
    const gnutls_datum_t *sig, gnutls_digest_algorithm_t hash, int salt_size,
    RsaKey *rsa_key, int hash_flag)
{
    int ret;
    int mgf = 0;
    int hash_len = 0;
    const byte *digest = NULL;
    byte *computed_digest = NULL;
    byte *verify_buf = NULL;

    WGW_FUNC_ENTER();

    /* Get MGF type and hash length */
    if (get_mgf_and_hash_len(hash_type, &mgf, &hash_len) != 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("hash_len: %d", hash_len);
    WGW_LOG("salt_size: %d", salt_size);

    if (hash_flag) {
        /* Allocate memory for the digest */
        computed_digest = gnutls_malloc(hash_len);
        if (!computed_digest) {
            WGW_ERROR("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Hash the message */
        ret = wolfssl_digest_fast(hash, msg_data->data, msg_data->size,
            computed_digest);
        if (ret != 0) {
            WGW_ERROR("Hashing of msg before verification failed with ret: %d",
                ret);
            gnutls_free(computed_digest);
            return GNUTLS_E_PK_SIGN_FAILED;
        }
        digest = computed_digest;
    } else {
        digest = msg_data->data;
        hash_len = msg_data->size;
    }

    /* Allocate memory for verification buffer */
    verify_buf = gnutls_malloc(RSA_PSS_SIG_SIZE);
    if (!verify_buf) {
        if (computed_digest) gnutls_free(computed_digest);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Verify using RSA-PSS */
    ret = wc_RsaPSS_Verify_ex(sig->data, sig->size, verify_buf,
        RSA_PSS_SIG_SIZE, hash_type, mgf, salt_size, rsa_key);
    if (ret <= 0) {
        WGW_ERROR("RSA-PSS verify failed");
        if (computed_digest) gnutls_free(computed_digest);
        gnutls_free(verify_buf);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    /* Verify using RSA-PSS */
    ret = wc_RsaPSS_CheckPadding_ex(digest, hash_len, verify_buf, ret,
        hash_type, salt_size, wc_RsaEncryptSize(rsa_key) * 8);

    /* Free resources */
    if (computed_digest)
        gnutls_free(computed_digest);
    gnutls_free(verify_buf);

    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_VerifyCheck", ret);
        ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    else {
        ret = 0;
    }

    return ret;
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
static int verify_rsa_pkcs1(int hash_type, const gnutls_datum_t *msg_data,
    const gnutls_datum_t *sig, RsaKey *rsa_key, int hash_flag, int hash_size)
{
    int ret;

    WGW_FUNC_ENTER();

    if (!hash_flag) {
        WGW_LOG("data not already hashed");
        /* Use SignatureVerify for PKCS#1 v1.5 */
        ret = wc_SignatureVerify(
                hash_type,
                WC_SIGNATURE_TYPE_RSA,
                msg_data->data, msg_data->size,
                sig->data, sig->size,
                rsa_key, sizeof(*rsa_key)
                );
        if (ret == SIG_VERIFY_E) {
            ret = wc_SignatureVerify(
                    hash_type,
                    WC_SIGNATURE_TYPE_RSA_W_ENC,
                    msg_data->data, msg_data->size,
                    sig->data, sig->size,
                    rsa_key, sizeof(*rsa_key)
                    );
        }
    } else {
        /* Use SignatureVerify for PKCS#1 v1.5 */
        unsigned char out[4096/8];
        ret = wc_RsaSSL_Verify(sig->data, sig->size, out, sizeof(out), rsa_key);
        if ((size_t)ret == msg_data->size) {
            if (XMEMCMP(out, msg_data->data, ret) != 0) {
                ret = -1;
            } else {
                ret = 0;
            }
        }
        else if (msg_data->size == (size_t)hash_size) {
            unsigned char padded[128];
            int oid = wc_HashGetOID(hash_type);
            int sz;
            sz = wc_EncodeSignature(padded, msg_data->data, msg_data->size,
                oid);
            if (sz < 0 || sz != ret) {
                ret = -1;
            } else if (XMEMCMP(padded, out, ret) != 0) {
                ret = -1;
            } else {
                ret = 0;
            }
        }
    }

    if (ret != 0) {
        WGW_ERROR("RSA PKCS#1 v1.5 verification failed with code %d", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

static int wolfssl_pk_verify_hash_rsa(struct wolfssl_pk_ctx *ctx,
    int algo, const gnutls_datum_t *hash, const gnutls_datum_t *signature)
{
    int ret;
    enum wc_HashType hash_type;
    gnutls_digest_algorithm_t hash_gnutls;
    int hash_size;
    int pss = 0;
#ifdef WOLFSSL_PSS_SALT_LEN_DISCOVER
    int salt_size = RSA_PSS_SALT_LEN_DISCOVER;
#else
    int salt_size = RSA_PSS_SALT_LEN_DEFAULT;
#endif

    if (ctx->algo == GNUTLS_PK_RSA_PSS && ctx->spki.salt_size != 0) {
        salt_size = ctx->spki.salt_size;
    }

    /* Determine hash algorithm and if using PSS */
    switch (algo) {
        case GNUTLS_SIGN_RSA_MD5:
            hash_type = WC_HASH_TYPE_MD5;
            hash_gnutls = GNUTLS_DIG_MD5;
            hash_size = 16;
            WGW_LOG("hash detected MD5 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA1:
            hash_type = WC_HASH_TYPE_SHA;
            hash_gnutls = GNUTLS_DIG_SHA1;
            hash_size = 20;
            WGW_LOG("hash detected SHA1 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA224:
            hash_type = WC_HASH_TYPE_SHA224;
            hash_gnutls = GNUTLS_DIG_SHA224;
            hash_size = 28;
            WGW_LOG("hash detected SHA224 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA256:
            hash_type = WC_HASH_TYPE_SHA256;
            hash_gnutls = GNUTLS_DIG_SHA256;
            hash_size = 32;
            WGW_LOG("hash detected SHA256 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA384:
            hash_type = WC_HASH_TYPE_SHA384;
            hash_gnutls = GNUTLS_DIG_SHA384;
            hash_size = 48;
            WGW_LOG("hash detected SHA384 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA512:
            hash_type = WC_HASH_TYPE_SHA512;
            hash_gnutls = GNUTLS_DIG_SHA512;
            hash_size = 64;
            WGW_LOG("hash detected SHA512 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA3_224:
            hash_type = WC_HASH_TYPE_SHA3_224;
            hash_gnutls = GNUTLS_DIG_SHA3_224;
            hash_size = 28;
            WGW_LOG("hash detected SHA3_224 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA3_256:
            hash_type = WC_HASH_TYPE_SHA3_256;
            hash_gnutls = GNUTLS_DIG_SHA3_256;
            hash_size = 32;
            WGW_LOG("hash detected SHA3_256 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA3_384:
            hash_type = WC_HASH_TYPE_SHA3_384;
            hash_gnutls = GNUTLS_DIG_SHA3_384;
            hash_size = 48;
            WGW_LOG("hash detected SHA3_384 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_SHA3_512:
            hash_type = WC_HASH_TYPE_SHA3_512;
            hash_gnutls = GNUTLS_DIG_SHA3_512;
            hash_size = 64;
            WGW_LOG("hash detected SHA3_512 (PKCS#1)");
            break;
        case GNUTLS_SIGN_RSA_PSS_SHA256:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
            hash_type = WC_HASH_TYPE_SHA256;
            hash_gnutls = GNUTLS_DIG_SHA256;
            hash_size = 32;
            pss = 1;
            WGW_LOG("hash detected SHA256 (PSS)");
            break;
        case GNUTLS_SIGN_RSA_PSS_SHA384:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
            hash_type = WC_HASH_TYPE_SHA384;
            hash_gnutls = GNUTLS_DIG_SHA384;
            hash_size = 48;
            pss = 1;
            WGW_LOG("hash detected SHA384 (PSS)");
            break;
        case GNUTLS_SIGN_RSA_PSS_SHA512:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:
            hash_type = WC_HASH_TYPE_SHA512;
            hash_gnutls = GNUTLS_DIG_SHA512;
            hash_size = 64;
            pss = 1;
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
        word32 idx = 0;

        WGW_LOG("public key is not set, importing now");

        /* Import the public key from DER */
        ret = wc_RsaPublicKeyDecode(ctx->pub_data, &idx, &ctx->key.rsa,
            ctx->pub_data_len);
        if (ret != 0) {
            WGW_ERROR("RSA public key import failed with code %d", ret);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
            return GNUTLS_E_INVALID_REQUEST;
        }
    }

    if (!pss) {
        ret = verify_rsa_pkcs1(hash_type, hash, signature, &ctx->key.rsa, 1,
            hash_size);
    }
    if (pss || ret < 0) {
        ret = verify_rsa_pss(hash_type, hash, signature, hash_gnutls, salt_size,
            &ctx->key.rsa, 0);
    }

    if (ret < 0) {
        WGW_ERROR("RSA signature verification failed");
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

/* verify a hash signature with a public key */
static int wolfssl_pk_verify_hash(void *_ctx, const void *key,
    gnutls_sign_algorithm_t algo, const gnutls_datum_t *hash,
    const gnutls_datum_t *signature, void *params)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    int verify_result = 0;
    gnutls_x509_spki_st *spki = (gnutls_x509_spki_st *)params;

    (void)key;
    (void)spki;

    WGW_FUNC_ENTER();
    WGW_LOG("algorithm %d", algo);

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("ctx not initialized, returning not supported");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!hash || !hash->data || hash->size == 0 ||
            !signature || !signature->data || signature->size == 0) {
        WGW_ERROR("hash ort signature invalid");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Handle based on signature algorithm */
    if (algo == GNUTLS_SIGN_ECDSA_SHA224 ||
            algo == GNUTLS_SIGN_ECDSA_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SHA512 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_224 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_256 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_384 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_512 ||
            algo == GNUTLS_SIGN_ECDSA_SECP256R1_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SECP384R1_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SECP521R1_SHA512 ||
            algo == GNUTLS_SIGN_ECDSA_SHA1 ||
            ctx->algo == GNUTLS_PK_ECDSA
            ) {

        /* Verify ECDSA signature */
        ret = wc_ecc_verify_hash(signature->data, signature->size,
                hash->data, hash->size,
                &verify_result, &ctx->key.ecc);

        if (ret != 0) {
            WGW_ERROR("ECDSA hash verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_result != 1) {
            WGW_ERROR("ECDSA hash signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    }
#if defined(HAVE_ED25519)
    else if (algo == GNUTLS_SIGN_EDDSA_ED25519 ||
               ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        int verify_status = 0;

        ret = wc_ed25519ph_verify_hash(signature->data, signature->size,
                hash->data, hash->size,
                &verify_status, &ctx->key.ed25519,
                NULL, 0);

        if (ret != 0) {
            WGW_ERROR("Ed25519 hash verification failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        if (verify_status != 1) {
            WGW_ERROR("Ed25519 hash signature verification failed\n");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    }
#endif
#if defined(HAVE_ED448)
    else if (algo == GNUTLS_SIGN_EDDSA_ED448 ||
               ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        int verify_status = 0;

        /* Verify Ed448 signature */
        ret = wc_ed448ph_verify_hash(signature->data, signature->size,
                hash->data, hash->size,
                &verify_status, &ctx->key.ed448, NULL, 0);

        if (ret != 0) {
            WGW_ERROR("Ed448 hash verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_status != 1) {
            WGW_ERROR("Ed448 hash signature verification failed\n");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    }
#endif
    else if (algo == GNUTLS_SIGN_RSA_SHA224 ||
               algo == GNUTLS_SIGN_RSA_SHA256 ||
               algo == GNUTLS_SIGN_RSA_SHA384 ||
               algo == GNUTLS_SIGN_RSA_SHA512 ||
               algo == GNUTLS_SIGN_RSA_SHA3_224 ||
               algo == GNUTLS_SIGN_RSA_SHA3_256 ||
               algo == GNUTLS_SIGN_RSA_SHA3_384 ||
               algo == GNUTLS_SIGN_RSA_SHA3_512 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA256 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA384 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA512 ||
               algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA256 ||
               algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA384 ||
               algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA512 ||
               algo == GNUTLS_SIGN_RSA_MD5 ||
               algo == GNUTLS_SIGN_RSA_SHA1 ||
               ctx->algo == GNUTLS_PK_RSA) {
        WGW_LOG("verifying with RSA");
        ret = wolfssl_pk_verify_hash_rsa(ctx, algo, hash, signature);
        if (ret != 0) {
            return ret;
        }
    } else {
        WGW_ERROR("unsupported algorithm for hash verification: %d\n", algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("hash signature verified successfully");
    return 0;
}

static int wolfssl_pk_generate_rsa(struct wolfssl_pk_ctx *ctx,
    unsigned int bits)
{
    int ret;

    /* Initialize RSA key */
    ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
    if (ret != 0) {
        WGW_ERROR("wc_InitRsaKey failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

#if !defined(HAVE_FIPS)
    ret = wc_RsaSetRNG(&ctx->key.rsa, &ctx->rng);
#endif

    if (ret != 0) {
        WGW_ERROR("wc_RsaSetRNG failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    WGW_LOG("bits: %d", bits);

    /* missing check for 1024, 1024 is not allowed */
    if (bits == 1024) {
        WGW_ERROR("Bits size not valid");
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Generate RSA key */
    ret = wc_MakeRsaKey(&ctx->key.rsa, bits, WC_RSA_EXPONENT, &ctx->rng);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_ERROR("RSA key generation failed with code %d", ret);
        wc_FreeRsaKey(&ctx->key.rsa);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    return 0;
}

int wolfssl_pk_get_curve_id(int bits, int *curve_id)
{
    if (GNUTLS_BITS_ARE_CURVE(bits) != 0) {
        /* Map GnuTLS curve to wolfSSL */
        switch (GNUTLS_BITS_TO_CURVE(bits)) {
            case GNUTLS_ECC_CURVE_SECP224R1: /* SECP224R1 */
                WGW_LOG("SECP224R1");
                *curve_id = ECC_SECP224R1;
                break;
            case GNUTLS_ECC_CURVE_SECP256R1: /* SECP256R1 */
                WGW_LOG("SECP256R1");
                *curve_id = ECC_SECP256R1;
                break;
            case GNUTLS_ECC_CURVE_SECP384R1: /* SECP384R1 */
                WGW_LOG("SECP384R1");
                *curve_id = ECC_SECP384R1;
                break;
            case GNUTLS_ECC_CURVE_SECP521R1: /* SECP521R1 */
                WGW_LOG("SECP521R1");
                *curve_id = ECC_SECP521R1;
                break;
            default:
                WGW_ERROR("unsupported curve bits: %d", bits);
                return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
        }
    }
    else {
        /* Map GnuTLS curve to wolfSSL */
        switch (bits) {
            case 224: /* SECP224R1 */
                WGW_LOG("SECP224R1");
                *curve_id = ECC_SECP224R1;
                break;
            case 256: /* SECP256R1 */
                WGW_LOG("SECP256R1");
                *curve_id = ECC_SECP256R1;
                break;
            case 384: /* SECP384R1 */
                WGW_LOG("SECP384R1");
                *curve_id = ECC_SECP384R1;
                break;
            case 521: /* SECP521R1 */
                WGW_LOG("SECP521R1");
                *curve_id = ECC_SECP521R1;
                break;
            default:
                WGW_ERROR("unsupported curve bits: %d", bits);
                return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
        }
    }

    return 0;
}

static int wolfssl_pk_generate_ecc(struct wolfssl_pk_ctx *ctx,
    unsigned int bits)
{
    int ret;
    int curve_id;
    int curve_size;

    WGW_FUNC_ENTER();

    /* Initialize ECC key */
    ret = wc_ecc_init(&ctx->key.ecc);
    if (ret != 0) {
        WGW_ERROR("wc_ecc_init failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wolfssl_pk_get_curve_id(bits, &curve_id);
    if (ret != 0) {
        wc_ecc_free(&ctx->key.ecc);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return ret;
    }

    curve_size = wc_ecc_get_curve_size_from_id(curve_id);
    WGW_LOG("curve size: %d", curve_size);

    PRIVATE_KEY_UNLOCK();

    /* Generate ECC key */
    ret = wc_ecc_make_key_ex(&ctx->rng, curve_size, &ctx->key.ecc, curve_id);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_ERROR("key generation failed with code %d", ret);
        wc_ecc_free(&ctx->key.ecc);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    ctx->curve = wolfssl_ecc_curve_id_to_curve_type(curve_id);

    return 0;
}

#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
static int wolfssl_pk_generate_ed25519(struct wolfssl_pk_ctx *ctx)
{
    int ret;

    /* Initialize Ed25519 key */
    ret = wc_ed25519_init(&ctx->key.ed25519);
    if (ret != 0) {
        WGW_ERROR("wc_ed25519_init failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Generate Ed25519 key */
    ret = wc_ed25519_make_key(&ctx->rng, ED25519_KEY_SIZE, &ctx->key.ed25519);
    if (ret != 0) {
        WGW_ERROR("Ed25519 key generation failed with code %d", ret);
        wc_ed25519_free(&ctx->key.ed25519);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    return 0;
}
#endif

#if defined(HAVE_ED448)
static int wolfssl_pk_generate_ed448(struct wolfssl_pk_ctx *ctx)
{
    int ret;

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
        WGW_ERROR("Ed448 key generation failed with code %d", ret);
        wc_ed448_free(&ctx->key.ed448);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    return 0;
}
#endif

#if defined(HAVE_CURVE25519)
static int wolfssl_pk_generate_x25519(struct wolfssl_pk_ctx *ctx)
{
    int ret;

    /* Initialize X25519 key */
    ret = wc_curve25519_init(&ctx->key.x25519);
    if (ret != 0) {
        WGW_ERROR("wc_curve25519_init failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Generate X25519 key */
    ret = wc_curve25519_make_key(&ctx->rng, CURVE25519_KEYSIZE,
        &ctx->key.x25519);
    if (ret != 0) {
        WGW_ERROR("X25519 key generation failed with code %d", ret);
        wc_curve25519_free(&ctx->key.x25519);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    return 0;
}
#endif

#if defined(HAVE_CURVE448)
static int wolfssl_pk_generate_x448(struct wolfssl_pk_ctx *ctx)
{
    int ret;

    /* Initialize X448 key */
    ret = wc_curve448_init(&ctx->key.x448);
    if (ret != 0) {
        WGW_ERROR("wc_curve448_init failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Generate X448 key */
    ret = wc_curve448_make_key(&ctx->rng, CURVE448_KEY_SIZE, &ctx->key.x448);
    if (ret != 0) {
        WGW_ERROR("X448 key generation failed with code %d", ret);
        wc_curve448_free(&ctx->key.x448);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

   return 0;
}
#endif
#endif

static int wolfssl_pk_generate_dh(struct wolfssl_pk_ctx *ctx,
    unsigned int bits, const void *p, const void *g, const void *q)
{
    int ret;
    byte priv[MAX_DH_BITS/8];
    byte pub[MAX_DH_BITS/8];
    word32 privSz = sizeof(priv);
    word32 pubSz = sizeof(pub);
    const DhParams* params = NULL;

    /* Initialize DH key */
    ret = wc_InitDhKey(&ctx->key.dh);
    if (ret != 0) {
        WGW_ERROR("wc_InitDhKey failed with code %d", ret);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Use predefined parameters based on bits size */
    switch (bits) {
        case 2048:
#ifdef HAVE_FFDHE_2048
            WGW_LOG("2048");
            params = wc_Dh_ffdhe2048_Get();
#endif
            break;
        case 3072:
#ifdef HAVE_FFDHE_3072
            WGW_LOG("3072");
            params = wc_Dh_ffdhe3072_Get();
#endif
            break;
        case 4096:
#ifdef HAVE_FFDHE_4096
            WGW_LOG("4096");
            params = wc_Dh_ffdhe4096_Get();
#endif
            break;
        case 0:
            break;
        default:
            WGW_ERROR("Unsupported DH key size: %d", bits);
            wc_FreeDhKey(&ctx->key.dh);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_INVALID_REQUEST;
    }

    if (params == NULL && bits != 0) {
        WGW_ERROR("No parameters available for %d bits", bits);
        wc_FreeDhKey(&ctx->key.dh);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (bits == 0) {
        /* Set the provided parameters */
        const gnutls_datum_t *p_param = (const gnutls_datum_t *)p;
        const gnutls_datum_t *g_param = (const gnutls_datum_t *)g;
        const gnutls_datum_t *q_param = (const gnutls_datum_t *)q;

        WGW_LOG("Setting provided params");

        if (!p_param || !g_param || !q_param) {
            WGW_ERROR("Params were not provided");
            wc_FreeDhKey(&ctx->key.dh);
            wc_FreeRng(&ctx->rng);
            gnutls_free(ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        WGW_LOG("p_aram->size: %u", p_param->size);
        WGW_LOG("g_aram->size: %u", g_param->size);
        WGW_LOG("q_aram->size: %u", q_param->size);

        ret = wc_DhSetCheckKey(&ctx->key.dh, p_param->data, p_param->size,
                g_param->data, g_param->size, q_param->data, q_param->size,
                1, &ctx->rng);
    } else {
        WGW_LOG("Setting predefined params");

        /* Set the predefined parameters */
        ret = wc_DhSetKey(&ctx->key.dh, params->p, params->p_len,
                params->g, params->g_len);
    }

    if (ret != 0) {
        WGW_ERROR("Failed to set DH params: %d\n", ret);
        wc_FreeDhKey(&ctx->key.dh);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate the key pair */
    ret = wc_DhGenerateKeyPair(&ctx->key.dh, &ctx->rng,
            priv, &privSz, pub, &pubSz);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_ERROR("DH key generation failed with code %d", ret);
        wc_FreeDhKey(&ctx->key.dh);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Import the key pair to ensure it's ready for exporting later */
    ret = wc_DhImportKeyPair(&ctx->key.dh, priv, privSz, pub, pubSz);
    if (ret != 0) {
        WGW_ERROR("wc_DhImportKeyPair failed: %d", ret);
        wc_FreeDhKey(&ctx->key.dh);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/* generate a pk key pair */
static int wolfssl_pk_generate(void **_ctx, const void *privkey,
    gnutls_pk_algorithm_t algo, unsigned int bits, const void *p, const void *g,
    const void *q)
{
    struct wolfssl_pk_ctx *ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("algo %d with %d bits", algo, bits);

    (void)privkey;

    /* Allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&ctx->rng);
    if (ret != 0) {
        WGW_ERROR("wc_InitRng failed with code %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    ctx->rng_initialized = 1;
    ctx->algo = algo;

    /* Handle different key types */
    if (algo == GNUTLS_PK_RSA ||
            algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("RSA");
        ret = wolfssl_pk_generate_rsa(ctx, bits);
        if (ret != 0) {
            return ret;
        }
    } else if (algo == GNUTLS_PK_EC) {
        WGW_LOG("EC");
        ret = wolfssl_pk_generate_ecc(ctx, bits);
        if (ret != 0) {
            return ret;
        }
#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
    } else if (algo == GNUTLS_PK_EDDSA_ED25519) {
        WGW_LOG("ED25519");
        ret = wolfssl_pk_generate_ed25519(ctx);
        if (ret != 0) {
            return ret;
        }
#endif
#if defined(HAVE_ED448)
    } else if (algo == GNUTLS_PK_EDDSA_ED448) {
        WGW_LOG("ED448");
        ret = wolfssl_pk_generate_ed448(ctx);
        if (ret != 0) {
            return ret;
        }
#endif
#if defined(HAVE_CURVE25519)
    } else if (algo == GNUTLS_PK_ECDH_X25519) {
        WGW_LOG("X25519");
        ret = wolfssl_pk_generate_x25519(ctx);
        if (ret != 0) {
            return ret;
        }
#endif
#if defined(HAVE_CURVE448)
    } else if (algo == GNUTLS_PK_ECDH_X448) {
        WGW_LOG("X448");
        ret = wolfssl_pk_generate_x448(ctx);
        if (ret != 0) {
            return ret;
        }
#endif
#endif
    } else if (algo == GNUTLS_PK_DH) {
        WGW_LOG("DH");
        ret = wolfssl_pk_generate_dh(ctx, bits, p, g, q);
        if (ret != 0) {
            return ret;
        }
    }
    else {
        WGW_ERROR("unsupported algorithm: %d", algo);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    ctx->initialized = 1;
    WGW_LOG("pk generated successfully");

    *_ctx = ctx;
    return 0;
}

static int wolfssl_rsa_export_pub(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *pub, struct wolfssl_pk_ctx *pub_ctx, int with_hdr)
{
    int ret;
    word32 pubSz = 0;

    WGW_FUNC_ENTER();

    /* Get size required for DER formatted public key */
    ret = wc_RsaPublicKeyDerSize(&priv_ctx->key.rsa, with_hdr);
    /* Note: wc_RsaPublicKeyDerSize returns size on success, negative on
     * error */
    if (ret < 0) {
        WGW_ERROR("RSA public key DER size calculation failed with code %d",
            ret);
        return GNUTLS_E_INVALID_REQUEST; /* Or a more specific error */
    }

    pubSz = ret;

    WGW_LOG("RSA public key DER size: %u", pubSz);

    /* Allocate memory for the public key */
    pub->data = gnutls_malloc(pubSz);
    if (!pub->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Export the public key in DER format */
    ret = wc_RsaKeyToPublicDer_ex(&priv_ctx->key.rsa, pub->data, pubSz,
        with_hdr);
    if (ret < 0) {
        WGW_ERROR("RSA public key DER export failed with code %d", ret);
        gnutls_free(pub->data);
        return GNUTLS_E_INVALID_REQUEST; /* Or a more specific error */
    }

    pub->size = ret; /* The actual size written */

    pub_ctx->pub_data_len = pub->size;
    XMEMCPY(pub_ctx->pub_data, pub->data, pub_ctx->pub_data_len);

    return 0;
}

static int wolfssl_ecc_export_pub(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *pub, struct wolfssl_pk_ctx *pub_ctx)
{
    int ret;
    word32 pubSz = 0;

    WGW_FUNC_ENTER();

    /* Get the size needed for X9.63 formatted public key */
    ret = wc_EccPublicKeyDerSize(&priv_ctx->key.ecc, 1);
    if (ret == BUFFER_E) {
        WGW_ERROR("public key size calculation failed with code %d", ret);
        WGW_ERROR("size: %d", pubSz);
        return GNUTLS_E_INVALID_REQUEST;
    }
    pubSz = ret;

    /* Allocate memory for the public key */
    pub->data = gnutls_malloc(pubSz);
    if (!pub->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Export the key in X9.63 format (0x04 | X | Y) */
    ret = wc_EccPublicKeyToDer(&priv_ctx->key.ecc, pub->data, pubSz, 1);
    if (ret < 0) {
        WGW_ERROR("public key export failed with code %d", ret);
        gnutls_free(pub->data);
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub->size = pubSz;

    WGW_LOG("pub->size: %d", pub->size);

    pub_ctx->pub_data_len = pubSz;
    XMEMCPY(pub_ctx->pub_data, pub->data, pub_ctx->pub_data_len);

    return 0;
}

#if defined(HAVE_ED25519)
static int wolfssl_ed25519_export_pub(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *pub, struct wolfssl_pk_ctx *pub_ctx)
{
    int ret;
    word32 pub_size = 0;

    WGW_FUNC_ENTER();

    if (!priv_ctx->key.ed25519.pubKeySet) {
        WGW_LOG("Deriving public key from private key before signing");
        priv_ctx->pub_data_len = ED25519_PUB_KEY_SIZE;

        ret = wc_ed25519_make_public(&priv_ctx->key.ed25519, priv_ctx->pub_data,
            priv_ctx->pub_data_len);
        if (ret == 0) {
            ret = wc_ed25519_import_public(priv_ctx->pub_data,
                priv_ctx->pub_data_len, &priv_ctx->key.ed25519);
        }
    }

    /* Export Ed25519 public key directly to pub_ctx->pub_data */
    if (!priv_ctx->pub_key_der_encoded) {
        pub_size = ED25519_PUB_KEY_SIZE;
        /* Export Ed25519 public key directly to pub_ctx->pub_data */
        ret = wc_ed25519_export_public(&priv_ctx->key.ed25519,
            pub_ctx->pub_data, &pub_size);
    } else {
        ret = wc_Ed25519PublicKeyToDer(&priv_ctx->key.ed25519,
            pub_ctx->pub_data, sizeof(pub_ctx->pub_data), 1);
        if (ret > 0) {
            pub_size = (word32)ret;
        }
    }

    if (ret < 0) {
        WGW_ERROR("Ed25519 public key export failed with code %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx->pub_data_len = pub_size;

    /* Allocate and copy public key to the external pubkey datum */
    pub->data = gnutls_malloc(pub_size);
    if (!pub->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
    pub->size = pub_size;

    return 0;
}
#endif

#if defined(HAVE_ED448)
static int wolfssl_ed448_export_pub(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *pub, struct wolfssl_pk_ctx *pub_ctx)
{
    int ret;
    word32 pub_size = 0;

    WGW_FUNC_ENTER();

    if (!priv_ctx->key.ed448.pubKeySet) {
        WGW_LOG("Deriving public key from private key before signing");
        priv_ctx->pub_data_len = ED448_PUB_KEY_SIZE;

        ret = wc_ed448_make_public(&priv_ctx->key.ed448, priv_ctx->pub_data,
            priv_ctx->pub_data_len);
        if (ret == 0) {
            ret = wc_ed448_import_public(priv_ctx->pub_data,
                priv_ctx->pub_data_len, &priv_ctx->key.ed448);
        }
    }

    /* Export Ed448 public key directly to pub_ctx->pub_data */
    if (!priv_ctx->pub_key_der_encoded) {
        WGW_LOG("not der encoded");
        pub_size = ED448_PUB_KEY_SIZE;
        /* Export Ed448 public key directly to pub_ctx->pub_data */
        ret = wc_ed448_export_public(&priv_ctx->key.ed448, pub_ctx->pub_data,
                &pub_size);
    } else {
        ret = wc_Ed448PublicKeyToDer(&priv_ctx->key.ed448, pub_ctx->pub_data,
                sizeof(pub_ctx->pub_data), 1);
        if (ret > 0) {
            pub_size = (word32)ret;
        }
    }

    if (ret < 0) {
        WGW_ERROR("Ed448 public key export failed with code %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx->pub_data_len = pub_size;

    /* Allocate and copy public key to the external pubkey datum */
    pub->data = gnutls_malloc(pub_size);
    if (!pub->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
    pub->size = pub_size;

    return 0;
}
#endif

#if defined(HAVE_CURVE25519)
static int wolfssl_x25519_export_pub(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *pub, struct wolfssl_pk_ctx *pub_ctx)
{
    int ret;
    word32 pub_size = CURVE25519_KEYSIZE;

    WGW_FUNC_ENTER();

    /* Export X25519 public key directly to pub_ctx->pub_data */
    ret = wc_curve25519_export_public_ex(&priv_ctx->key.x25519,
        pub_ctx->pub_data, &pub_size, EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_ERROR("X25519 public key export failed with code %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx->pub_data_len = pub_size;

    /* Allocate and copy public key to the external pubkey datum */
    pub->data = gnutls_malloc(pub_size);
    if (!pub->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
    pub->size = pub_size;

    return 0;
}
#endif

#if defined(HAVE_CURVE448)
static int wolfssl_x448_export_pub(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *pub, struct wolfssl_pk_ctx *pub_ctx)
{
    int ret;
    word32 pub_size = CURVE448_KEY_SIZE;

    WGW_FUNC_ENTER();

    /* Export X448 public key directly to pub_ctx->pub_data */
    ret = wc_curve448_export_public_ex(&priv_ctx->key.x448, pub_ctx->pub_data,
            &pub_size, EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_ERROR("X448 public key export failed with code %d", ret);
        gnutls_free(pub_ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx->pub_data_len = pub_size;

    /* Allocate and copy public key to the external pubkey datum */
    pub->data = gnutls_malloc(pub_size);
    if (!pub->data) {
        WGW_ERROR("Memory allocation failed");
        gnutls_free(pub_ctx);
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(pub->data, pub_ctx->pub_data, pub_size);
    pub->size = pub_size;

    return 0;
}
#endif

/* export pub from the key pair */
static int wolfssl_pk_export_pub(void **_pub_ctx, void *_priv_ctx,
    const void *pubkey, int with_hdr)
{
    struct wolfssl_pk_ctx *priv_ctx = _priv_ctx;
    struct wolfssl_pk_ctx *pub_ctx;
    gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;
    int ret;
    int key_found = 0;

    WGW_FUNC_ENTER();

    WGW_LOG("With hdr = %d", with_hdr);

    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    /* Check if pubkey parameter is provided */
    if (!pubkey) {
        WGW_ERROR("pubkey parameter is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!_pub_ctx) {
        WGW_ERROR("invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (pub_ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize pub_ctx with the same algorithm as priv_ctx */
    pub_ctx->algo = priv_ctx->algo;

    if (priv_ctx->algo == GNUTLS_PK_RSA ||
            priv_ctx->algo == GNUTLS_PK_RSA_PSS) {
        ret = wolfssl_rsa_export_pub(priv_ctx, pub, pub_ctx, with_hdr);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    } else if (priv_ctx->algo == GNUTLS_PK_ECDSA) {
        ret = wolfssl_ecc_export_pub(priv_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#if defined(HAVE_ED25519)
    else if (priv_ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        ret = wolfssl_ed25519_export_pub(priv_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
#if defined(HAVE_ED448)
    else if (priv_ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        ret = wolfssl_ed448_export_pub(priv_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
#if defined(HAVE_CURVE25519)
    else if (priv_ctx->algo == GNUTLS_PK_ECDH_X25519) {
        ret = wolfssl_x25519_export_pub(priv_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
#if defined(HAVE_CURVE448)
    else if (priv_ctx->algo == GNUTLS_PK_ECDH_X448) {
        ret = wolfssl_x448_export_pub(priv_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
    else if (priv_ctx->algo == GNUTLS_PK_DH) {
        WGW_LOG("DH");

        /* Export DH public key to pub_ctx->pub_data using wc_DhExportKeyPair */
        pub_ctx->pub_data_len = sizeof(pub_ctx->pub_data);
        ret = wc_DhExportKeyPair(&priv_ctx->key.dh, NULL, NULL,
                pub_ctx->pub_data, &pub_ctx->pub_data_len);
        if (ret != 0) {
            WGW_ERROR("DH public key export failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Allocate and copy public key to the external pubkey datum */
        pub->data = gnutls_malloc(pub_ctx->pub_data_len);
        if (!pub->data) {
            WGW_ERROR("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, pub_ctx->pub_data, pub_ctx->pub_data_len);
        pub->size = pub_ctx->pub_data_len;
    } else {
        WGW_ERROR("unsupported algorithm for exporting public key: %d",
            priv_ctx->algo);
        gnutls_free(pub_ctx);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    pub_ctx->initialized = 1;
    *_pub_ctx = pub_ctx;

    ret = wolfssl_pk_import_public(pub_ctx, pub->data, pub->size, &key_found);
    if (ret != 0) {
        return ret;
    }

    WGW_LOG("public key exported successfully");
    return 0;
}

static int wolfssl_rsa_export_priv(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *priv)
{
    int ret;

    ret = wc_RsaKeyToDer(&priv_ctx->key.rsa, NULL, 0);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->data = gnutls_malloc(ret);
    if (!priv->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_RsaKeyToDer(&priv_ctx->key.rsa, priv->data, ret);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->size = ret;

    return 0;
}

static int wolfssl_ecc_export_priv(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *priv)
{
    int ret;

    ret = wc_EccKeyDerSize(&priv_ctx->key.ecc, 1);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->data = gnutls_malloc(ret);
    if (!priv->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_EccKeyToDer(&priv_ctx->key.ecc, priv->data, ret);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->size = ret;

    return 0;
}

#if defined(HAVE_ED25519)
static int wolfssl_ed25519_export_priv(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *priv)
{
    int ret;

    ret = wc_Ed25519KeyToDer(&priv_ctx->key.ed25519, NULL, 0);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->data = gnutls_malloc(ret);
    if (!priv->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_Ed25519PrivateKeyToDer(&priv_ctx->key.ed25519, priv->data, ret);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->size = ret;

    return 0;
}
#endif

#if defined(HAVE_ED448)
static int wolfssl_ed448_export_priv(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *priv)
{
    int ret;

    ret = wc_Ed448KeyToDer(&priv_ctx->key.ed448, NULL, 0);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->data = gnutls_malloc(ret);
    if (!priv->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_Ed448PrivateKeyToDer(&priv_ctx->key.ed448, priv->data, ret);
    if (ret < 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv->size = ret;

    return 0;
}
#endif

/* Exports the private key in der format and stores it in the datum */
static int wolfssl_pk_export_privkey_x509(void *_priv_ctx, const void *privkey)
{
    struct wolfssl_pk_ctx *priv_ctx = _priv_ctx;
    gnutls_datum_t *priv = (gnutls_datum_t *)privkey;
    int ret;

    WGW_FUNC_ENTER();

    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (priv_ctx->algo == GNUTLS_PK_RSA ||
               priv_ctx->algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("RSA");
        ret = wolfssl_rsa_export_priv(priv_ctx, priv);
        if (ret != 0) {
            return ret;
        }
    } else if (priv_ctx->algo == GNUTLS_PK_ECDSA) {
        WGW_LOG("ECC");
        ret = wolfssl_ecc_export_priv(priv_ctx, priv);
        if (ret != 0) {
            return ret;
        }
    } else if (priv_ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        WGW_LOG("ED25519");
#if defined(HAVE_ED25519)
        ret = wolfssl_ed25519_export_priv(priv_ctx, priv);
        if (ret != 0) {
            return ret;
        }
#endif
    } else if (priv_ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        WGW_LOG("ED448");
#if defined(HAVE_ED448)
        ret = wolfssl_ed448_export_priv(priv_ctx, priv);
        if (ret != 0) {
            return ret;
        }
#endif
    } else {
        WGW_ERROR("unsupported algorithm for exporting private key: %d",
            priv_ctx->algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    return 0;
}

/* Exports the pubkey key in der format and stores it in the datum */
static int wolfssl_pk_export_pubkey_x509(void *_pub_ctx, const void *pubkey) {
    struct wolfssl_pk_ctx *pub_ctx = _pub_ctx;
    gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;
    int ret;

    WGW_FUNC_ENTER();

    /* Check if pubkey parameter is provided */
    if (!pubkey) {
        WGW_ERROR("pubkey parameter is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!pub_ctx || !pub_ctx->initialized) {
        WGW_ERROR("invalid context pointer");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (pub_ctx->algo == GNUTLS_PK_RSA ||
            pub_ctx->algo == GNUTLS_PK_RSA_PSS) {
        ret = wolfssl_rsa_export_pub(pub_ctx, pub, pub_ctx, 1);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    } else if (pub_ctx->algo == GNUTLS_PK_ECDSA) {
        ret = wolfssl_ecc_export_pub(pub_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#if defined(HAVE_ED25519)
    else if (pub_ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        ret = wolfssl_ed25519_export_pub(pub_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
#if defined(HAVE_ED448)
    else if (pub_ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        ret = wolfssl_ed448_export_pub(pub_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
#if defined(HAVE_CURVE25519)
    else if (pub_ctx->algo == GNUTLS_PK_ECDH_X25519) {
        ret = wolfssl_x25519_export_pub(pub_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
#if defined(HAVE_CURVE448)
    else if (pub_ctx->algo == GNUTLS_PK_ECDH_X448) {
        ret = wolfssl_x448_export_pub(pub_ctx, pub, pub_ctx);
        if (ret != 0) {
            gnutls_free(pub_ctx);
            return ret;
        }
    }
#endif
    else if (pub_ctx->algo == GNUTLS_PK_DH) {
        WGW_LOG("DH");

        /* Export DH public key to pub_ctx->pub_data using wc_DhExportKeyPair */
        pub_ctx->pub_data_len = sizeof(pub_ctx->pub_data);
        ret = wc_DhExportKeyPair(&pub_ctx->key.dh, NULL, NULL,
                pub_ctx->pub_data, &pub_ctx->pub_data_len);
        if (ret != 0) {
            WGW_ERROR("DH public key export failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Allocate and copy public key to the external pubkey datum */
        pub->data = gnutls_malloc(pub_ctx->pub_data_len);
        if (!pub->data) {
            WGW_ERROR("Memory allocation failed");
            gnutls_free(pub_ctx);
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, pub_ctx->pub_data, pub_ctx->pub_data_len);
        pub->size = pub_ctx->pub_data_len;
    } else {
        WGW_ERROR("unsupported algorithm for exporting public key: %d",
            pub_ctx->algo);
        gnutls_free(pub_ctx);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    WGW_LOG("public key exported successfully");
    return 0;
}


static int wolfssl_pk_sign_rsa(struct wolfssl_pk_ctx *ctx,
    enum wc_HashType hash_type, int hash_enc, const gnutls_datum_t *msg_data,
    gnutls_datum_t *sig)
{
    int ret;
    int sign_type = WC_SIGNATURE_TYPE_RSA;
    /* Get the maximum signature size - typically the key size */
    word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
    word32 actual_sig_size = sig_buf_len;

    byte *sig_buf = gnutls_malloc(sig_buf_len);
    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("using RSA PKCS#1 v1.5 padding");
    if (hash_enc) {
        WGW_LOG("Encoding digest in DER");
        sign_type = WC_SIGNATURE_TYPE_RSA_W_ENC;
    }

    if (!ctx->rng_initialized) {
#ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
#endif
        ret = wc_InitRng(&ctx->rng);
        if (ret != 0) {
            WGW_ERROR("wc_InitRng failed with code %d", ret);
            gnutls_free(ctx);
            return GNUTLS_E_RANDOM_FAILED;
        }
        ctx->rng_initialized = 1;
    }

    /* Use wc_SignatureGenerate for PKCS#1 v1.5 */
    ret = wc_SignatureGenerate(hash_type, sign_type, msg_data->data,
        msg_data->size, sig_buf, &actual_sig_size, &ctx->key.rsa,
        sizeof(ctx->key.rsa), &ctx->rng);
    if (ret != 0) {
        WGW_ERROR("RSA PKCS#1 v1.5 signing failed with code %d", ret);
        WGW_LOG("found the problem!");
        gnutls_free(sig_buf);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Allocate space for the final signature and copy it */
    sig->data = gnutls_malloc(actual_sig_size);
    if (!sig->data) {
        gnutls_free(sig_buf);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("RSA sig_size: %u", actual_sig_size);
    XMEMCPY(sig->data, sig_buf, actual_sig_size);
    sig->size = actual_sig_size;
    gnutls_free(sig_buf);

    return 0;
}

static int wolfssl_pk_sign_rsa_pss(struct wolfssl_pk_ctx *ctx,
    gnutls_digest_algorithm_t hash, enum wc_HashType hash_type,
    const gnutls_datum_t *msg_data, gnutls_datum_t *sig,
    gnutls_sign_algorithm_t algo)
{
    int ret;
    /* Get the maximum signature size - typically the key size */
    word32 sig_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
    word32 actual_sig_size = sig_buf_len;
    int mgf = 0;
    int hash_len = 0;
    byte *sig_buf = gnutls_malloc(sig_buf_len);
    int salt_size = RSA_PSS_SALT_LEN_DEFAULT;

    WGW_LOG("using RSA-PSS padding");

    if (algo == GNUTLS_SIGN_RSA_MD5 || algo == GNUTLS_SIGN_RSA_SHA1 ||
            algo == GNUTLS_SIGN_RSA_SHA224 || algo == GNUTLS_SIGN_RSA_SHA256 ||
            algo == GNUTLS_SIGN_RSA_SHA384 || algo == GNUTLS_SIGN_RSA_SHA512 ||
            algo == GNUTLS_SIGN_RSA_SHA3_224 ||
            algo == GNUTLS_SIGN_RSA_SHA3_256 ||
            algo == GNUTLS_SIGN_RSA_SHA3_384 ||
            algo == GNUTLS_SIGN_RSA_SHA3_512) {
        return GNUTLS_E_CONSTRAINT_ERROR;
    }

    if (ctx->spki.salt_size != 0) {
        salt_size = ctx->spki.salt_size;
    }
    if (ctx->algo == GNUTLS_PK_RSA_PSS) {
        WGW_LOG("key pk algorithm is GNUTLS_PK_RSA_PSS");
    }
    else {
        WGW_LOG("key pk algorithm is GNUTLS_PK_RSA");
    }
    WGW_LOG("salt_size = %d", salt_size);

    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

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
            WGW_ERROR("Unsupported hash algorithm: %d", hash);
            return GNUTLS_E_INVALID_REQUEST;
    }
    byte *digest = gnutls_malloc(hash_len);
    ret = wolfssl_digest_fast(hash, msg_data->data, msg_data->size, digest);
    if (ret != 0) {
        WGW_ERROR("Hashing of the message before signing failed with ret: %d\n",
            ret);
        gnutls_free(sig_buf);
        gnutls_free(digest);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    ret = wc_RsaPSS_Sign_ex(digest, hash_len, sig_buf, sig_buf_len, hash_type,
        mgf, salt_size, &ctx->key.rsa, &ctx->rng);
    if (ret < 0) {
        WGW_ERROR("RSA-PSS signing failed with code %d", ret);
        gnutls_free(sig_buf);
        gnutls_free(digest);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    actual_sig_size = ret;
    /* Allocate space for the final signature and copy it */
    sig->data = gnutls_malloc(actual_sig_size);
    if (!sig->data) {
        gnutls_free(sig_buf);
        gnutls_free(digest);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("RSA sig_size: %u", actual_sig_size);
    XMEMCPY(sig->data, sig_buf, actual_sig_size);
    sig->size = actual_sig_size;
    gnutls_free(sig_buf);
    gnutls_free(digest);

    return 0;
}

static int wolfssl_pk_sign_ecdsa(struct wolfssl_pk_ctx *ctx,
    enum wc_HashType hash_type, const gnutls_datum_t *msg_data,
    gnutls_datum_t *sig)
{
    int ret;
    /* Get the maximum signature size */
    word32 sig_size = wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC,
            &ctx->key.ecc, sizeof(ctx->key.ecc));
    byte *sig_buf = gnutls_malloc(sig_size);

    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Sign the message with ECDSA using SignatureGenerate */
    ret = wc_SignatureGenerate(hash_type, WC_SIGNATURE_TYPE_ECC,
        msg_data->data, msg_data->size, sig_buf, &sig_size, &ctx->key.ecc,
        sizeof(ctx->key.ecc), &ctx->rng);
    if (ret != 0) {
        WGW_ERROR("ECDSA signing failed with code %d", ret);
        gnutls_free(sig_buf);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Allocate space for the signature and copy it */
    sig->data = gnutls_malloc(sig_size);
    if (!sig->data) {
        gnutls_free(sig_buf);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("sig_size: %d", sig_size);
    XMEMCPY(sig->data, sig_buf, sig_size);
    sig->size = sig_size;
    gnutls_free(sig_buf);

    return 0;
}

#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
static int wolfssl_pk_sign_ed25519(struct wolfssl_pk_ctx *ctx,
    const void *privkey, const gnutls_datum_t *msg_data, gnutls_datum_t *sig)
{
    int ret;
    /* Allocate buffer for Ed25519 signature */
    word32 sig_size = ED25519_SIG_SIZE;
    byte *sig_buf = gnutls_malloc(sig_size);

    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    if (!ctx->key.ed25519.privKeySet) {
        const gnutls_datum_t *private_key_raw = (const gnutls_datum_t *)privkey;

        WGW_LOG("private key not imported, importing it now");
        WGW_LOG("size of private key: %d", private_key_raw->size);

        ret = wc_ed25519_import_private_only(private_key_raw->data,
            private_key_raw->size, &ctx->key.ed25519);
        if (ret != 0) {
             WGW_ERROR("Error while importing the private key, ret = %d", ret);
             return GNUTLS_E_INVALID_REQUEST;
        } else {
             WGW_LOG("Private key imported successfully.");
        }
    }

    if (!ctx->key.ed25519.pubKeySet) {
        WGW_LOG("Deriving public key from private key before signing");
        ctx->pub_data_len = ED25519_PUB_KEY_SIZE;

        ret = wc_ed25519_make_public(&ctx->key.ed25519, ctx->pub_data,
            ctx->pub_data_len);
        if (ret != 0) {
            WGW_ERROR("Failed to derive public key before signing, ret = %d",
                ret);
            return GNUTLS_E_PK_SIGN_FAILED;
        } else {
            WGW_LOG("Success to derive public key before signing");

            ret = wc_ed25519_import_public(ctx->pub_data, ctx->pub_data_len,
                &ctx->key.ed25519);
            if (ret != 0) {
                WGW_ERROR("Error while importing the public key");
                return GNUTLS_E_INVALID_REQUEST;
            }
        }
    } else {
         WGW_LOG("Public key already set in signing context");
    }

    ret = wc_ed25519_check_key(&ctx->key.ed25519);
    if (ret != 0) {
        WGW_ERROR("Ed25519 check key failed (pub and priv set), with ret = %d",
            ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Sign the message with Ed25519 */
    ret = wc_ed25519_sign_msg(msg_data->data, msg_data->size, sig_buf,
        &sig_size, &ctx->key.ed25519);

    if (ret != 0) {
        WGW_ERROR("Ed25519 signing failed with code %d", ret);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Allocate space for the signature and copy it */
    sig->data = gnutls_malloc(sig_size);
    if (!sig->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(sig->data, sig_buf, sig_size);
    sig->size = sig_size;
    gnutls_free(sig_buf);

    return 0;
}
#endif

#if defined(HAVE_ED448)
static int wolfssl_pk_sign_ed448(struct wolfssl_pk_ctx *ctx,
    const void *privkey, const gnutls_datum_t *msg_data, gnutls_datum_t *sig)
{
    int ret;
    /* Allocate buffer for Ed448 signature */
    word32 sig_size = ED448_SIG_SIZE;
    byte *sig_buf = gnutls_malloc(sig_size);

    if (!sig_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    if (!ctx->key.ed448.privKeySet) {
        WGW_LOG("private key not imported, importing it now");

        const gnutls_datum_t *private_key_raw = (const gnutls_datum_t *)privkey;
        WGW_LOG("size of private key: %d", private_key_raw->size);

        ret = wc_ed448_import_private_only(private_key_raw->data,
            private_key_raw->size, &ctx->key.ed448);
        if (ret != 0) {
             WGW_ERROR("Error while importing the private key, ret = %d", ret);
             return GNUTLS_E_INVALID_REQUEST;
        } else {
             WGW_LOG("Private key imported successfully.");
        }
    }

    if (!ctx->key.ed448.pubKeySet) {
        WGW_LOG("Deriving public key from private key before signing");
        ctx->pub_data_len = ED448_PUB_KEY_SIZE;

        ret = wc_ed448_make_public(&ctx->key.ed448, ctx->pub_data,
            ctx->pub_data_len);

        if (ret != 0) {
            WGW_ERROR("Failed to derive public key before signing, ret = %d",
                ret);
            return GNUTLS_E_PK_SIGN_FAILED;
        } else {
            WGW_LOG("Success to derive public key before signing");

            ret = wc_ed448_import_public(ctx->pub_data, ctx->pub_data_len,
                &ctx->key.ed448);
            if (ret != 0) {
                WGW_ERROR("Error while importing the public key");
                return GNUTLS_E_INVALID_REQUEST;
            }
        }
    } else {
         WGW_LOG("Public key already set in signing context");
    }

    ret = wc_ed448_check_key(&ctx->key.ed448);
    if (ret != 0) {
        WGW_ERROR("Ed448 check key failed (pub and priv set), with ret = %d",
            ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Sign the message with Ed448 */
    ret = wc_ed448_sign_msg(msg_data->data, msg_data->size, sig_buf, &sig_size,
        &ctx->key.ed448, NULL, 0);

    if (ret != 0) {
        WGW_ERROR("Ed448 signing failed with code %d", ret);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Allocate space for the signature and copy it */
    sig->data = gnutls_malloc(sig_size);
    if (!sig->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(sig->data, sig_buf, sig_size);
    sig->size = sig_size;
    gnutls_free(sig_buf);

    return ret;
}
#endif
#endif

/* sign message */
static int wolfssl_pk_sign(void *_ctx, const void *privkey,
    gnutls_digest_algorithm_t hash, int hash_enc, const void *data,
    const void *signature, unsigned int flags, gnutls_sign_algorithm_t algo,
    void* params)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    enum wc_HashType hash_type;
    const gnutls_datum_t *msg_data = (const gnutls_datum_t *)data;
    gnutls_datum_t *sig = (gnutls_datum_t *)signature;
    gnutls_pk_algorithm_t pk_algo;
    gnutls_x509_spki_st *spki = (gnutls_x509_spki_st *)params;

#if !defined(HAVE_ED25519) || !defined(HAVE_ED448)
    (void)privkey;
#endif
    (void)spki;

    WGW_FUNC_ENTER();
    WGW_LOG("hash %d", hash);

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("PK context not initialized, using fallback");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!msg_data || !msg_data->data || msg_data->size == 0 || !sig) {
        WGW_ERROR("Bad message data or signature");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if ((int)algo != GNUTLS_E_NO_SIGN_ALGORITHM_SET && !is_pk_supported(algo) &&
            !is_pk_sign_supported(algo)) {
        WGW_ERROR("Algo not supported, algo: %d", algo);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    /* Map GnuTLS hash algorithm to WolfSSL hash type */
    switch (hash) {
        case GNUTLS_DIG_MD5:
            hash_type = WC_HASH_TYPE_MD5;
            WGW_LOG("hash detected MD5");
            break;
        case GNUTLS_DIG_SHA1:
            hash_type = WC_HASH_TYPE_SHA;
            WGW_LOG("hash detected SHA1");
            break;
        case GNUTLS_DIG_SHA256:
            hash_type = WC_HASH_TYPE_SHA256;
            WGW_LOG("hash detected SHA256");
            break;
        case GNUTLS_DIG_SHA224:
            hash_type = WC_HASH_TYPE_SHA224;
            WGW_LOG("hash detected SHA224");
            break;
        case GNUTLS_DIG_SHA384:
            hash_type = WC_HASH_TYPE_SHA384;
            WGW_LOG("hash detected SHA384");
            break;
        case GNUTLS_DIG_SHA512:
            hash_type = WC_HASH_TYPE_SHA512;
            WGW_LOG("hash detected SHA512");
            break;
#if defined(WOLFSSL_SHAKE256)
        case GNUTLS_DIG_SHAKE_256:
            hash_type = WC_HASH_TYPE_SHAKE256;
            WGW_LOG("hash detected SHAKE256");
            break;
#endif
        case GNUTLS_DIG_SHA3_256:
            hash_type = WC_HASH_TYPE_SHA3_256;
            break;
        case GNUTLS_DIG_SHA3_224:
            hash_type = WC_HASH_TYPE_SHA3_224;
            break;
        case GNUTLS_DIG_SHA3_384:
            hash_type = WC_HASH_TYPE_SHA3_384;
            break;
        case GNUTLS_DIG_SHA3_512:
            hash_type = WC_HASH_TYPE_SHA3_512;
            break;
        default:
            WGW_ERROR("Unsupported hash algorithm: %d", hash);
#if defined(WOLFSSL_SHAKE256)
            WGW_LOG("have_shake256 enabled");
#endif
#if defined(HAVE_FIPS)
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
            return GNUTLS_E_INVALID_REQUEST;
    }

    pk_algo = ctx->algo;
    /* check if any RSA-PSS flags/arguments were provided, and if so, update the
     * algo */
    if ((flags & GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS) ||
            algo == GNUTLS_SIGN_RSA_PSS_SHA256 ||
            algo == GNUTLS_SIGN_RSA_PSS_SHA384 ||
            algo == GNUTLS_SIGN_RSA_PSS_SHA512 ||
            algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA256 ||
            algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA384 ||
            algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA512) {
        pk_algo = GNUTLS_PK_RSA_PSS;
    }

    if (pk_algo == GNUTLS_PK_RSA) {
        WGW_LOG("signing with RSA");
        ret = wolfssl_pk_sign_rsa(ctx, hash_type, hash_enc, msg_data, sig);
        if (ret != 0) {
            return ret;
        }
    } else if (pk_algo == GNUTLS_PK_RSA_PSS) {
        int bits;

        WGW_LOG("signing with RSA-PSS");
        bits = (wc_RsaEncryptSize(&ctx->key.rsa) * 8);
        WGW_LOG("bits: %d", bits);
        if (ctx->algo == GNUTLS_PK_RSA_PSS) {
            if (hash != rsa_hash_from_bits(bits)) {
                return GNUTLS_E_CONSTRAINT_ERROR;
            }
        }
        ret = wolfssl_pk_sign_rsa_pss(ctx, hash, hash_type, msg_data, sig,
            algo);
        if (ret != 0) {
            return ret;
        }
    } else if (pk_algo == GNUTLS_PK_ECDSA) {
        WGW_LOG("signing with ECDSA");
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K)
        if ((flags & GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE) != 0) {
            WGW_LOG("signing determinitically");
            wc_ecc_set_deterministic_ex(&ctx->key.ecc, 1, hash_type);
        }
#endif
        ret = wolfssl_pk_sign_ecdsa(ctx, hash_type, msg_data, sig);
        if (ret != 0) {
            return ret;
        }
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K)
        if ((flags & GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE) != 0) {
            wc_ecc_set_deterministic_ex(&ctx->key.ecc, 1, hash_type);
        }
#endif
#if !defined(HAVE_FIPS)
#if defined(HAVE_ED25519)
    } else if (pk_algo == GNUTLS_PK_EDDSA_ED25519) {
        WGW_LOG("signing with EDDSA ed25519");
        ret = wolfssl_pk_sign_ed25519(ctx, privkey, msg_data, sig);
        if (ret != 0) {
            return ret;
        }
#endif
#if defined(HAVE_ED448)
    } else if (pk_algo == GNUTLS_PK_EDDSA_ED448) {
        WGW_LOG("signing with EDDSA ed448");
        ret = wolfssl_pk_sign_ed448(ctx, privkey, msg_data, sig);
        if (ret != 0) {
            return ret;
        }
#endif
#endif
    } else {
        WGW_ERROR("unsupported algorithm for signing: %d", pk_algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    WGW_LOG("signed message successfully");
    return 0;
}


/* verify message */
static int wolfssl_pk_verify(void *_ctx, const void *pubkey,
    gnutls_sign_algorithm_t algo, const void *data, const void *signature,
    unsigned int flags, void *params)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    gnutls_x509_spki_st *spki = (gnutls_x509_spki_st *)params;

#if !defined(HAVE_ED25519) || !defined(HAVE_ED448)
    (void)pubkey;
#endif
    (void)spki;

    WGW_FUNC_ENTER();
    WGW_LOG("algorithm %d", algo);

    if (algo == GNUTLS_SIGN_RSA_MD5 &&
            (flags & GNUTLS_VERIFY_ALLOW_BROKEN) == 0) {
        return GNUTLS_E_INSUFFICIENT_SECURITY;
    }
    if (!is_pk_sign_supported(algo)) {
        WGW_ERROR("Algo not supported, algo: %d", algo);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized, initializing");

        ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
        if (ctx == NULL) {
            WGW_ERROR("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        ctx->initialized = 1;
    }

    const gnutls_datum_t *msg_data = (const gnutls_datum_t *)data;
    const gnutls_datum_t *sig = (const gnutls_datum_t *)signature;

    if (!msg_data || !msg_data->data || msg_data->size == 0 ||
            !sig || !sig->data || sig->size == 0) {
        WGW_ERROR("Message data or signature data invalid");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (algo == GNUTLS_SIGN_ECDSA_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SECP256R1_SHA256 ||
            algo == GNUTLS_SIGN_ECDSA_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SECP384R1_SHA384 ||
            algo == GNUTLS_SIGN_ECDSA_SHA512||
            algo == GNUTLS_SIGN_ECDSA_SECP521R1_SHA512 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_224 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_256 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_384 ||
            algo == GNUTLS_SIGN_ECDSA_SHA3_512||
            ctx->algo == GNUTLS_PK_ECDSA) {
        WGW_LOG("verifying with ECDSA");

        if (!(ctx->key.ecc.type == ECC_PUBLICKEY)) {
            word32 idx = 0;
            WGW_LOG("public key is not set, importing now, size: %d",
                ctx->pub_data_len);
            ret = wc_EccPublicKeyDecode(ctx->pub_data, &idx, &ctx->key.ecc,
                ctx->pub_data_len);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_EccPublicKeyDecode", ret);
                wc_ecc_free(&ctx->key.ecc);
                return GNUTLS_E_INVALID_REQUEST;
            }
        }

        enum wc_HashType hash_type;
        switch (algo) {
            case GNUTLS_SIGN_ECDSA_SHA1:
                hash_type = WC_HASH_TYPE_SHA;
                WGW_LOG("hash detected SHA256");
                break;
            case GNUTLS_SIGN_ECDSA_SHA224:
                hash_type = WC_HASH_TYPE_SHA224;
                WGW_LOG("hash detected SHA224");
                break;
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
                WGW_ERROR("Unsupported algorithm: %d", algo);
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
            WGW_ERROR("ECDSA verifying failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    }
#if defined(HAVE_ED25519)
    else if (algo == GNUTLS_SIGN_EDDSA_ED25519 ||
               ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        int verify_status = 0;
        if (!ctx->key.ed25519.pubKeySet) {
            WGW_LOG("pub key was not set");
            ret = wc_ed25519_import_public(ctx->pub_data, ctx->pub_data_len,
                &ctx->key.ed25519);
            if (ret != 0) {
                WGW_LOG("Error importing public key, trying from arguments");
                gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;
                ret = wc_ed25519_import_public(pub->data, pub->size,
                    &ctx->key.ed25519);
                if (ret != 0) {
                    WGW_ERROR("Error while importing the public key");
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
            WGW_ERROR("Ed25519 verification failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        if (verify_status != 1) {
            WGW_ERROR("Ed25519 signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    }
#endif
#if defined(HAVE_ED448)
    else if (algo == GNUTLS_SIGN_EDDSA_ED448) {
        int verify_status = 0;
        if (!ctx->key.ed448.pubKeySet) {
            WGW_LOG("pub key was not set");
            ret = wc_ed448_import_public(ctx->pub_data, ctx->pub_data_len,
                &ctx->key.ed448);
            if (ret != 0) {
                WGW_LOG("Error importing public key, trying from arguments");
                gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;
                ret = wc_ed448_import_public(pub->data, pub->size,
                    &ctx->key.ed448);
                if (ret != 0) {
                    WGW_ERROR("Error while importing the public key");
                    WGW_ERROR("pub->size: %d", pub->size);
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
            WGW_ERROR("Ed448 verification failed with code %d", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        if (verify_status != 1) {
            WGW_ERROR("Ed448 signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    }
#endif
    else if (algo == GNUTLS_SIGN_RSA_SHA256 ||
               algo == GNUTLS_SIGN_RSA_MD5 ||
               algo == GNUTLS_SIGN_RSA_SHA1 ||
               algo == GNUTLS_SIGN_RSA_SHA224 ||
               algo == GNUTLS_SIGN_RSA_SHA384 ||
               algo == GNUTLS_SIGN_RSA_SHA512 ||
               algo == GNUTLS_SIGN_RSA_SHA3_224 ||
               algo == GNUTLS_SIGN_RSA_SHA3_256 ||
               algo == GNUTLS_SIGN_RSA_SHA3_384 ||
               algo == GNUTLS_SIGN_RSA_SHA3_512 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA256 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA384 ||
               algo == GNUTLS_SIGN_RSA_PSS_SHA512 ||
               algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA256 ||
               algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA384 ||
               algo == GNUTLS_SIGN_RSA_PSS_RSAE_SHA512 ||
               ctx->algo == GNUTLS_PK_RSA) {
        WGW_LOG("verifying with RSA");
        enum wc_HashType hash_type;
        gnutls_digest_algorithm_t hash;
        int pss = 0;
    #ifdef WOLFSSL_PSS_SALT_LEN_DISCOVER
        int salt_size = RSA_PSS_SALT_LEN_DISCOVER;
    #else
        int salt_size = RSA_PSS_SALT_LEN_DEFAULT;
    #endif

        if (ctx->spki.salt_size != 0) {
            salt_size = ctx->spki.salt_size;
        }

        /* Determine hash algorithm and if using PSS */
        switch (algo) {
            case GNUTLS_SIGN_RSA_MD5:
                hash_type = WC_HASH_TYPE_MD5;
                hash = GNUTLS_DIG_MD5;
                WGW_LOG("hash detected SHA1 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA1:
                hash_type = WC_HASH_TYPE_SHA;
                hash = GNUTLS_DIG_SHA1;
                WGW_LOG("hash detected SHA1 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA224:
                hash_type = WC_HASH_TYPE_SHA224;
                hash = GNUTLS_DIG_SHA224;
                WGW_LOG("hash detected SHA224 (PKCS#1)");
                break;
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
            case GNUTLS_SIGN_RSA_SHA3_224:
                hash_type = WC_HASH_TYPE_SHA3_224;
                hash = GNUTLS_DIG_SHA3_224;
                WGW_LOG("hash detected SHA3_224 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA3_256:
                hash_type = WC_HASH_TYPE_SHA3_256;
                hash = GNUTLS_DIG_SHA3_256;
                WGW_LOG("hash detected SHA3_256 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA3_384:
                hash_type = WC_HASH_TYPE_SHA3_384;
                hash = GNUTLS_DIG_SHA3_384;
                WGW_LOG("hash detected SHA3_384 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_SHA3_512:
                hash_type = WC_HASH_TYPE_SHA3_512;
                hash = GNUTLS_DIG_SHA3_512;
                WGW_LOG("hash detected SHA3_512 (PKCS#1)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA256:
            case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
                hash_type = WC_HASH_TYPE_SHA256;
                hash = GNUTLS_DIG_SHA256;
                if ((flags & GNUTLS_VERIFY_RSA_PSS_FIXED_SALT_LENGTH) != 0) {
                    salt_size = WC_SHA256_DIGEST_SIZE;
                }
                pss = 1;
                WGW_LOG("hash detected SHA256 (PSS)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA384:
            case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
                hash_type = WC_HASH_TYPE_SHA384;
                hash = GNUTLS_DIG_SHA384;
                if ((flags & GNUTLS_VERIFY_RSA_PSS_FIXED_SALT_LENGTH) != 0) {
                    salt_size = WC_SHA384_DIGEST_SIZE;
                }
                pss = 1;
                WGW_LOG("hash detected SHA384 (PSS)");
                break;
            case GNUTLS_SIGN_RSA_PSS_SHA512:
            case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:
                hash_type = WC_HASH_TYPE_SHA512;
                hash = GNUTLS_DIG_SHA512;
                if ((flags & GNUTLS_VERIFY_RSA_PSS_FIXED_SALT_LENGTH) != 0) {
                    salt_size = WC_SHA512_DIGEST_SIZE;
                }
                pss = 1;
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
            word32 idx = 0;
            WGW_LOG("public key is not set, importing now");

            /* Import the public key from DER */
            ret = wc_RsaPublicKeyDecode(ctx->pub_data, &idx, &ctx->key.rsa,
                ctx->pub_data_len);
            if (ret != 0) {
                WGW_ERROR("RSA public key import failed with code %d", ret);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
                return GNUTLS_E_INVALID_REQUEST;
            }
        }

        if (pss) {
            /* First try RSA-PSS verification */
            ret = verify_rsa_pss(hash_type, msg_data, sig, hash, salt_size,
                &ctx->key.rsa, 1);
        }

        /* If RSA-PSS fails, fall back to PKCS#1 v1.5 */
        if (!pss || ret < 0) {
            WGW_LOG("RSA-PSS verification failed, trying PKCS#1 v1.5");
            ret = verify_rsa_pkcs1(hash_type, msg_data, sig, &ctx->key.rsa, 0,
                0);
        }

        if (ret < 0) {
            WGW_ERROR("RSA signature verification failed");
#if defined(HAVE_FIPS)
            return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else {
        WGW_ERROR("unsupported algorithm for verification: %d", algo);
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
        }
#if defined(HAVE_ED25519)
        else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
            wc_ed25519_free(&ctx->key.ed25519);
        }
#endif
#if defined(HAVE_ED448)
        else if (ctx->algo == GNUTLS_PK_EDDSA_ED448) {
            wc_ed448_free(&ctx->key.ed448);
        }
#endif
#if defined(HAVE_CURVE25519)
        else if (ctx->algo == GNUTLS_PK_ECDH_X25519) {
            wc_curve25519_free(&ctx->key.x25519);
        }
#endif
#if defined(HAVE_CURVE448)
        else if (ctx->algo == GNUTLS_PK_ECDH_X448) {
            wc_curve448_free(&ctx->key.x448);
        }
#endif
        else if (ctx->algo == GNUTLS_PK_DH) {
            wc_FreeDhKey(&ctx->key.dh);
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
static int wolfssl_pk_derive_shared_secret(void *_pub_ctx, void *_priv_ctx,
    const void *privkey, const void *pubkey, const gnutls_datum_t *nonce,
    gnutls_datum_t *secret)
{
    struct wolfssl_pk_ctx *priv_ctx = _priv_ctx;
    struct wolfssl_pk_ctx *pub_ctx = _pub_ctx;
    int ret;
    gnutls_datum_t local_pub = {0};

    WGW_FUNC_ENTER();

    (void)nonce;

    /* Parameters sanity checks */
    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!secret) {
        WGW_ERROR("missing required parameters");
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
            WGW_LOG("Using public key from context (size: %d bytes)",
                local_pub.size);
        } else {
            WGW_ERROR("No public key available in context either");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }

    /* Handle based on algorithm type */
    switch (priv_ctx->algo) {
        case GNUTLS_PK_EC:
            {
                word32 idx = 0;
                ecc_key peer_key;

                /* Initialize the peer's public key */
                ret = wc_ecc_init(&peer_key);
                if (ret != 0) {
                    WGW_ERROR("wc_ecc_init failed with code %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Import the peer's public key from X963 format (0x04 | X | Y)
                 */
                ret = wc_EccPublicKeyDecode(pub->data, &idx, &peer_key,
                    pub->size);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_EccPublicKeyDecode", ret);
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                ret = wc_ecc_check_key(&peer_key);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_PK_INVALID_PUBKEY;
                }

                /* Determine how much space we need for the shared secret */
                word32 secret_size = wc_ecc_size(&priv_ctx->key.ecc);
                if (secret_size == 0) {
                    WGW_ERROR("error getting key size");
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_INTERNAL_ERROR;
                }

                /* Allocate buffer for the shared secret */
                byte *shared_secret = gnutls_malloc(secret_size);
                if (!shared_secret) {
                    WGW_ERROR("Memory allocation failed");
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_MEMORY_ERROR;
                }

                priv_ctx->key.ecc.rng = &priv_ctx->rng;

#if !defined(HAVE_FIPS)
                mp_int* priv_mp = wc_ecc_key_get_priv(&priv_ctx->key.ecc);
                if (!(priv_mp != NULL && !mp_iszero(priv_mp))) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv =
                        (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_ERROR("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }

                    ret = wc_ecc_import_private_key(priv->data, priv->size,
                        NULL, 0, &priv_ctx->key.ecc);
                    if (ret != 0) {
                        WGW_WOLFSSL_ERROR("wc_ecc_import_private_key", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }
#else
                ecc_key* key_ptr = &priv_ctx->key.ecc;
                if ( (key_ptr->type != ECC_PRIVATEKEY &&
                        key_ptr->type != ECC_PRIVATEKEY_ONLY) ||
                        mp_iszero(&key_ptr->k) ) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv =
                        (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_LOG("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }

                    ret = wc_ecc_import_private_key(priv->data, priv->size,
                        NULL, 0, &priv_ctx->key.ecc);
                    if (ret != 0) {
                        WGW_WOLFSSL_ERROR("wc_ecc_import_private_key", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }
#endif

                PRIVATE_KEY_UNLOCK();

                /* Generate the shared secret */
                ret = wc_ecc_shared_secret(&priv_ctx->key.ecc, &peer_key,
                    shared_secret, &secret_size);

                PRIVATE_KEY_LOCK();

                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_ecc_shared_secret", ret);
                    gnutls_free(shared_secret);
                    wc_ecc_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Free the peer's public key */
                wc_ecc_free(&peer_key);

                /* Set result data */
                secret->data = shared_secret;
                secret->size = secret_size;

                WGW_LOG("EC shared secret derived successfully "
                        "(size: %d bytes)", secret_size);
                return 0;
            }
#if defined(HAVE_CURVE25519)
        case GNUTLS_PK_ECDH_X25519:
            {
                curve25519_key peer_key;
                byte shared_secret_buf[CURVE25519_KEYSIZE];
                word32 secret_size = sizeof(shared_secret_buf);

                /* Initialize the peer's public key */
                ret = wc_curve25519_init(&peer_key);
                if (ret != 0) {
                    WGW_ERROR("wc_curve25519_init failed with code %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Import the peer's public key */
                ret = wc_curve25519_import_public_ex(pub->data, pub->size,
                    &peer_key, EC25519_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_curve25519_import_public_ex", ret);
                    wc_curve25519_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }


                if (!priv_ctx->key.x25519.privSet) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv =
                        (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_ERROR("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }

                    ret = wc_curve25519_import_private_ex(priv->data,
                        priv->size, &priv_ctx->key.x25519,
                        EC25519_LITTLE_ENDIAN);
                    if (ret != 0) {
                        WGW_WOLFSSL_ERROR("wc_curve25519_import_private_ex",
                            ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }


#if !defined(HAVE_FIPS) && defined(WOLFSSL_CURVE25519_BLINDING)
                wc_curve25519_set_rng(&priv_ctx->key.x25519, &priv_ctx->rng);
#endif

                /* Generate the shared secret */
                ret = wc_curve25519_shared_secret_ex(&priv_ctx->key.x25519,
                    &peer_key, shared_secret_buf, &secret_size,
                    EC25519_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_curve25519_shared_secret_ex", ret);
                    wc_curve25519_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Free the peer's public key */
                wc_curve25519_free(&peer_key);

                /* Allocate and set result data */
                secret->data = gnutls_malloc(secret_size);
                if (!secret->data) {
                    WGW_ERROR("Memory allocation failed");
                    return GNUTLS_E_MEMORY_ERROR;
                }

                memcpy(secret->data, shared_secret_buf, secret_size);
                secret->size = secret_size;

                WGW_LOG("X25519 shared secret derived successfully "
                        "(size: %d bytes)", secret_size);
                return 0;
            }
#endif

#if defined(HAVE_CURVE448)
        case GNUTLS_PK_ECDH_X448:
            {
                curve448_key peer_key;
                byte shared_secret_buf[CURVE448_KEY_SIZE];
                word32 secret_size = sizeof(shared_secret_buf);

                /* Initialize the peer's public key */
                ret = wc_curve448_init(&peer_key);
                if (ret != 0) {
                    WGW_ERROR("wc_curve448_init failed with code %d", ret);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Import the peer's public key */
                ret = wc_curve448_import_public_ex(pub->data, pub->size,
                    &peer_key, EC448_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_curve448_import_public_ex", ret);
                    wc_curve448_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                if (!priv_ctx->key.x448.privSet) {
                    WGW_LOG("Private key is not set, importing now");
                    const gnutls_datum_t *priv =
                        (const gnutls_datum_t *)privkey;
                    if (!priv->data || priv->size == 0) {
                        WGW_ERROR("invalid private key data in arguments");
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                    ret = wc_curve448_import_private_ex(priv->data, priv->size,
                        &priv_ctx->key.x448, EC448_LITTLE_ENDIAN);
                    if (ret != 0) {
                        WGW_WOLFSSL_ERROR("wc_curve448_import_private_ex", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }

                /* Generate the shared secret */
                ret = wc_curve448_shared_secret_ex(&priv_ctx->key.x448,
                    &peer_key, shared_secret_buf, &secret_size,
                    EC448_LITTLE_ENDIAN);
                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_curve448_shared_secret_ex", ret);
                    wc_curve448_free(&peer_key);
                    return GNUTLS_E_INVALID_REQUEST;
                }

                /* Free the peer's public key */
                wc_curve448_free(&peer_key);

                /* Allocate and set result data */
                secret->data = gnutls_malloc(secret_size);
                if (!secret->data) {
                    WGW_ERROR("Memory allocation failed");
                    return GNUTLS_E_MEMORY_ERROR;
                }

                memcpy(secret->data, shared_secret_buf, secret_size);
                secret->size = secret_size;

                WGW_LOG("X448 shared secret derived successfully "
                        "(size: %d bytes)", secret_size);
                return 0;
            }
#endif
        case GNUTLS_PK_DH:
            {
                static unsigned char shared_secret[MAX_DH_BITS/8];
                word32 shared_secret_len = sizeof(shared_secret);


                if (!(priv_ctx->priv_data_len > 0)) {
                    priv_ctx->priv_data_len = sizeof(priv_ctx->priv_data);
                    WGW_LOG("Private key not in the context, exporting now");
                    ret = wc_DhExportKeyPair(&priv_ctx->key.dh,
                        priv_ctx->priv_data, &priv_ctx->priv_data_len, NULL,
                         NULL);
                    if (ret != 0) {
                        WGW_ERROR("wc_DhExportKeyPair failed: %d", ret);
                        return GNUTLS_E_INVALID_REQUEST;
                    }
                }

                PRIVATE_KEY_UNLOCK();

                /* Generate shared secret */
                ret = wc_DhAgree(&priv_ctx->key.dh,
                        shared_secret, &shared_secret_len,
                        priv_ctx->priv_data,
                        priv_ctx->priv_data_len,
                        pub->data, pub->size);

                PRIVATE_KEY_LOCK();

                if (ret != 0) {
                    WGW_WOLFSSL_ERROR("wc_DhAgree", ret);
                    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
                }

                /* Set result data */
                secret->data = shared_secret;
                secret->size = shared_secret_len;

                WGW_LOG("DH shared secret derived successfully "
                        "(size: %d bytes)", secret->size);
                return 0;
            }
        default:
            WGW_ERROR("PK algorithm not supported for key exchange: %d",
                priv_ctx->algo);
            return GNUTLS_E_INVALID_REQUEST;
    }
}

/* encrypt with pk */
static int wolfssl_pk_encrypt(void *_ctx, gnutls_pubkey_t key,
                             const gnutls_datum_t *plaintext,
                             gnutls_datum_t *ciphertext)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    (void)key;

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("PK context not initialized, using fallback");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!plaintext || !plaintext->data || plaintext->size == 0 || !ciphertext) {
        WGW_ERROR("Bad plaintext data or ciphertext");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Only support RSA for encryption */
    if (ctx->algo == GNUTLS_PK_RSA_PSS) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (ctx->algo != GNUTLS_PK_RSA) {
        WGW_ERROR("Only RSA is supported for encryption, algorithm is: %d",
            ctx->algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
        WGW_LOG("PKCS#1 RSA encryption disabled");
        return GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM;
    }

    /* Import the public key if needed */
    if (mp_iszero(&ctx->key.rsa.n) || mp_iszero(&ctx->key.rsa.e)) {
        word32 idx = 0;

        WGW_LOG("public key is not set, importing now");

        /* Import the public key from DER */
        ret = wc_RsaPublicKeyDecode(ctx->pub_data, &idx, &ctx->key.rsa,
            ctx->pub_data_len);
        if (ret != 0) {
            WGW_ERROR("RSA public key import failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }
    }

    /* Get the maximum ciphertext size - typically the key size */
    word32 cipher_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
    byte *cipher_buf = gnutls_malloc(cipher_buf_len);
    if (!cipher_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize RNG */
    if (!ctx->rng_initialized) {
#ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
#endif
        ret = wc_InitRng(&ctx->rng);
        if (ret != 0) {
            WGW_ERROR("wc_InitRng failed with code %d", ret);
            gnutls_free(ctx);
            return GNUTLS_E_RANDOM_FAILED;
        }
        ctx->rng_initialized = 1;
    }

#if !defined(HAVE_FIPS)
    ret = wc_RsaSetRNG(&ctx->key.rsa, &ctx->rng);
#endif

    WGW_LOG("cipher_buf_len: %d", cipher_buf_len);

    /* Encrypt using RSA PKCS#1 v1.5 padding */
    ret = wc_RsaPublicEncrypt(
            plaintext->data, plaintext->size,   /* Data to encrypt */
            cipher_buf, cipher_buf_len,         /* Output buffer and length */
            &ctx->key.rsa,                      /* RSA key */
            &ctx->rng                           /* RNG */
    );

    if (ret < 0) {
        WGW_ERROR("RSA encryption failed with code %d", ret);
        gnutls_free(cipher_buf);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Actual size of the ciphertext */
    word32 actual_cipher_size = ret;

    /* Allocate space for the ciphertext and copy it */
    ciphertext->data = gnutls_malloc(actual_cipher_size);
    if (!ciphertext->data) {
        gnutls_free(cipher_buf);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("RSA cipher_size: %u", actual_cipher_size);
    XMEMCPY(ciphertext->data, cipher_buf, actual_cipher_size);
    ciphertext->size = actual_cipher_size;
    gnutls_free(cipher_buf);

    WGW_LOG("encrypted message successfully");
    return 0;
}

static int wolfssl_pk_decrypt(void *_ctx, gnutls_privkey_t key,
                             const gnutls_datum_t *ciphertext,
                             gnutls_datum_t *plaintext)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    (void)key;

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("PK context not initialized, using fallback");
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!ciphertext || !ciphertext->data || ciphertext->size == 0 ||
            !plaintext) {
        WGW_ERROR("Bad ciphertext data or plaintext");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Only support RSA for decryption */
    if (ctx->algo != GNUTLS_PK_RSA) {
        WGW_ERROR("Only RSA is supported for decryption, algorithm is: %d",
            ctx->algo);
        return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
        WGW_LOG("PKCS#1 RSA encryption disabled");
        return GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM;
    }

    /* Get the maximum plaintext size - typically the key size */
    word32 plain_buf_len = wc_RsaEncryptSize(&ctx->key.rsa);
    byte *plain_buf = gnutls_malloc(plain_buf_len);
    if (!plain_buf) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#if !defined(HAVE_FIPS)
    ret = wc_RsaSetRNG(&ctx->key.rsa, &ctx->rng);
#endif

    /* Decrypt using RSA PKCS#1 v1.5 padding */
    ret = wc_RsaPrivateDecrypt(
            ciphertext->data, ciphertext->size, /* Data to decrypt */
            plain_buf, plain_buf_len,           /* Output buffer and length */
            &ctx->key.rsa                       /* RSA key */
    );

    if (ret < 0) {
        WGW_ERROR("RSA decryption failed with code %d", ret);
        gnutls_free(plain_buf);
        return GNUTLS_E_DECRYPTION_FAILED;
    }

    /* Actual size of the plaintext */
    word32 actual_plain_size = ret;

    /* Allocate space for the plaintext and copy it */
    plaintext->data = gnutls_malloc(actual_plain_size);
    if (!plaintext->data) {
        gnutls_free(plain_buf);
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    WGW_LOG("RSA plaintext_size: %u", actual_plain_size);
    XMEMCPY(plaintext->data, plain_buf, actual_plain_size);
    plaintext->size = actual_plain_size;
    gnutls_free(plain_buf);

    WGW_LOG("decrypted message successfully");
    return 0;
}

static int wolfssl_pk_import_rsa_raw(void *_ctx, const gnutls_datum_t *m,
    const gnutls_datum_t *e, const gnutls_datum_t *d, const gnutls_datum_t *p,
    const gnutls_datum_t *q, const gnutls_datum_t *u, const gnutls_datum_t *e1,
    const gnutls_datum_t *e2)
{
    struct wolfssl_pk_ctx *ctx;
    int ret;

    if (!_ctx) {
        WGW_ERROR("PK context pointer NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_InitRsaKey(&ctx->key.rsa, NULL);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
        gnutls_free(ctx);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    if (m) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.n, m->data, m->size);
        if (ret != 0) {
            WGW_LOG("Modulus");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
    if (e) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.e, e->data, e->size);
        if (ret != 0) {
            WGW_LOG("Public Exponent");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
    if (d) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.d, d->data, d->size);
        if (ret != 0) {
            WGW_LOG("Private Exponent");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
    if (p) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.p, p->data, p->size);
        if (ret != 0) {
            WGW_LOG("Prime 1");
            return GNUTLS_E_INVALID_REQUEST;
        }
        ctx->key.rsa.type = RSA_PRIVATE;
    }
    if (q) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.q, q->data, q->size);
        if (ret != 0) {
            WGW_LOG("Prime 2");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
    if (u) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.u, u->data, u->size);
        if (ret != 0) {
            WGW_LOG("CRT u");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
    if (e1) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.dP, e1->data, e1->size);
        if (ret != 0) {
            WGW_LOG("CRT dP");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }
    if (e2) {
        ret = mp_read_unsigned_bin(&ctx->key.rsa.dQ, e2->data, e2->size);
        if (ret != 0) {
            WGW_LOG("CRT dQ");
            return GNUTLS_E_INVALID_REQUEST;
        }
    }

    ctx->algo = GNUTLS_PK_RSA;
    ctx->initialized = 1;

    *(struct wolfssl_pk_ctx **)_ctx = ctx;
    return 0;
}

static int mp_to_datum(mp_int *mp, gnutls_datum_t *d, int lz)
{
    int ret;

    if (d == NULL) {
        return 0;
    }

    lz &= mp_leading_bit(mp);
    d->size = mp_unsigned_bin_size(mp) + lz;
    if (d->size > 0) {
        d->data = gnutls_malloc(d->size);
        if (d->data == NULL) {
            WGW_ERROR("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }
        ret = mp_to_unsigned_bin_len(mp, d->data, d->size);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("mp_to_unsigned_bin", ret);
            return GNUTLS_E_INTERNAL_ERROR;
        }
    }
    else {
        d->data = NULL;
    }

    return 0;
}

/* Export each of the RSA values.
 * Only not NULL items returned.
 */
static int wolfssl_pk_export_rsa_raw(void *_ctx, gnutls_datum_t *m,
    gnutls_datum_t *e, gnutls_datum_t *d, gnutls_datum_t *p, gnutls_datum_t *q,
    gnutls_datum_t *u, gnutls_datum_t *e1, gnutls_datum_t *e2,
    unsigned int flags)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    int lz = (flags & GNUTLS_EXPORT_FLAG_NO_LZ) == 0;

    WGW_FUNC_ENTER();

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = mp_to_datum(&ctx->key.rsa.n, m, lz);
    if (ret != 0) {
        WGW_LOG("Modulus");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.e, e, lz);
    if (ret != 0) {
        WGW_LOG("Public Exponent");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.d, d, lz);
    if (ret != 0) {
        WGW_LOG("Private Exponent");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.p, p, lz);
    if (ret != 0) {
        WGW_LOG("Prime 1");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.q, q, lz);
    if (ret != 0) {
        WGW_LOG("Prime 2");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.u, u, lz);
    if (ret != 0) {
        WGW_LOG("CRT u");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.dP, e1, lz);
    if (ret != 0) {
        WGW_LOG("CRT dP");
        return ret;
    }

    ret = mp_to_datum(&ctx->key.rsa.dQ, e2, lz);
    if (ret != 0) {
        WGW_LOG("CRT dQ");
        return ret;
    }

    return ret;
}

/* export private key (and optionally public key) in raw bytes to the provided
 * gnutls_datum_t */
static int wolfssl_pk_export_privkey_dh_raw(void *ctx, const void *y,
    const void *x)
{
    struct wolfssl_pk_ctx *priv_ctx = ctx;
    gnutls_datum_t *priv_datum = (gnutls_datum_t *)x;
    gnutls_datum_t *pub_datum = (gnutls_datum_t *)y;
    int ret;
    byte priv_buffer[1024];
    byte pub_buffer[1024];
    word32 priv_size = sizeof(priv_buffer);
    word32 pub_size = sizeof(pub_buffer);

    WGW_FUNC_ENTER();

    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!priv_datum) {
        WGW_ERROR("Private key datum parameter (x) is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (priv_ctx->algo != GNUTLS_PK_DH) {
        WGW_ERROR("Context algorithm is not DH (%d)", priv_ctx->algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Export private key and optionally public key using wc_DhExportKeyPair */
    if (pub_datum) {
        ret = wc_DhExportKeyPair(&priv_ctx->key.dh, priv_buffer, &priv_size,
                                pub_buffer, &pub_size);
    } else {
        ret = wc_DhExportKeyPair(&priv_ctx->key.dh, priv_buffer, &priv_size,
                                NULL, NULL);
    }

    if (ret != 0) {
        WGW_ERROR("wc_DhExportKeyPair failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Allocate and copy private key */
    priv_datum->data = gnutls_malloc(priv_size);
    if (!priv_datum->data) {
        WGW_ERROR("Memory allocation failed for private key");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(priv_datum->data, priv_buffer, priv_size);
    priv_datum->size = priv_size;
    XMEMCPY(priv_ctx->priv_data, priv_buffer, priv_size);
    priv_ctx->priv_data_len = priv_size;

    /* If public key requested, allocate and copy it */
    if (pub_datum) {
        pub_datum->data = gnutls_malloc(pub_size);
        if (!pub_datum->data) {
            WGW_ERROR("Memory allocation failed for public key");
            gnutls_free(priv_datum->data);
            priv_datum->data = NULL;
            priv_datum->size = 0;
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub_datum->data, pub_buffer, pub_size);
        pub_datum->size = pub_size;

        WGW_LOG("DH public key exported successfully (pubSz=%u)",
            pub_datum->size);
    }

    WGW_LOG("DH private key exported successfully (privSz=%u)",
        priv_datum->size);
    return 0;
}

/* export public key in raw bytes to the provided gnutls_datum_t */
static int wolfssl_pk_export_pubkey_dh_raw(void *ctx, const void *y)
{
    struct wolfssl_pk_ctx *pub_ctx = ctx;
    gnutls_datum_t *pub_datum = (gnutls_datum_t *)y;
    int ret;
    byte pub_buffer[1024];
    word32 pub_size = sizeof(pub_buffer);

    WGW_FUNC_ENTER();

    if (!pub_ctx || !pub_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!pub_datum) {
        WGW_ERROR("Public key datum parameter (y) is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Ensure the context is for DH algorithm */
    if (pub_ctx->algo != GNUTLS_PK_DH) {
        WGW_ERROR("Context algorithm is not DH (%d)", pub_ctx->algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Export public key using wc_DhExportKeyPair */
    ret = wc_DhExportKeyPair(&pub_ctx->key.dh, NULL, NULL,
                           pub_buffer, &pub_size);

    if (ret != 0) {
        WGW_ERROR("wc_DhExportKeyPair failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (pub_size == 0) {
        ret = wc_DhImportKeyPair(&pub_ctx->key.dh,
                NULL,
                0,
                pub_ctx->pub_data, pub_ctx->pub_data_len);
        if (ret != 0) {
            WGW_ERROR("wc_DhImportKeyPair failed: %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        pub_size = sizeof(pub_buffer);

        ret = wc_DhExportKeyPair(&pub_ctx->key.dh, NULL, NULL,
                pub_buffer, &pub_size);

        if (ret != 0) {
            WGW_ERROR("wc_DhExportKeyPair failed: %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }
    }

    /* Allocate and copy public key */
    pub_datum->data = gnutls_malloc(pub_size);
    if (!pub_datum->data) {
        WGW_ERROR("Memory allocation failed for public key");
        return GNUTLS_E_MEMORY_ERROR;
    }

    XMEMCPY(pub_datum->data, pub_buffer, pub_size);
    pub_datum->size = pub_size;
    XMEMCPY(pub_ctx->pub_data, pub_buffer, pub_size);
    pub_ctx->pub_data_len = pub_size;

    WGW_LOG("DH public key exported successfully (pubSz=%u)", pub_datum->size);

    return 0;
}

static int wolfssl_pk_import_privkey_ecdh_raw(void *ctx, int curve,
    const void *x, const void*  y, const void *k)
{
    struct wolfssl_pk_ctx *priv_ctx;
    gnutls_datum_t *x_datum = (gnutls_datum_t *)x;
    gnutls_datum_t *y_datum = (gnutls_datum_t *)y;
    gnutls_datum_t *k_datum = (gnutls_datum_t *)k;
    unsigned char x_data[66];
    unsigned char y_data[66];
    unsigned char k_data[66];
    int curve_id;
    int ret;
    int len;

    WGW_FUNC_ENTER();

    if (!ctx) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!k) {
        WGW_ERROR("Private key datum parameter (k) is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

#if !defined(HAVE_FIPS)
    if (curve == GNUTLS_ECC_CURVE_ED25519 ||
        curve == GNUTLS_ECC_CURVE_ED448 ||
        curve == GNUTLS_ECC_CURVE_X25519 ||
        curve == GNUTLS_ECC_CURVE_X448) {
        /* Allocate a new context */
        priv_ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
        if (priv_ctx == NULL) {
            WGW_ERROR("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Initialize RNG */
        ret = wc_InitRng(&priv_ctx->rng);
        if (ret != 0) {
            WGW_ERROR("wc_InitRng failed with code %d", ret);
            gnutls_free(priv_ctx);
            return GNUTLS_E_RANDOM_FAILED;
        }
        priv_ctx->rng_initialized = 1;

#if defined(HAVE_ED25519)
        if (curve == GNUTLS_ECC_CURVE_ED25519) {
            WGW_LOG("Ed25519");
            priv_ctx->algo = GNUTLS_PK_EDDSA_ED25519;
            ret = wc_ed25519_import_private_only(k_datum->data, k_datum->size,
                &priv_ctx->key.ed25519);
            if (ret == 0 && x_datum) {
                ret = wc_ed25519_import_public_ex(x_datum->data, x_datum->size,
                    &priv_ctx->key.ed25519, 1);
            }
        } else
#endif
#if defined(HAVE_ED448)
        if (curve == GNUTLS_ECC_CURVE_ED448) {
            WGW_LOG("Ed448");
            priv_ctx->algo = GNUTLS_PK_EDDSA_ED448;
            ret = wc_ed448_import_private_only(k_datum->data, k_datum->size,
                &priv_ctx->key.ed448);
            if (ret == 0 && x_datum) {
                ret = wc_ed448_import_public_ex(x_datum->data, x_datum->size,
                    &priv_ctx->key.ed448, 1);
            }
        }
#endif
#if defined(HAVE_CURVE25519)
        if (curve == GNUTLS_ECC_CURVE_X25519) {
            WGW_LOG("X25519");
            priv_ctx->algo = GNUTLS_PK_ECDH_X25519;
            ret = wc_curve25519_import_private_ex(k_datum->data, k_datum->size,
                &priv_ctx->key.x25519, EC25519_LITTLE_ENDIAN);
            if (ret == 0 && x_datum) {
                ret = wc_curve25519_import_public(x_datum->data, x_datum->size,
                    &priv_ctx->key.x25519);
            }
        }
#endif
#if defined(HAVE_CURVE448)
        if (curve == GNUTLS_ECC_CURVE_X448) {
            WGW_LOG("X448");
            priv_ctx->algo = GNUTLS_PK_ECDH_X448;
            ret = wc_curve448_import_private_ex(k_datum->data, k_datum->size,
                &priv_ctx->key.x448, EC448_LITTLE_ENDIAN);
            if (ret == 0 && x_datum) {
                ret = wc_curve448_import_public(x_datum->data, x_datum->size,
                    &priv_ctx->key.x448);
            }
        }
#endif
        if (ret == 0) {
            priv_ctx->initialized = 1;
            priv_ctx->curve = curve;
            *(struct wolfssl_pk_ctx **)ctx = priv_ctx;
        }
        else {
            WGW_WOLFSSL_ERROR("import private/public", ret);
            ret = GNUTLS_E_INVALID_REQUEST;
        }
        return ret;
    }
#endif

    switch (curve) {
        case GNUTLS_ECC_CURVE_SECP224R1: /* SECP224R1 */
            WGW_LOG("SECP224R1");
            curve_id = ECC_SECP224R1;
            len = 24;
            break;
        case GNUTLS_ECC_CURVE_SECP256R1: /* SECP256R1 */
            WGW_LOG("SECP256R1");
            curve_id = ECC_SECP256R1;
            len = 32;
            break;
        case GNUTLS_ECC_CURVE_SECP384R1: /* SECP384R1 */
            WGW_LOG("SECP384R1");
            curve_id = ECC_SECP384R1;
            len = 48;
            break;
        case GNUTLS_ECC_CURVE_SECP521R1: /* SECP521R1 */
            WGW_LOG("SECP521R1");
            curve_id = ECC_SECP521R1;
            len = 66;
            break;
        default:
            WGW_ERROR("unsupported curve: %d", curve);
            return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    XMEMSET(x_data, 0, sizeof(x_data));
    XMEMSET(y_data, 0, sizeof(y_data));
    XMEMSET(k_data, 0, sizeof(k_data));
    if (x) {
        XMEMCPY(x_data + len - x_datum->size, x_datum->data, x_datum->size);
    }
    if (y) {
        XMEMCPY(y_data + len - y_datum->size, y_datum->data, y_datum->size);
    }
    XMEMCPY(k_data + len - k_datum->size, k_datum->data, k_datum->size);

    /* Allocate a new context */
    priv_ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (priv_ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&priv_ctx->rng);
    if (ret != 0) {
        WGW_ERROR("wc_InitRng failed with code %d", ret);
        gnutls_free(priv_ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    priv_ctx->rng_initialized = 1;
    priv_ctx->algo = GNUTLS_PK_EC;
    priv_ctx->curve = curve;

    ret = wc_ecc_import_unsigned(&priv_ctx->key.ecc, x_data, y_data, k_data,
        curve_id);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_import_unsigned", ret);
        wc_FreeRng(&priv_ctx->rng);
        gnutls_free(priv_ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    priv_ctx->initialized = 1;
    *(struct wolfssl_pk_ctx **)ctx = priv_ctx;
    return 0;
}

static int wolfssl_pk_import_pubkey_ecdh_raw(void *ctx, int curve,
    const void *x, const void*  y)
{
    struct wolfssl_pk_ctx *pub_ctx;
    gnutls_datum_t *x_datum = (gnutls_datum_t *)x;
    gnutls_datum_t *y_datum = (gnutls_datum_t *)y;
    unsigned char x_data[66];
    unsigned char y_data[66];
    int ret;
    int curve_id;
    int len;
#if !defined(HAVE_FIPS)
    int found;
#endif

    WGW_FUNC_ENTER();

    if (!ctx) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!x) {
        WGW_ERROR("Public key datum parameter x is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

#if !defined(HAVE_FIPS)
    if (curve == GNUTLS_ECC_CURVE_ED25519 ||
        curve == GNUTLS_ECC_CURVE_ED448 ||
        curve == GNUTLS_ECC_CURVE_X25519 ||
        curve == GNUTLS_ECC_CURVE_X448) {
        /* Allocate a new context */
        pub_ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
        if (pub_ctx == NULL) {
            WGW_ERROR("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Initialize RNG */
        ret = wc_InitRng(&pub_ctx->rng);
        if (ret != 0) {
            WGW_ERROR("wc_InitRng failed with code %d", ret);
            gnutls_free(pub_ctx);
            return GNUTLS_E_RANDOM_FAILED;
        }
        pub_ctx->rng_initialized = 1;

#if defined(HAVE_ED25519)
        if (curve == GNUTLS_ECC_CURVE_ED25519) {
            WGW_LOG("Ed25519");
            pub_ctx->algo = GNUTLS_PK_EDDSA_ED25519;
            ret = wolfssl_ed25519_import_public(pub_ctx, x_datum->data,
                x_datum->size, &found);
        }
#endif
#if defined(HAVE_ED448)
        if (curve == GNUTLS_ECC_CURVE_ED448) {
            WGW_LOG("Ed448");
            pub_ctx->algo = GNUTLS_PK_EDDSA_ED448;
            ret = wolfssl_ed448_import_public(pub_ctx, x_datum->data,
                x_datum->size, &found);
        }
#endif
#if defined(HAVE_CURVE25519)
        if (curve == GNUTLS_ECC_CURVE_X25519) {
            WGW_LOG("X25519");
            pub_ctx->algo = GNUTLS_PK_ECDH_X25519;
            ret = wolfssl_x25519_import_public(pub_ctx, x_datum->data,
                x_datum->size, &found);
        }
#endif
#if defined(HAVE_CURVE448)
        if (curve == GNUTLS_ECC_CURVE_X448) {
            WGW_LOG("X448");
            pub_ctx->algo = GNUTLS_PK_ECDH_X448;
            ret = wolfssl_x448_import_public(pub_ctx, x_datum->data,
                x_datum->size, &found);
        }
#endif
        if (ret == 0) {
            pub_ctx->initialized = 1;
            *(struct wolfssl_pk_ctx **)ctx = pub_ctx;
        }
        return ret;
    }
#endif

    switch (curve) {
        case GNUTLS_ECC_CURVE_SECP224R1: /* SECP224R1 */
            WGW_LOG("SECP224R1");
            curve_id = ECC_SECP224R1;
            len = 24;
            break;
        case GNUTLS_ECC_CURVE_SECP256R1: /* SECP256R1 */
            WGW_LOG("SECP256R1");
            curve_id = ECC_SECP256R1;
            len = 32;
            break;
        case GNUTLS_ECC_CURVE_SECP384R1: /* SECP384R1 */
            WGW_LOG("SECP384R1");
            curve_id = ECC_SECP384R1;
            len = 48;
            break;
        case GNUTLS_ECC_CURVE_SECP521R1: /* SECP521R1 */
            WGW_LOG("SECP521R1");
            curve_id = ECC_SECP521R1;
            len = 66;
            break;
        default:
            WGW_ERROR("unsupported curve: %d", curve);
            return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    if (!y) {
        WGW_ERROR("Public key datum parameter y is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    XMEMSET(x_data, 0, sizeof(x_data));
    XMEMSET(y_data, 0, sizeof(y_data));
    XMEMCPY(x_data + len - x_datum->size, x_datum->data, x_datum->size);
    XMEMCPY(y_data + len - y_datum->size, y_datum->data, y_datum->size);

    /* Allocate a new context */
    pub_ctx = gnutls_calloc(1, sizeof(struct wolfssl_pk_ctx));
    if (pub_ctx == NULL) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RNG */
    ret = wc_InitRng(&pub_ctx->rng);
    if (ret != 0) {
        WGW_ERROR("wc_InitRng failed with code %d", ret);
        gnutls_free(pub_ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }
    pub_ctx->rng_initialized = 1;
    pub_ctx->algo = GNUTLS_PK_EC;

    ret = wc_ecc_import_unsigned(&pub_ctx->key.ecc, x_data, y_data, NULL,
        curve_id);
    if (ret != IS_POINT_E && ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_import_unsigned", ret);
        wc_FreeRng(&pub_ctx->rng);
        gnutls_free(pub_ctx);
        if (ret == ECC_INF_E)
            return GNUTLS_E_MPI_SCAN_FAILED;
        return GNUTLS_E_INVALID_REQUEST;
    }

    pub_ctx->initialized = 1;
    *(struct wolfssl_pk_ctx **)ctx = pub_ctx;
    return 0;
}

static int wolfssl_pk_export_privkey_ecc_raw(struct wolfssl_pk_ctx *priv_ctx,
    gnutls_datum_t *x, gnutls_datum_t *y, gnutls_datum_t *k)
{
    int ret;
    word32 k_size = k->size;

    /* Export private key and optionally public key using
     * wc_ecc_export_private_raw */
    if (x && y) {
        word32 x_size = x->size;
        word32 y_size = y->size;
        ret = wc_ecc_export_private_raw(&priv_ctx->key.ecc, x->data, &x_size,
            y->data, &y_size, k->data, &k_size);
        x->size = x_size;
        y->size = y_size;
    } else {
        ret = wc_ecc_export_private_only(&priv_ctx->key.ecc, k->data, &k_size);
    }
    k->size = k_size;

    if (ret != 0) {
        WGW_ERROR("wc_ecc_export_private_raw failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

static int wolfssl_pk_export_privkey_ed25519_raw(
    struct wolfssl_pk_ctx *priv_ctx, gnutls_datum_t *x, gnutls_datum_t *k)
{
    int ret;
    word32 k_size = k->size;

    /* Export private key and optionally public key using
     * wc_ecc_export_private_raw */
    if (x) {
        word32 x_size = x->size;
        ret = wc_ed25519_export_public(&priv_ctx->key.ed25519, x->data,
            &x_size);
        if (ret != 0) {
            WGW_ERROR("wc_ed25519_export_public failed: %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }
        x->size = x_size;
    }

    ret = wc_ed25519_export_private_only(&priv_ctx->key.ed25519, k->data,
        &k_size);
    if (ret != 0) {
        WGW_ERROR("wc_ed25519_export_private_only failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }
    k->size = k_size;

    return 0;
}

static int wolfssl_pk_export_privkey_ed448_raw(
    struct wolfssl_pk_ctx *priv_ctx, gnutls_datum_t *x, gnutls_datum_t *k)
{
    int ret;
    word32 k_size = k->size;

    /* Export private key and optionally public key using
     * wc_ecc_export_private_raw */
    if (x) {
        word32 x_size = x->size;
        ret = wc_ed448_export_public(&priv_ctx->key.ed448, x->data,
            &x_size);
        if (ret != 0) {
            WGW_ERROR("wc_ed448_export_public failed: %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }
        x->size = x_size;
    }

    ret = wc_ed448_export_private_only(&priv_ctx->key.ed448, k->data,
        &k_size);
    if (ret != 0) {
        WGW_ERROR("wc_ed448_export_private_only failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }
    k->size = k_size;

    return 0;
}

static int wolfssl_pk_export_privkey_x25519_raw(
    struct wolfssl_pk_ctx *priv_ctx, gnutls_datum_t *x, gnutls_datum_t *k)
{
    int ret;
    word32 k_size = k->size;

    /* Export private key and optionally public key using
     * wc_ecc_export_private_raw */
    if (x) {
        word32 x_size = x->size;
        ret = wc_curve25519_export_public(&priv_ctx->key.x25519, x->data,
            &x_size);
        if (ret != 0) {
            WGW_ERROR("wc_curve25519_export_public failed: %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }
        x->size = x_size;
    }

    ret = wc_curve25519_export_private_raw(&priv_ctx->key.x25519, k->data,
        &k_size);
    if (ret != 0) {
        WGW_ERROR("wc_curve25519_export_private_raw failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }
    k->size = k_size;

    return 0;
}

static int wolfssl_pk_export_privkey_x448_raw(
    struct wolfssl_pk_ctx *priv_ctx, gnutls_datum_t *x, gnutls_datum_t *k)
{
    int ret;
    word32 k_size = k->size;

    /* Export private key and optionally public key using
     * wc_ecc_export_private_raw */
    if (x) {
        word32 x_size = x->size;
        ret = wc_curve448_export_public(&priv_ctx->key.x448, x->data,
            &x_size);
        if (ret != 0) {
            WGW_ERROR("wc_curve448_export_public failed: %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }
        x->size = x_size;
    }

    ret = wc_curve448_export_private_raw(&priv_ctx->key.x448, k->data,
        &k_size);
    if (ret != 0) {
        WGW_ERROR("wc_curve448_export_private_raw failed: %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }
    k->size = k_size;

    return 0;
}

static int copy_into_datum(gnutls_datum_t *src, gnutls_datum_t *dst, int lz)
{
    if (src->size == 0) {
        dst->data = NULL;
        dst->size = 0;
        return 0;
    }

    /* Leading zero required if requested and first byte has top bit set. */
    lz &= src->data[0] >> 7;
    dst->data = gnutls_malloc(src->size + lz);
    if (!dst->data) {
        WGW_ERROR("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    if (lz)
        dst->data[0] = 0x00;
    XMEMCPY(dst->data + lz, src->data, src->size);
    dst->size = src->size + lz;

    return 0;
}

/* export private key (and optionally public key) in raw bytes to the provided
 * gnutls_datum_t */
static int wolfssl_pk_export_privkey_ecdh_raw(void *ctx,
    gnutls_ecc_curve_t *curve, const void *_x, const void *_y, const void *_k,
    int lz)
{
    struct wolfssl_pk_ctx *priv_ctx = ctx;
    int ret;
    gnutls_datum_t *x_datum = (gnutls_datum_t *)_x;
    gnutls_datum_t *y_datum = (gnutls_datum_t *)_y;
    gnutls_datum_t *k_datum = (gnutls_datum_t *)_k;
    byte x_buffer[66];
    byte y_buffer[66];
    byte k_buffer[66];
    gnutls_datum_t x = {
        .data = x_buffer,
        .size = sizeof(x_buffer)
    };
    gnutls_datum_t y = {
        .data = y_buffer,
        .size = sizeof(y_buffer)
    };
    gnutls_datum_t k = {
        .data = k_buffer,
        .size = sizeof(k_buffer)
    };

    WGW_FUNC_ENTER();

    if (!priv_ctx || !priv_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (curve) {
        *curve = priv_ctx->curve;
    }

    if (!k_datum) {
        WGW_ERROR("Private key datum parameter (k) is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    switch (priv_ctx->algo) {
        case GNUTLS_PK_EDDSA_ED25519:
            if (x_datum) {
                ret = wolfssl_pk_export_privkey_ed25519_raw(priv_ctx, &x, &k);
            } else {
                ret = wolfssl_pk_export_privkey_ed25519_raw(priv_ctx, NULL, &k);
            }
            if (ret < 0) {
                return ret;
            }
            y.size = 0;
            lz = 0;
            break;
        case GNUTLS_PK_EDDSA_ED448:
            if (x_datum) {
                ret = wolfssl_pk_export_privkey_ed448_raw(priv_ctx, &x, &k);
            } else {
                ret = wolfssl_pk_export_privkey_ed448_raw(priv_ctx, NULL, &k);
            }
            if (ret < 0) {
                return ret;
            }
            y.size = 0;
            lz = 0;
            break;
        case GNUTLS_PK_ECDH_X25519:
            if (x_datum) {
                ret = wolfssl_pk_export_privkey_x25519_raw(priv_ctx, &x, &k);
            } else {
                ret = wolfssl_pk_export_privkey_x25519_raw(priv_ctx, NULL, &k);
            }
            if (ret < 0) {
                return ret;
            }
            y.size = 0;
            lz = 0;
            break;
        case GNUTLS_PK_ECDH_X448:
            if (x_datum) {
                ret = wolfssl_pk_export_privkey_x448_raw(priv_ctx, &x, &k);
            } else {
                ret = wolfssl_pk_export_privkey_x448_raw(priv_ctx, NULL, &k);
            }
            if (ret < 0) {
                return ret;
            }
            y.size = 0;
            lz = 0;
            break;
        case GNUTLS_PK_ECDSA:
            if (x_datum || y_datum) {
                ret = wolfssl_pk_export_privkey_ecc_raw(priv_ctx, &x, &y, &k);
            } else {
                ret = wolfssl_pk_export_privkey_ecc_raw(priv_ctx, NULL, NULL,
                    &k);
            }
            if (ret < 0) {
                return ret;
            }
            break;
        default:
            WGW_ERROR("Context algorithm is not ECDH/ECDSA (%d)",
                priv_ctx->algo);
            return GNUTLS_E_INVALID_REQUEST;
    }

    ret = copy_into_datum(&k, k_datum, lz);
    if (ret != 0) {
        return ret;
    }
    WGW_LOG("ECDH k exported successfully (k size=%u)", k_datum->size);

    /* If public key requested, allocate and copy it */
    if (x_datum) {
        ret = copy_into_datum(&x, x_datum, lz);
        if (ret != 0) {
            return ret;
        }
        WGW_LOG("ECDH x exported successfully (x size=%u)", x_datum->size);
    }
    if (y_datum) {
        ret = copy_into_datum(&y, y_datum, lz);
        if (ret != 0) {
            return ret;
        }
        WGW_LOG("ECDH y exported successfully (y size=%u)", y_datum->size);
    }

    return 0;
}

/* export public key in raw bytes to the provided gnutls_datum_t */
static int wolfssl_pk_export_pubkey_ecdh_raw(void *ctx, const void *x,
    const void *y, gnutls_ecc_curve_t *curve)
{
    struct wolfssl_pk_ctx *pub_ctx = ctx;
    gnutls_datum_t *x_datum = (gnutls_datum_t *)x;
    gnutls_datum_t *y_datum = (gnutls_datum_t *)y;
    int ret;
    byte x_buffer[66];
    byte y_buffer[66];
    word32 x_size = sizeof(x_buffer);
    word32 y_size = sizeof(y_buffer);

    WGW_FUNC_ENTER();

    if (!pub_ctx || !pub_ctx->initialized) {
        WGW_ERROR("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    *curve = pub_ctx->curve;

    if (!x && !y) {
        WGW_LOG("Returning curve only - not X and Y");
        return 0;
    }

    switch(pub_ctx->algo) {
        case GNUTLS_PK_EC:
            WGW_LOG("EC");
            if (!x_datum || !y_datum) {
                WGW_ERROR("Public key datum parameter (x or y) is NULL");
                return GNUTLS_E_ALGO_NOT_SUPPORTED;
            }

            /* Export public key using wc_ecc_export_public_raw */
            ret = wc_ecc_export_public_raw(&pub_ctx->key.ecc, x_buffer, &x_size,
                    y_buffer, &y_size);
            if (ret != 0) {
                WGW_ERROR("wc_ecc_export_public_raw failed: %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }

            /* Allocate and copy public key x-ordinate */
            x_datum->data = gnutls_malloc(x_size);
            if (!x_datum->data) {
                WGW_ERROR("Memory allocation failed for public key");
                return GNUTLS_E_MEMORY_ERROR;
            }
            /* Allocate and copy public key y-ordinate */
            y_datum->data = gnutls_malloc(y_size);
            if (!x_datum->data) {
                WGW_ERROR("Memory allocation failed for public key");
                gnutls_free(x_datum->data);
                x_datum->data = NULL;
                x_datum->size = 0;
                return GNUTLS_E_MEMORY_ERROR;
            }

            XMEMCPY(x_datum->data, x_buffer, x_size);
            x_datum->size = x_size;
            XMEMCPY(y_datum->data, y_buffer, y_size);
            y_datum->size = y_size;
            pub_ctx->curve = wolfssl_ecc_curve_id_to_curve_type(
                    pub_ctx->key.ecc.dp->id);
            break;
#if defined(HAVE_ED25519)
       case GNUTLS_PK_EDDSA_ED25519:
            WGW_LOG("ED25519");
            pub_ctx->pub_data_len = ED25519_PUB_KEY_SIZE;
            ret = wc_ed25519_export_public(&pub_ctx->key.ed25519, x_buffer,
                    &x_size);
            if (ret != 0) {
                WGW_ERROR("wc_ed25519_export_public failed: %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
            pub_ctx->curve = GNUTLS_ECC_CURVE_ED25519;

            /* Allocate and copy public key x-ordinate */
            x_datum->data = gnutls_malloc(x_size);
            if (!x_datum->data) {
                WGW_ERROR("Memory allocation failed for public key");
                return GNUTLS_E_MEMORY_ERROR;
            }

            XMEMCPY(x_datum->data, x_buffer, x_size);
            x_datum->size = x_size;
            if (y_datum) {
                y_datum->data = NULL;
                y_datum->size = 0;
            }
            break;
#endif
#if defined(HAVE_ED448)
       case GNUTLS_PK_EDDSA_ED448:
            WGW_LOG("ED448");
            pub_ctx->pub_data_len = ED448_PUB_KEY_SIZE;
            ret = wc_ed448_export_public(&pub_ctx->key.ed448, x_buffer,
                    &x_size);
            if (ret != 0) {
                WGW_ERROR("wc_ed448_export_public failed: %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
            pub_ctx->curve = GNUTLS_ECC_CURVE_ED448;

            /* Allocate and copy public key x-ordinate */
            x_datum->data = gnutls_malloc(x_size);
            if (!x_datum->data) {
                WGW_ERROR("Memory allocation failed for public key");
                return GNUTLS_E_MEMORY_ERROR;
            }

            XMEMCPY(x_datum->data, x_buffer, x_size);
            x_datum->size = x_size;
            if (y_datum) {
                y_datum->data = NULL;
                y_datum->size = 0;
            }
            break;
#endif
#if defined(HAVE_X25519)
       case GNUTLS_PK_ECDH_X25519:
            WGW_LOG("X25519");
            pub_ctx->pub_data_len = CURVE25519_PUB_KEY_SIZE;
            ret = wc_curve25519_export_public_ex(&pub_ctx->key.x25519,
                x_buffer, &x_size, EC25519_LITTLE_ENDIAN);
            if (ret != 0) {
                WGW_ERROR("wc_curve25519_export_public failed: %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
            pub_ctx->curve = GNUTLS_ECC_CURVE_X25519;

            /* Allocate and copy public key x-ordinate */
            x_datum->data = gnutls_malloc(x_size);
            if (!x_datum->data) {
                WGW_ERROR("Memory allocation failed for public key");
                return GNUTLS_E_MEMORY_ERROR;
            }

            XMEMCPY(x_datum->data, x_buffer, x_size);
            x_datum->size = x_size;
            if (y_datum) {
                y_datum->data = NULL;
                y_datum->size = 0;
            }
            break;
#endif
#if defined(HAVE_X448)
       case GNUTLS_PK_ECDH_X448:
            WGW_LOG("X448");
            pub_ctx->pub_data_len = CURVE448_PUB_KEY_SIZE;
            ret = wc_curve448_export_public_ex(&pub_ctx->key.x448, x_buffer,
                &x_size, EC448_LITTLE_ENDIAN);
            if (ret != 0) {
                WGW_ERROR("wc_curve448_export_public failed: %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }
            pub_ctx->curve = GNUTLS_ECC_CURVE_X448;

            /* Allocate and copy public key x-ordinate */
            x_datum->data = gnutls_malloc(x_size);
            if (!x_datum->data) {
                WGW_ERROR("Memory allocation failed for public key");
                return GNUTLS_E_MEMORY_ERROR;
            }

            XMEMCPY(x_datum->data, x_buffer, x_size);
            x_datum->size = x_size;
            if (y_datum) {
                y_datum->data = NULL;
                y_datum->size = 0;
            }
            break;
#endif
       default:
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    *curve = pub_ctx->curve;

    WGW_LOG("ECDH public key exported successfully");

    return 0;
}

/* structure containing function pointers for the pk implementation */
static const gnutls_crypto_pk_st wolfssl_pk_struct = {
    /* the init function is not needed, since the init functions of gnutls
     * default to just allocate the key's structs using gnutls_calloc.
     * so we do the init and the generate of the key pair directly in the
     * wolfssl_pk_generate function. */
    .get_bits = wolfssl_pk_get_bits,
    .get_spki = wolfssl_pk_get_spki,
    .set_spki = wolfssl_pk_set_spki,
    .generate_backend = wolfssl_pk_generate,
    .import_pubkey_backend = wolfssl_pk_import_pub,
    .export_pubkey_backend = wolfssl_pk_export_pub,
    .export_privkey_x509_backend = wolfssl_pk_export_privkey_x509,
    .export_pubkey_x509_backend = wolfssl_pk_export_pubkey_x509,
    .verify_privkey_params_backend = wolfssl_pk_verify_privkey_params,
    .verify_pubkey_params_backend = wolfssl_pk_verify_pubkey_params,
    .sign_backend = wolfssl_pk_sign,
    .verify_backend = wolfssl_pk_verify,
    .pubkey_encrypt_backend = wolfssl_pk_encrypt,
    .privkey_decrypt_backend = wolfssl_pk_decrypt,
    .import_privkey_x509_backend = wolfssl_pk_import_privkey_x509,
    .import_pubkey_x509_backend = wolfssl_pk_import_pubkey_x509,
    .sign_hash_backend = wolfssl_pk_sign_hash,
    .verify_hash_backend = wolfssl_pk_verify_hash,
    .derive_shared_secret_backend = wolfssl_pk_derive_shared_secret,
    .import_rsa_raw_backend = wolfssl_pk_import_rsa_raw,
    .export_rsa_raw_backend = wolfssl_pk_export_rsa_raw,
    .privkey_export_dh_raw_backend = wolfssl_pk_export_privkey_dh_raw,
    .pubkey_export_dh_raw_backend = wolfssl_pk_export_pubkey_dh_raw,
    .privkey_import_ecdh_raw_backend = wolfssl_pk_import_privkey_ecdh_raw,
    .pubkey_import_ecdh_raw_backend = wolfssl_pk_import_pubkey_ecdh_raw,
    .privkey_export_ecdh_raw_backend = wolfssl_pk_export_privkey_ecdh_raw,
    .pubkey_export_ecdh_raw_backend = wolfssl_pk_export_pubkey_ecdh_raw,
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

#if defined(HAVE_ED25519)
   /* Register Ed25519 */
   if (wolfssl_pk_supported[GNUTLS_PK_EDDSA_ED25519]) {
        WGW_LOG("registering EdDSA-ED25519");
        ret = gnutls_crypto_single_pk_register(
                GNUTLS_PK_EDDSA_ED25519, 80, &wolfssl_pk_struct, 0);
        if (ret < 0) {
            return ret;
        }
   }
#endif

#if defined(HAVE_ED448)
  /* Register Ed448 */
  if (wolfssl_pk_supported[GNUTLS_PK_EDDSA_ED448]) {
      WGW_LOG("registering EdDSA-ED448");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_EDDSA_ED448, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }
#endif

#if defined(HAVE_CURVE25519)
  /* Register X25519 */
  if (wolfssl_pk_supported[GNUTLS_PK_ECDH_X25519]) {
      WGW_LOG("registering X25519");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_ECDH_X25519, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }
#endif

#if defined(HAVE_CURVE448)
  /* Register X448 */
  if (wolfssl_pk_supported[GNUTLS_PK_ECDH_X448]) {
      WGW_LOG("registering X448");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_ECDH_X448, 80, &wolfssl_pk_struct, 0);
      if (ret < 0) {
          return ret;
      }
  }
#endif

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

  /* Register DH */
  if (wolfssl_pk_supported[GNUTLS_PK_DH]) {
      WGW_LOG("registering DH");
      ret = gnutls_crypto_single_pk_register(
              GNUTLS_PK_DH, 80, &wolfssl_pk_struct, 0);
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

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

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
#if !defined(HAVE_FIPS)
        (void)wc_RNG_DRBG_Reseed(&ctx->pub_rng, (unsigned char*)&curr_pid,
            sizeof(curr_pid));
#else
        /* Re-initialize the public random with the current process ID as nonce.
         */
        wc_FreeRng(&ctx->pub_rng);
        ret = wc_InitRngNonce(&ctx->pub_rng, (unsigned char*)&curr_pid,
            sizeof(curr_pid));
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_InitRngNonce for pub_rng", ret);
            return GNUTLS_E_RANDOM_FAILED;
        }
#endif
        /* Restart the private random. */
        wc_FreeRng(&ctx->priv_rng);

#ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
#endif

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

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif
        /* Initialize private wolfSSL random for use again. */
        ret = wc_InitRng(&ctx->priv_rng);
        if (ret != 0) {
            WGW_LOG("wolfSSL initialize of private random failed: %d", ret);
            WGW_WOLFSSL_ERROR("wc_InitRng", ret);
            /* Set context initialized to 0 to indicate it isn't available. */
            ctx->initialized = 0;
        }

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif
        /* Initialize public wolfSSL random for use again. */
        ret = wc_InitRng(&ctx->pub_rng);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("wc_InitRng", ret);
            wc_FreeRng(&ctx->priv_rng);
            /* Set context initialized to 0 to indicate it isn't available. */
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
#endif
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
            /* Try opening file for writing. */
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
#ifdef DEBUG_WOLFSSL
    if (loggingEnabled) {
        wolfSSL_Debugging_ON();
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

    /* If FIPS is enabled, check its status */
#if defined(HAVE_FIPS)
    /* Check the status of FIPS in wolfssl */
    if (wolfCrypt_GetStatus_fips() != 0) {
        WGW_LOG("FIPS mode initialization failed");
        return GNUTLS_E_INVALID_REQUEST;
    } else {
        WGW_LOG("FIPS mode enabled in wolfSSL");
    }

    /* Make sure that FIPS mode is enabled
     * on gnutls also */
    if (!gnutls_fips140_mode_enabled()) {
        WGW_LOG("FIPS mode not enabled in gnutls");
        return GNUTLS_E_INVALID_REQUEST;
    } else {
        WGW_LOG("FIPS mode enabled in GnuTLS");
    }
#endif

    return 0;
}

/**
 * Module deinitialization
 */
void _gnutls_wolfssl_deinit(void)
{
    WGW_FUNC_ENTER();

    if (loggingFd != stdout && loggingFd != stderr && loggingFd != XBADFILE) {
        XFCLOSE(loggingFd);
    }

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
