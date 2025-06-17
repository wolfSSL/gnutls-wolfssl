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
        WGW_LOG("Initialize SHAKE-128");
        ret = wc_InitShake128(&ctx->shake, NULL, INVALID_DEVID);
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (algorithm == GNUTLS_DIG_SHAKE_256) {
        WGW_LOG("Initialize SHAKE-256");
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
        WGW_ERROR("SHAKE is already squeezing");
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
            WGW_LOG("Absorb SHAKE-128");
            ret = wc_Shake128_Update(&ctx->shake, (const byte*)text, size);
        }
    #endif
    #ifdef WOLFSSL_SHAKE256
        if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
            WGW_LOG("Absorb SHAKE-256");
            ret = wc_Shake256_Update(&ctx->shake, (const byte*)text, size);
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
        WGW_LOG("squeeze SHAKE-128");

        if (!ctx->squeezing) {
            ret = wc_Shake128_Absorb(&ctx->shake, ctx->block, 0);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_Shake128_Absorb", ret);
                return GNUTLS_E_HASH_FAILED;
            }
        }

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
        WGW_LOG("squeeze SHAKE-256");

        if (!ctx->squeezing) {
            ret = wc_Shake256_Absorb(&ctx->shake, ctx->block, 0);
            if (ret != 0) {
                WGW_WOLFSSL_ERROR("wc_Shake256_Absorb", ret);
                return GNUTLS_E_HASH_FAILED;
            }
        }

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

#define IS_ALGO_ECC_SIG(a)                  \
    (((a) == GNUTLS_PK_ECDSA)   ||          \
     ((a) == GNUTLS_PK_EDDSA_ED25519) ||    \
     ((a) == GNUTLS_PK_EDDSA_ED448))


int mp_to_bigint(mp_int *mp, bigint_t *bi)
{
    int ret;
    unsigned char data[1024];
    int size = mp_unsigned_bin_size(mp);

    ret = mp_to_unsigned_bin(mp, data);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_to_unsigned_bin", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = _gnutls_mpi_init_scan(bi, data, size);
    return ret;
}

int bigint_to_mp(bigint_t bi, mp_int *mp)
{
    int ret;
    gnutls_datum_t datum = { .data = NULL, .size = 0 };

    ret = mp_init(mp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = _gnutls_mpi_dprint(bi, &datum);
    if (ret != 0) {
        WGW_ERROR("_gnutls_mpi_print: %d", ret);
        return ret;
    }

    ret = mp_read_unsigned_bin(mp, datum.data, datum.size);
    gnutls_free(datum.data);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_read_unsigned_bin", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

static int rsa_load_params(RsaKey *rsa, const gnutls_pk_params_st *pk_params,
    int priv)
{
    int ret;

    ret = wc_InitRsaKey(rsa, NULL);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = bigint_to_mp(pk_params->params[RSA_MODULUS], &rsa->n);
    if (ret == 0) {
        ret = bigint_to_mp(pk_params->params[RSA_PUB], &rsa->e);
    }
    if ((ret == 0) && priv) {
        ret = bigint_to_mp(pk_params->params[RSA_PRIV], &rsa->d);
    }
    if ((ret == 0) && priv) {
        ret = bigint_to_mp(pk_params->params[RSA_PRIME1], &rsa->p);
    }
    if ((ret == 0) && priv) {
        ret = bigint_to_mp(pk_params->params[RSA_PRIME2], &rsa->q);
    }
    if ((ret == 0) && priv && (pk_params->params[RSA_COEF] != NULL)) {
        ret = bigint_to_mp(pk_params->params[RSA_COEF], &rsa->u);
    }
    if ((ret == 0) && priv && (pk_params->params[RSA_E1] != NULL)) {
        ret = bigint_to_mp(pk_params->params[RSA_E1], &rsa->dP);
    }
    if ((ret == 0) && priv && (pk_params->params[RSA_E2] != NULL)) {
        ret = bigint_to_mp(pk_params->params[RSA_E2], &rsa->dQ);
    }
    if ((ret == 0) && priv) {
        rsa->type = RSA_PRIVATE;
    }

    if (ret != 0) {
        wc_FreeRsaKey(rsa);
    }
    return ret;
}

static int dh_load_params(DhKey *dh, const gnutls_pk_params_st *params)
{
    int ret;

    ret = wc_InitDhKey(dh);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitDhKey", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = bigint_to_mp(params->params[DH_P], &dh->p);
    if (ret == 0) {
        ret = bigint_to_mp(params->params[DH_G], &dh->g);
    }

    if (ret != 0) {
        wc_FreeDhKey(dh);
    }
    return ret;
}

static int ecc_level_to_curve(int level, int *curve_id, int *curve_size)
{
    switch (level) {
#if ECC_MIN_KEY_SZ <= 192
        case GNUTLS_ECC_CURVE_SECP192R1:
            WGW_LOG("SECP192R1 - 24 bytes");
            *curve_id = ECC_SECP192R1;
            *curve_size = 24;
            break;
#endif
#if ECC_MIN_KEY_SZ <= 224
        case GNUTLS_ECC_CURVE_SECP224R1:
            WGW_LOG("SECP224R1 - 28 bytes");
            *curve_id = ECC_SECP224R1;
            *curve_size = 28;
            break;
#endif
        case GNUTLS_ECC_CURVE_SECP256R1:
            WGW_LOG("SECP256R1 - 32 bytes");
            *curve_id = ECC_SECP256R1;
            *curve_size = 32;
            break;
        case GNUTLS_ECC_CURVE_SECP384R1:
            WGW_LOG("SECP384R1 - 48 bytes");
            *curve_id = ECC_SECP384R1;
            *curve_size = 48;
            break;
        case GNUTLS_ECC_CURVE_SECP521R1:
            WGW_LOG("SECP521R1 - 66 bytes");
            *curve_id = ECC_SECP521R1;
            *curve_size = 66;
            break;
        default:
            return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

static int ecc_load_params(ecc_key *ecc, const gnutls_pk_params_st *pk_params,
    int priv)
{
    int ret;
    int curve_id;
    int curve_size;

    ret = ecc_level_to_curve(pk_params->curve, &curve_id, &curve_size);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_init(ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_init", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = wc_ecc_set_curve(ecc, curve_size, curve_id);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_set_curve", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = bigint_to_mp(pk_params->params[ECC_X], ecc->pubkey.x);
    if (ret == 0) {
        ret = bigint_to_mp(pk_params->params[ECC_Y], ecc->pubkey.y);
    }
    if (ret == 0) {
        ret = mp_set(ecc->pubkey.z, 1);
    }
    if ((ret == 0) && priv) {
        ret = bigint_to_mp(pk_params->params[ECC_K], ecc->k);
    }
    if (ret == 0) {
        if (priv) {
            ecc->type = ECC_PRIVATEKEY;
        }
        else {
            ecc->type = ECC_PUBLICKEY;
        }
    }

    return ret;
}

static int wolfssl_pk_encrypt_rsa(gnutls_datum_t *ciphertext,
    const gnutls_datum_t *plaintext, const gnutls_pk_params_st *pk_params)
{
    int ret;
    RsaKey rsa;
    WC_RNG rng;

    WGW_FUNC_ENTER();

    if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
        WGW_LOG("PKCS#1 RSA encryption disabled");
        return GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 0);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    ciphertext->size = wc_RsaEncryptSize(&rsa);
    ciphertext->data = gnutls_malloc(ciphertext->size);
    if (ciphertext->data == NULL) {
        WGW_ERROR("Allocating memory for ciphertext");
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Encrypt using RSA PKCS#1 v1.5 padding */
    ret = wc_RsaPublicEncrypt(plaintext->data, plaintext->size,
        ciphertext->data, ciphertext->size, &rsa, &rng);
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPublicEncrypt", ret);
        gnutls_free(ciphertext->data);
        ciphertext->data = NULL;
        ciphertext->size = 0;
        return GNUTLS_E_ENCRYPTION_FAILED;
    }
    ciphertext->size = ret;

    return 0;
}

static int wolfssl_pk_encrypt_rsa_oaep(gnutls_datum_t *ciphertext,
    const gnutls_datum_t *plaintext, const gnutls_pk_params_st *pk_params)
{
    int ret;
    RsaKey rsa;
    WC_RNG rng;
    int hash_type;
    int mgf;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 0);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    ciphertext->size = wc_RsaEncryptSize(&rsa);
    ciphertext->data = gnutls_malloc(ciphertext->size);
    if (ciphertext->data == NULL) {
        WGW_ERROR("Allocating memory for ciphertext");
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Encrypt using RSA PKCS#1 OAEP padding. */
    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        pk_params->spki.rsa_oaep_dig);
    get_mgf_and_hash_len(hash_type, &mgf, NULL);
    ret = wc_RsaPublicEncrypt_ex(plaintext->data, plaintext->size,
        ciphertext->data, ciphertext->size, &rsa, &rng, WC_RSA_OAEP_PAD,
        hash_type, mgf, pk_params->spki.rsa_oaep_label.data,
        pk_params->spki.rsa_oaep_label.size);
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPublicEncrypt_ex", ret);
        gnutls_free(ciphertext->data);
        ciphertext->data = NULL;
        ciphertext->size = 0;
        return GNUTLS_E_ENCRYPTION_FAILED;
    }
    ciphertext->size = ret;

    return 0;
}

static int wolfssl_pk_encrypt(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *ciphertext, const gnutls_datum_t *plaintext,
    const gnutls_pk_params_st *pk_params)
{
    int ret;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP) {
        algo = GNUTLS_PK_RSA_OAEP;
    }

    switch (algo) {
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_encrypt_rsa(ciphertext, plaintext, pk_params);
            break;

        case GNUTLS_PK_RSA_OAEP:
            ret = wolfssl_pk_encrypt_rsa_oaep(ciphertext, plaintext, pk_params);
            break;

        default:
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

static int wolfssl_pk_decrypt_rsa(gnutls_datum_t *plaintext,
    const gnutls_datum_t *ciphertext, const gnutls_pk_params_st *pk_params,
    int alloc_plaintext)
{
    int ret;
    RsaKey rsa;
    WC_RNG rng;
    unsigned char out[1024];
    unsigned char *plain;
    word32 plain_size;

    WGW_FUNC_ENTER();

    if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
        WGW_LOG("PKCS#1 RSA encryption disabled");
        return GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }
    plain_size = wc_RsaEncryptSize(&rsa);

#if !defined(HAVE_FIPS)
    ret = wc_RsaSetRNG(&rsa, &rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSetRNG", ret);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_RANDOM_FAILED;
    }
#endif

    if (alloc_plaintext) {
        plaintext->data = gnutls_malloc(plain_size);
        if (plaintext->data == NULL) {
            WGW_ERROR("Allocating memory for plaintext");
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }
    if ((!alloc_plaintext) &&
            (plaintext->size < (unsigned int)wc_RsaEncryptSize(&rsa))) {
        plain = out;
    }
    else {
        plain = plaintext->data;
    }

    /* Decrypt using RSA PKCS#1 v1.5 padding */
    ret = wc_RsaPrivateDecrypt(ciphertext->data, ciphertext->size, plain,
        plain_size, &rsa);
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPrivateDecrypt", ret);
        if (alloc_plaintext) {
            gnutls_free(plaintext->data);
            plaintext->data = NULL;
            plaintext->size = 0;
        }
        return GNUTLS_E_DECRYPTION_FAILED;
    }
    if (plain != plaintext->data) {
        if ((unsigned int)ret > plaintext->size) {
            WGW_ERROR("Decrypted data too big for plaintext buffer: %d > %d",
                ret, plaintext->size);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        XMEMCPY(plaintext->data, plain, ret);
    }
    plaintext->size = ret;

    return 0;
}

static int wolfssl_pk_decrypt_rsa_oaep(gnutls_datum_t *plaintext,
    const gnutls_datum_t *ciphertext, const gnutls_pk_params_st *pk_params,
    int alloc_plaintext)
{
    int ret;
    RsaKey rsa;
    WC_RNG rng;
    int hash_type;
    int mgf;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

#if !defined(HAVE_FIPS)
    ret = wc_RsaSetRNG(&rsa, &rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSetRNG", ret);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_RANDOM_FAILED;
    }
#endif

    if (alloc_plaintext) {
        plaintext->size = wc_RsaEncryptSize(&rsa);
        plaintext->data = gnutls_malloc(plaintext->size);
        if (plaintext->data == NULL) {
            WGW_ERROR("Allocating memory for plaintext");
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Decrypt using RSA PKCS#1 OAEP padding. */
    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        pk_params->spki.rsa_oaep_dig);
    get_mgf_and_hash_len(hash_type, &mgf, NULL);
    ret = wc_RsaPrivateDecrypt_ex(ciphertext->data, ciphertext->size,
        plaintext->data, plaintext->size, &rsa, WC_RSA_OAEP_PAD,
        hash_type, mgf, pk_params->spki.rsa_oaep_label.data,
        pk_params->spki.rsa_oaep_label.size);
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPublicEncrypt_ex", ret);
        gnutls_free(plaintext->data);
        plaintext->data = NULL;
        plaintext->size = 0;
        return GNUTLS_E_ENCRYPTION_FAILED;
    }
    plaintext->size = ret;

    return 0;
}

static int wolfssl_pk_decrypt(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *plaintext, const gnutls_datum_t *ciphertext,
    const gnutls_pk_params_st *pk_params)
{
    int ret;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP) {
        algo = GNUTLS_PK_RSA_OAEP;
    }

    switch (algo) {
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_decrypt_rsa(plaintext, ciphertext, pk_params, 1);
            break;

        case GNUTLS_PK_RSA_OAEP:
            ret = wolfssl_pk_decrypt_rsa_oaep(plaintext, ciphertext, pk_params,
                1);
            break;

        default:
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

static int wolfssl_pk_decrypt2(gnutls_pk_algorithm_t algo,
    const gnutls_datum_t *ciphertext, unsigned char *plaintext,
    size_t plaintext_size, const gnutls_pk_params_st *pk_params)
{
    int ret;
    gnutls_datum_t plain;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP) {
        algo = GNUTLS_PK_RSA_OAEP;
    }

    plain.data = plaintext;
    plain.size = plaintext_size;

    switch (algo) {
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_decrypt_rsa(&plain, ciphertext, pk_params, 0);
            break;

        case GNUTLS_PK_RSA_OAEP:
            ret = wolfssl_pk_decrypt_rsa_oaep(&plain, ciphertext, pk_params, 0);
            break;

        default:
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

static int wolfssl_pk_sign_rsa(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *pk_params)
{
    int ret;
    RsaKey rsa;
    WC_RNG rng;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    signature->size = wc_RsaEncryptSize(&rsa);
    signature->data = gnutls_malloc(signature->size);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature");
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_RsaSSL_Sign(vdata->data, vdata->size, signature->data,
        signature->size, &rsa, &rng);
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSSL_Sign", ret);
        gnutls_free(signature->data);
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->size = ret;

    return 0;
}

static int wolfssl_pk_sign_rsa_pss(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;
    RsaKey rsa;
    WC_RNG rng;
    int hash_type;
    int mgf;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    signature->size = wc_RsaEncryptSize(&rsa);
    signature->data = gnutls_malloc(signature->size);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature");
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_MEMORY_ERROR;
    }

    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        sign_params->rsa_pss_dig);
    get_mgf_and_hash_len(hash_type, &mgf, NULL);
    ret = wc_RsaPSS_Sign_ex(vdata->data, vdata->size, signature->data,
        signature->size, hash_type, mgf, sign_params->salt_size, &rsa,
        &rng);
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_Sign_ex", ret);
        gnutls_free(signature->data);
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->size = ret;

    return 0;
}

static int wolfssl_pk_sign_ecc(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;
    ecc_key ecc;
    WC_RNG rng;
    word32 len;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = ecc_load_params(&ecc, pk_params, 1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    len = signature->size = wc_ecc_sig_size_calc(wc_ecc_size(&ecc));
    signature->data = gnutls_malloc(signature->size);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature");
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        return GNUTLS_E_MEMORY_ERROR;
    }

#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K)
    if ((sign_params->flags & GNUTLS_PK_FLAG_REPRODUCIBLE) != 0) {
        WGW_LOG("signing determinitically");
        int hash_type = get_hash_type((gnutls_mac_algorithm_t)
            sign_params->dsa_dig);
        wc_ecc_set_deterministic_ex(&ecc, 1, hash_type);
    }
#endif

    ret = wc_ecc_sign_hash(vdata->data, vdata->size, signature->data, &len,
        &rng, &ecc);
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_sign_hash", ret);
        gnutls_free(signature->data);
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->size = len;

    return 0;
}

#ifdef HAVE_ED25519
static int wolfssl_pk_sign_ed25519(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *pk_params)
{
    int ret;
    ed25519_key ed25519;
    word32 len = ED25519_SIG_SIZE;

    WGW_FUNC_ENTER();

    /* Initialize Ed25519 private key */
    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    if (pk_params->raw_priv.size == ED25519_PRV_KEY_SIZE) {
        ret = wc_ed25519_import_private_key(pk_params->raw_priv.data,
            pk_params->raw_priv.size, NULL, 0, &ed25519);
    } else {
        ret = wc_ed25519_import_private_key(pk_params->raw_priv.data,
            pk_params->raw_priv.size, pk_params->raw_pub.data,
            pk_params->raw_pub.size, &ed25519);
    }
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    signature->data = gnutls_malloc(len);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature: %d", len);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    ret = wc_ed25519_sign_msg(vdata->data, vdata->size, signature->data, &len,
        &ed25519);

    PRIVATE_KEY_LOCK();

    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_sign_msg", ret);
        gnutls_free(signature->data);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->size = len;

    return 0;
}
#endif

#ifdef HAVE_ED448
static int wolfssl_pk_sign_ed448(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *pk_params)
{
    int ret;
    ed448_key ed448;
    word32 len = ED448_SIG_SIZE;

    WGW_FUNC_ENTER();

    /* Initialize Ed448 private key */
    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    if (pk_params->raw_priv.size == ED448_PRV_KEY_SIZE) {
        ret = wc_ed448_import_private_key(pk_params->raw_priv.data,
            pk_params->raw_priv.size, NULL, 0, &ed448);
    } else {
        ret = wc_ed448_import_private_key(pk_params->raw_priv.data,
            pk_params->raw_priv.size, pk_params->raw_pub.data,
            pk_params->raw_pub.size, &ed448);
    }
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        wc_ed448_free(&ed448);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    signature->data = gnutls_malloc(len);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature: %d", len);
        wc_ed448_free(&ed448);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    ret = wc_ed448_sign_msg(vdata->data, vdata->size, signature->data, &len,
        &ed448, NULL, 0);

    PRIVATE_KEY_LOCK();

    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_sign_msg", ret);
        gnutls_free(signature->data);
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->size = len;

    return 0;
}
#endif

static int wolfssl_pk_sign(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *signature, const gnutls_datum_t *vdata,
    const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    if (IS_ALGO_ECC_SIG(algo) &&
            (gnutls_ecc_curve_get_pk(pk_params->curve) != algo)) {
        WGW_ERROR("ECC curve does not match algorithm: %d %d\n", algo,
            pk_params->curve);
    }

    switch (algo) {
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_sign_rsa(signature, vdata, pk_params);
            break;
        case GNUTLS_PK_RSA_PSS:
            ret = wolfssl_pk_sign_rsa_pss(signature, vdata, pk_params,
                sign_params);
            break;

        case GNUTLS_PK_ECDSA:
            ret = wolfssl_pk_sign_ecc(signature, vdata, pk_params, sign_params);
            break;

#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            ret = wolfssl_pk_sign_ed25519(signature, vdata, pk_params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            ret = wolfssl_pk_sign_ed448(signature, vdata, pk_params);
            break;
#endif

        default:
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

static int wolfssl_pk_verify_rsa(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *pk_params)
{
    int ret;
    RsaKey rsa;
    unsigned char verify[1024];

    WGW_FUNC_ENTER();

    ret = rsa_load_params(&rsa, pk_params, 0);
    if (ret != 0) {
        return ret;
    }

    ret = wc_RsaSSL_Verify(signature->data, signature->size, verify,
        sizeof(verify), &rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSSL_Verify", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    if (ret != (int)vdata->size) {
        WGW_ERROR("Decrypted data size size bad: %d %d", ret, vdata->size);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    if (XMEMCMP(verify, vdata->data, ret)) {
        WGW_ERROR("Decrypted data doesn't match");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

static int wolfssl_pk_verify_rsa_pss(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;
    RsaKey rsa;
    int hash_type;
    int mgf;
    unsigned char verify[1024];

    WGW_FUNC_ENTER();

    if ((sign_params->flags & GNUTLS_PK_FLAG_RSA_PSS_FIXED_SALT_LENGTH) &&
            (sign_params->salt_size != vdata->size)) {
        WGW_ERROR("Fixed salt length doesn't match hash size");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    ret = rsa_load_params(&rsa, pk_params, 0);
    if (ret != 0) {
        return ret;
    }

    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        sign_params->rsa_pss_dig);
    get_mgf_and_hash_len(hash_type, &mgf, NULL);
    ret = wc_RsaPSS_Verify_ex(signature->data,
        signature->size, verify, sizeof(verify), hash_type, mgf,
        sign_params->salt_size, &rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_Verify_ex", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    ret = wc_RsaPSS_CheckPadding(vdata->data, vdata->size, verify, ret,
        hash_type);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_CheckPadding", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

static int wolfssl_pk_verify_ecc(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *pk_params)
{
    int ret;
    ecc_key ecc;
    int res;

    WGW_FUNC_ENTER();

    ret = ecc_load_params(&ecc, pk_params, 0);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_verify_hash(signature->data, signature->size, vdata->data,
        vdata->size, &res, &ecc);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSSL_Verify", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    if (!res) {
        WGW_ERROR("Failed verification\n");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

#ifdef HAVE_ED25519
static int wolfssl_pk_verify_ed25519(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *pk_params)
{
    int ret;
    ed25519_key ed25519;
    int res;

    WGW_FUNC_ENTER();

    /* Initialize Ed25519 private key */
    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_ed25519_import_public(pk_params->raw_pub.data,
        pk_params->raw_pub.size, &ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private", ret);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = wc_ed25519_verify_msg(signature->data, signature->size, vdata->data,
        vdata->size, &res, &ed25519);
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_verify_msg", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    if (!res) {
        WGW_ERROR("Failed verification\n");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}
#endif

#ifdef HAVE_ED448
static int wolfssl_pk_verify_ed448(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *pk_params)
{
    int ret;
    ed448_key ed448;
    int res;

    WGW_FUNC_ENTER();

    /* Initialize Ed448 private key */
    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_ed448_import_public(pk_params->raw_pub.data,
        pk_params->raw_pub.size, &ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private", ret);
        wc_ed448_free(&ed448);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = wc_ed448_verify_msg(signature->data, signature->size, vdata->data,
        vdata->size, &res, &ed448, NULL, 0);
    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_verify_msg", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    if (!res) {
        WGW_ERROR("Failed verification\n");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}
#endif

static int wolfssl_pk_verify(gnutls_pk_algorithm_t algo,
    const gnutls_datum_t *vdata, const gnutls_datum_t *signature,
    const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    if (IS_ALGO_ECC_SIG(algo) &&
            (gnutls_ecc_curve_get_pk(pk_params->curve) != algo)) {
        WGW_ERROR("ECC curve does not match algorithm: %d %d\n", algo,
            pk_params->curve);
    }

    switch (algo) {
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_verify_rsa(vdata, signature, pk_params);
            break;
        case GNUTLS_PK_RSA_PSS:
            ret = wolfssl_pk_verify_rsa_pss(vdata, signature, pk_params,
                sign_params);
            break;
        case GNUTLS_PK_ECDSA:
            ret = wolfssl_pk_verify_ecc(vdata, signature, pk_params);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            ret = wolfssl_pk_verify_ed25519(vdata, signature, pk_params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            ret = wolfssl_pk_verify_ed448(vdata, signature, pk_params);
            break;
#endif
        default:
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

static int wolfssl_pk_verify_priv_params_ecdsa(
    const gnutls_pk_params_st *params)
{
    int ret;
    ecc_key ecc;

    WGW_FUNC_ENTER();

    ret = ecc_load_params(&ecc, params, 1);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_check_key(&ecc);
    wc_ecc_free(&ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }

    return 0;
}

#ifdef HAVE_ED25519
static int wolfssl_pk_verify_priv_params_ed25519(
    const gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;

    WGW_FUNC_ENTER();

    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    if (params->raw_priv.size == ED25519_PRV_KEY_SIZE) {
        ret = wc_ed25519_import_private_key(params->raw_priv.data,
            params->raw_priv.size, NULL, 0, &ed25519);
    } else {
        ret = wc_ed25519_import_private_key(params->raw_priv.data,
            params->raw_priv.size, params->raw_pub.data,
            params->raw_pub.size, &ed25519);
    }
    wc_ed25519_free(&ed25519);
    if (ret == PUBLIC_KEY_E) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}
#endif

#ifdef HAVE_ED448
static int wolfssl_pk_verify_priv_params_ed448(
    const gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;

    WGW_FUNC_ENTER();

    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    if (params->raw_priv.size == ED448_PRV_KEY_SIZE) {
        ret = wc_ed448_import_private_key(params->raw_priv.data,
            params->raw_priv.size, NULL, 0, &ed448);
    } else {
        ret = wc_ed448_import_private_key(params->raw_priv.data,
            params->raw_priv.size, params->raw_pub.data,
            params->raw_pub.size, &ed448);
    }
    wc_ed448_free(&ed448);
    if (ret == PUBLIC_KEY_E) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}
#endif

static int wolfssl_pk_verify_priv_params(gnutls_pk_algorithm_t algo,
    const gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    switch (algo) {
        case GNUTLS_PK_ECDSA:
            ret = wolfssl_pk_verify_priv_params_ecdsa(params);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            ret = wolfssl_pk_verify_priv_params_ed25519(params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            ret = wolfssl_pk_verify_priv_params_ed448(params);
            break;
#endif
        default:
            ret = 0;
    }

    return ret;
}

static int wolfssl_pk_verify_pub_params_ecdsa(const gnutls_pk_params_st *params)
{
    int ret;
    ecc_key ecc;

    WGW_FUNC_ENTER();

    ret = ecc_load_params(&ecc, params, 0);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_check_key(&ecc);
    wc_ecc_free(&ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }

    return 0;
}

static int wolfssl_pk_verify_pub_params(gnutls_pk_algorithm_t algo,
    const gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    switch (algo) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
#endif
            ret = 0;
            break;
        case GNUTLS_PK_ECDSA:
            ret = wolfssl_pk_verify_pub_params_ecdsa(params);;
            break;
        default:
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

static int wolfssl_pk_generate_keys_rsa(unsigned int bits,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    RsaKey rsa;

    WGW_FUNC_ENTER();

    WGW_LOG("bits: %d", bits);
#if defined(HAVE_FIPS)
    /* missing check for 1024, 1024 is not allowed */
    if (bits == 1024) {
        WGW_ERROR("Bits size not valid");
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
    }
#endif

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) {
        WGW_ERROR("wc_InitRsaKey failed with code %d", ret);
        wc_FreeRng(&rng);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

#if !defined(HAVE_FIPS)
    ret = wc_RsaSetRNG(&rsa, &rng);
    if (ret != 0) {
        WGW_ERROR("wc_RsaSetRNG failed with code %d", ret);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }
#endif

    PRIVATE_KEY_UNLOCK();

    /* Generate RSA key */
    ret = wc_MakeRsaKey(&rsa, bits, WC_RSA_EXPONENT, &rng);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_ERROR("RSA key generation failed with code %d", ret);
        wc_FreeRsaKey(&rsa);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#endif
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    params->params_nr = 0;

    ret = mp_to_bigint(&rsa.n, &params->params[RSA_MODULUS]);
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.e, &params->params[RSA_PUB]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.d, &params->params[RSA_PRIV]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.p, &params->params[RSA_PRIME1]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.q, &params->params[RSA_PRIME2]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.u, &params->params[RSA_COEF]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.dP, &params->params[RSA_E1]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(&rsa.dQ, &params->params[RSA_E2]);
    }
    if (ret == 0) {
        params->params_nr++;
    }
    wc_FreeRsaKey(&rsa);

    return ret;
}

static int wolfssl_pk_generate_params_dh(unsigned int bits,
    gnutls_pk_params_st *params)
{
    int ret;
    const DhParams* dh = NULL;

    WGW_FUNC_ENTER();

    /* Use predefined parameters based on bits size */
    switch (bits) {
        case 2048:
#ifdef HAVE_FFDHE_2048
            WGW_LOG("2048");
            dh = wc_Dh_ffdhe2048_Get();
#endif
            break;
        case 3072:
#ifdef HAVE_FFDHE_3072
            WGW_LOG("3072");
            dh = wc_Dh_ffdhe3072_Get();
#endif
            break;
        case 4096:
#ifdef HAVE_FFDHE_4096
            WGW_LOG("4096");
            dh = wc_Dh_ffdhe4096_Get();
#endif
            break;
        case 6144:
#ifdef HAVE_FFDHE_6144
            WGW_LOG("6144");
            dh = wc_Dh_ffdhe6144_Get();
#endif
            break;
        case 8192:
#ifdef HAVE_FFDHE_8192
            WGW_LOG("8192");
            dh = wc_Dh_ffdhe8192_Get();
#endif
            break;
        default:
            WGW_ERROR("Unsupported DH key size: %d", bits);
            return GNUTLS_E_INVALID_REQUEST;
    }

    params->params_nr = 0;

    ret = _gnutls_mpi_init_scan(&params->params[DH_P], dh->p, dh->p_len);
    if (ret == 0) {
        params->params_nr++;
        ret = _gnutls_mpi_init_scan(&params->params[DH_G], dh->g, dh->g_len);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = _gnutls_mpi_init_scan(&params->params[DH_Q], dh->q, dh->q_len);
    }
    if (ret == 0) {
        params->params_nr++;
    }

    return ret;
}

/* Generates algorithm's parameters. That is:
 *  For DSA: p, q, and g are generated.
 *  For RSA: nothing
 *  For ECDSA/EDDSA: nothing
 *
 * level      Either bits or curve.
 */
static int wolfssl_pk_generate_params(gnutls_pk_algorithm_t algo,
    unsigned int level, gnutls_pk_params_st *params)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    /* Handle different key types */
    if (algo == GNUTLS_PK_DH) {
        ret = wolfssl_pk_generate_params_dh(level, params);
    }

    return ret;
}


static int wolfssl_pk_generate_keys_dh(unsigned int bits,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    DhKey dh;
    unsigned char *priv;
    word32 privSz;
    unsigned char *pub;
    word32 pubSz;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    if (bits == 256) {
        bits = 2048;
    }
    else if (bits == 276) {
        bits = 3072;
    }
    else if (bits == 336) {
        bits = 4096;
    }
    else if (bits == 376) {
        bits = 6144;
    }
    else if (bits == 512) {
        bits = 8192;
    }
    if (bits != 0) {
        WGW_LOG("Get fixed parameters");
        ret = wolfssl_pk_generate_params_dh(bits, params);
        if (ret != 0) {
            wc_FreeRng(&rng);
            return ret;
        }
    }
    WGW_LOG("Load DH parameters from params");
    ret = dh_load_params(&dh, params);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_FreeDhKey(&dh);
        return ret;
    }
    if (bits == 0) {
        bits = mp_count_bits(&dh.p);
    }

    privSz = (bits + 7) / 8;
    priv = gnutls_malloc(privSz);
    if (priv == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_FreeRng(&rng);
        wc_FreeDhKey(&dh);
        return GNUTLS_E_MEMORY_ERROR;
    }
    pubSz = (bits + 7) / 8;
    pub = gnutls_malloc(pubSz);
    if (pub == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        gnutls_free(priv);
        wc_FreeRng(&rng);
        wc_FreeDhKey(&dh);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    ret = wc_DhGenerateKeyPair(&dh, &rng, priv, &privSz, pub, &pubSz);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    wc_FreeDhKey(&dh);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_DhGenerateKeyPair", ret);
        gnutls_free(pub);
        gnutls_free(priv);
        wc_FreeDhKey(&dh);
        return ret;
    }

    ret = _gnutls_mpi_init_scan(&params->params[DSA_Y], pub, pubSz);
    if (ret == 0) {
        params->params_nr++;
        ret = _gnutls_mpi_init_scan(&params->params[DSA_X], priv, privSz);
    }
    if (ret == 0) {
        params->params_nr++;
    }

    return ret;
}

static int wolfssl_pk_generate_keys_ecc(unsigned int level,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    ecc_key ecc;
    int curve_id;
    int curve_size;

    WGW_FUNC_ENTER();

    ret = ecc_level_to_curve(level, &curve_id, &curve_size);
    if (ret != 0) {
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate ECC key */
    ret = wc_ecc_make_key_ex(&rng, curve_size, &ecc, curve_id);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_make_key_ex", ret);
        wc_ecc_free(&ecc);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    params->curve = level;
    params->params_nr = 0;

    ret = mp_to_bigint(ecc.pubkey.x, &params->params[ECC_X]);
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(ecc.pubkey.y, &params->params[ECC_Y]);
    }
    if (ret == 0) {
        params->params_nr++;
        ret = mp_to_bigint(ecc.k, &params->params[ECC_K]);
    }
    if (ret == 0) {
        params->params_nr++;
    }
    wc_ecc_free(&ecc);

    return ret;
}

#ifdef HAVE_ED25519
static int wolfssl_pk_generate_keys_ed25519(unsigned int level,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    ed25519_key ed25519;
    word32 privSz = ED25519_PRV_KEY_SIZE;
    word32 pubSz = ED25519_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize Ed25519 key */
    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        wc_FreeRng(&rng);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate Ed25519 key */
    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed25519);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_make_key", ret);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    params->curve = level;
    params->params_nr = 0;

    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_MEMORY_ERROR;
    }
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_ed25519_export_key(&ed25519, params->raw_priv.data, &privSz,
        params->raw_pub.data, &pubSz);
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_export_key", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    params->raw_priv.size = ED25519_KEY_SIZE;
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

#ifdef HAVE_ED448
static int wolfssl_pk_generate_keys_ed448(unsigned int level,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    ed448_key ed448;
    word32 privSz = ED448_PRV_KEY_SIZE;
    word32 pubSz = ED448_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize Ed448 key */
    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        wc_FreeRng(&rng);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate Ed448 key */
    ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed448);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_make_key", ret);
        wc_ed448_free(&ed448);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    params->curve = level;
    params->params_nr = 0;

    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_ed448_free(&ed448);
        return GNUTLS_E_MEMORY_ERROR;
    }
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_ed448_free(&ed448);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_ed448_export_key(&ed448, params->raw_priv.data, &privSz,
        params->raw_pub.data, &pubSz);
    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_export_key", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    params->raw_priv.size = ED448_KEY_SIZE;
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

#ifdef HAVE_CURVE25519
static int wolfssl_pk_generate_keys_x25519(unsigned int level,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    curve25519_key x25519;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize X25519 key */
    ret = wc_curve25519_init(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        wc_FreeRng(&rng);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate X25519 key */
    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &x25519);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_make_key", ret);
        wc_curve25519_free(&x25519);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    params->curve = level;
    params->params_nr = 0;

    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_curve25519_free(&x25519);
        return GNUTLS_E_MEMORY_ERROR;
    }
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_curve25519_free(&x25519);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_curve25519_export_key_raw_ex(&x25519, params->raw_priv.data,
        &privSz, params->raw_pub.data, &pubSz, EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_export_key_raw", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    params->raw_priv.size = privSz;
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

#ifdef HAVE_CURVE448
static int wolfssl_pk_generate_keys_x448(unsigned int level,
    gnutls_pk_params_st *params)
{
    int ret;
    WC_RNG rng;
    curve448_key x448;
    word32 privSz = CURVE448_KEY_SIZE;
    word32 pubSz = CURVE448_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize X448 key */
    ret = wc_curve448_init(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate X448 key */
    ret = wc_curve448_make_key(&rng, CURVE448_KEY_SIZE, &x448);

    PRIVATE_KEY_LOCK();

    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_make_key", ret);
        wc_curve448_free(&x448);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    params->curve = level;
    params->params_nr = 0;

    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_curve448_free(&x448);
        return GNUTLS_E_MEMORY_ERROR;
    }
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_curve448_free(&x448);
        return GNUTLS_E_MEMORY_ERROR;
    }

    ret = wc_curve448_export_key_raw_ex(&x448, params->raw_priv.data, &privSz,
        params->raw_pub.data, &pubSz, EC448_LITTLE_ENDIAN);
    wc_curve448_free(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_export_key_raw_ex", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    params->raw_priv.size = privSz;
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

/* To generate a DH key either q must be set in the params or
 * level should be set to the number of required bits.
 *
 * level      Either bits or curve.
 * ephemeral  non-zero indicates true.
 */
static int wolfssl_pk_generate_keys(gnutls_pk_algorithm_t algo,
    unsigned int level, gnutls_pk_params_st *params,
    unsigned ephemeral)
{
    int ret;

    WGW_FUNC_ENTER();

    if (_gnutls_have_lib_error())
        return GNUTLS_E_LIB_IN_ERROR_STATE;

    (void)ephemeral;

    switch (algo) {
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_generate_keys_rsa(level, params);
            break;

        case GNUTLS_PK_DH:
            ret = wolfssl_pk_generate_keys_dh(level, params);
            break;

        case GNUTLS_PK_ECDSA:
            ret = wolfssl_pk_generate_keys_ecc(level, params);
            break;

#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            ret = wolfssl_pk_generate_keys_ed25519(level, params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            ret = wolfssl_pk_generate_keys_ed448(level, params);
            break;
#endif

#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
            ret = wolfssl_pk_generate_keys_x25519(level, params);
            break;
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
            ret = wolfssl_pk_generate_keys_x448(level, params);
            break;
#endif

        default:
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    params->algo = algo;

    return ret;
}

#define RSA_MAX_PARAMS      8
#define RSA_MIN_PRIV_PARAMS 5

static int wolfssl_pk_fixup_rsa_calc_exp(gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;
    mp_int tmp;

    WGW_FUNC_ENTER();

    /* Clear out all extra parameters in case they were left over. */
    _gnutls_mpi_zrelease(&params->params[RSA_COEF]);
    _gnutls_mpi_zrelease(&params->params[RSA_E1]);
    _gnutls_mpi_zrelease(&params->params[RSA_E2]);

    params->params_nr = RSA_MIN_PRIV_PARAMS;

    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Ensure P is valid for inversion. */
    if (mp_iszero(&rsa.p)) {
        WGW_ERROR("First prime is 0 - can't invert");
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    /* Calculate coefficient (u) and add to parameters. */
    ret = mp_invmod(&rsa.q, &rsa.p, &rsa.u);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_invmod", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_to_bigint(&rsa.u, &params->params[RSA_COEF]);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        return ret;
    }
    params->params_nr++;

    ret = mp_init(&tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Calculate exponent 1 (dP) and add to parameters. */
    ret = mp_sub_d(&rsa.p, 1, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_mod(&rsa.dP, &rsa.d, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_invmod", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_to_bigint(&rsa.dP, &params->params[RSA_E1]);
    if (ret != 0) {
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return ret;
    }
    params->params_nr++;

    /* Calculate exponent 2 (dQ) and add to parameters. */
    ret = mp_sub_d(&rsa.q, 1, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_mod(&rsa.dQ, &rsa.d, &tmp);
    mp_free(&tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_invmod", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_to_bigint(&rsa.dQ, &params->params[RSA_E2]);
    wc_FreeRsaKey(&rsa);
    if (ret != 0) {
        return ret;
    }
    params->params_nr++;

    return 0;
}

static int wolfssl_pk_fixup_rsa_check_p_q(gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;
    mp_int tmp;

    WGW_FUNC_ENTER();

    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

    if (mp_count_bits(&rsa.q) + mp_count_bits(&rsa.u) < mp_count_bits(&rsa.p)) {
        WGW_ERROR("q and c smaller than p");
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    ret = mp_init(&tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = mp_mul(&rsa.p, &rsa.q, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    ret = mp_cmp(&rsa.n, &tmp);
    mp_free(&tmp);
    wc_FreeRsaKey(&rsa);
    if (ret != MP_EQ) {
        WGW_ERROR("p * q != n");
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    return 0;
}

static int wolfssl_pk_fixup_rsa(gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check we have the basic RSA private key parameters: n, e, d, p, q */
    if (params->params_nr < RSA_MIN_PRIV_PARAMS) {
        WGW_ERROR("Too few parameters for RSA private key");
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    if (params->params_nr < RSA_MAX_PARAMS) {
        WGW_LOG("RSA private key missing exp parameters");
        ret = wolfssl_pk_fixup_rsa_calc_exp(params);
        if (ret != 0) {
            return ret;
        }
    }

    return wolfssl_pk_fixup_rsa_check_p_q(params);
}

#ifdef HAVE_ED25519
static int wolfssl_pk_fixup_ed25519(gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;

    WGW_FUNC_ENTER();

    if (params->curve != GNUTLS_ECC_CURVE_ED25519) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_ED25519,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    if (params->raw_pub.data == NULL) {
        params->raw_pub.data = gnutls_malloc(ED25519_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                ED25519_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize Ed25519 private key */
    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_ed25519_import_private_only(params->raw_priv.data,
        params->raw_priv.size, &ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }


    ret = wc_ed25519_make_public(&ed25519, params->raw_pub.data,
        ED25519_PUB_KEY_SIZE);
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_make_public", ret);
        gnutls_free(params->raw_pub.data);
        params->raw_pub.data = NULL;
        return GNUTLS_E_INTERNAL_ERROR;
    }
    params->raw_pub.size = ED25519_PUB_KEY_SIZE;

    return 0;
}
#endif

#ifdef HAVE_ED448
static int wolfssl_pk_fixup_ed448(gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;

    WGW_FUNC_ENTER();

    if (params->curve != GNUTLS_ECC_CURVE_ED448) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_ED448,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    if (params->raw_pub.data == NULL) {
        params->raw_pub.data = gnutls_malloc(ED448_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                ED448_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize Ed448 private key */
    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_ed448_import_private_only(params->raw_priv.data,
        params->raw_priv.size, &ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        wc_ed448_free(&ed448);
        return GNUTLS_E_INTERNAL_ERROR;
    }


    ret = wc_ed448_make_public(&ed448, params->raw_pub.data,
        ED448_PUB_KEY_SIZE);
    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_make_public", ret);
        gnutls_free(params->raw_pub.data);
        params->raw_pub.data = NULL;
        return GNUTLS_E_INTERNAL_ERROR;
    }
    params->raw_pub.size = ED448_PUB_KEY_SIZE;

    return 0;
}
#endif

#ifdef HAVE_CURVE25519
static int wolfssl_pk_fixup_x25519(gnutls_pk_params_st *params)
{
    int ret;
    curve25519_key x25519;

    WGW_FUNC_ENTER();

    if (params->curve != GNUTLS_ECC_CURVE_X25519) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_X25519,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    if (params->raw_pub.data == NULL) {
        params->raw_pub.data = gnutls_malloc(CURVE25519_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                CURVE25519_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize X25519 private key */
    ret = wc_curve25519_init(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_curve25519_import_private(params->raw_priv.data,
        params->raw_priv.size, &x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_import_private_key", ret);
        wc_curve25519_free(&x25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }


    ret = wc_curve25519_make_pub(CURVE25519_PUB_KEY_SIZE, params->raw_pub.data,
        params->raw_priv.size, params->raw_priv.data);
    wc_curve25519_free(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_make_pub", ret);
        gnutls_free(params->raw_pub.data);
        params->raw_pub.data = NULL;
        return GNUTLS_E_INTERNAL_ERROR;
    }
    params->raw_pub.size = CURVE25519_PUB_KEY_SIZE;

    return 0;
}
#endif

#ifdef HAVE_CURVE448
static int wolfssl_pk_fixup_x448(gnutls_pk_params_st *params)
{
    int ret;
    curve448_key x448;

    WGW_FUNC_ENTER();

    if (params->curve != GNUTLS_ECC_CURVE_X448) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_X448,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    if (params->raw_pub.data == NULL) {
        params->raw_pub.data = gnutls_malloc(CURVE448_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                CURVE448_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize X448 private key */
    ret = wc_curve448_init(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_curve448_import_private(params->raw_priv.data,
        params->raw_priv.size, &x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_import_private_key", ret);
        wc_curve448_free(&x448);
        return GNUTLS_E_INTERNAL_ERROR;
    }


    ret = wc_curve448_make_pub(CURVE448_PUB_KEY_SIZE, params->raw_pub.data,
        params->raw_priv.size, params->raw_priv.data);
    wc_curve448_free(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_make_pub", ret);
        gnutls_free(params->raw_pub.data);
        params->raw_pub.data = NULL;
        return GNUTLS_E_INTERNAL_ERROR;
    }
    params->raw_pub.size = CURVE448_PUB_KEY_SIZE;

    return 0;
}
#endif

/* this function should convert params to ones suitable
 * for the above functions
 */
static int wolfssl_pk_fixup(gnutls_pk_algorithm_t algo,
    gnutls_direction_t direction, gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    if (direction != GNUTLS_IMPORT)
        return 0;

    switch (algo) {
        case GNUTLS_PK_RSA:
            ret = wolfssl_pk_fixup_rsa(params);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            ret = wolfssl_pk_fixup_ed25519(params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            ret = wolfssl_pk_fixup_ed448(params);
            break;
#endif
#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
            ret = wolfssl_pk_fixup_x25519(params);
            break;
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
            ret = wolfssl_pk_fixup_x448(params);
            break;
#endif
        default:
            ret = 0;
            break;
    }

    return ret;
}

static int wolfssl_pk_derive_dh(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce, unsigned int flags)
{
    int ret;
    DhKey dh;
    word32 len;
    gnutls_datum_t private;
    gnutls_datum_t public;
    gnutls_datum_t q;

    WGW_FUNC_ENTER();

    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = _gnutls_mpi_dprint(priv->params[DH_X], &private);
    if (ret != 0) {
        WGW_ERROR("_gnutls_mpi_print: %d", ret);
        return ret;
    }
    ret = _gnutls_mpi_dprint(pub->params[DH_Y], &public);
    if (ret != 0) {
        WGW_ERROR("_gnutls_mpi_print: %d", ret);
        gnutls_free(private.data);
        return ret;
    }

    ret = wc_InitDhKey(&dh);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitDhKey", ret);
        gnutls_free(public.data);
        gnutls_free(private.data);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    WGW_LOG("Load DH parameters from params");
    ret = dh_load_params(&dh, priv);
    if (ret != 0) {
        wc_FreeDhKey(&dh);
        gnutls_free(public.data);
        gnutls_free(private.data);
        return ret;
    }

    if (priv->params[DH_Q] != NULL) {
        ret = _gnutls_mpi_dprint(priv->params[DH_Q], &q);
        if (ret != 0) {
            WGW_ERROR("_gnutls_mpi_print: %d", ret);
            return ret;
        }
    } else {
        q.data = NULL;
        q.size = 0;
    }

    ret = wc_DhCheckPubKey_ex(&dh, public.data, public.size, q.data, q.size);
    gnutls_free(q.data);
    if (ret != 0) {
        wc_FreeDhKey(&dh);
        gnutls_free(public.data);
        gnutls_free(private.data);
        return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

    len = (mp_count_bits(&dh.p) + 7) / 8;
    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_FreeDhKey(&dh);
        gnutls_free(public.data);
        gnutls_free(private.data);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    if (flags & PK_DERIVE_TLS13) {
        ret = wc_DhAgree_ct(&dh, out->data, &len, private.data, private.size,
            public.data, public.size);
    } else {
        ret = wc_DhAgree(&dh, out->data, &len, private.data, private.size,
            public.data, public.size);
    }

    PRIVATE_KEY_LOCK();

    wc_FreeDhKey(&dh);
    gnutls_free(public.data);
    gnutls_free(private.data);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_DhAgree", ret);
        out->data = NULL;
        out->size = 0;
        return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

    out->size = len;

    return 0;
}

static int wolfssl_pk_derive_ecc(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce)
{
    int ret;
    ecc_key private;
    ecc_key public;
    WC_RNG rng;
    word32 len;

    WGW_FUNC_ENTER();

    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        return GNUTLS_E_RANDOM_FAILED;
    }

    ret = ecc_load_params(&private, priv, 1);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }
    private.rng = &rng;

    ret = ecc_load_params(&public, pub, 0);
    if (ret != 0) {
        wc_ecc_free(&private);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_ecc_check_key(&public);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
        wc_ecc_free(&public);
        wc_ecc_free(&private);
        wc_FreeRng(&rng);
        return GNUTLS_E_PK_INVALID_PUBKEY;
    }

    len = private.dp->size;
    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_ecc_free(&public);
        wc_ecc_free(&private);
        wc_FreeRng(&rng);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    ret = wc_ecc_shared_secret(&private, &public, out->data, &len);

    PRIVATE_KEY_LOCK();

    wc_ecc_free(&public);
    wc_ecc_free(&private);
    wc_FreeRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_shared_secret", ret);
        gnutls_free(out->data);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->size = len;

    return 0;
}

#ifdef HAVE_CURVE25519
static int wolfssl_pk_derive_x25519(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce)
{
    int ret;
    curve25519_key private;
    curve25519_key public;
    word32 len = CURVE25519_KEYSIZE;
#ifdef WOLFSSL_CURVE25519_BLINDING
    WC_RNG rng;
#endif

    WGW_FUNC_ENTER();

    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = wc_curve25519_check_public(pub->raw_pub.data, pub->raw_pub.size,
        EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_check_public", ret);
        return GNUTLS_E_PK_INVALID_PUBKEY;
    }

    /* Initialize X25519 private key */
    ret = wc_curve25519_init(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Initialize X25519 public key */
    ret = wc_curve25519_init(&public);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        wc_curve25519_free(&private);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_curve25519_import_private_ex(priv->raw_priv.data,
        priv->raw_priv.size, &private, EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_import_private", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = wc_curve25519_import_public_ex(pub->raw_pub.data, pub->raw_pub.size,
        &public, EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_import_public", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_MEMORY_ERROR;
    }

#ifdef WOLFSSL_CURVE25519_BLINDING
    /* Initialize private random. */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRng", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_RANDOM_FAILED;
    }
    /* Set random into private key. */
    ret = wc_curve25519_set_rng(&private, &rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_set_rng", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        wc_FreeRng(&rng);
        return GNUTLS_E_INTERNAL_ERROR;
    }
#endif

    PRIVATE_KEY_UNLOCK();

    ret = wc_curve25519_shared_secret_ex(&private, &public, out->data, &len,
        EC25519_LITTLE_ENDIAN);

    PRIVATE_KEY_LOCK();

    wc_curve25519_free(&public);
    wc_curve25519_free(&private);
#ifdef WOLFSSL_CURVE25519_BLINDING
    wc_FreeRng(&rng);
#endif
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_shared_secret_ex", ret);
        gnutls_free(out->data);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->size = len;

    return 0;
}
#endif

#ifdef HAVE_CURVE448
static int wolfssl_pk_derive_x448(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce)
{
    int ret;
    curve448_key private;
    curve448_key public;
    word32 len = CURVE448_KEY_SIZE;

    WGW_FUNC_ENTER();

    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = wc_curve448_check_public(pub->raw_pub.data, pub->raw_pub.size,
        EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_check_public", ret);
        return GNUTLS_E_PK_INVALID_PUBKEY;
    }

    /* Initialize X448 private key */
    ret = wc_curve448_init(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Initialize X448 public key */
    ret = wc_curve448_init(&public);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        wc_curve448_free(&private);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    ret = wc_curve448_import_private_ex(priv->raw_priv.data,
        priv->raw_priv.size, &private, EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_import_private_ex", ret);
        wc_curve448_free(&public);
        wc_curve448_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ret = wc_curve448_import_public_ex(pub->raw_pub.data, pub->raw_pub.size,
        &public, EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_import_public", ret);
        wc_curve448_free(&public);
        wc_curve448_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_curve448_free(&public);
        wc_curve448_free(&private);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    ret = wc_curve448_shared_secret_ex(&private, &public, out->data, &len,
        EC448_LITTLE_ENDIAN);

    PRIVATE_KEY_LOCK();

    wc_curve448_free(&public);
    wc_curve448_free(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_shared_secret_ex", ret);
        gnutls_free(out->data);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->size = len;

    return 0;
}
#endif

static int wolfssl_pk_derive(gnutls_pk_algorithm_t algo, gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce, unsigned int flags)
{
    int ret;

    WGW_FUNC_ENTER();

    switch (algo) {
        case GNUTLS_PK_DH:
            ret = wolfssl_pk_derive_dh(out, priv, pub, nonce, flags);
            break;
        case GNUTLS_PK_EC:
            ret = wolfssl_pk_derive_ecc(out, priv, pub, nonce);
            break;
#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
            ret = wolfssl_pk_derive_x25519(out, priv, pub, nonce);
            break;
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
            ret = wolfssl_pk_derive_x448(out, priv, pub, nonce);
            break;
#endif

        default:
            return GNUTLS_E_INTERNAL_ERROR;
    }

    return ret;
}

static int wolfssl_pk_encaps(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *ciphertext, gnutls_datum_t *shared_secret,
    const gnutls_datum_t *pub)
{
    WGW_FUNC_ENTER();

    (void)algo;
    (void)ciphertext;
    (void)shared_secret;
    (void)pub;

    return GNUTLS_E_UNKNOWN_ALGORITHM;
}

static int wolfssl_pk_decaps(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *shared_secret, const gnutls_datum_t *ciphertext,
    const gnutls_datum_t *priv)
{
    WGW_FUNC_ENTER();

    (void)algo;
    (void)shared_secret;
    (void)ciphertext;
    (void)priv;

    return GNUTLS_E_UNKNOWN_ALGORITHM;
}

static int wolfssl_pk_curve_exists(gnutls_ecc_curve_t curve)
{
    WGW_FUNC_ENTER();

    switch (curve) {
#ifdef HAVE_ED25519
        case GNUTLS_ECC_CURVE_ED25519:
#endif
#ifdef HAVE_CURVE25519
        case GNUTLS_ECC_CURVE_X25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_ECC_CURVE_ED448:
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_ECC_CURVE_X448:
#endif
#if ECC_MIN_KEY_SZ <= 192
        case GNUTLS_ECC_CURVE_SECP192R1:
#endif
#if ECC_MIN_KEY_SZ <= 224
        case GNUTLS_ECC_CURVE_SECP224R1:
#endif
        case GNUTLS_ECC_CURVE_SECP256R1:
        case GNUTLS_ECC_CURVE_SECP384R1:
        case GNUTLS_ECC_CURVE_SECP521R1:
            WGW_LOG("Curve exists: %d", curve);
            return 1;
        default:
            WGW_ERROR("Curve doesn't exist: %d", curve);
            return 0;
    }
}

static int wolfssl_pk_exists(gnutls_pk_algorithm_t pk)
{
    WGW_FUNC_ENTER();

    switch (pk) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_DH:
        case GNUTLS_PK_ECDSA:
#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
#endif
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
#endif
            WGW_LOG("Algorithm exists: %d", pk);
            return 1;
        default:
            WGW_ERROR("Algorithm doesn't exist: %d", pk);
            return 0;
    }
}

static int wolfssl_pk_sign_exists(gnutls_sign_algorithm_t sign)
{
    WGW_FUNC_ENTER();

    switch (sign) {
        case GNUTLS_SIGN_RSA_RAW:

        case GNUTLS_SIGN_RSA_MD5:
        case GNUTLS_SIGN_RSA_SHA1:
        case GNUTLS_SIGN_RSA_SHA256:
        case GNUTLS_SIGN_RSA_SHA384:
        case GNUTLS_SIGN_RSA_SHA512:
        case GNUTLS_SIGN_RSA_SHA224:

        case GNUTLS_SIGN_RSA_SHA3_224:
        case GNUTLS_SIGN_RSA_SHA3_256:
        case GNUTLS_SIGN_RSA_SHA3_384:
        case GNUTLS_SIGN_RSA_SHA3_512:

        case GNUTLS_SIGN_RSA_PSS_SHA256:
        case GNUTLS_SIGN_RSA_PSS_SHA384:
        case GNUTLS_SIGN_RSA_PSS_SHA512:

        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:

        case GNUTLS_SIGN_ECDSA_SHA1:
        case GNUTLS_SIGN_ECDSA_SHA224:
        case GNUTLS_SIGN_ECDSA_SHA256:
        case GNUTLS_SIGN_ECDSA_SHA384:
        case GNUTLS_SIGN_ECDSA_SHA512:
        case GNUTLS_SIGN_ECDSA_SHA3_224:
        case GNUTLS_SIGN_ECDSA_SHA3_256:
        case GNUTLS_SIGN_ECDSA_SHA3_384:
        case GNUTLS_SIGN_ECDSA_SHA3_512:

        case GNUTLS_SIGN_ECDSA_SECP256R1_SHA256:
        case GNUTLS_SIGN_ECDSA_SECP384R1_SHA384:
        case GNUTLS_SIGN_ECDSA_SECP521R1_SHA512:

#ifdef HAVE_ED25519
        case GNUTLS_SIGN_EDDSA_ED25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_SIGN_EDDSA_ED448:
#endif
            WGW_LOG("Signature exists: %d", sign);
            return 1;
        default:
            WGW_ERROR("Signature doesn't exist: %d", sign);
            return 0;
    }
}


/* structure containing function pointers for the pk implementation */
static const gnutls_crypto_pk_st wolfssl_pk_struct = {
    .encrypt = wolfssl_pk_encrypt,
    .decrypt = wolfssl_pk_decrypt,
    .decrypt2 = wolfssl_pk_decrypt2,
    .sign = wolfssl_pk_sign,
    .verify = wolfssl_pk_verify,
    .verify_priv_params = wolfssl_pk_verify_priv_params,
    .verify_pub_params = wolfssl_pk_verify_pub_params,
    .generate_params = wolfssl_pk_generate_params,
    .generate_keys = wolfssl_pk_generate_keys,
    .pk_fixup_private_params = wolfssl_pk_fixup,
    .derive = wolfssl_pk_derive,
    .encaps = wolfssl_pk_encaps,
    .decaps = wolfssl_pk_decaps,
    .curve_exists = wolfssl_pk_curve_exists,
    .pk_exists = wolfssl_pk_exists,
    .sign_exists = wolfssl_pk_sign_exists
};

/* register the pk algorithm with GnuTLS */
static int wolfssl_pk_register(void)
{
    return 0;
}

const gnutls_crypto_pk_st *gnutls_get_pk_ops(void)
{
    WGW_FUNC_ENTER();

    return &wolfssl_pk_struct;
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
