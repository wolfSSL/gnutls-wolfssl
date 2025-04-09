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
#include <wolfssl/wolfcrypt/kdf.h>

#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>


void __attribute__((constructor)) wolfssl_init(void) {
    _gnutls_wolfssl_init();
}

#ifdef ENABLE_WOLFSSL

/********************************** Logging **********************************/

/**
 * Log function entry.
 */
#define WGW_FUNC_ENTER()    wgw_log(__LINE__, __func__)
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
    CBC,
    GCM
};

/** Size of GCM tag. */
#define GCM_TAG_SIZE        WC_AES_BLOCK_SIZE
/** Maximum AES key size. */
#define MAX_AES_KEY_SIZE    AES_256_KEY_SIZE
/** Maximum authentication data. */
#define MAX_AUTH_DATA       1024
/** Maximum plaintext data stored. */
#define MAX_PLAINTEXT       16*1024
/** Macimum number of encrypted data locations to keep. */
#define MAX_GCM_ENC_DATA    10

/** Encrypted data locations. */
struct gcm_enc_data {
    /** Pointer to copy encrypted data to. */
    unsigned char* data;
    /** Amount of encrypted data to copy. */
    size_t size;
};

/** Context structure for wolfssl AES. */
struct wolfssl_cipher_ctx {
    /** AES encryption context. */
    Aes enc_aes_ctx;
    /** AES decryption context. */
    Aes dec_aes_ctx;
    /** Indicates that this context as been initialized. */
    int initialized;
    /** Indicates whether we are doing encryption or decryption.  */
    int enc;
    /** Indicates that we have been initialized for encryption. */
    int enc_initialized;
    /** Indicates that we have been initialized for decryption. */
    int dec_initialized;
    /** The GnuTLS cipher algorithm ID. */
    gnutls_cipher_algorithm_t algorithm;
    /** Mode of AES to use. */
    int mode;

    /** Key to use. */
    unsigned char key[MAX_AES_KEY_SIZE];
    /** Size of key to use. */
    size_t key_size;
    /** IV/nonce to use.  */
    unsigned char iv[AES_IV_SIZE];
    /** Size of IV/nonce to use.  */
    size_t iv_size;

    /* For GCM mode */
    /** Authentication data to use. */
    unsigned char auth_data[MAX_AUTH_DATA];
    /** Size of authentication data to use. */
    size_t auth_data_size;
    /** Calculated authentication tag. */
    unsigned char tag[GCM_TAG_SIZE];
    /** Size of calculated authentication tag. */
    size_t tag_size;
    /** Tag has been set. */
    int tag_set;
    /** Plaintext to encrypt. */
    unsigned char* plaintext;
    /** Plaintext size. */
    size_t plaintext_size;
    /** Ciphertext locations. */
    struct gcm_enc_data enc_data[MAX_GCM_ENC_DATA];
    /** Number of ciphertext locations. */
    int enc_cnt;
};

/** Array of supported ciphers. */
static const int wolfssl_cipher_supported[] = {
    [GNUTLS_CIPHER_AES_128_CBC] = 1,
    [GNUTLS_CIPHER_AES_192_CBC] = 1,
    [GNUTLS_CIPHER_AES_256_CBC] = 1,
    [GNUTLS_CIPHER_AES_128_GCM] = 1,
    [GNUTLS_CIPHER_AES_192_GCM] = 1,
    [GNUTLS_CIPHER_AES_256_GCM] = 1,
    /* TODO: CCM, CCM-8, XTS, CFB8?. */
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
    if (algorithm >= 0 && algorithm < WOLFSSL_CIPHER_SUPPORTED_LEN &&
            wolfssl_cipher_supported[algorithm] == 1) {
        return 1;
    }

    WGW_LOG("cipher %d is not supported", algorithm);
    return 0;
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
    }

    WGW_LOG("Cipher not supported: %d", algorithm);

    return GNUTLS_E_INVALID_REQUEST;
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
    int mode;

    WGW_FUNC_ENTER();
    WGW_LOG("enc=%d", enc);

    /* check if cipher is supported */
    if (!is_cipher_supported((int)algorithm)) {
        WGW_LOG("Cipher not supported: %d", algorithm);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_cipher_ctx));
    if (ctx == NULL) {
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize context with default values */
    /* TODO: context was set to all zeros on allocation - no needd for this? */
    ctx->initialized = 0;
    ctx->enc = 0;
    ctx->enc_initialized = 0;
    ctx->dec_initialized = 0;
    ctx->key_size = 0;
    ctx->iv_size = 0;
    ctx->auth_data_size = 0;
    ctx->tag_size = 0;
    ctx->tag_set = 0;
    ctx->algorithm = 0;
    /* TODO: mode should be able to be determined here. */

    if (enc) {
        /* initialize wolfSSL AES contexts */
        if (wc_AesInit(&ctx->enc_aes_ctx, NULL, INVALID_DEVID) != 0) {
            gnutls_free(ctx);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        ctx->enc = enc;
        ctx->enc_initialized = 1;

        WGW_LOG("encryption context initialized successfully");

        mode = get_cipher_mode(algorithm);
        if (mode == GCM) {
            WGW_LOG("running in GCM mode, single context, initializing also "
                    "decryption");
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

        WGW_LOG("decryption context initialized successfully");
    }

    ctx->tag_size = GCM_TAG_SIZE;
    ctx->algorithm = algorithm;
    ctx->initialized = 1;
    *_ctx = ctx;

    WGW_LOG("cipher context initialized successfully");
    return 0;
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

    WGW_FUNC_ENTER();
    WGW_LOG("keysize %zu", keysize);

    if (!ctx->initialized) {
        WGW_LOG("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* store key for later use when setting up IV */
    if (keysize > sizeof(ctx->key)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* save key */
    XMEMCPY(ctx->key, key, keysize);
    ctx->key_size = keysize;
    ctx->tag_set = 0;

    WGW_LOG("key stored, waiting for IV");
    return 0;
}

/**
 * Set the Initialization Vector (IV) into the cipher context.
 *
 * @param [in, out] ctx      Cipher context.
 * @param [in]      iv       IV data. Assumed not NULL.
 * @param [in]      iv_size  Size of key in bytes.
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
    int mode = -1;

    WGW_FUNC_ENTER();
    WGW_LOG("iv_size %zu", iv_size);

    if (!ctx->initialized) {
        WGW_LOG("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    mode = get_cipher_mode(ctx->algorithm);

    /* for GCM, we expect a 8-16 byte nonce */
    if (mode == GCM && (iv_size < GCM_NONCE_MIN_SZ ||
            iv_size > GCM_NONCE_MAX_SZ)) {
        WGW_LOG("IV size invalid for GCM");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* for CBC, validate IV size */
    if (mode == CBC && iv_size != AES_IV_SIZE) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* save IV */
    XMEMCPY(ctx->iv, iv, iv_size);
    ctx->iv_size = iv_size;

    /* now we have both key and IV, so we can set the keys in wolfSSL */
    if (ctx->key_size > 0) {
        if (mode == CBC) {
            WGW_LOG("setting key for CBC mode");
            WGW_LOG("setting key and IV for %s",
                    ctx->enc ? "encryption" : "decryption");
            if (ctx->enc && ctx->enc_initialized) {
                ret = wc_AesSetKey(&ctx->enc_aes_ctx, ctx->key, ctx->key_size,
                    ctx->iv, AES_ENCRYPTION);
                if (ret != 0) {
                    WGW_LOG("wc_AesSetKey failed for encryption with code %d",
                        ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
                ctx->enc_initialized = 1;
            } else if (!ctx->enc && ctx->dec_initialized) {
                ret = wc_AesSetKey(&ctx->dec_aes_ctx, ctx->key, ctx->key_size,
                    ctx->iv, AES_DECRYPTION);
                if (ret != 0) {
                    WGW_LOG("wc_AesSetKey failed for decryption with code %d",
                        ret);
                    return GNUTLS_E_ENCRYPTION_FAILED;
                }
                ctx->dec_initialized = 1;
            }
            ctx->mode = mode;
        } else if (mode == GCM) {
            WGW_LOG("setting key for GCM mode");
            ret = wc_AesGcmSetKey(&ctx->enc_aes_ctx, ctx->key, ctx->key_size);
            if (ret != 0) {
                WGW_LOG("wc_AesGcmSetKey failed for encryption with code %d",
                    ret);
                return GNUTLS_E_ENCRYPTION_FAILED;
            }
            ctx->mode = mode;
            ctx->tag_set = 0;
        } else {
            WGW_LOG("encryption/decryption struct not correctly initialized");
            return GNUTLS_E_INVALID_REQUEST;
        }
    } else {
        WGW_LOG("no key set yet, deferring key setup");
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("setiv completed successfully");
    return 0;
}

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
        WGW_LOG("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (auth_size > sizeof(ctx->auth_data)) {
        WGW_LOG("Auth data too big");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* store AAD for later use in encrypt/decrypt operations */
    XMEMCPY(ctx->auth_data + ctx->auth_data_size, auth_data, auth_size);
    ctx->auth_data_size += auth_size;
    ctx->tag_set = 0;

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
        WGW_LOG("cipher context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* check if encryption context is initialized */
    if (!ctx->enc_initialized) {
        WGW_LOG("encryption context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (dst_size < src_size) {
        WGW_LOG("Destination size is too small for source size");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* always use the encryption context for encryption operations */
    if (ctx->mode == CBC) {
        WGW_LOG("wc_AesCbcEncrypt");

        /* check block alignment for CBC mode */
        if (src_size % AES_BLOCK_SIZE != 0) {
            WGW_LOG("Source size not a multiple of the block size");
            return GNUTLS_E_INVALID_REQUEST;
        }

        ret = wc_AesCbcEncrypt(&ctx->enc_aes_ctx, dst, src, src_size);
        if (ret != 0) {
            WGW_LOG("wc_AesCbcEncrypt failed with code %d", ret);
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        unsigned char* ptr;

        WGW_LOG("Caching platintext and output location");

        ctx->enc = 1;

        /* Check we have enough entries for another encrypted data location. */
        if (ctx->enc_cnt == MAX_GCM_ENC_DATA) {
            WGW_LOG("Too many encrypted data locations");
            return GNUTLS_E_ENCRYPTION_FAILED;
        }

        /* Add the new plaintext on to the existing buffer. */
        ptr = gnutls_realloc(ctx->plaintext, ctx->plaintext_size + src_size);
        if (ptr == NULL) {
            WGW_LOG("realloc of gmac data failed");
            return GNUTLS_E_ENCRYPTION_FAILED;
        }
        ctx->plaintext = ptr;
        XMEMCPY(ctx->plaintext + ctx->plaintext_size, src, src_size);
        ctx->plaintext_size += src_size;

        /* Store the encryption data location. */
        ctx->enc_data[ctx->enc_cnt].data = dst;
        ctx->enc_data[ctx->enc_cnt].size = src_size;
        ctx->enc_cnt++;
    } else {
        WGW_LOG("AES mode not set");
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
        WGW_LOG("decryption failed - context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* check if decryption context is initialized */
    if (!ctx->dec_initialized) {
        WGW_LOG("decryption context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (dst_size < src_size) {
        WGW_LOG("Destination size is too small for source size");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* always use the decryption context for decryption operations */
    if (ctx->mode == CBC) {
        WGW_LOG("wc_AesCbcDecrypt");
        /* check block alignment for CBC mode */
        if (src_size % AES_BLOCK_SIZE != 0) {
            WGW_LOG("Source size not a multiple of the block size");
            return GNUTLS_E_INVALID_REQUEST;
        }

        ret = wc_AesCbcDecrypt(&ctx->dec_aes_ctx, dst, src, src_size);
        if (ret != 0) {
            WGW_LOG("wc_AesCbcDecrypt failed with code %d", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
    } else if (ctx->mode == GCM) {
        WGW_LOG("wc_AesGcmDecrypt");

        ctx->enc = 0;

        /* for GCM mode, we need to use the GCM decrypt function with AAD */
        ret = wc_AesGcmDecrypt(&ctx->enc_aes_ctx, dst, src, src_size,
            ctx->iv, ctx->iv_size, ctx->tag, ctx->tag_size, ctx->auth_data,
                ctx->auth_data_size);
        if (ret != 0) {
            WGW_LOG("wc_AesGcmDecrypt failed with code %d", ret);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        else {
            /* Authentication data used - reset count. */
            ctx->auth_data_size = 0;
        }
    } else {
        WGW_LOG("AES mode not set");
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
    WGW_LOG("wolfssl_cipher_tag with tag_size %zu", tag_size);

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
        XMEMCPY(tag, ctx->tag, tag_size);
        WGW_LOG("tag stored successfully");
    /* When encrypting, generate tag now. */
    } else if (ctx->enc) {
        int ret;

        WGW_LOG("wc_AesGcmEncrypt");

        /* Do encryption now we have all the data. */
        ret = wc_AesGcmEncrypt( &ctx->enc_aes_ctx, ctx->plaintext,
            ctx->plaintext, ctx->plaintext_size, ctx->iv, ctx->iv_size,
            ctx->tag, ctx->tag_size, ctx->auth_data, ctx->auth_data_size);
        if (ret != 0) {
            WGW_LOG("wc_AesGcmEncrypt failed with code %d", ret);
        } else {
            int i;
            unsigned char* enc = ctx->plaintext;

            /* Copy out the encrypted data into various locations. */
            for (i = 0; i < ctx->enc_cnt; i++) {
                XMEMCPY(ctx->enc_data[i].data, enc, ctx->enc_data[i].size);
                enc += ctx->enc_data[i].size;
            }
            /* Done with encryption locations. */
            ctx->enc_cnt = 0;

            /* Authentication data used - reset count. */
            ctx->auth_data_size = 0;
            /* Dispose of cached plaintext. */
            gnutls_free(ctx->plaintext);
            ctx->plaintext = NULL;
            ctx->plaintext_size = 0;

            /* Have a tag and copy it out. */
            ctx->tag_set = 1;
            XMEMCPY(tag, ctx->tag, tag_size);
            WGW_LOG("tag stored successfully");
        }
    /* Decrypting and we need to set tag for decrypt operation. */
    } else {
        XMEMCPY(ctx->tag, tag, tag_size);
        ctx->tag_set = 1;
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
        WGW_LOG("aead encrypt failed - context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check encrypted data is big enough for ciphertext and tag. */
    if (encr_size < plain_size + tag_size) {
        WGW_LOG("encrypted size too small: %d < %d + %d", encr_size, plain_size,
            tag_size);
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    ctx->enc = 1;

    /* Set the IV/nonce. */
    ret = wolfssl_cipher_setiv(_ctx, nonce, nonce_size);
    if (ret != 0) {
        return ret;
    }
    /* Set the authentication data. */
    ret = wolfssl_cipher_auth(_ctx, auth, auth_size);
    if (ret != 0) {
        return ret;
    }
    /* Encrypt plain text. */
    ret = wolfssl_cipher_encrypt(_ctx, plain, plain_size, encr, encr_size);
    if (ret != 0) {
        return ret;
    }
    /* Put tag after the encrypted data. */
    wolfssl_cipher_tag(_ctx, encr + plain_size, tag_size);

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
        WGW_LOG("aead decrypt failed - context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (encr_size < tag_size) {
        WGW_LOG("encrypted size too small: %d < %d ", encr_size, tag_size);
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    ctx->enc = 0;

    /* Encrypted size includes tag. */
    encr_size -= tag_size;

    /* Set the IV/nonce. */
    ret = wolfssl_cipher_setiv(_ctx, nonce, nonce_size);
    if (ret != 0) {
        return ret;
    }
    /* Set the authentication data. */
    ret = wolfssl_cipher_auth(_ctx, auth, auth_size);
    if (ret != 0) {
        return ret;
    }
    /* Set the tag for decrypt to use. */
    wolfssl_cipher_tag(_ctx, ((byte*)encr) + encr_size, tag_size);
    /* Decrypt ciphertext. */
    return wolfssl_cipher_decrypt(_ctx, encr, encr_size, plain, plain_size);
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
        gnutls_free(ctx->plaintext);
        /* free the wolfSSL AES contexts */
        wc_AesFree(&ctx->enc_aes_ctx);
        wc_AesFree(&ctx->dec_aes_ctx);
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

/** Function pointers for the wolfSSL implementation of GCM ciphers. */
static const gnutls_crypto_cipher_st wolfssl_cipher_gcm_struct = {
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
                GNUTLS_CIPHER_AES_128_GCM, 80, &wolfssl_cipher_gcm_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-128-GCM failed");
            return ret;
        }
    }

    /* Register AES-192-GCM */
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_192_GCM]) {
        WGW_LOG("registering AES-192-GCM");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_192_GCM, 80, &wolfssl_cipher_gcm_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-192-GCM failed");
            return ret;
        }
    }

    /* Register AES-256-GCM*/
    if (wolfssl_cipher_supported[GNUTLS_CIPHER_AES_256_GCM]) {
        WGW_LOG("registering AES-256-GCM");
        ret = gnutls_crypto_single_cipher_register(
                GNUTLS_CIPHER_AES_256_GCM, 80, &wolfssl_cipher_gcm_struct, 0);
        if (ret < 0) {
            WGW_LOG("registering AES-256-GCM failed");
            return ret;
        }
    }

    return ret;
}

/*************************** MAC algorithms (HMAC) ***************************/

/** Context for wolfssl HMAC. */
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
    if (algorithm >= 0 && algorithm < WOLFSSL_MAC_SUPPORTED_LEN &&
            wolfssl_mac_supported[algorithm]) {
        return 1;
    }

    WGW_LOG("mac algorithm %d is not supported", algorithm);
    return 0;
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

    /* check if mac is supported */
    if (!is_mac_supported(algorithm)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hmac_ctx));
    if (ctx == NULL) {
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize wolfSSL HMAC context */
    ret = wc_HmacInit(&ctx->hmac_ctx, NULL, INVALID_DEVID);
    if (ret != 0) {
        WGW_LOG("wc_HmacInit has failed with code %d", ret);
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* get wolfssl hash type */
    hash_type = get_hash_type(ctx->algorithm);
    if (hash_type < 0) {
        WGW_LOG("HMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* set the key */
    ret = wc_HmacSetKey(&ctx->hmac_ctx, hash_type, (const byte*)key,
        (word32)keysize);
    if (ret != 0) {
        WGW_LOG("wc_HmacSetKey failed with code %d", ret);
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
 * @return  GNUTLS_E_HASH_FAILED when wolfssl HMAC update fails.
 */
static int wolfssl_hmac_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_hmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", textsize);

    if (!ctx->initialized) {
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Can only do 32-bit sized updates at a time. */
    do {
        /* Use a max that is a multiple of the maximum block size. */
        word32 size = 0xffffffc0;
        if (textsize < (size_t)size) {
            size = textsize;
        }

        /* update the hmac */
        ret = wc_HmacUpdate(&ctx->hmac_ctx, (const byte*)text, size);
        if (ret != 0) {
            WGW_LOG("wc_HmacUpdate failed with code %d", ret);
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* get the digest size based on the hash algorithm */
    digest_size = wc_HmacSizeByType(get_hash_type(ctx->algorithm));
    if (digest_size <= 0) {
        WGW_LOG("HMAC not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* make sure the output buffer is large enough */
    if (digestsize < (size_t)digest_size) {
        WGW_LOG("digestsize too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* finalize the hmac and get the result */
    ret = wc_HmacFinal(&ctx->hmac_ctx, (byte*)digest);
    if (ret != 0) {
        WGW_LOG("wc_HmacFinal failed with code %d", ret);
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

    WGW_LOG("wolfssl_hmac_deinit");

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
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL  operation fails.
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

    /* Output the MAC. */
    ret = wolfssl_hmac_output(ctx, digest, WC_SHA512_DIGEST_SIZE);
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
    if (algorithm == GNUTLS_MAC_AES_CMAC_128 ||
            algorithm == GNUTLS_MAC_AES_CMAC_256) {
        return 1;
    }

    WGW_LOG("mac algorithm %d is not CMAC", algorithm);
    return 0;
}

/** Context for wolfssl CMAC. */
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
    }
    else if (algorithm == GNUTLS_MAC_AES_CMAC_256) {
        return AES_256_KEY_SIZE;
    }
    else {
         WGW_LOG("Unsupported algorithm: %d\n", algorithm);
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

    /* check if mac is supported */
    if (!is_mac_supported(algorithm)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if mac is CMAC. */
    if (!is_mac_cmac(algorithm)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_cmac_ctx));
    if (ctx == NULL) {
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ctx->initialized = 1;
    ctx->algorithm = algorithm;
    *_ctx = ctx;

    WGW_LOG("cmac context initialized successfully");
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check key size. */
    if (keysize != cmac_alg_key_size(ctx->algorithm)) {
        WGW_LOG("CMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Initialize and set the key */
    ret = wc_InitCmac(&ctx->cmac_ctx, (const byte*)key, (word32)keysize,
        WC_CMAC_AES, NULL);
    if (ret != 0) {
        WGW_LOG("wc_InitCmac has failed with code %d", ret);
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
 * @return  GNUTLS_E_HASH_FAILED when wolfssl CMAC update fails.
 */
static int wolfssl_cmac_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_cmac_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", textsize);

    if (!ctx->initialized) {
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Can only do 32-bit sized updates at a time. */
    do {
        /* Use a max that is a multiple of the block size. */
        word32 size = 0xfffffff0;
        if (textsize < (size_t)size) {
            size = textsize;
        }

        /* update the cmac */
        ret = wc_CmacUpdate(&ctx->cmac_ctx, (const byte*)text, size);
        if (ret != 0) {
            WGW_LOG("wc_CmacUpdate failed with code %d", ret);
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* make sure the output buffer is large enough */
    if (digestsize < WC_CMAC_TAG_MIN_SZ) {
        WGW_LOG("digestsize too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    /* finalize the cmac and get the result */
    ret = wc_CmacFinal(&ctx->cmac_ctx, (byte*)digest, &digest_size);
    if (ret != 0) {
        WGW_LOG("wc_HmacFinal failed with code %d", ret);
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
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL  operation fails.
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
    if (algorithm == GNUTLS_MAC_AES_GMAC_128 ||
            algorithm == GNUTLS_MAC_AES_GMAC_192  ||
            algorithm == GNUTLS_MAC_AES_GMAC_256) {
        return 1;
    }

    WGW_LOG("mac algorithm %d is not GMAC", algorithm);
    return 0;
}

/** Context for wolfssl GMAC. */
struct wolfssl_gmac_ctx {
    /** wolfSSL GMAC object. */
    Gmac gmac_ctx;
    /** Indicates that this context as been initialized. */
    int initialized;
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
    }
    else if (algorithm == GNUTLS_MAC_AES_GMAC_192) {
        return AES_192_KEY_SIZE;
    }
    else if (algorithm == GNUTLS_MAC_AES_GMAC_256) {
        return AES_256_KEY_SIZE;
    }
    else {
         WGW_LOG("Unsupported algorithm: %d\n", algorithm);
         return (size_t)-1;
    }
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

    /* check if mac is supported */
    if (!is_mac_supported(algorithm)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if mac is GMAC. */
    if (!is_mac_gmac(algorithm)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_gmac_ctx));
    if (ctx == NULL) {
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* initialize wolfSSL GMAC context */
    ret = wc_AesInit(&ctx->gmac_ctx.aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        WGW_LOG("wc_AesInit has failed with code %d", ret);
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check the key size is valid for algorithm. */
    if (keysize != gmac_alg_key_size(ctx->algorithm)) {
        WGW_LOG("GMAC algorithm not supported");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Initialize and set the key */
    ret = wc_GmacSetKey(&ctx->gmac_ctx, (const byte*)key, (word32)keysize);
    if (ret != 0) {
        WGW_LOG("wc_InitCmac has failed with code %d", ret);
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (nonce_size < GCM_NONCE_MIN_SZ || nonce_size > GCM_NONCE_MAX_SZ) {
        WGW_LOG("Nonce size not supported: %d", nonce_size);
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
 * @return  GNUTLS_E_HASH_FAILED when wolfssl GMAC update fails.
 */
static int wolfssl_gmac_hash(void *_ctx, const void *text, size_t textsize)
{
    struct wolfssl_gmac_ctx *ctx = _ctx;
    unsigned char* ptr;

    WGW_FUNC_ENTER();
    WGW_LOG("data size %zu", textsize);

    if (!ctx->initialized) {
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ptr = gnutls_realloc(ctx->data, ctx->data_size + textsize);
    if (ptr == NULL) {
        WGW_LOG("realloc of gmac data failed");
        return GNUTLS_E_HASH_FAILED;
    }

    ctx->data = ptr;
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
        WGW_LOG("MAC context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* make sure the output buffer is large enough */
    if (digestsize < AES_BLOCK_SIZE) {
        WGW_LOG("digestsize too small");
        return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

    ret = wc_GmacUpdate(&ctx->gmac_ctx, ctx->nonce, ctx->nonce_size, ctx->data,
        ctx->data_size, digest, digestsize);
    gnutls_free(ctx->data);
    ctx->data = NULL;
    if (ret != 0) {
        WGW_LOG("wc_GmacUpdate has failed with code %d", ret);
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
        /* free the wolfSSL GMAC context */
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
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL  operation fails.
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
    #if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
        wc_Shake  shake;
    #endif
    } obj;
    /** The GnuTLS digest algorithm ID. */
    gnutls_digest_algorithm_t algorithm;
    /** Indicates that this context as been initialized. */
    int initialized;
#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
    int squeezing;
#endif
};

/** Array of supported ciphers. */
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
#ifdef WOLFSSL_SHAKE128
    [GNUTLS_DIG_SHAKE_128] = 1,
#endif
#ifdef WOLFSSL_SHAKE256
    [GNUTLS_DIG_SHAKE_256] = 1,
#endif
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
    if (algorithm >= 0 && algorithm < WOLFSSL_DIGEST_SUPPORTED_LEN &&
            wolfssl_digest_supported[algorithm] == 1) {
        return 1;
    }

    WGW_LOG("digest %d is not supported", algorithm);
    return 0;
}

/**
 * Initialize the wolfssl digest.
 *
 * @param [in, out] ctx  Hash context.
 * @return  0 on success.
 * @return  Other value on failure.
 */
static int wolfssl_digest_init_alg(struct wolfssl_hash_ctx *ctx)
{
    int ret = -1;
    gnutls_digest_algorithm_t algorithm = ctx->algorithm;

    /* initialize the wolfssl digest object */
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
#ifdef WOLFSSL_SHAKE128
    } else if (algorithm == GNUTLS_DIG_SHAKE_128) {
        ret = wc_InitShake128(&ctx->obj.shake, NULL, INVALID_DEVID);
#endif
#ifdef WOLFSSL_SHAKE256
    } else if (algorithm == GNUTLS_DIG_SHAKE_256) {
        ret = wc_InitShake256(&ctx->obj.shake, NULL, INVALID_DEVID);
#endif
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

    /* return error if digest's not supported */
    if (!is_digest_supported(algorithm)) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* allocate gnutls context */
    ctx = gnutls_calloc(1, sizeof(struct wolfssl_hash_ctx));
    if (ctx == NULL) {
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    ctx->algorithm = algorithm;

    /* Initialize digest. */
    ret = wolfssl_digest_init_alg(ctx);
    if (ret != 0) {
        WGW_LOG("Initialization of wolfSSL object failed: %d", ret);
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
        WGW_LOG("Digest context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
    if (ctx->squeezing) {
        WGW_LOG("SHAKE is already aqueezing");
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

        /* update the wolfssl digest object with data */
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
    #ifdef WOLFSSL_SHAKE128
        } else if (ctx->algorithm == GNUTLS_DIG_SHAKE_128) {
            ret = wc_Shake128_Update(&ctx->obj.shake, (const byte*)text, size);
    #endif
    #ifdef WOLFSSL_SHAKE256
        } else if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
            ret = wc_Shake256_Update(&ctx->obj.shake, (const byte*)text, size);
    #endif
        }
        if (ret != 0) {
            WGW_LOG("wolfSSL update failed: %d", ret);
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
        WGW_LOG("Digest context not initialized");
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

    /* finalize the digest and get the result */
    if (ctx->algorithm == GNUTLS_DIG_MD5) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_MD5_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for MD5 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Md5Final(&ctx->obj.md5, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA1) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA-1 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_ShaFinal(&ctx->obj.sha, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA224) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA224_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA-224 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha224Final(&ctx->obj.sha224, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA256) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA256_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA-256 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha256Final(&ctx->obj.sha256, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA384) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA384_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA-384 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha384Final(&ctx->obj.sha384, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA512) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA512_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA-512 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha512Final(&ctx->obj.sha512, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_224) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA3_224_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA3-224 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_224_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_256) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA3_256_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA3-256 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_256_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_384) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA3_384_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA3-384 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_384_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_512) {
        /* make sure the output buffer is large enough */
        if (digestsize < WC_SHA3_512_DIGEST_SIZE) {
            WGW_LOG("digestsize too small for SHA3-512 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_512_Final(&ctx->obj.sha3, (byte*)digest);
#ifdef WOLFSSL_SHAKE128
    } else if (ctx->algorithm == GNUTLS_DIG_SHAKE_128) {
        ret = wc_Shake128_Final(&ctx->obj.shake, (byte*)digest, digestsize);
        /* When squeezing, can no longer add data. */
        ctx->squeezing = 1;
#endif
#ifdef WOLFSSL_SHAKE256
    } else if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
        ret = wc_Shake256_Final(&ctx->obj.sha3, (byte*)digest, digestsize);
        /* When squeezing, can no longer add data. */
        ctx->squeezing = 1;
#endif
    }
    if (ret != 0) {
        WGW_LOG("wolfSSL final operation failed with code %d", ret);
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
        /* free the wolfssl digest object */
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
    #ifdef WOLFSSL_SHAKE128
        } else if (ctx->algorithm == GNUTLS_DIG_SHAKE_128) {
            wc_Shake128_Free(&ctx->obj.shake);
    #endif
    #ifdef WOLFSSL_SHAKE256
        } else if (ctx->algorithm == GNUTLS_DIG_SHAKE_256) {
            wc_Shake256_Free(&ctx->obj.shake);
    #endif
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
 * @return  GNUTLS_E_HASH_FAILED when wolfSSL  operation fails.
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
                GNUTLS_DIG_SHAKE_128, 80, &wolfssl_digest_struct, 0);
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
                GNUTLS_DIG_SHAKE_256, 80, &wolfssl_digest_struct, 0);
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
    } key;
    int initialized;
    /** The GnuTLS public key algorithm ID.  */
    gnutls_pk_algorithm_t algo;
    WC_RNG rng;
    int rng_initialized;

    byte pub_data[128];
    word32 pub_data_len;
};

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
    if (algo == GNUTLS_PK_ECDSA) {
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
            case 256: /* SECP256R1 */
                curve_id = ECC_SECP256R1;
                break;
            case 384: /* SECP384R1 */
                curve_id = ECC_SECP384R1;
                break;
            case 521: /* SECP521R1 */
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

    } else {
        WGW_LOG("unsupported algorithm: %d", algo);
        wc_FreeRng(&ctx->rng);
        gnutls_free(ctx);
        return GNUTLS_E_INVALID_REQUEST;
    }

    ctx->initialized = 1;
    WGW_LOG("pk generated successfully");

    *_ctx = ctx;
    return 0;
}

/* export pub from the key pair */
static int wolfssl_pk_export_pub(void *_ctx, const void *pubkey)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();

    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check if pubkey parameter is provided */
    if (!pubkey) {
        WGW_LOG("pubkey parameter is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    gnutls_datum_t *pub = (gnutls_datum_t *)pubkey;

    if (ctx->algo == GNUTLS_PK_ECDSA) {
        word32 x_len = sizeof(ctx->pub_data);
        word32 y_len = sizeof(ctx->pub_data);
        byte *x = ctx->pub_data;
        byte *y = ctx->pub_data + x_len;

        /* Export ECDSA public key coordinates */
        ret = wc_ecc_export_public_raw(&ctx->key.ecc, x, &x_len, y, &y_len);
        if (ret != 0) {
            WGW_LOG("public key export failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Construct X963 format: 0x04 | X | Y */
        pub->data = gnutls_malloc(1 + x_len + y_len);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        pub->data[0] = 0x04; /* Uncompressed point format */
        XMEMCPY(pub->data + 1, x, x_len);
        XMEMCPY(pub->data + 1 + x_len, y, y_len);
        pub->size = 1 + x_len + y_len;

    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        word32 pub_size = ED25519_PUB_KEY_SIZE;

        /* Export Ed25519 public key */
        ret = wc_ed25519_export_public(&ctx->key.ed25519, ctx->pub_data, &pub_size);
        if (ret != 0) {
            WGW_LOG("Ed25519 public key export failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Allocate and copy public key */
        pub->data = gnutls_malloc(pub_size);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, ctx->pub_data, pub_size);
        pub->size = pub_size;

    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        word32 pub_size = ED448_PUB_KEY_SIZE;

        /* Export Ed448 public key */
        ret = wc_ed448_export_public(&ctx->key.ed448, ctx->pub_data, &pub_size);
        if (ret != 0) {
            WGW_LOG("Ed448 public key export failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        /* Allocate and copy public key */
        pub->data = gnutls_malloc(pub_size);
        if (!pub->data) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        XMEMCPY(pub->data, ctx->pub_data, pub_size);
        pub->size = pub_size;

    } else {
        WGW_LOG("unsupported algorithm for exporting public key: %d", ctx->algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    WGW_LOG("public key exported successfully");
    return 0;
}

/* sign message */
static int wolfssl_pk_sign(void *_ctx, const void *privkey,
    gnutls_digest_algorithm_t hash, const void *data, const void *signature)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;

    WGW_FUNC_ENTER();
    WGW_LOG("hash %d", hash);

    (void)privkey;

    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    const gnutls_datum_t *msg_data = (const gnutls_datum_t *)data;
    gnutls_datum_t *sig = (gnutls_datum_t *)signature;

    if (!msg_data || !msg_data->data || msg_data->size == 0 || !sig) {
        WGW_LOG("Bad message data or signature");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (ctx->algo == GNUTLS_PK_ECDSA) {
        WGW_LOG("signing with ECDSA");
        /* Allocate buffer for ECDSA signature */
        word32 sig_size = wc_ecc_sig_size(&ctx->key.ecc);
        byte *sig_buf = gnutls_malloc(sig_size);

        if (!sig_buf) {
            WGW_LOG("Memory allocation failed");
            return GNUTLS_E_MEMORY_ERROR;
        }

        /* Sign the hash with ECDSA */
        ret = wc_ecc_sign_hash(msg_data->data, msg_data->size,
                sig_buf, &sig_size, &ctx->rng, &ctx->key.ecc);

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

        XMEMCPY(sig->data, sig_buf, sig_size);
        sig->size = sig_size;
        gnutls_free(sig_buf);

    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED25519) {
        WGW_LOG("signing with EDDSA ed25519");
        /* Allocate buffer for Ed25519 signature */
        word32 sig_size = ED25519_SIG_SIZE;
        byte sig_buf[ED25519_SIG_SIZE];

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
    } else if (ctx->algo == GNUTLS_PK_EDDSA_ED448) {
        WGW_LOG("signing with EDDSA ed448");
        /* Allocate buffer for Ed448 signature */
        word32 sig_size = ED448_SIG_SIZE;
        byte sig_buf[ED448_SIG_SIZE];

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
    } else {
        WGW_LOG("unsupported algorithm for signing: %d", ctx->algo);
        return GNUTLS_E_INVALID_REQUEST;
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
    int verify_result = 0;

    WGW_FUNC_ENTER();

    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    const gnutls_datum_t *msg_data = (const gnutls_datum_t *)data;
    const gnutls_datum_t *sig = (const gnutls_datum_t *)signature;

    if (!msg_data || !msg_data->data || msg_data->size == 0 ||
            !sig || !sig->data || sig->size == 0) {
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (algo == GNUTLS_SIGN_ECDSA_SHA256) {
        /* Verify ECDSA signature */
        ret = wc_ecc_verify_hash(sig->data, sig->size,
                msg_data->data, msg_data->size,
                &verify_result, &ctx->key.ecc);

        if (ret != 0) {
            WGW_LOG("ECDSA verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_result != 1) {
            WGW_LOG("ECDSA signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    } else if (algo == GNUTLS_SIGN_EDDSA_ED25519) {
        int verify_status = 0;

        if (pubkey) {
            /* Use the provided public key */
            const gnutls_datum_t *pub = (const gnutls_datum_t *)pubkey;
            ed25519_key verify_key;

            ret = wc_ed25519_init(&verify_key);
            if (ret != 0) {
                WGW_LOG("Ed25519 key init failed with code %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }

            ret = wc_ed25519_import_public(pub->data, pub->size, &verify_key);
            if (ret != 0) {
                WGW_LOG("Ed25519 public key import failed with code %d", ret);
                wc_ed25519_free(&verify_key);
                return GNUTLS_E_INVALID_REQUEST;
            }

            /* Verify using imported key */
            ret = wc_ed25519_verify_msg(sig->data, sig->size,
                    msg_data->data, msg_data->size,
                    &verify_status, &verify_key);

            wc_ed25519_free(&verify_key);
        } else {
            /* Use the context's key */
            ret = wc_ed25519_verify_msg(sig->data, sig->size,
                    msg_data->data, msg_data->size,
                    &verify_status, &ctx->key.ed25519);
        }

        if (ret != 0) {
            WGW_LOG("Ed25519 verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_status != 1) {
            WGW_LOG("Ed25519 signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

    } else if (algo == GNUTLS_SIGN_EDDSA_ED448) {
        int verify_status = 0;

        if (pubkey) {
            /* Use the provided public key */
            const gnutls_datum_t *pub = (const gnutls_datum_t *)pubkey;
            ed448_key verify_key;

            ret = wc_ed448_init(&verify_key);
            if (ret != 0) {
                WGW_LOG("Ed448 key init failed with code %d", ret);
                return GNUTLS_E_INVALID_REQUEST;
            }

            ret = wc_ed448_import_public(pub->data, pub->size, &verify_key);
            if (ret != 0) {
                WGW_LOG("Ed448 public key import failed with code %d", ret);
                wc_ed448_free(&verify_key);
                return GNUTLS_E_INVALID_REQUEST;
            }

            /* Verify using imported key */
            ret = wc_ed448_verify_msg(sig->data, sig->size,
                    msg_data->data, msg_data->size,
                    &verify_status, &verify_key, NULL, 0);

            wc_ed448_free(&verify_key);
        } else {
            /* Use the context's key */
            ret = wc_ed448_verify_msg(sig->data, sig->size,
                    msg_data->data, msg_data->size,
                    &verify_status, &ctx->key.ed448, NULL, 0);
        }

        if (ret != 0) {
            WGW_LOG("Ed448 verification failed with code %d", ret);
            return GNUTLS_E_INVALID_REQUEST;
        }

        if (verify_status != 1) {
            WGW_LOG("Ed448 signature verification failed");
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }
    } else {
        WGW_LOG("unsupported algorithm for verification: %d", algo);
        return GNUTLS_E_INVALID_REQUEST;
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
static int wolfssl_pk_derive_shared_secret(void *_ctx, const void *privkey,
    const void *pubkey, const gnutls_datum_t *nonce, gnutls_datum_t *secret)
{
    struct wolfssl_pk_ctx *ctx = _ctx;
    int ret;
    ecc_key peer_key;

    WGW_FUNC_ENTER();

    (void)nonce;
    (void)privkey;

    /* Parameters sanity checks */
    if (!ctx || !ctx->initialized) {
        WGW_LOG("PK context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    if (!pubkey || !secret) {
        WGW_LOG("missing required parameters");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* We only support ECDSA for now */
    if (ctx->algo != GNUTLS_PK_ECDSA) {
        WGW_LOG("PK algorithm not supported: %d", ctx->algo);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Cast pubkey to the expected type */
    const gnutls_datum_t *pub = (const gnutls_datum_t *)pubkey;
    if (!pub->data || pub->size == 0) {
        WGW_LOG("invalid public key data");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Initialize the peer's public key */
    ret = wc_ecc_init(&peer_key);
    if (ret != 0) {
        WGW_LOG("wc_ecc_init failed with code %d", ret);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Import the peer's public key from X963 format (0x04 | X | Y) */
    ret = wc_ecc_import_x963(pub->data, pub->size, &peer_key);
    if (ret != 0) {
        WGW_LOG("public key import failed with code %d", ret);
        wc_ecc_free(&peer_key);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Determine how much space we need for the shared secret */
    word32 secret_size = wc_ecc_size(&ctx->key.ecc);
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

    ctx->key.ecc.rng = &ctx->rng;

    /* Generate the shared secret */
    ret = wc_ecc_shared_secret(&ctx->key.ecc, &peer_key, shared_secret, &secret_size);
    if (ret != 0) {
        WGW_LOG("shared secret generation failed with code %d", ret);
        gnutls_free(shared_secret);
        wc_ecc_free(&peer_key);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Free the peer's public key as we don't need it anymore */
    wc_ecc_free(&peer_key);

    /* Allocate gnutls_datum for the result */
    secret->data = shared_secret;
    secret->size = secret_size;

    WGW_LOG("shared secret derived successfully (size: %d bytes)", secret_size);
    return 0;
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
    .derive_shared_secret_backend = wolfssl_pk_derive_shared_secret,
    .deinit_backend = wolfssl_pk_deinit,
};

/* mapping of gnutls pk algorithms to wolfssl pk */
static const int wolfssl_pk_supported[] = {
        [GNUTLS_PK_ECDSA] = 1,
        [GNUTLS_PK_EDDSA_ED25519] = 1,
        [GNUTLS_PK_EDDSA_ED448] = 1,
};

/* register the pk algorithm with GnuTLS */
static int wolfssl_pk_register(void)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    /* Register ECDSA */
    if (wolfssl_pk_supported[GNUTLS_PK_ECDSA]) {
        WGW_LOG("registering ECDSA-ALL-CURVES");
        ret = gnutls_crypto_single_pk_register(
                GNUTLS_PK_ECDSA, 80, &wolfssl_pk_struct, 0);
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

    return ret;
}

/***************************** RNG functions **********************************/

/** Context structure for wolfssl RNG. */
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
        WGW_LOG("Memory allocation failed");
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Initialize private random. */
    ret = wc_InitRng(&ctx->priv_rng);
    if (ret != 0) {
        WGW_LOG("wolfSSL initialize of private random failed: %d", ret);
        gnutls_free(ctx);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Initialize public random. */
    ret = wc_InitRng(&ctx->pub_rng);
    if (ret != 0) {
        WGW_LOG("wolfSSL initialize of public random failed: %d", ret);
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

    WGW_FUNC_ENTER();

    if (!ctx || !ctx->initialized) {
        WGW_LOG("random context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Get the random corresponding the level requested. */
    if (level == GNUTLS_RND_RANDOM || level == GNUTLS_RND_KEY) {
        WGW_LOG("using private random");
        rng = &ctx->priv_rng;
    } else if (level == GNUTLS_RND_NONCE) {
        WGW_LOG("using public random");
        rng = &ctx->pub_rng;
    } else {
        WGW_LOG("level not supported: %d", level);
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
            WGW_LOG("wolfSSL initialize of private random failed: %d", ret);
            gnutls_free(ctx);
            return GNUTLS_E_RANDOM_FAILED;
        }
    }

    /* Generate up to a block at a time. */
    do {
        size_t size = MIN(RNG_MAX_BLOCK_LEN, datasize);

        ret = wc_RNG_GenerateBlock(rng, data, size);
        if (ret != 0) {
            WGW_LOG("Requested %d bytes", size);
            WGW_LOG("wolfSSL generation of of random failed: %d", ret);
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
            /* Set context initialized to 0 to indicate it isn't avaialble. */
            ctx->initialized = 0;
        }

        /* Initialize public wolfSSL random for use again. */
        ret = wc_InitRng(&ctx->pub_rng);
        if (ret != 0) {
            WGW_LOG("wolfSSL initialize of public random failed: %d", ret);
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

/***************************** PRF functions **********************************/

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
                WGW_LOG("TLS MD5/SHA-1 PRF failed: %d", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        case GNUTLS_MAC_SHA256:
            ret = wc_PRF_TLS((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, 1, sha256_mac, NULL,
                INVALID_DEVID);
            if (ret != 0) {
                WGW_LOG("TLS SHA-256 PRF failed: %d", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        case GNUTLS_MAC_SHA384:
            ret = wc_PRF_TLS((byte*)out, outsize, master, master_size,
                (byte*)label, label_size, seed, seed_size, 1, sha384_mac, NULL,
                INVALID_DEVID);
            if (ret != 0) {
                WGW_LOG("TLS SHA-384 PRF failed: %d", ret);
                return GNUTLS_E_INTERNAL_ERROR;
            }
            break;
        default:
            WGW_LOG("prf mac %d is not supported", mac);
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

/* TODO: TLS 1.3 PRF */

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
