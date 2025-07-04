#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "logging.h"
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef ENABLE_WOLFSSL
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
        WGW_LOG("Outputting Md5");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_MD5_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for MD5 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Md5Final(&ctx->obj.md5, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA1) {
        WGW_LOG("Outputting Sha1");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-1 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_ShaFinal(&ctx->obj.sha, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA224) {
        WGW_LOG("Outputting Sha224");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA224_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-224 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha224Final(&ctx->obj.sha224, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA256) {
        WGW_LOG("Outputting Sha256");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA256_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-256 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha256Final(&ctx->obj.sha256, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA384) {
        WGW_LOG("Outputting Sha384");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA384_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-384 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha384Final(&ctx->obj.sha384, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA512) {
        WGW_LOG("Outputting Sha512");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA512_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA-512 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha512Final(&ctx->obj.sha512, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_224) {
        WGW_LOG("Outputting Sha3 224");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_224_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-224 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_224_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_256) {
        WGW_LOG("Outputting Sha3 256");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_256_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-256 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_256_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_384) {
        WGW_LOG("Outputting Sha3 384");
        /* Make sure the output buffer is large enough. */
        if (digestsize < WC_SHA3_384_DIGEST_SIZE) {
            WGW_ERROR("digestsize too small for SHA3-384 output");
            return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }
        ret = wc_Sha3_384_Final(&ctx->obj.sha3, (byte*)digest);
    } else if (ctx->algorithm == GNUTLS_DIG_SHA3_512) {
        WGW_LOG("Outputting Sha3 512");
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
int wolfssl_digest_fast(gnutls_digest_algorithm_t algorithm,
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
int wolfssl_digest_register(void)
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

#endif
