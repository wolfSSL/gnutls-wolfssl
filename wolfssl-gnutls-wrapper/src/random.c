#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "logging.h"
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifdef ENABLE_WOLFSSL
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
    /* Set the seed callback to get entropy. */
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

#endif
