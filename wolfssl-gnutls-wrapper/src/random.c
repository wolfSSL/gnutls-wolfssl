#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "logging.h"
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <pthread.h>

#ifdef ENABLE_WOLFSSL
/** Context structure for wolfSSL RNG. */
struct wolfssl_rng_ctx {
    /** Indicates that this context as been initialized. */
    int initialized;
};

/* global objects shared by the whole process */
/** wolfSSL RNG object for private data. */
WC_RNG priv_rng;
/** wolfSSL RNG object for public data. */
WC_RNG pub_rng;
/** Process id to detect forking.
 * Also indicates the current process that owns the above RNGs objects. */
pid_t pid = -1;
/** Indicates if the DBRG needs to be reseeded.*/
int rng_ready = 0;

/** Serializes all use of the RNG objects above. A WC_RNG is not thread safe
 * unless wolfSSL locks it itself (5.9.4 and later, unless built with
 * --disable-rng-autolock). */
static wolfSSL_Mutex wc_rng_lock;
/** Initializes wc_rng_lock exactly once, whichever thread gets there first. */
static pthread_once_t wc_rng_lock_once = PTHREAD_ONCE_INIT;

static void wc_rng_lock_init(void)
{
    wc_InitMutex(&wc_rng_lock);
}

/**
 * Take the lock that guards priv_rng and pub_rng.
 *
 * Hold it across every wolfCrypt call that uses one of them, including calls
 * on a key that keeps a pointer to one (wc_RsaSetRNG(), ecc_key.rng,
 * wc_curve25519_set_rng()). Not recursive: do not call wolfssl_ensure_rng()
 * while holding it.
 */
void wolfssl_rng_lock(void)
{
    pthread_once(&wc_rng_lock_once, wc_rng_lock_init);
    wc_LockMutex(&wc_rng_lock);
}

/** Release the lock taken by wolfssl_rng_lock(). */
void wolfssl_rng_unlock(void)
{
    wc_UnLockMutex(&wc_rng_lock);
}

/* Seed DRBGs on first use or after a fork */
int wolfssl_ensure_rng(void)
{
    WGW_FUNC_ENTER();

    pid_t p = getpid();

    wolfssl_rng_lock();

    /* We check if the pid is different (a fork happened)
     * or if the the first time creating a context (a first seed is needed). */
    if (!rng_ready || p != pid) {

        if (rng_ready) {
            /* child after fork, we drop the old state and
             * do a reseed. */
            wc_FreeRng(&priv_rng);
            wc_FreeRng(&pub_rng);
            /* not ready until both are re-initialized: a failed reseed
             * must not leave freed DRBGs marked usable */
            rng_ready = 0;
        }

    #ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
    #endif

        if (wc_InitRng(&priv_rng) != 0) {
            wolfssl_rng_unlock();
            return GNUTLS_E_RANDOM_FAILED;
        }

        if (wc_InitRng(&pub_rng)  != 0) {
            wc_FreeRng(&priv_rng);
            wolfssl_rng_unlock();
            return GNUTLS_E_RANDOM_FAILED;
        }

        pid   = p;
        rng_ready = 1;
    }

    wolfssl_rng_unlock();

    return 0;
}

/**
 * Initialize random.
 *
 * @param [out]  _ctx  Random context.
 * @return  0 on success.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 */
static int wolfssl_rnd_init(void **_ctx)
{
    WGW_FUNC_ENTER();

    struct wolfssl_rng_ctx* ctx = gnutls_calloc(1, sizeof(*ctx));
    if (!ctx) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    ctx->initialized = 1;
    *_ctx = ctx;

    /* We check if we need to seed the context. */
    return wolfssl_ensure_rng();
}

/**
 * Generate random data using the shared DRBGs.
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
    struct wolfssl_rng_ctx* ctx = (struct wolfssl_rng_ctx *)_ctx;
    WC_RNG* rng = NULL;
    int ret;

    if (!ctx || !ctx->initialized) {
        WGW_ERROR("random context not initialized");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* make sure the process-wide DRBGs are ready (seed or reseed on fork) */
    ret = wolfssl_ensure_rng();
    if (ret != 0)
        return ret;

    if (level == GNUTLS_RND_RANDOM || level == GNUTLS_RND_KEY)
        rng = &priv_rng;          /* strong RNG */
    else if (level == GNUTLS_RND_NONCE)
        rng = &pub_rng;           /* nonce RNG  */
    else {
        WGW_ERROR("level not supported: %d", level);
        return GNUTLS_E_RANDOM_FAILED;
    }

    wolfssl_rng_lock();

    /* clear output buffer before filling */
    XMEMSET(data, 0, datasize);

    /* Generate up to a block at a time. */
    do {
        size_t size = MIN(RNG_MAX_BLOCK_LEN, datasize);

        ret = wc_RNG_GenerateBlock(rng, data, size);
        if (ret != 0) {
            wolfssl_rng_unlock();
            WGW_ERROR("Requested %d bytes", size);
            WGW_WOLFSSL_ERROR("wc_RNG_GenerateBlock", ret);
            return GNUTLS_E_RANDOM_FAILED;
        }

        /* Move over generated data. */
        data += size;
        datasize -= size;
    } while (datasize > 0);

    wolfssl_rng_unlock();

    return 0;
}

/**
 * Refresh the random number generators.
 *
 * @param [in, out] _ctx  Random context.
 */
static void wolfssl_rnd_refresh(void *_ctx)
{
    WGW_FUNC_ENTER();

    (void)_ctx;

    /* this forces a reseed of the random number generators
     * on the next call (wolfssl_ensure_rng). */
    wolfssl_rng_lock();
    rng_ready = 0;
    wolfssl_rng_unlock();
}

/**
 * Clean up random resources.
 *
 * @param [in, out]  _ctx  Random context.
 */
static void wolfssl_rnd_deinit(void *_ctx)
{
    WGW_FUNC_ENTER();

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
