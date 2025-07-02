/* Integration of wolfssl crypto with GnuTLS */
#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "wolfssl.h"
#include "logging.h"
#include "cipher.h"
#include "mac.h"
#include "digest.h"
#include "pk.h"

#include <wolfssl/wolfcrypt/fips_test.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_DH_BITS       4096
#define MAX_DH_Q_SIZE     256

/*
 * TODO
 *   o Consider making bigint_t implementation use mp_int.
 */

/**
 * Constructor for shared library.
 *
 * Initializes the library.
 */
void __attribute__((constructor)) wolfssl_init(void) {
    _gnutls_wolfssl_init();
}

#ifdef ENABLE_WOLFSSL
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
