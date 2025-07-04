#include <stdio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
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
#endif

extern int  loggingEnabled;
extern FILE *loggingFd;

void wgw_log(int line, const char* fmt, ...);
