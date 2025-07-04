#include <stdio.h>
#include <stdarg.h>

#ifdef ENABLE_WOLFSSL
/** Whether logging output will be written. */
int loggingEnabled = 0;

/** File descriptor to log to. Set in _gnutls_wolfssl_init. */
FILE* loggingFd = NULL;

/**
 * Log a message.
 *
 * @param [in] line  Line number of log message.
 * @param [in] fmt   Format of string to print.
 */
void wgw_log(int line, const char* fmt, ...)
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
#endif
