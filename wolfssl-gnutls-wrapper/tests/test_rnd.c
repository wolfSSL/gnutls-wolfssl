
#include <gnutls/crypto.h>

#include "test_util.h"

static int test_rnd_level(gnutls_rnd_level_t level)
{
    int ret;
    unsigned char buf[1024];
    int i;

    for (i = 0; i < 0x8000; i++) {
        ret = gnutls_rnd(level, buf, sizeof(buf));
        if (ret != 0) {
            print_gnutls_error("getting random", ret);
            return 1;
        }
    }

    return 0;
}

static int test_rnd()
{
    int ret;

    ret = test_rnd_level(GNUTLS_RND_NONCE);
    if (ret == 0) {
        ret = test_rnd_level(GNUTLS_RND_RANDOM);
    }
    if (ret == 0) {
        ret = test_rnd_level(GNUTLS_RND_KEY);
    }

    return ret;
}

static int test_rnd_large(void)
{
    int ret;
    unsigned char* buf;
    size_t buf_sz = 0x20000l;

    buf = gnutls_calloc(1, buf_sz);
    if (buf == NULL) {
        printf("FAILURE - Could not allocate memory\n");
        return 1;
    }

    ret = gnutls_rnd(GNUTLS_RND_RANDOM, buf, buf_sz);
    if (ret != 0) {
        print_gnutls_error("getting large random", ret);
        return 1;
    }

    gnutls_free(buf);

    return 0;
}

int main(void)
{
    int ret;

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_rnd();
    if (ret == 0) {
        gnutls_rnd_refresh();
        ret = test_rnd();
    }
    if (ret == 0) {
        ret = test_rnd_large();
    }
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}

