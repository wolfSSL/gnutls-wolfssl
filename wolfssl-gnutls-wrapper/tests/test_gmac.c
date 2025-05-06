
#include <gnutls/crypto.h>

#include "test_util.h"


const unsigned char test_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
const unsigned char test_nonce[] = {
    0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
    0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
};
const char test_data[] = "Hi There";

const unsigned char expected_aes_gmac_128[] = {
    0x2c, 0xc1, 0xca, 0x2e, 0xd2, 0x0f, 0x4d, 0x3c,
    0x17, 0xe6, 0x1d, 0x74, 0x11, 0x72, 0x3c, 0x5c
};
const unsigned char expected_aes_gmac_192[] = {
    0xf0, 0xdc, 0xd7, 0x5b, 0x71, 0xda, 0xfc, 0xbd,
    0xda, 0xef, 0x51, 0x4e, 0xbc, 0x98, 0x24, 0xe9
};
const unsigned char expected_aes_gmac_256[] = {
    0xbb, 0xbd, 0x6f, 0x72, 0xa5, 0xa1, 0x70, 0x8e,
    0x2a, 0xec, 0x38, 0x1f, 0x11, 0xa2, 0x8b, 0x89
};


static int test_gmac(int algorithm, size_t key_sz,
    const unsigned char* expected, size_t sz)
{
    int ret;
    unsigned char output[64];
    gnutls_hmac_hd_t gmac;
    int i;

    printf("input data: \"%s\"\n", test_data);
    printf("key: [16/24/32 bytes of 0x0b]\n");
    printf("nonce: [16 bytes of 0x0f]\n");

    ret = gnutls_hmac_init(&gmac, algorithm, test_key, key_sz);
    if (ret != 0) {
        print_gnutls_error("initializing GMAC", ret);
        return 1;
    }
    gnutls_hmac_set_nonce(gmac, test_nonce, sizeof(test_nonce));

    ret = gnutls_hmac(gmac, test_data, strlen(test_data));
    if (ret != 0) {
        print_gnutls_error("updating GMAC", ret);
        gnutls_hmac_deinit(gmac, NULL);
        return 1;
    }

    gnutls_hmac_output(gmac, output);
    gnutls_hmac_deinit(gmac, NULL);

    if (compare("GMAC", output, expected, sz) != 0) {
        return 1;
    }

    memset(output, 0, sz);

    ret = gnutls_hmac_init(&gmac, algorithm, test_key, key_sz);
    if (ret != 0) {
        print_gnutls_error("initializing GMAC", ret);
        return 1;
    }
    gnutls_hmac_set_nonce(gmac, test_nonce, sizeof(test_nonce));

    for (i = 0; i < strlen(test_data); i++) {
        ret = gnutls_hmac(gmac, test_data + i, 1);
        if (ret != 0) {
            print_gnutls_error("updating GMAC", ret);
            gnutls_hmac_deinit(gmac, NULL);
            return 1;
        }
    }

    gnutls_hmac_output(gmac, output);
    gnutls_hmac_deinit(gmac, NULL);

    if (compare("GMAC", output, expected, sz) != 0) {
        return 1;
    }

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

    printf("testing wolfssl's AES-GMAC-128 implementation via gnutls...\n");
    ret = test_gmac(GNUTLS_MAC_AES_GMAC_128, 16, expected_aes_gmac_128,
        sizeof(expected_aes_gmac_128));
    if (ret == 0) {
        printf("testing wolfssl's AES-GMAC-192 implementation via gnutls...\n");
        ret = test_gmac(GNUTLS_MAC_AES_GMAC_192, 24, expected_aes_gmac_192,
            sizeof(expected_aes_gmac_192));
    }
    if (ret == 0) {
        printf("testing wolfssl's AES-GMAC-256 implementation via gnutls...\n");
        ret = test_gmac(GNUTLS_MAC_AES_GMAC_256, 32, expected_aes_gmac_256,
            sizeof(expected_aes_gmac_256));
    }

    gnutls_global_deinit();

    return ret;
}

