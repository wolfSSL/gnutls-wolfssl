
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

const unsigned char expected_aes_cmac_128[] = {
    0xa9, 0x62, 0xdd, 0x30, 0xac, 0xd5, 0xbf, 0xed,
    0x67, 0x1c, 0x4b, 0xb6, 0x4e, 0x8f, 0xbe, 0x42
};
const unsigned char expected_aes_cmac_256[] = {
    0xbe, 0x00, 0x87, 0x3f, 0x2f, 0x7f, 0x59, 0x08,
    0xbb, 0x21, 0x12, 0x63, 0x28, 0x29, 0x62, 0x94
};


static int test_cmac(int algorithm, size_t key_sz,
    const unsigned char* expected, size_t sz)
{
    int ret;
    unsigned char output[64];
    gnutls_hmac_hd_t cmac;
    int i;

    printf("input data: \"%s\"\n", test_data);
    printf("key: [16/32 bytes of 0x0b]\n");
    printf("nonce: [16 bytes of 0x0f]\n");

    ret = gnutls_hmac_init(&cmac, algorithm, test_key, key_sz);
    if (ret != 0) {
        print_gnutls_error("initializing CMAC", ret);
        return 1;
    }
    gnutls_hmac_set_nonce(cmac, test_nonce, sizeof(test_nonce));

    ret = gnutls_hmac(cmac, test_data, strlen(test_data));
    if (ret != 0) {
        print_gnutls_error("updating CMAC", ret);
        gnutls_hmac_deinit(cmac, NULL);
        return 1;
    }

    gnutls_hmac_output(cmac, output);
    gnutls_hmac_deinit(cmac, NULL);

    if (compare("CMAC", output, expected, sz) != 0) {
        return 1;
    }

    ret = gnutls_hmac_init(&cmac, algorithm, test_key, key_sz);
    if (ret != 0) {
        print_gnutls_error("initializing CMAC", ret);
        return 1;
    }

    for (i = 0; i < strlen(test_data); i++) {
        ret = gnutls_hmac(cmac, test_data + i, 1);
        if (ret != 0) {
            print_gnutls_error("updating CMAC", ret);
            gnutls_hmac_deinit(cmac, NULL);
            return 1;
        }
    }

    gnutls_hmac_output(cmac, output);
    gnutls_hmac_deinit(cmac, NULL);

    if (compare("CMAC", output, expected, sz) != 0) {
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

    printf("testing wolfssl's AES-CMAC-128 implementation via gnutls...\n");
    ret = test_cmac(GNUTLS_MAC_AES_CMAC_128, 16, expected_aes_cmac_128,
        sizeof(expected_aes_cmac_128));
    if (ret == 0) {
        printf("testing wolfssl's AES-CMAC-256 implementation via gnutls...\n");
        ret = test_cmac(GNUTLS_MAC_AES_CMAC_256, 32, expected_aes_cmac_256,
            sizeof(expected_aes_cmac_256));
    }

    gnutls_global_deinit();

    return ret;
}
