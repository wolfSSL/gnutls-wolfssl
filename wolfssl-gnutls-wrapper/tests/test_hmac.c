
#include <gnutls/crypto.h>

#include "test_util.h"


/* Test vector from RFC 4231 - Test Case 1 */
const unsigned char test_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b
};
const char test_data[] = "Hi There";

const unsigned char expected_hmac_sha224[] = {
    0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19,
    0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f,
    0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f,
    0x53, 0x68, 0x4b, 0x22
};
const unsigned char expected_hmac_sha256[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
    0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};
const unsigned char expected_hmac_sha384[] = {
    0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
    0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
    0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
    0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
    0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
    0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6
};
const unsigned char expected_hmac_sha512[] = {
    0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
    0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
    0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
    0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
    0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
    0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
    0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
    0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
};


static int test_hmac(int algorithm, const unsigned char* expected_hmac,
    size_t sz)
{
    int ret;
    unsigned char output[64];
    gnutls_hmac_hd_t hmac;
    int i;

    printf("input data: \"%s\"\n", test_data);
    printf("key: [20 bytes of 0x0b]\n");

    ret = gnutls_hmac_init(&hmac, algorithm, test_key, sizeof(test_key));
    if (ret != 0) {
        print_gnutls_error("initializing HMAC\n", ret);
        return 1;
    }

    ret = gnutls_hmac(hmac, test_data, strlen(test_data));
    if (ret != 0) {
        print_gnutls_error("updating HMAC\n", ret);
        gnutls_hmac_deinit(hmac, NULL);
        return 1;
    }

    gnutls_hmac_output(hmac, output);
    gnutls_hmac_deinit(hmac, NULL);

    if (compare("HMAC", output, expected_hmac, sz) != 0) {
        return 1;
    }

    ret = gnutls_hmac_init(&hmac, algorithm, test_key, sizeof(test_key));
    if (ret != 0) {
        print_gnutls_error("initializing HMAC\n", ret);
        return 1;
    }

    for (i = 0; i < strlen(test_data); i++) {
        ret = gnutls_hmac(hmac, test_data + i, 1);
        if (ret != 0) {
            print_gnutls_error("updating HMAC\n", ret);
            gnutls_hmac_deinit(hmac, NULL);
            return 1;
        }
    }

    gnutls_hmac_output(hmac, output);
    gnutls_hmac_deinit(hmac, NULL);

    if (compare("HMAC", output, expected_hmac, sz) != 0) {
        return 1;
    }

    return 0;
}

int main(void)
{
    int ret;

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    printf("testing wolfssl's HMAC-SHA224 implementation via gnutls...\n");
    ret = test_hmac(GNUTLS_MAC_SHA224, expected_hmac_sha224,
        sizeof(expected_hmac_sha224));
    if (ret == 0) {
        printf("testing wolfssl's HMAC-SHA256 implementation via gnutls...\n");
        ret = test_hmac(GNUTLS_MAC_SHA256, expected_hmac_sha256,
            sizeof(expected_hmac_sha256));
    }
    if (ret == 0) {
        printf("testing wolfssl's HMAC-SHA384 implementation via gnutls...\n");
        ret = test_hmac(GNUTLS_MAC_SHA384, expected_hmac_sha384,
            sizeof(expected_hmac_sha384));
    }
    if (ret == 0) {
        printf("testing wolfssl's HMAC-SHA512 implementation via gnutls...\n");
        ret = test_hmac(GNUTLS_MAC_SHA512, expected_hmac_sha512,
            sizeof(expected_hmac_sha512));
    }

    gnutls_global_deinit();

    return ret;
}
