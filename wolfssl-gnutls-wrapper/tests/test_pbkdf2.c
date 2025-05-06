
#include <gnutls/crypto.h>

#include "test_util.h"


const char* passwd = "passwordpassword";
const unsigned char salt_data[] = {
    0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06
};

const unsigned char expected_sha256[] = {
    0x43, 0x6d, 0xb5, 0xe8, 0xd0, 0xfb, 0x3f, 0x35,
    0x42, 0x48, 0x39, 0xbc, 0x2d, 0xd4, 0xf9, 0x37,
    0xd4, 0x95, 0x16, 0xa7, 0x2a, 0x9a, 0x21, 0xd1
};
const unsigned char expected_sha384[] = {
    0xb9, 0xbd, 0x77, 0xf8, 0x32, 0x2f, 0x3c, 0xac,
    0xd1, 0xfc, 0xfe, 0xbd, 0x56, 0xc1, 0xe1, 0xfb,
    0xa2, 0x45, 0x5f, 0xc3, 0x8f, 0xa5, 0xa3, 0x07
};


static int test_pbkdf2(gnutls_mac_algorithm_t mac_alg, int iterations,
    const unsigned char* expected, size_t sz)
{
    int ret;
    unsigned char derived[64];
    gnutls_datum_t ikm = {
        .data = (unsigned char*)passwd,
        .size = strlen(passwd)
    };
    gnutls_datum_t salt = {
        .data = (unsigned char*)salt_data,
        .size = sizeof(salt_data)
    };

    /* Rest of test code remains the same */
    printf("Testing wolfSSL's %s PBKDF2 implementation via GnuTLS...\n",
        gnutls_mac_get_name(mac_alg));

    ret = gnutls_pbkdf2(mac_alg, &ikm, &salt, iterations, derived, sz);
    if (ret != 0) {
        print_gnutls_error("deriving", ret);
        return 1;
    }

    if (compare("PBKDF2 derivation", derived, expected, sz) != 0) {
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

    ret = test_pbkdf2(GNUTLS_MAC_SHA256, 2048, expected_sha256,
        sizeof(expected_sha256));
    if (ret == 0) {
        ret = test_pbkdf2(GNUTLS_MAC_SHA384, 4096, expected_sha384,
            sizeof(expected_sha384));
    }
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}

