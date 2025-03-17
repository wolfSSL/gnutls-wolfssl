#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <dlfcn.h>

/* Test vector from RFC 4231 - Test Case 1 */
const unsigned char test_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
    0x0b, 0x0b, 0x0b, 0x0b
};
const char test_data[] = "Hi There";

const unsigned char expected_hmac[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 
    0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 
    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

void print_hex(const unsigned char * data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i+1) % 16 == 0 && i != len - 1)
            printf("\n");
        else if ((i+1) % 8 == 0 && i != len - 1)
            printf(" ");
        else if (i != len - 1)
            printf(" ");
    }
    printf("\n");
}

int main(void) {
    int ret;

    gnutls_global_init();

    printf("testing wolfssl's HMAC-SHA256 implementation via gnutls...\n");

    printf("input data: \"%s\"\n", test_data);
    printf("key: [20 bytes of 0x0b]\n");

    gnutls_hmac_hd_t hmac;
    ret = gnutls_hmac_init(&hmac, GNUTLS_MAC_SHA256,
                          test_key, sizeof(test_key));
    if (ret != 0) {
        printf("Error initializing HMAC: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    ret = gnutls_hmac(hmac, test_data, strlen(test_data));
    if (ret != 0) {
        printf("Error updating HMAC with data\n");
        printf("ret value: %d\n", ret);
        return 1;
    }

    unsigned char output[32];
    gnutls_hmac_output(hmac, output);
    gnutls_hmac_deinit(hmac, NULL);

    printf("Expected HMAC:\n");
    print_hex(expected_hmac, sizeof(output));
    printf("Calculated HMAC:\n");
    print_hex(output, sizeof(output));

    if (memcmp(output, expected_hmac, 32) == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILURE\n");
        gnutls_global_deinit();
        return 1;
    }

    gnutls_global_deinit();
    return 0;
}
