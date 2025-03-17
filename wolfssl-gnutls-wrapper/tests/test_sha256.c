#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

const char test_data[] = "abc";
const unsigned char expected_hash[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
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

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Rest of test code remains the same */
    printf("Testing wolfSSL's SHA256 implementation via GnuTLS...\n");
    printf("Input data: \"%s\"\n", test_data);

    gnutls_hash_hd_t hash;
    ret = gnutls_hash_init(&hash, GNUTLS_DIG_SHA256);
    if (ret != 0) {
        printf("Error initializing hash: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    ret = gnutls_hash(hash, test_data, strlen(test_data));
    if (ret != 0) {
        printf("Error hashing the data\n");
        printf("ret value: %d\n", ret);
        gnutls_global_deinit();
        return 1;
    }

    unsigned char output[32];
    gnutls_hash_deinit(hash, output);

    printf("Expected:\n");
    print_hex(expected_hash, sizeof(output));
    printf("Output:\n");
    print_hex(output, sizeof(output));

    if (memcmp(output, expected_hash, 32) == 0) {
        printf("SUCCESS - Hash operation using wolfSSL provider completed correctly\n");
    } else {
        printf("FAILURE - Hash result does not match expected value\n");
        gnutls_global_deinit();
        return 1;
    }

    gnutls_global_deinit();
    return 0;
}
