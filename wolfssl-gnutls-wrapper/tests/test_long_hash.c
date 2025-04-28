
#include <gnutls/crypto.h>

#include "test_util.h"

const unsigned char expected_sha256_hash[] = {
    0x84, 0x79, 0xe4, 0x39, 0x11, 0xdc, 0x45, 0xe8,
    0x9f, 0x93, 0x4f, 0xe4, 0x8d, 0x01, 0x29, 0x7e,
    0x16, 0xf5, 0x1d, 0x17, 0xaa, 0x56, 0x1d, 0x4d,
    0x1c, 0x21, 0x6b, 0x1a, 0xe0, 0xfc, 0xdd, 0xca
};

const unsigned char expected_sha256_hmac[] = {
    0x4e, 0xdc, 0x1a, 0x95, 0x7d, 0x34, 0x3a, 0x6f,
    0x8e, 0x2f, 0xd3, 0x66, 0x03, 0xd2, 0x57, 0xb4,
    0x17, 0x65, 0x57, 0x8e, 0xd0, 0x67, 0xf0, 0x37,
    0xd6, 0xb5, 0x99, 0xfa, 0x38, 0x4f, 0xa1, 0x50
};

const unsigned char expected_aes_cmac_128[] = {
    0x41, 0x83, 0x93, 0x5b, 0x5f, 0x82, 0x1c, 0x4f,
    0x83, 0xed, 0x73, 0x07, 0x23, 0x28, 0x53, 0xa4,
};


static int hash_long(const unsigned char* buf, size_t buf_sz,
    unsigned char* output)
{
    int ret;

    /* Hash */
    ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, buf, buf_sz, output);
    if (ret != 0) {
        print_gnutls_error("Hash large buffer", ret);
        return 1;
    }

    ret = compare("Hash", output, expected_sha256_hash,
         sizeof(expected_sha256_hash));

    return ret;
}

static int hmac_long(const unsigned char* buf, size_t buf_sz,
    unsigned char* output)
{
    int ret;
    const char* key = "KeyForHmacSha256Operation";

    /* HMAC */
    ret = gnutls_hmac_fast(GNUTLS_MAC_SHA256, key, strlen(key), buf, buf_sz,
        output);
    if (ret != 0) {
        print_gnutls_error("HMAC large buffer", ret);
        return 1;
    }

    ret = compare("HMAC", output, expected_sha256_hmac,
         sizeof(expected_sha256_hmac));

    return ret;
}

static int cmac_long(const unsigned char* buf, size_t buf_sz,
    unsigned char* output)
{
    int ret;
    const char* key = "KeyForCMAC128Ops";
    const char* nonce = "NonceForTheCMACs";
    gnutls_hmac_hd_t cmac;

    /* CMAC */
    ret = gnutls_hmac_init(&cmac, GNUTLS_MAC_AES_CMAC_128, key, strlen(key));
    if (ret != 0) {
        print_gnutls_error("initializing CMAC", ret);
        return 1;
    }
    gnutls_hmac_set_nonce(cmac, nonce, strlen(nonce));

    ret = gnutls_hmac(cmac, buf, buf_sz);
    if (ret != 0) {
        print_gnutls_error("CMAC large buffer", ret);
        gnutls_hmac_deinit(cmac, NULL);
        return 1;
    }

    gnutls_hmac_output(cmac, output);
    gnutls_hmac_deinit(cmac, NULL);

    ret = compare("CMAC", output, expected_aes_cmac_128,
         sizeof(expected_aes_cmac_128));

    return ret;
}

int main(void)
{
    int ret;
    unsigned char* buf;
    size_t buf_sz = 0x100000000;
    unsigned char output[32];

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Rest of test code remains the same */
    printf("Testing wolfSSL's digest implementation via GnuTLS...\n");

    buf = gnutls_calloc(1, buf_sz);
    if (buf == NULL) {
        printf("FAILURE - Could not allocate memory\n");
        gnutls_global_deinit();
        return 1;
    }

    ret = hash_long(buf, buf_sz, output);
    if (ret == 0) {
        ret = hmac_long(buf, buf_sz, output);
    }
    if (ret == 0) {
        ret = cmac_long(buf, buf_sz, output);
    }
    /* Can't do GMAC long unless we implement with GCM streaming. */

    gnutls_free(buf);

    gnutls_global_deinit();

    return ret;
}
