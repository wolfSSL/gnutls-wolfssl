/* A request the provider refuses must fail with a negative error.
 *
 * GnuTLS treats any provider return >= 0 as success. A FIPS wolfCrypt refuses
 * an HMAC key shorter than 14 bytes; if that refusal is not returned as a
 * negative error, gnutls_hmac_fast() reports success without writing the MAC,
 * and gnutls_hmac_init() succeeds with an HMAC that does not depend on the
 * key, so a forged tag verifies.
 *
 * HMAC-SHA256 with the 4-byte key "Jefe" (RFC 4231 test case 2), one-shot and
 * streaming: each must either fail with a negative error (FIPS) or give the
 * RFC value. Two different short keys must not give the same MAC.
 */
#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "test_util.h"

static const char *msg = "what do ya want for nothing?";

/* RFC 4231, section 4.3. */
static const unsigned char tc2_mac[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26,
    0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
    0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
};

static int hmac_stream(const char *key, unsigned char *mac)
{
    gnutls_hmac_hd_t hd;
    int ret;

    ret = gnutls_hmac_init(&hd, GNUTLS_MAC_SHA256, key, strlen(key));
    if (ret < 0) {
        return ret;
    }
    ret = gnutls_hmac(hd, msg, strlen(msg));
    gnutls_hmac_deinit(hd, mac);
    return ret;
}

/* 0 when ret is a negative error, or success with the RFC 4231 value. */
static int check(const char *op, int ret, const unsigned char *mac)
{
    if (ret < 0) {
        printf("%s refused: %s\n", op, gnutls_strerror(ret));
        return 0;
    }
    if (ret > 0) {
        printf("FAILURE - %s returned %d, not an error code\n", op, ret);
        return 1;
    }
    return compare(op, mac, tc2_mac, sizeof(tc2_mac));
}

int main(void)
{
    unsigned char mac[32], mac2[32];
    int ret, ret2;

    printf("Testing that refused HMAC keys fail with an error...\n");

    ret = gnutls_global_init();
    if (ret != 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    memset(mac, 0, sizeof(mac));
    ret = gnutls_hmac_fast(GNUTLS_MAC_SHA256, "Jefe", 4, msg, strlen(msg), mac);
    if (check("HMAC-SHA256 one-shot, 4-byte key", ret, mac) != 0) {
        gnutls_global_deinit();
        return 1;
    }

    memset(mac, 0, sizeof(mac));
    ret = hmac_stream("Jefe", mac);
    if (check("HMAC-SHA256 streaming, 4-byte key", ret, mac) != 0) {
        gnutls_global_deinit();
        return 1;
    }

    memset(mac, 0, sizeof(mac));
    memset(mac2, 0, sizeof(mac2));
    ret = hmac_stream("Jefe", mac);
    ret2 = hmac_stream("Jeff", mac2);
    if (ret == 0 && ret2 == 0 && memcmp(mac, mac2, sizeof(mac)) == 0) {
        printf("FAILURE - two different keys gave the same MAC\n");
        gnutls_global_deinit();
        return 1;
    }

    gnutls_global_deinit();
    printf("\nAll refusal tests completed successfully!\n");
    return 0;
}
