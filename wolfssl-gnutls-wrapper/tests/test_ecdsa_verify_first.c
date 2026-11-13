#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include "test_util.h"

/* The ECDSA verify below must be the first crypto operation in the process.
 * A FIPS wolfCrypt runs its ECDSA self test on first use and needs the seed
 * callback registered by then, so do not add any other crypto before it. */

/* P-256 public key (SubjectPublicKeyInfo DER), generated with OpenSSL. */
static const unsigned char pub_der[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x17, 0x43, 0x4a, 0x88, 0x9f,
    0xbd, 0x50, 0x1f, 0x75, 0xfe, 0x6c, 0x8e, 0x8a, 0xbd, 0x63, 0x4b, 0xb7, 0x17, 0x33, 0x17, 0x78,
    0xee, 0xee, 0x54, 0x29, 0x23, 0xaf, 0x96, 0x61, 0x89, 0x9e, 0x65, 0x0d, 0xf3, 0x57, 0x3f, 0x4e,
    0x57, 0xf9, 0x2a, 0xe3, 0xf7, 0xbc, 0xbd, 0x90, 0x6f, 0x41, 0xc4, 0x68, 0x6c, 0x20, 0x08, 0xb4,
    0x00, 0x0a, 0x73, 0x9f, 0x14, 0x8b, 0x23, 0x5f, 0x6d, 0xb3, 0xa1
};

static const unsigned char msg[] = "verify first";

/* ECDSA-SHA256 signature over msg, made by OpenSSL with the matching key. */
static const unsigned char sig_der[] = {
    0x30, 0x46, 0x02, 0x21, 0x00, 0xc1, 0x26, 0x55, 0x6b, 0x48, 0x32, 0xdd, 0x2c, 0x78, 0xfc, 0x47,
    0x2e, 0x4a, 0x50, 0xb3, 0x33, 0xe8, 0x15, 0x77, 0x12, 0x3d, 0x28, 0x10, 0x81, 0x61, 0x31, 0x36,
    0x00, 0xc1, 0xe8, 0x0d, 0x20, 0x02, 0x21, 0x00, 0xa6, 0x7b, 0x0d, 0xbb, 0x10, 0xe0, 0xd9, 0x44,
    0x46, 0x36, 0x3c, 0x2a, 0x11, 0xec, 0x45, 0xfd, 0x44, 0x53, 0x1d, 0x2f, 0x16, 0xcf, 0x72, 0x09,
    0xb5, 0x99, 0xe0, 0x25, 0xf9, 0x74, 0xba, 0x92
};

static int test_ecdsa_verify_first(void)
{
    int ret;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t pub = { (unsigned char*)pub_der, sizeof(pub_der) };
    gnutls_datum_t data = { (unsigned char*)msg, sizeof(msg) - 1 };
    gnutls_datum_t bad = { (unsigned char*)msg, sizeof(msg) - 2 };
    gnutls_datum_t sig = { (unsigned char*)sig_der, sizeof(sig_der) };

    ret = gnutls_pubkey_init(&pubkey);
    if (ret < 0) {
        print_gnutls_error("initializing public key", ret);
        return 1;
    }

    ret = gnutls_pubkey_import(pubkey, &pub, GNUTLS_X509_FMT_DER);
    if (ret < 0) {
        print_gnutls_error("importing public key", ret);
        gnutls_pubkey_deinit(pubkey);
        return 1;
    }

    ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0,
        &data, &sig);
    if (ret < 0) {
        printf("FAILURE verifying first ECDSA signature: %s\n",
            gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        return 1;
    }
    printf("SUCCESS verifying first ECDSA signature\n");

    ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0,
        &bad, &sig);
    if (ret != GNUTLS_E_PK_SIG_VERIFY_FAILED) {
        printf("FAILURE altered data not rejected: %d\n", ret);
        gnutls_pubkey_deinit(pubkey);
        return 1;
    }
    printf("SUCCESS rejecting ECDSA signature over altered data\n");

    gnutls_pubkey_deinit(pubkey);
    return 0;
}

int main(void)
{
    int ret;

    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_ecdsa_verify_first();
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}
