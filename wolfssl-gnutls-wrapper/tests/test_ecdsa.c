#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <dlfcn.h>

void print_hex(const unsigned char *data, size_t len) {
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
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t signature;
    const char *test_data = "Test data to be signed";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };

    memset(&signature, 0, sizeof(signature));

    printf("testing GnuTLS's ECDSA implementation...\n");

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Initialize keys */
    ret = gnutls_privkey_init(&privkey);
    if (ret != 0) {
        printf("Error initializing private key: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    ret = gnutls_pubkey_init(&pubkey);
    if (ret != 0) {
        printf("Error initializing public key: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        gnutls_global_deinit();
        return 1;
    }

    /* Generate an ECDSA key pair (SECP256R1 curve) */
    printf("Generating ECDSA key pair (SECP256R1)...\n");
    ret = gnutls_privkey_generate2(privkey, GNUTLS_PK_ECDSA, 
                                  GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1),
                                  0, NULL, 0);
    if (ret != 0) {
        printf("Error generating private key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        gnutls_global_deinit();
        return 1;
    }

    /* Extract the public key from the private key */
    ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
    if (ret != 0) {
        printf("Error extracting public key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        gnutls_global_deinit();
        return 1;
    }

    /* Sign the test data */
    printf("input data: \"%s\"\n", test_data);
    ret = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &data, &signature);
    if (ret != 0) {
        printf("Error signing data: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        gnutls_global_deinit();
        return 1;
    }

    printf("Signature created (size: %d bytes)\n", signature.size);
    printf("Signature value:\n");
    print_hex(signature.data, signature.size);

    /* Verify the signature */
    printf("Verifying signature...\n");
    ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 
                                    0, &data, &signature);
    if (ret == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILURE: %s\n", gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        gnutls_global_deinit();
        return 1;
    }

    /* Clean up */
    gnutls_free(signature.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);
    gnutls_global_deinit();

    return 0;
}
