#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

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

int test_eddsa_curve(const char *curve_name) {
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t signature, signature_hash;
    const char *test_data = "Test data to be signed";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };
    int algo, sign_algo;
    unsigned char hash_buffer[64]; // Big enough for both Ed25519 (64 bytes) and Ed448 (114 bytes)
    gnutls_datum_t hash;
    gnutls_digest_algorithm_t digest_algo;

    memset(&signature, 0, sizeof(signature));
    memset(&signature_hash, 0, sizeof(signature_hash));
    memset(hash_buffer, 0, sizeof(hash_buffer));

    printf("\n=== Testing EdDSA with %s ===\n", curve_name);

    /* Set algorithms based on curve type */
    if (strcmp(curve_name, "Ed25519") == 0) {
        algo = GNUTLS_PK_EDDSA_ED25519;
        sign_algo = GNUTLS_SIGN_EDDSA_ED25519;
        digest_algo = GNUTLS_DIG_SHA512;
    } else {
        algo = GNUTLS_PK_EDDSA_ED448;
        sign_algo = GNUTLS_SIGN_EDDSA_ED448;
        digest_algo = GNUTLS_DIG_SHAKE_256;
    }

    /* Initialize keys */
    ret = gnutls_privkey_init(&privkey);
    if (ret != 0) {
        printf("Error initializing private key: %s\n", gnutls_strerror(ret));
        return 1;
    }

    ret = gnutls_pubkey_init(&pubkey);
    if (ret != 0) {
        printf("Error initializing public key: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    /* Generate an EdDSA key pair */
    printf("Generating EdDSA key pair (%s)...\n", curve_name);
    ret = gnutls_privkey_generate2(privkey, algo, 0, 0, NULL, 0);
    if (ret != 0) {
        printf("Error generating private key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    /* Extract the public key from the private key */
    ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
    if (ret != 0) {
        printf("Error extracting public key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    /* Test 1: Sign and verify raw data */
    printf("\n--- Test 1: Sign/Verify Raw Data ---\n");
    printf("Input data: \"%s\"\n", test_data);
    
    ret = gnutls_privkey_sign_data(privkey, digest_algo, 0, &data, &signature);
    if (ret != 0) {
        printf("Error signing data: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    printf("Data signature created (size: %d bytes)\n", signature.size);
    printf("Data signature value:\n");
    print_hex(signature.data, signature.size);

    printf("Verifying data signature...\n");
    ret = gnutls_pubkey_verify_data2(pubkey, sign_algo, 0, &data, &signature);
    if (ret != 0) {
        printf("FAILURE verifying data signature for %s: %s\n", curve_name, gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }
    printf("SUCCESS verifying data signature for %s\n", curve_name);

    /* Clean up */
    gnutls_free(signature.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

int main(void) {
    int ret;
    unsigned int fips_mode;

    printf("Testing GnuTLS's EdDSA implementation...\n");

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Check if FIPS mode is enabled */
    fips_mode = gnutls_fips140_mode_enabled();
    if (fips_mode == 1) {
        printf("This test can be run only when FIPS140 mode is not enabled\n");
        return 0; /* Skip test */
    }

    /* Test Ed25519 */
    ret = test_eddsa_curve("Ed25519");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test Ed448 */
    ret = test_eddsa_curve("Ed448");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Clean up global resources */
    gnutls_global_deinit();

    printf("\nAll EdDSA tests completed successfully!\n");
    return 0;
}
