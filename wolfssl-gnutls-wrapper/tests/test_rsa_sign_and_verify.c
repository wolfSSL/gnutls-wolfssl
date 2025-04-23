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

int test_rsa_key_size(unsigned int bits) {
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t signature;
    const char *test_data = "Test data to be signed";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };
    gnutls_digest_algorithm_t digest_algo;
    gnutls_sign_algorithm_t sign_algo;

    /* Select appropriate digest algorithm based on key size */
    if (bits <= 2048) {
        digest_algo = GNUTLS_DIG_SHA256;
        sign_algo = GNUTLS_SIGN_RSA_SHA256;
    } else if (bits <= 3072) {
        digest_algo = GNUTLS_DIG_SHA384;
        sign_algo = GNUTLS_SIGN_RSA_SHA384;
    } else {
        digest_algo = GNUTLS_DIG_SHA512;
        sign_algo = GNUTLS_SIGN_RSA_SHA512;
    }

    memset(&signature, 0, sizeof(signature));

    printf("\n=== Testing RSA with %d bits ===\n", bits);

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

    /* Generate an RSA key pair with the specified size */
    printf("Generating RSA key pair (%d bits)...\n", bits);
    ret = gnutls_privkey_generate2(privkey, GNUTLS_PK_RSA,
            bits,
            0, NULL, 0);
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

    /* Sign the test data */
    printf("input data: \"%s\"\n", test_data);
    ret = gnutls_privkey_sign_data(privkey, digest_algo, 0, &data, &signature);
    if (ret != 0) {
        printf("Error signing data: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    printf("Signature created (size: %d bytes)\n", signature.size);
    printf("Signature value:\n");
    print_hex(signature.data, signature.size);

    /* Verify the signature */
    printf("Verifying signature...\n");
    ret = gnutls_pubkey_verify_data2(pubkey, sign_algo,
            0, &data, &signature);
    if (ret == 0) {
        printf("SUCCESS for RSA %d bits\n", bits);
    } else {
        printf("FAILURE for RSA %d bits: %s\n", bits, gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    /* Clean up */
    gnutls_free(signature.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

int test_rsa_pss_key_size(unsigned int bits) {
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t signature;
    const char *test_data = "Test data to be signed with RSA-PSS";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };
    gnutls_digest_algorithm_t digest_algo;
    gnutls_sign_algorithm_t sign_algo;

    /* Select appropriate digest algorithm based on key size */
    if (bits <= 2048) {
        digest_algo = GNUTLS_DIG_SHA256;
        sign_algo = GNUTLS_SIGN_RSA_PSS_SHA256;
    } else if (bits <= 3072) {
        digest_algo = GNUTLS_DIG_SHA384;
        sign_algo = GNUTLS_SIGN_RSA_PSS_SHA384;
    } else {
        digest_algo = GNUTLS_DIG_SHA512;
        sign_algo = GNUTLS_SIGN_RSA_PSS_SHA512;
    }

    memset(&signature, 0, sizeof(signature));

    printf("\n=== Testing RSA-PSS with %d bits ===\n", bits);

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

    /* Generate an RSA-PSS key pair with the specified size */
    printf("Generating RSA-PSS key pair (%d bits)...\n", bits);
    ret = gnutls_privkey_generate2(privkey, GNUTLS_PK_RSA_PSS,
            bits,
            0, NULL, 0);
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

    /* Sign the test data */
    printf("input data: \"%s\"\n", test_data);
    ret = gnutls_privkey_sign_data(privkey, digest_algo, 0, &data, &signature);
    if (ret != 0) {
        printf("Error signing data: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    printf("Signature created (size: %d bytes)\n", signature.size);
    printf("Signature value:\n");
    print_hex(signature.data, signature.size);

    /* Verify the signature */
    printf("Verifying signature...\n");
    ret = gnutls_pubkey_verify_data2(pubkey, sign_algo,
            0, &data, &signature);
    if (ret == 0) {
        printf("SUCCESS for RSA-PSS %d bits\n", bits);
    } else {
        printf("FAILURE for RSA-PSS %d bits: %s\n", bits, gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    /* Clean up */
    gnutls_free(signature.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

int main(void) {
    int ret;

    printf("Testing GnuTLS's RSA and RSA-PSS implementations with multiple key sizes...\n");

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Test standard RSA */
    printf("\n--- Testing Standard RSA ---\n");

    /* Test 2048-bit RSA */
    ret = test_rsa_key_size(2048);
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test 4096-bit RSA */
    ret = test_rsa_key_size(4096);
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test RSA-PSS */
    printf("\n--- Testing RSA-PSS ---\n");

    /* Test 2048-bit RSA-PSS */
    ret = test_rsa_pss_key_size(2048);
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }


    /* Test 4096-bit RSA-PSS */
    ret = test_rsa_pss_key_size(4096);
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Clean up global resources */
    gnutls_global_deinit();

    printf("\nAll RSA and RSA-PSS key size tests completed successfully!\n");
    return 0;
}
