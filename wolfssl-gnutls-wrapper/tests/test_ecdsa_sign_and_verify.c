#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <dlfcn.h>
#include "test_util.h"

int test_ecdsa_curve(gnutls_ecc_curve_t curve, const char *curve_name) {
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t signature, signature_hash;
    const char *test_data = "Test data to be signed";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };
    gnutls_digest_algorithm_t digest_algo;
    gnutls_sign_algorithm_t sign_algo;
    unsigned char hash_buffer[64]; // Big enough for any hash we'll use
    gnutls_datum_t hash;
    unsigned int bits;

    // Select appropriate hash algorithm based on curve
    if (curve == GNUTLS_ECC_CURVE_SECP256R1) {
        digest_algo = GNUTLS_DIG_SHA256;
        sign_algo = GNUTLS_SIGN_ECDSA_SHA256;
        bits = 256;
    } else if (curve == GNUTLS_ECC_CURVE_SECP384R1) {
        digest_algo = GNUTLS_DIG_SHA384;
        sign_algo = GNUTLS_SIGN_ECDSA_SHA384;
        bits = 384;
    } else if (curve == GNUTLS_ECC_CURVE_SECP521R1) {
        digest_algo = GNUTLS_DIG_SHA512;
        sign_algo = GNUTLS_SIGN_ECDSA_SHA512;
        bits = 521;
    } else {
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    memset(&signature, 0, sizeof(signature));
    memset(&signature_hash, 0, sizeof(signature_hash));
    memset(hash_buffer, 0, sizeof(hash_buffer));

    printf("\n=== Testing ECDSA with %s (%d bits) ===\n", curve_name, bits);

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

    /* Generate an ECDSA key pair with the specified curve */
    printf("Generating ECDSA key pair (%s)...\n", curve_name);
    
    /* Use GNUTLS_CURVE_TO_BITS macro to properly encode the curve */
    ret = gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA, 
                                  bits, 0);
    
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
    printf("input data: \"%s\"\n", test_data);
    
    ret = gnutls_privkey_sign_data(privkey, digest_algo, 0, &data, &signature);
    if (ret != 0) {
        printf("Error signing data: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    printf("Data signature created (size: %d bytes)\n", signature.size);
    print_hex("Data signature value", signature.data, signature.size);

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

    /* Test 2: Sign and verify hash */
    printf("\n--- Test 2: Sign/Verify Hash ---\n");
    
    /* Hash the test data */
    ret = gnutls_hash_fast(digest_algo, data.data, data.size, hash_buffer);
    if (ret != 0) {
        printf("Error hashing data: %s\n", gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    hash.data = hash_buffer;
    hash.size = gnutls_hash_get_len(digest_algo);

    print_hex("Hash value", hash.data, hash.size);

    /* Sign the hash */
    ret = gnutls_privkey_sign_hash(privkey, digest_algo, 0, &hash, &signature_hash);
    if (ret != 0) {
        printf("Error signing hash: %s\n", gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    printf("Hash signature created (size: %d bytes)\n", signature_hash.size);
    print_hex("Hash signature value", signature_hash.data, signature_hash.size);

    /* Verify the hash signature */
    printf("Verifying hash signature...\n");
    ret = gnutls_pubkey_verify_hash2(pubkey, sign_algo, 0, &hash, &signature_hash);
    if (ret != 1) {
        printf("FAILURE verifying hash signature for %s: %s\n", curve_name, gnutls_strerror(ret));
        gnutls_free(signature.data);
        gnutls_free(signature_hash.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }
    printf("SUCCESS verifying hash signature for %s\n", curve_name);

    /* Clean up */
    gnutls_free(signature.data);
    gnutls_free(signature_hash.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

int main(void) {
    int ret;

    printf("Testing GnuTLS's ECDSA implementation with multiple curves...\n");

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Test SECP256R1 (P-256) */
    ret = test_ecdsa_curve(GNUTLS_ECC_CURVE_SECP256R1, "SECP256R1");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test SECP384R1 (P-384) */
    ret = test_ecdsa_curve(GNUTLS_ECC_CURVE_SECP384R1, "SECP384R1");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test SECP521R1 (P-521) */
    ret = test_ecdsa_curve(GNUTLS_ECC_CURVE_SECP521R1, "SECP521R1");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Clean up global resources */
    gnutls_global_deinit();

    printf("\nAll ECDSA curve tests completed successfully!\n");
    return 0;
}
