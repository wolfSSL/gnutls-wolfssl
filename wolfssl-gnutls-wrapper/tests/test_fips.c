#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

/* Tests some algos against the v5.2.1 CAVP
 * when both GnuTLS and wolfSSL are running
 * in FIPS mode. */

static int test_invalid_aes_cbc(void);
static int test_invalid_aes_ccm(void);
static int test_invalid_aes_gcm(void);
static int test_invalid_ecdsa(void);
static int test_invalid_rsa(void);

static uint8_t key_data[64];
static uint8_t iv_data[16];
static const gnutls_datum_t test_data = { .data = (unsigned char *)"Test data for CAVP compliance testing", 35 };

/* Test AES-CBC with invalid parameters */
static int test_invalid_aes_cbc(void)
{
    int ret;
    /* Invalid key sizes outside 128, 192, 256 bits */
    size_t invalid_key_sizes[] = {8, 20, 64};

    printf("Testing invalid AES-CBC parameters...\n");

    for (size_t i = 0; i < sizeof(invalid_key_sizes)/sizeof(invalid_key_sizes[0]); i++) {
        gnutls_cipher_hd_t handle;
        gnutls_datum_t key = { key_data, invalid_key_sizes[i] };
        gnutls_datum_t iv = { iv_data, 16 }; /* AES block size */

        memset(key_data, (int)i + 1, invalid_key_sizes[i]);
        memset(iv_data, (int)i + 1, 16);

        printf("  Trying AES-CBC with invalid %zu-bit key... \n", invalid_key_sizes[i] * 8);
        ret = gnutls_cipher_init(&handle, GNUTLS_CIPHER_AES_128_CBC, &key, &iv);
        if (ret == 0) {
            gnutls_cipher_deinit(handle);
            return -1;
        }
    }

    return 0;
}

/* Test AES-CCM with invalid parameters */
static int test_invalid_aes_ccm(void)
{
    int ret;
    uint8_t buffer[256];
    size_t outlen;
    gnutls_aead_cipher_hd_t handle;

    /* Invalid key sizes outside 128, 192, 256 bits */
    size_t invalid_key_sizes[] = {8, 20, 64};
    /* Invalid tag sizes outside 32, 48, 64, 80, 96, 112, 128 bits */
    size_t invalid_tag_sizes[] = {1, 2, 3};
    /* Invalid IV lengths outside 56, 64, 72, 80, 88, 96 bits */
    size_t invalid_iv_sizes[] = {4, 5, 6, 14};

    printf("Testing invalid AES-CCM parameters...\n");

    /* Test invalid key sizes */
    for (size_t i = 0; i < sizeof(invalid_key_sizes)/sizeof(invalid_key_sizes[0]); i++) {
        gnutls_datum_t key = { key_data, invalid_key_sizes[i] };
        memset(key_data, (int)i + 1, invalid_key_sizes[i]);

        printf("  Trying AES-CCM with invalid %zu-bit key...\n", invalid_key_sizes[i] * 8);
        ret = gnutls_aead_cipher_init(&handle, GNUTLS_CIPHER_AES_128_CCM, &key);
        if (ret == 0) {
            gnutls_aead_cipher_deinit(handle);
            return -1;
        }
    }

    /* Setup valid parameters for testing other invalid scenarios */
    gnutls_datum_t valid_key = { key_data, 16 };
    memset(key_data, 0x01, 16);
    ret = gnutls_aead_cipher_init(&handle, GNUTLS_CIPHER_AES_128_CCM, &valid_key);
    if (ret < 0) {
        printf("  ERROR: Failed to initialize AES-CCM for testing: %s\n", gnutls_strerror(ret));
        return -1;
    }

    /* Test invalid tag sizes */
    for (size_t i = 0; i < sizeof(invalid_tag_sizes)/sizeof(invalid_tag_sizes[0]); i++) {
        memset(iv_data, 0x02, 12); /* Valid IV */

        printf("  Trying AES-CCM with invalid %zu-bit tag...\n", invalid_tag_sizes[i] * 8);
        outlen = sizeof(buffer);
        ret = gnutls_aead_cipher_encrypt(handle, 
                iv_data, 12,
                NULL, 0,
                invalid_tag_sizes[i],
                test_data.data, test_data.size,
                buffer, &outlen);
        if (ret == 0) {
            return -1;
        }
    }

    /* Test invalid IV lengths */
    for (size_t i = 0; i < sizeof(invalid_iv_sizes)/sizeof(invalid_iv_sizes[0]); i++) {
        memset(iv_data, 0x03, invalid_iv_sizes[i]);

        printf("  Trying AES-CCM with invalid %zu-bit IV...\n", invalid_iv_sizes[i] * 8);
        outlen = sizeof(buffer);
        ret = gnutls_aead_cipher_encrypt(handle, 
                iv_data, invalid_iv_sizes[i],
                NULL, 0,
                16, /* Valid tag length */
                test_data.data, test_data.size,
                buffer, &outlen);
        if (ret == 0) {
            return -1;
        }
    }

    gnutls_aead_cipher_deinit(handle);

    return 0;
}

/* Test AES-GCM with invalid parameters */
static int test_invalid_aes_gcm(void)
{
    int ret;
    uint8_t buffer[256];
    size_t outlen;
    gnutls_aead_cipher_hd_t handle;

    /* Invalid key sizes outside 128, 192, 256 bits */
    size_t invalid_key_sizes[] = {8, 20, 64};
    /* Invalid tag sizes outside 96, 104, 112, 120, 128 bits */
    size_t invalid_tag_sizes[] = {4, 8, 9, 10};
    /* Invalid IV lengths outside 64-128 bits */
    size_t invalid_iv_sizes[] = {17};

    printf("Testing invalid AES-GCM parameters...\n");

    /* Test invalid key sizes */
    for (size_t i = 0; i < sizeof(invalid_key_sizes)/sizeof(invalid_key_sizes[0]); i++) {
        gnutls_datum_t key = { key_data, invalid_key_sizes[i] };
        memset(key_data, (int)i + 1, invalid_key_sizes[i]);

        printf("  Trying AES-GCM with invalid %zu-bit key...\n", invalid_key_sizes[i] * 8);
        ret = gnutls_aead_cipher_init(&handle, GNUTLS_CIPHER_AES_128_GCM, &key);
        if (ret == 0) {
            gnutls_aead_cipher_deinit(handle);
            return -1;
        }
    }

    /* Setup valid parameters for testing other invalid scenarios */
    gnutls_datum_t valid_key = { key_data, 16 };
    memset(key_data, 0x01, 16);
    ret = gnutls_aead_cipher_init(&handle, GNUTLS_CIPHER_AES_128_GCM, &valid_key);
    if (ret < 0) {
        printf("  ERROR: Failed to initialize AES-GCM for testing: %s\n", gnutls_strerror(ret));
        return -1;
    }

    /* Test invalid tag sizes */
    for (size_t i = 0; i < sizeof(invalid_tag_sizes)/sizeof(invalid_tag_sizes[0]); i++) {
        memset(iv_data, 0x02, 12); /* Valid IV */

        printf("  Trying AES-GCM with invalid %zu-bit tag...\n", invalid_tag_sizes[i] * 8);
        outlen = sizeof(buffer);
        ret = gnutls_aead_cipher_encrypt(handle,
                iv_data, 12,
                NULL, 0,
                invalid_tag_sizes[i],
                test_data.data, test_data.size,
                buffer, &outlen);

        if (ret == 0) {
            gnutls_aead_cipher_deinit(handle);
            return -1;
        }
    }

    gnutls_aead_cipher_deinit(handle);

    return 0;
}

/* Test ECDSA with invalid parameters */
static int test_invalid_ecdsa(void)
{
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey; // For verification tests if needed
    gnutls_datum_t signature;
    uint8_t hash_buffer[64];
    gnutls_datum_t hash_data;

    /* Invalid curves not in approved list for SigGen */
    gnutls_ecc_curve_t invalid_curves[] = {
        GNUTLS_ECC_CURVE_SECP192R1,  /* P-192 not allowed for SigGen */
        GNUTLS_ECC_CURVE_ED25519,     /* Not in FIPS boundary */
        GNUTLS_ECC_CURVE_ED448 /* Not in FIPS boundary */
    };

    /* Invalid hash algorithms not in approved list */
    gnutls_digest_algorithm_t invalid_hash_algos[] = {
        GNUTLS_DIG_SHA1,  /* SHA-1 not approved for SigGen */
    };

    printf("Testing ECDSA with invalid parameters...\n");

    /* Test generation with invalid curves */
    for (size_t i = 0; i < sizeof(invalid_curves)/sizeof(invalid_curves[0]); i++) {
        ret = gnutls_privkey_init(&privkey);
        if (ret < 0) {
            printf("ERROR: ECDSA privkey init failed: %s\n", gnutls_strerror(ret));
            continue;
        }

        printf("Trying ECDSA key generation with invalid curve %s...\n",
                gnutls_ecc_curve_get_name(invalid_curves[i]));

        ret = gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA,
                gnutls_ecc_curve_get_size(invalid_curves[i]), 0);
        if (ret == 0) {
            return -1;
        }

        gnutls_privkey_deinit(privkey);
    }

    /* Generate a valid ECDSA key for testing invalid hash algorithms */
    ret = gnutls_privkey_init(&privkey);
    if (ret < 0) {
        printf("ERROR: ECDSA privkey init failed: %s\n", gnutls_strerror(ret));
        return -1;
    }

    ret = gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA,
            256, 0);
    if (ret < 0) {
        printf("ret: %d\n", ret);
        printf("ERROR: ECDSA key generation failed for P-256: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        return -1;
    }

    // Initialize pubkey for verification (not strictly needed for failure tests but good practice)
    ret = gnutls_pubkey_init(&pubkey);
    if (ret < 0) {
        printf("ERROR: ECDSA pubkey init failed: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        return -1;
    }
    ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
    if (ret < 0) {
        printf("ERROR: Importing privkey to pubkey failed: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return -1;
    }

    /* Test signing raw data with invalid hash algorithms */
    for (size_t i = 0; i < sizeof(invalid_hash_algos)/sizeof(invalid_hash_algos[0]); i++) {
        printf("Trying ECDSA sign_data with invalid hash %s...\n",
                gnutls_digest_get_name(invalid_hash_algos[i]));

        ret = gnutls_privkey_sign_data(privkey, invalid_hash_algos[i], 0, &test_data, &signature);
        if (ret == 1) {
            return -1;
        }
    }

    /* Test signing hash with invalid hash algorithms */
    for (size_t i = 0; i < sizeof(invalid_hash_algos)/sizeof(invalid_hash_algos[0]); i++) {
        /* Create hash of test data */
        ret = gnutls_hash_fast(invalid_hash_algos[i], test_data.data, test_data.size, hash_buffer);
        if (ret < 0) {
            return -1;
        }

        hash_data.data = hash_buffer;
        hash_data.size = gnutls_hash_get_len(invalid_hash_algos[i]);

        printf("Trying ECDSA sign_hash with invalid hash %s...\n",
                gnutls_digest_get_name(invalid_hash_algos[i]));

        ret = gnutls_privkey_sign_hash(privkey, invalid_hash_algos[i], 0, &hash_data, &signature);
        if (ret == 1) {
            return -1;
        }
    }


    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

/* Test RSA with invalid parameters */
static int test_invalid_rsa(void)
{
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey; // For verification tests if needed
    gnutls_datum_t signature;
    uint8_t hash_buffer[64];
    gnutls_datum_t hash_data;

    /* Key sizes below FIPS minimum of 2048 */
    unsigned int invalid_key_sizes[] = {512, 1024};

    /* Invalid hash algorithms for RSA in FIPS */
    gnutls_digest_algorithm_t invalid_hash_algos[] = {
        GNUTLS_DIG_SHA1,  /* SHA-1 not approved for SigGen */
    };

    printf("Testing RSA with invalid parameters...\n");

    /* Test generation with invalid key sizes */
    for (size_t i = 0; i < sizeof(invalid_key_sizes)/sizeof(invalid_key_sizes[0]); i++) {
        ret = gnutls_privkey_init(&privkey);
        if (ret < 0) {
            printf("ERROR: RSA privkey init failed: %s\n", gnutls_strerror(ret));
            continue;
        }

        printf("Trying RSA key generation with invalid size %u bits...\n", invalid_key_sizes[i]);

        ret = gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, invalid_key_sizes[i], 0);
        if (ret == 0) {
            return -1;
        }

        gnutls_privkey_deinit(privkey);
    }

    /* Generate a valid RSA key for testing invalid hash algorithms */
    ret = gnutls_privkey_init(&privkey);
    if (ret < 0) {
        printf("  ERROR: RSA privkey init failed: %s\n", gnutls_strerror(ret));
        return -1;
    }

    ret = gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, 2048, 0);
    if (ret < 0) {
        printf("ERROR: RSA key generation failed for 2048 bits: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        return -1;
    }

    // Initialize pubkey for verification (not strictly needed for failure tests but good practice)
    ret = gnutls_pubkey_init(&pubkey);
    if (ret < 0) {
        printf("ERROR: RSA pubkey init failed: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        return -1;
    }

    ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
    if (ret < 0) {
        printf("ERROR: Importing privkey to pubkey failed: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return -1;
    }

    /* Test signing raw data with invalid hash algorithms */
    for (size_t i = 0; i < sizeof(invalid_hash_algos)/sizeof(invalid_hash_algos[0]); i++) {
        printf("Trying RSA sign_data with invalid hash %s...\n",
                gnutls_digest_get_name(invalid_hash_algos[i]));

        ret = gnutls_privkey_sign_data(privkey, invalid_hash_algos[i], 0, &test_data, &signature);
        if (ret == 1) {
            return -1;
        }
    }

    /* Test signing hash with invalid hash algorithms */
    for (size_t i = 0; i < sizeof(invalid_hash_algos)/sizeof(invalid_hash_algos[0]); i++) {
        /* Create hash of test data */
        ret = gnutls_hash_fast(invalid_hash_algos[i], test_data.data, test_data.size, hash_buffer);
        if (ret < 0) {
            return -1;
        }

        hash_data.data = hash_buffer;
        hash_data.size = gnutls_hash_get_len(invalid_hash_algos[i]);

        printf("Trying RSA sign_hash with invalid hash %s...\n",
                gnutls_digest_get_name(invalid_hash_algos[i]));

        ret = gnutls_privkey_sign_hash(privkey, invalid_hash_algos[i], 0, &hash_data, &signature);
        if (ret == 1) {
            return -1;
        }
    }

    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

int main(void)
{
    int ret;
    unsigned int fips_mode;

    /* Check if FIPS mode is enabled */
    fips_mode = gnutls_fips140_mode_enabled();
    if (fips_mode == 0) {
        printf("This test can be run only when FIPS140 mode is enabled\n");
        return 0; /* Skip test */
    }

    printf("FIPS140 mode is enabled (mode: %u)\n", fips_mode);

    ret = gnutls_global_init();
    if (ret < 0) {
        fprintf(stderr, "Error: Cannot initialize GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Initialize random key/iv data */
    ret = gnutls_rnd(GNUTLS_RND_NONCE, key_data, sizeof(key_data));
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to generate random data: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    ret = gnutls_rnd(GNUTLS_RND_NONCE, iv_data, sizeof(iv_data));
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to generate random data: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    /* Run tests with invalid parameters */
    if (test_invalid_aes_cbc() < 0) {
        printf("AES-CBC failed\n");
        return -1;
    }
    if (test_invalid_aes_ccm() < 0) {
        printf("AES-CCM failed\n");
        return -1;
    }
    if (test_invalid_aes_gcm() < 0) {
        printf("AES-GCM failed\n");
        return -1;
    };
    if (test_invalid_ecdsa() < 0) {
        printf("ECDSA failed\n");
        return -1;
    }
    if (test_invalid_rsa() < 0) {
        printf("RSA failed\n");
        return -1;
    }

    printf("All FIPS non-compliance tests completed\n");

    gnutls_global_deinit();
    return 0;
}
