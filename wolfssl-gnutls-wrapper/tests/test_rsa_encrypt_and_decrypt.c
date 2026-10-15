#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <dlfcn.h>
#include "test_util.h"

int test_rsa_encrypt_decrypt(unsigned int bits) {
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;
    gnutls_datum_t ciphertext;
    gnutls_datum_t decrypted;
    const char *test_data = "Test data to be encrypted with RSA";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };

    memset(&ciphertext, 0, sizeof(ciphertext));
    memset(&decrypted, 0, sizeof(decrypted));

    printf("\n=== Testing RSA encryption/decryption with %d bits ===\n", bits);

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

    /* Encrypt the test data */
    printf("Original data: \"%s\"\n", test_data);
    ret = gnutls_pubkey_encrypt_data(pubkey, 0, &data, &ciphertext);
    if (ret != 0) {
        printf("Error encrypting data: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    printf("Encrypted data (size: %d bytes)\n", ciphertext.size);
    print_hex("Encrypted value", ciphertext.data, ciphertext.size);

    /* Decrypt the data */
    printf("Decrypting data...\n");
    ret = gnutls_privkey_decrypt_data(privkey, 0, &ciphertext, &decrypted);
    if (ret != 0) {
        printf("Error decrypting data: %s\n", gnutls_strerror(ret));
        gnutls_free(ciphertext.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    /* Verify decryption worked correctly */
    if (decrypted.size != data.size || 
        memcmp(decrypted.data, data.data, data.size) != 0) {
        printf("FAILURE: Decrypted data doesn't match original for RSA %d bits\n", bits);
        gnutls_free(ciphertext.data);
        gnutls_free(decrypted.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }
    
    printf("Decrypted data: \"%.*s\"\n", (int)decrypted.size, (char *)decrypted.data);
    printf("SUCCESS for RSA %d bits\n", bits);

    /* Clean up */
    gnutls_free(ciphertext.data);
    gnutls_free(decrypted.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
}

#define DECRYPT2_LEN 48

/* Only an intact DECRYPT2_LEN-byte message decrypts, else buffer unchanged. */
static int decrypt2_check(gnutls_privkey_t privkey, gnutls_pubkey_t pubkey,
    size_t msg_len, int corrupt)
{
    int ret;
    unsigned char msg[64];
    unsigned char buf[DECRYPT2_LEN];
    unsigned char prefill[DECRYPT2_LEN];
    gnutls_datum_t data = { msg, msg_len };
    gnutls_datum_t ciphertext = { NULL, 0 };
    int expect_ok = (msg_len == DECRYPT2_LEN) && !corrupt;
    size_t i;

    memset(msg, 'P', sizeof(msg));
    ret = gnutls_pubkey_encrypt_data(pubkey, 0, &data, &ciphertext);
    if (ret != 0) {
        printf("Error encrypting data: %s\n", gnutls_strerror(ret));
        return 1;
    }
    if (corrupt) {
        ciphertext.data[ciphertext.size / 2] ^= 0x01;
    }

    for (i = 0; i < sizeof(prefill); i++) {
        prefill[i] = (unsigned char)(0xa0 + i);
    }
    memcpy(buf, prefill, sizeof(buf));

    ret = gnutls_privkey_decrypt_data2(privkey, 0, &ciphertext, buf,
        sizeof(buf));
    gnutls_free(ciphertext.data);
    printf("%zu-byte message%s into %d-byte buffer: %s\n", msg_len,
        corrupt ? " (corrupted)" : "", DECRYPT2_LEN,
        ret == 0 ? "decrypted" : gnutls_strerror(ret));

    if (expect_ok) {
        if (ret != 0 || memcmp(buf, msg, sizeof(buf)) != 0) {
            printf("FAILURE: exact-length message did not decrypt "
                "correctly\n");
            return 1;
        }
        return 0;
    }
    if (ret >= 0) {
        printf("FAILURE: reported as decrypted\n");
        return 1;
    }
    if (memcmp(buf, prefill, sizeof(buf)) != 0) {
        printf("FAILURE: output buffer changed on failure\n");
        return 1;
    }
    return 0;
}

static int test_rsa_decrypt2_length(void)
{
    int ret;
    gnutls_privkey_t privkey;
    gnutls_pubkey_t pubkey;

    printf("\n=== Testing RSA decrypt_data2 with exact and wrong lengths "
        "===\n");

    if ((ret = gnutls_privkey_init(&privkey)) != 0) {
        printf("Error initializing private key: %s\n", gnutls_strerror(ret));
        return 1;
    }
    if ((ret = gnutls_pubkey_init(&pubkey)) != 0) {
        printf("Error initializing public key: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(privkey);
        return 1;
    }
    if ((ret = gnutls_privkey_generate2(privkey, GNUTLS_PK_RSA, 2048, 0,
            NULL, 0)) != 0 ||
        (ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0)) != 0) {
        printf("Error setting up RSA key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }

    ret = decrypt2_check(privkey, pubkey, DECRYPT2_LEN, 0) ||
          decrypt2_check(privkey, pubkey, 16, 0) ||
          decrypt2_check(privkey, pubkey, DECRYPT2_LEN - 1, 0) ||
          decrypt2_check(privkey, pubkey, 64, 0) ||
          decrypt2_check(privkey, pubkey, DECRYPT2_LEN, 1);

    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    if (ret == 0) {
        printf("SUCCESS for RSA decrypt_data2\n");
    }
    return ret;
}

int main(void) {
    int ret;

    printf("Testing GnuTLS's RSA encryption/decryption with multiple key sizes...\n");

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Test standard RSA with different key sizes */
    printf("\n--- Testing RSA Encryption/Decryption ---\n");

    /* Test 2048-bit RSA */
    ret = test_rsa_encrypt_decrypt(2048);
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test 4096-bit RSA */
    ret = test_rsa_encrypt_decrypt(4096);
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    ret = test_rsa_decrypt2_length();
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Clean up global resources */
    gnutls_global_deinit();

    printf("\nAll RSA encryption/decryption tests completed successfully!\n");
    return 0;
}
