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
    printf("Encrypted value:\n");
    print_hex(ciphertext.data, ciphertext.size);

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

    /* Test the fixed length API */
    printf("\nTesting fixed length API...\n");
    unsigned char fixed_buffer[512]; /* Large enough buffer for any RSA key size we test */
    size_t fixed_size = sizeof(fixed_buffer);
    
    memset(fixed_buffer, 0, fixed_size);
    
    ret = gnutls_privkey_decrypt_data2(privkey, 0, &ciphertext, fixed_buffer, fixed_size);
    if (ret != 0) {
        printf("Error using fixed length decrypt API: %s\n", gnutls_strerror(ret));
        gnutls_free(ciphertext.data);
        gnutls_free(decrypted.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }
    
    if (memcmp(fixed_buffer, data.data, data.size) != 0) {
        printf("FAILURE: Fixed length API decrypted data doesn't match original\n");
        gnutls_free(ciphertext.data);
        gnutls_free(decrypted.data);
        gnutls_pubkey_deinit(pubkey);
        gnutls_privkey_deinit(privkey);
        return 1;
    }
    
    printf("Fixed length API SUCCESS\n");

    /* Clean up */
    gnutls_free(ciphertext.data);
    gnutls_free(decrypted.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);

    return 0;
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

    /* Clean up global resources */
    gnutls_global_deinit();

    printf("\nAll RSA encryption/decryption tests completed successfully!\n");
    return 0;
}
