#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <stdlib.h>
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

int test_ec_encrypt_decrypt(unsigned int bits, const char *curve_name) {
    int ret;
    gnutls_privkey_t alice_privkey, bob_privkey;
    gnutls_pubkey_t alice_pubkey, bob_pubkey;
    gnutls_datum_t shared_key;
    gnutls_datum_t encrypted, decrypted;
    const char *test_data = "Test data to be encrypted";
    gnutls_datum_t data = { (unsigned char *)test_data, strlen(test_data) };
    unsigned char iv[16] = {0};  // 16 bytes IV for GCM
    unsigned char tag[16] = {0}; // 16 bytes authentication tag for GCM

    printf("\n=== Testing EC encryption/decryption with %s (%d bits) ===\n", curve_name, bits);

    /* Initialize keys */
    ret = gnutls_privkey_init(&alice_privkey);
    if (ret != 0) {
        printf("Error initializing Alice's private key: %s\n", gnutls_strerror(ret));
        return 1;
    }

    ret = gnutls_pubkey_init(&alice_pubkey);
    if (ret != 0) {
        printf("Error initializing Alice's public key: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }
    
    ret = gnutls_privkey_init(&bob_privkey);
    if (ret != 0) {
        printf("Error initializing Bob's private key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    ret = gnutls_pubkey_init(&bob_pubkey);
    if (ret != 0) {
        printf("Error initializing Bob's public key: %s\n", gnutls_strerror(ret));
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Generate EC key pairs with the specified curve */
    printf("Generating EC key pairs (%s)...\n", curve_name);
    ret = gnutls_privkey_generate2(alice_privkey,  GNUTLS_PK_ECDSA, bits, 0, NULL, 0);
    if (ret != 0) {
        printf("Error generating Alice's private key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    ret = gnutls_privkey_generate2(bob_privkey, GNUTLS_PK_ECDSA, bits, 0, NULL, 0);
    if (ret != 0) {
        printf("Error generating Bob's private key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Extract the public keys from the private keys */
    ret = gnutls_pubkey_import_privkey(alice_pubkey, alice_privkey, 0, 0);
    if (ret != 0) {
        printf("Error extracting Alice's public key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    ret = gnutls_pubkey_import_privkey(bob_pubkey, bob_privkey, 0, 0);
    if (ret != 0) {
        printf("Error extracting Bob's public key: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Perform ECDH key exchange for encryption key derivation */
    printf("Performing ECDH key exchange...\n");
    ret = gnutls_privkey_derive_secret(alice_privkey, bob_pubkey, NULL, &shared_key, 0);
    if (ret != 0) {
        printf("Error deriving shared secret: %s\n", gnutls_strerror(ret));
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    printf("Shared secret derived (size: %d bytes)\n", shared_key.size);
    printf("Shared secret value:\n");
    print_hex(shared_key.data, shared_key.size);

    /* Use AES-GCM for authenticated encryption with the derived key */
    printf("input data: \"%s\"\n", test_data);

    /* Derive an appropriate AES key from the shared secret using SHA-256 */
    unsigned char key_material[32]; // 256 bits for AES-256
    gnutls_hash_fast(GNUTLS_DIG_SHA256, shared_key.data, shared_key.size, key_material);
    gnutls_datum_t aes_key = { key_material, sizeof(key_material) };

    /* Initialize AES-GCM cipher for encryption */
    gnutls_cipher_hd_t handle;
    ret = gnutls_cipher_init(&handle, GNUTLS_CIPHER_AES_256_GCM, &aes_key, &(gnutls_datum_t){ iv, sizeof(iv) });
    if (ret != 0) {
        printf("Error initializing cipher: %s\n", gnutls_strerror(ret));
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Encrypt the data */
    encrypted.size = data.size;
    encrypted.data = gnutls_malloc(encrypted.size);
    if (encrypted.data == NULL) {
        printf("Error allocating memory for encrypted data\n");
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    ret = gnutls_cipher_encrypt2(handle, data.data, data.size, encrypted.data, encrypted.size);
    if (ret != 0) {
        printf("Error encrypting data: %s\n", gnutls_strerror(ret));
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Get authentication tag */
    ret = gnutls_cipher_tag(handle, tag, sizeof(tag));
    if (ret != 0) {
        printf("Error getting authentication tag: %s\n", gnutls_strerror(ret));
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    gnutls_cipher_deinit(handle);

    printf("Data encrypted (size: %d bytes)\n", encrypted.size);
    printf("Encrypted data:\n");
    print_hex(encrypted.data, encrypted.size);
    printf("Authentication tag:\n");
    print_hex(tag, sizeof(tag));

    /* Decrypt the data using the same shared secret */
    printf("Decrypting data...\n");
    
    /* Initialize cipher for decryption */
    ret = gnutls_cipher_init(&handle, GNUTLS_CIPHER_AES_256_GCM, &aes_key, &(gnutls_datum_t){ iv, sizeof(iv) });
    if (ret != 0) {
        printf("Error initializing decryption cipher: %s\n", gnutls_strerror(ret));
        gnutls_free(encrypted.data);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Decrypt the data */
    decrypted.size = encrypted.size;
    decrypted.data = gnutls_malloc(decrypted.size);
    if (decrypted.data == NULL) {
        printf("Error allocating memory for decrypted data\n");
        gnutls_cipher_deinit(handle);
        gnutls_free(encrypted.data);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    ret = gnutls_cipher_decrypt2(handle, encrypted.data, encrypted.size, decrypted.data, decrypted.size);
    if (ret != 0) {
        printf("Error decrypting data: %s\n", gnutls_strerror(ret));
        gnutls_free(decrypted.data);
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Verify authentication tag */
    unsigned char verify_tag[16] = {0};
    ret = gnutls_cipher_tag(handle, verify_tag, sizeof(verify_tag));
    if (ret != 0 || memcmp(tag, verify_tag, sizeof(tag)) != 0) {
        printf("Error: Authentication tag verification failed\n");
        gnutls_free(decrypted.data);
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Convert to null-terminated string for printing */
    char *decrypted_str = malloc(decrypted.size + 1);
    if (decrypted_str == NULL) {
        printf("Error allocating memory for decrypted string\n");
        gnutls_free(decrypted.data);
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }
    memcpy(decrypted_str, decrypted.data, decrypted.size);
    decrypted_str[decrypted.size] = '\0';
    
    printf("Decrypted data: \"%s\"\n", decrypted_str);

    /* Check if decryption was successful */
    if (decrypted.size == data.size && memcmp(decrypted.data, data.data, data.size) == 0) {
        printf("SUCCESS for %s\n", curve_name);
    } else {
        printf("FAILURE for %s: Decrypted data does not match original\n", curve_name);
        free(decrypted_str);
        gnutls_free(decrypted.data);
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Clean up */
    free(decrypted_str);
    gnutls_free(decrypted.data);
    gnutls_free(encrypted.data);
    gnutls_cipher_deinit(handle);
    gnutls_free(shared_key.data);
    gnutls_pubkey_deinit(bob_pubkey);
    gnutls_privkey_deinit(bob_privkey);
    gnutls_pubkey_deinit(alice_pubkey);
    gnutls_privkey_deinit(alice_privkey);
    
    return 0;
}

int main(void) {
    int ret;

    printf("Testing GnuTLS's EC encryption/decryption with multiple curves...\n");

    /* Initialize GnuTLS */
    ret = gnutls_global_init();
    if (ret != 0) {
        printf("Error initializing GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /* Test SECP256R1 (P-256) */
    ret = test_ec_encrypt_decrypt(256, "SECP256R1");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test SECP384R1 (P-384) */
    ret = test_ec_encrypt_decrypt(384, "SECP384R1");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Test SECP521R1 (P-521) */
    ret = test_ec_encrypt_decrypt(521, "SECP521R1");
    if (ret != 0) {
        gnutls_global_deinit();
        return 1;
    }

    /* Clean up global resources */
    gnutls_global_deinit();

    printf("\nAll EC encryption/decryption tests completed successfully!\n");
    return 0;
}
