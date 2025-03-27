#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <stdlib.h>
#include <dlfcn.h>

/* NIST test vector AAD */
const unsigned char aad_data[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef
};

const unsigned char iv_data[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* HKDF parameters */
const char hkdf_salt[] = "ECDH-Key-Derivation-Salt";
const char hkdf_info[] = "AES-256-GCM-Encryption-Key";

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
    ret = gnutls_privkey_generate2(alice_privkey, GNUTLS_PK_ECDSA, bits, 0, NULL, 0);
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

    /* Derive AES key using HKDF */
    
    /* Step 1: HKDF-Extract to get pseudorandom key */
    unsigned char prk[32]; /* Size based on SHA-256 output */
    const gnutls_datum_t salt = { (unsigned char *)hkdf_salt, strlen(hkdf_salt) };
    const gnutls_datum_t key_datum = { shared_key.data, shared_key.size };
    
    ret = gnutls_hkdf_extract(GNUTLS_MAC_SHA256, &key_datum, &salt, prk);
    if (ret < 0) {
        printf("Error in HKDF-Extract: %s\n", gnutls_strerror(ret));
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }
    
    printf("HKDF-Extract PRK:\n");
    print_hex(prk, sizeof(prk));
    
    /* Step 2: HKDF-Expand to get final key */
    unsigned char key_material[32]; /* 256 bits for AES-256 */
    const gnutls_datum_t prk_datum = { prk, sizeof(prk) };
    const gnutls_datum_t info = { (unsigned char *)hkdf_info, strlen(hkdf_info) };
    
    ret = gnutls_hkdf_expand(GNUTLS_MAC_SHA256, &prk_datum, &info, key_material, sizeof(key_material));
    if (ret < 0) {
        printf("Error in HKDF-Expand: %s\n", gnutls_strerror(ret));
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }
    
    printf("Derived AES key:\n");
    print_hex(key_material, sizeof(key_material));
    
    gnutls_datum_t aes_key = { key_material, sizeof(key_material) };
    
    /* Create datum for IV */
    gnutls_datum_t iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };

    /********** ENCRYPTION **********/
    /* Initialize AES-GCM cipher for encryption */
    gnutls_cipher_hd_t encrypt_handle;
    ret = gnutls_cipher_init(&encrypt_handle, GNUTLS_CIPHER_AES_256_GCM, &aes_key, &iv);
    if (ret != 0) {
        printf("Error initializing cipher for encryption: %s\n", gnutls_strerror(ret));
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Set the additional authenticated data (AAD) */
    ret = gnutls_cipher_add_auth(encrypt_handle, aad_data, sizeof(aad_data));
    if (ret != 0) {
        printf("Error adding AAD for encryption: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Allocate memory for encrypted data */
    encrypted.size = data.size;
    encrypted.data = gnutls_malloc(encrypted.size);
    if (encrypted.data == NULL) {
        printf("Error allocating memory for encrypted data\n");
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Copy original data for in-place encryption */
    memcpy(encrypted.data, data.data, data.size);

    /* Encrypt the data in-place */
    ret = gnutls_cipher_encrypt(encrypt_handle, encrypted.data, encrypted.size);
    if (ret != 0) {
        printf("Error encrypting data: %s\n", gnutls_strerror(ret));
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Get authentication tag */
    ret = gnutls_cipher_tag(encrypt_handle, tag, sizeof(tag));
    if (ret != 0) {
        printf("Error getting authentication tag: %s\n", gnutls_strerror(ret));
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    gnutls_cipher_deinit(encrypt_handle);

    printf("Data encrypted (size: %d bytes)\n", encrypted.size);
    printf("Encrypted data:\n");
    print_hex(encrypted.data, encrypted.size);
    printf("Authentication tag:\n");
    print_hex(tag, sizeof(tag));

    /********** DECRYPTION **********/
    /* Initialize cipher for decryption with same parameters */
    gnutls_cipher_hd_t decrypt_handle;
    ret = gnutls_cipher_init(&decrypt_handle, GNUTLS_CIPHER_AES_256_GCM, &aes_key, &iv);
    if (ret != 0) {
        printf("Error initializing cipher for decryption: %s\n", gnutls_strerror(ret));
        gnutls_free(encrypted.data);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Set the same AAD for decryption */
    ret = gnutls_cipher_add_auth(decrypt_handle, aad_data, sizeof(aad_data));
    if (ret != 0) {
        printf("Error adding AAD for decryption: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_free(encrypted.data);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Set the authentication tag for verification */
    ret = gnutls_cipher_tag(decrypt_handle, tag, sizeof(tag));
    if (ret != 0) {
        printf("Error setting authentication tag for verification: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_free(encrypted.data);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Allocate memory for decrypted data */
    decrypted.size = encrypted.size;
    decrypted.data = gnutls_malloc(decrypted.size);
    if (decrypted.data == NULL) {
        printf("Error allocating memory for decrypted data\n");
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_free(encrypted.data);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    /* Copy encrypted data for in-place decryption */
    memcpy(decrypted.data, encrypted.data, encrypted.size);

    /* Decrypt the data in-place */
    printf("Decrypting data...\n");
    ret = gnutls_cipher_decrypt(decrypt_handle, decrypted.data, decrypted.size);
    if (ret != 0) {
        printf("Error decrypting data: %s\n", gnutls_strerror(ret));
        gnutls_free(decrypted.data);
        gnutls_free(encrypted.data);
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_free(shared_key.data);
        gnutls_pubkey_deinit(bob_pubkey);
        gnutls_privkey_deinit(bob_privkey);
        gnutls_pubkey_deinit(alice_pubkey);
        gnutls_privkey_deinit(alice_privkey);
        return 1;
    }

    gnutls_cipher_deinit(decrypt_handle);

    /* Convert to null-terminated string for printing */
    char *decrypted_str = malloc(decrypted.size + 1);
    if (decrypted_str == NULL) {
        printf("Error allocating memory for decrypted string\n");
        gnutls_free(decrypted.data);
        gnutls_free(encrypted.data);
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
