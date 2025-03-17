#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/* Test vectors for AES-GCM based on NIST SP 800-38D */
const unsigned char key_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

const unsigned char iv_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
}; // Using 16-byte IV for AES-GCM

const unsigned char plaintext_data[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};

// Optional additional authenticated data (AAD)
const unsigned char aad_data[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef
};

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i != len - 1)
            printf("\n   ");
        else if ((i + 1) % 8 == 0 && i != len - 1)
            printf("  ");
        else if (i != len - 1)
            printf(" ");
    }
    printf("\n");
}

int main(void) {
    int ret;
    unsigned char ciphertext[sizeof(plaintext_data)];
    unsigned char decrypted[sizeof(plaintext_data)];
    unsigned char auth_tag[16]; // 16 bytes is a common tag length for GCM
    unsigned char plaintext[sizeof(plaintext_data)];

    memset(ciphertext, 0, sizeof(plaintext_data));
    memset(decrypted, 0, sizeof(plaintext_data));
    memset(auth_tag, 0, 16);
    memset(plaintext, 0, sizeof(plaintext_data));

    /* Create gnutls_datum_t structures for key and IV */
    gnutls_datum_t key = {
        .data = (unsigned char *)key_128,
        .size = sizeof(key_128)
    };

    gnutls_datum_t iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };

    /* Copy plaintext to a non-const buffer for GnuTLS */
    memcpy(plaintext, plaintext_data, sizeof(plaintext_data));

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        fprintf(stderr, "Failed to initialize GnuTLS: %s\n", gnutls_strerror(ret));
        return 1;
    }

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-128-GCM */
    gnutls_cipher_hd_t encrypt_handle;
    if ((ret = gnutls_cipher_init(&encrypt_handle, GNUTLS_CIPHER_AES_128_GCM,
                                 &key, &iv)) < 0) {
        fprintf(stderr, "Error initializing cipher for encryption: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    /* Set the additional authenticated data (AAD) */
    if ((ret = gnutls_cipher_add_auth(encrypt_handle, aad_data, sizeof(aad_data))) < 0) {
        fprintf(stderr, "Error adding AAD for decryption: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_global_deinit();
        return 1;
    }

    /* Encrypt the plaintext */
    if ((ret = gnutls_cipher_encrypt(encrypt_handle, plaintext, sizeof(plaintext))) < 0) {
        fprintf(stderr, "Error encrypting: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_global_deinit();
        return 1;
    }

    /* Copy the encrypted data to our ciphertext buffer */
    memcpy(ciphertext, plaintext, sizeof(plaintext));

    /* Get the authentication tag */
    if ((ret = gnutls_cipher_tag(encrypt_handle, auth_tag, sizeof(auth_tag))) < 0) {
        fprintf(stderr, "Error getting authentication tag: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(encrypt_handle);
        gnutls_global_deinit();
        return 1;
    }

    gnutls_cipher_deinit(encrypt_handle);

    /********** DECRYPTION TEST **********/
    /* Create a fresh IV for decryption */
    gnutls_datum_t decrypt_iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };

    /* Decrypt using AES-128-GCM */
    gnutls_cipher_hd_t decrypt_handle;
    if ((ret = gnutls_cipher_init(&decrypt_handle, GNUTLS_CIPHER_AES_128_GCM,
                    &key, &decrypt_iv)) < 0) {
        fprintf(stderr, "Error initializing cipher for decryption: %s\n", gnutls_strerror(ret));
        gnutls_global_deinit();
        return 1;
    }

    /* Set the additional authenticated data (AAD) for decryption */
    if ((ret = gnutls_cipher_add_auth(decrypt_handle, aad_data, sizeof(aad_data))) < 0) {
        fprintf(stderr, "Error adding AAD for decryption: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_global_deinit();
        return 1;
    }

    /* Set the authentication tag */
    if ((ret = gnutls_cipher_tag(decrypt_handle, auth_tag, sizeof(auth_tag))) < 0) {
        fprintf(stderr, "Error getting authentication tag for verification: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_global_deinit();
        return 1;
    }

    /* Copy ciphertext to a buffer for decryption */
    memcpy(decrypted, ciphertext, sizeof(ciphertext));

    if ((ret = gnutls_cipher_decrypt(decrypt_handle, decrypted, sizeof(decrypted))) < 0) {
        fprintf(stderr, "Error decrypting: %s\n", gnutls_strerror(ret));
        gnutls_cipher_deinit(decrypt_handle);
        gnutls_global_deinit();
        return 1;
    }

    gnutls_cipher_deinit(decrypt_handle);

    if (memcmp(decrypted, plaintext_data, sizeof(decrypted)) != 0) {
        printf("FAILURE: Decryption output does not match original plaintext.\n");
    } else {
        printf("SUCCESS: Decryption output matches original plaintext.\n");
    }

    gnutls_global_deinit();

    printf("Test completed.\n");
    return 0;
}
