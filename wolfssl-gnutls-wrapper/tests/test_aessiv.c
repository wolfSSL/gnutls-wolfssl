#include <gnutls/crypto.h>
#include <stdlib.h>

#include "test_util.h"


/* Test vector from test_vectors.txt - RFC 5297 Example A.1 */
static int test_aessiv_a1_aead(void)
{
    /* Skip A.1 test when running without provider (GNUTLS_NO_PROVIDER=1)
     * because Nettle requires nonce >= 1 byte, but A.1 uses empty nonce */
    if (getenv("GNUTLS_NO_PROVIDER")) {
        printf("Skipping A.1 test (empty nonce) when GNUTLS_NO_PROVIDER=1 - incompatible with Nettle\n");
        return 0;
    }
    int ret;

    /* From RFC 5297 Example A.1 test vector */
    const unsigned char key[] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    const unsigned char assoc[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };

    const unsigned char plaintext_orig[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
    };

    const unsigned char expected_siv[] = {
        0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93
    };

    const unsigned char expected_ciphertext[] = {
        0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
        0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c
    };

    /* Expected output: SIV (16 bytes) + ciphertext (14 bytes) */
    unsigned char expected_output[30];
    memcpy(expected_output, expected_siv, 16);
    memcpy(expected_output + 16, expected_ciphertext, 14);

    unsigned char ciphertext[sizeof(plaintext_orig) + 16]; /* plaintext + SIV tag */
    unsigned char decrypted[sizeof(plaintext_orig)];
    size_t ciphertext_sz;
    size_t decrypted_sz;
    gnutls_aead_cipher_hd_t encrypt_handle;
    gnutls_aead_cipher_hd_t decrypt_handle;

    /* Create gnutls_datum_t structure for key */
    gnutls_datum_t key_datum = {
        .data = (unsigned char *)key,
        .size = sizeof(key)
    };

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-256-SIV AEAD */
    if ((ret = gnutls_aead_cipher_init(&encrypt_handle, GNUTLS_CIPHER_AES_128_SIV, &key_datum)) != 0) {
        print_gnutls_error("initializing AEAD cipher for encryption", ret);
        return 1;
    }

    /* Encrypt the plaintext with AEAD API */
    ciphertext_sz = sizeof(ciphertext);
    if ((ret = gnutls_aead_cipher_encrypt(encrypt_handle,
            NULL, 0,                                /* nonce, nonce_size (no nonce for A.1) */
            assoc, sizeof(assoc),                   /* aad, aad_size */
            16,                                     /* tag_size (SIV is 16 bytes) */
            plaintext_orig, sizeof(plaintext_orig), /* plaintext, plaintext_size */
            ciphertext, &ciphertext_sz)) < 0) {     /* output, output_size */
        print_gnutls_error("AEAD encrypting", ret);
        gnutls_aead_cipher_deinit(encrypt_handle);
        return 1;
    }

    gnutls_aead_cipher_deinit(encrypt_handle);

    if (compare_sz("Encryption A.1", ciphertext, ciphertext_sz, expected_output,
            sizeof(expected_output)) != 0) {
        return 1;
    }

    /********** DECRYPTION TEST **********/
    /* Decrypt using AES-128-SIV AEAD */
    if ((ret = gnutls_aead_cipher_init(&decrypt_handle, GNUTLS_CIPHER_AES_128_SIV, &key_datum)) < 0) {
        print_gnutls_error("initializing AEAD cipher for decryption", ret);
        return 1;
    }

    /* Decrypt the ciphertext (including SIV tag) */
    decrypted_sz = sizeof(decrypted);
    if ((ret = gnutls_aead_cipher_decrypt(decrypt_handle,
            NULL, 0,                      /* nonce, nonce_size (no nonce for A.1) */
            assoc, sizeof(assoc),         /* aad, aad_size */
            16,                           /* tag_size (SIV is 16 bytes) */
            ciphertext, ciphertext_sz,    /* ciphertext, ciphertext_size */
            decrypted, &decrypted_sz)) < 0) { /* output, output_size */
        print_gnutls_error("AEAD decrypting", ret);
        gnutls_aead_cipher_deinit(decrypt_handle);
        return 1;
    }

    gnutls_aead_cipher_deinit(decrypt_handle);

    if (compare_sz("Decryption A.1", decrypted, decrypted_sz, plaintext_orig,
            sizeof(plaintext_orig)) != 0) {
        return 1;
    }

    return 0;
}

/* Test vector from test_vectors.txt - RFC 5297 Example A.2 */
static int test_aessiv_a2_aead(void)
{
    int ret;

    /* From RFC 5297 Example A.2 test vector */
    const unsigned char key[] = {
        0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78,
        0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };

    const unsigned char nonce_data[] = {
        0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b,
        0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0
    };

    const unsigned char assoc1[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xda, 0xda, 0xde, 0xad, 0xda, 0xda,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };

    const unsigned char assoc2[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0
    };

    /* Concatenated AAD for AEAD API */
    unsigned char aad_combined[sizeof(assoc1) + sizeof(assoc2)];
    memcpy(aad_combined, assoc1, sizeof(assoc1));
    memcpy(aad_combined + sizeof(assoc1), assoc2, sizeof(assoc2));

    const unsigned char plaintext_orig[] = {
        0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x73, 0x6f, 0x6d, 0x65, 0x20, 0x70, 0x6c, 0x61,
        0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x74,
        0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20,
        0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53
    };

    /* Expected values for GnuTLS concatenated AAD approach (not RFC 5297 A.2) */
    const unsigned char expected_siv[] = {
        0xb9, 0x37, 0xae, 0xcb, 0xbb, 0x18, 0xaa, 0x98,
        0x29, 0xf8, 0x6c, 0xb7, 0xaf, 0x93, 0x73, 0x35
    };

    const unsigned char expected_ciphertext[] = {
        0xf2, 0xcb, 0xb1, 0x5b, 0xf9, 0x49, 0xde, 0x93,
        0xcc, 0xa5, 0x5a, 0x26, 0xb5, 0xb3, 0xec, 0x8d,
        0x1f, 0x80, 0x70, 0x46, 0x96, 0xe0, 0xf3, 0xd7,
        0xce, 0xdf, 0x28, 0xed, 0x73, 0x34, 0x59, 0xd9,
        0x23, 0xec, 0x69, 0x6c, 0x66, 0x14, 0x66, 0x79,
        0x10, 0x4d, 0xe0, 0x23, 0x52, 0x0a, 0xc5
    };

    /* Expected output: SIV (16 bytes) + ciphertext (47 bytes) */
    unsigned char expected_output[63];
    memcpy(expected_output, expected_siv, 16);
    memcpy(expected_output + 16, expected_ciphertext, 47);

    unsigned char ciphertext[sizeof(plaintext_orig) + 16]; /* plaintext + SIV tag */
    unsigned char decrypted[sizeof(plaintext_orig)];
    size_t ciphertext_sz;
    size_t decrypted_sz;
    gnutls_aead_cipher_hd_t encrypt_handle;
    gnutls_aead_cipher_hd_t decrypt_handle;

    /* Create gnutls_datum_t structure for key */
    gnutls_datum_t key_datum = {
        .data = (unsigned char *)key,
        .size = sizeof(key)
    };

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-128-SIV AEAD */
    if ((ret = gnutls_aead_cipher_init(&encrypt_handle, GNUTLS_CIPHER_AES_128_SIV, &key_datum)) != 0) {
        print_gnutls_error("initializing AEAD cipher for encryption", ret);
        return 1;
    }

    /* Encrypt the plaintext with AEAD API */
    ciphertext_sz = sizeof(ciphertext);
    if ((ret = gnutls_aead_cipher_encrypt(encrypt_handle,
            nonce_data, sizeof(nonce_data),         /* nonce, nonce_size */
            aad_combined, sizeof(aad_combined),     /* aad, aad_size */
            16,                                     /* tag_size (SIV is 16 bytes) */
            plaintext_orig, sizeof(plaintext_orig), /* plaintext, plaintext_size */
            ciphertext, &ciphertext_sz)) < 0) {     /* output, output_size */
        print_gnutls_error("AEAD encrypting", ret);
        gnutls_aead_cipher_deinit(encrypt_handle);
        return 1;
    }

    gnutls_aead_cipher_deinit(encrypt_handle);

    if (compare_sz("Encryption A.2", ciphertext, ciphertext_sz, expected_output,
            sizeof(expected_output)) != 0) {
        return 1;
    }

    /********** DECRYPTION TEST **********/
    /* Decrypt using AES-128-SIV AEAD */
    if ((ret = gnutls_aead_cipher_init(&decrypt_handle, GNUTLS_CIPHER_AES_128_SIV, &key_datum)) < 0) {
        print_gnutls_error("initializing AEAD cipher for decryption", ret);
        return 1;
    }

    /* Decrypt the ciphertext (including SIV tag) */
    decrypted_sz = sizeof(decrypted);
    if ((ret = gnutls_aead_cipher_decrypt(decrypt_handle,
            nonce_data, sizeof(nonce_data),       /* nonce, nonce_size */
            aad_combined, sizeof(aad_combined),   /* aad, aad_size */
            16,                                   /* tag_size (SIV is 16 bytes) */
            ciphertext, ciphertext_sz,            /* ciphertext, ciphertext_size */
            decrypted, &decrypted_sz)) < 0) {     /* output, output_size */
        print_gnutls_error("AEAD decrypting", ret);
        gnutls_aead_cipher_deinit(decrypt_handle);
        return 1;
    }

    gnutls_aead_cipher_deinit(decrypt_handle);

    if (compare_sz("Decryption A.2", decrypted, decrypted_sz, plaintext_orig,
            sizeof(plaintext_orig)) != 0) {
        return 1;
    }

    return 0;
}

int main(void)
{
    int ret;

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_aessiv_a1_aead();
    if (ret != 0) {
        printf("failed test_aessiv_a1");
        return 1;
    }

    ret = test_aessiv_a2_aead();
    if (ret != 0) {
        printf("failed test_aessiv_a2");
        return 1;
    }

    printf("Test completed.\n");
    gnutls_global_deinit();

    return ret;
}
