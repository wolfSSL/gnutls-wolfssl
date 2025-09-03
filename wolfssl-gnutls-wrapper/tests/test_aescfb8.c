
#include <gnutls/crypto.h>

#include "test_util.h"


const unsigned char key_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
const unsigned char key_192[] = {
    0x3e, 0x41, 0xf1, 0x17, 0xdc, 0x9e, 0x0f, 0x01,
    0x9b, 0x58, 0x96, 0x4d, 0x29, 0xe3, 0xfe, 0x6b,
    0x60, 0x95, 0x81, 0x02, 0xcc, 0xef, 0xfe, 0x6e,
};
const unsigned char key_256[] = {
    0x00, 0xa9, 0x9e, 0x4e, 0x75, 0x84, 0x69, 0xc5,
    0x5c, 0xb4, 0xb8, 0xf8, 0xb9, 0x48, 0x7f, 0xde,
    0x7d, 0xd2, 0xbd, 0x5a, 0xb2, 0x45, 0xee, 0x38,
    0x3f, 0x4d, 0x82, 0x0e, 0xe1, 0x46, 0xd9, 0x23,
};

const unsigned char iv_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const unsigned char plaintext_data[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e
};

const unsigned char expected_ciphertext_128[] = {
    0x3b, 0x79, 0x42, 0x4c, 0x9c, 0x0d, 0xd4, 0x36,
    0xba, 0xce, 0x9e, 0x0e, 0xd4, 0x58, 0x6a, 0x4f,
    0x32, 0xb9, 0xde, 0xd5, 0x0a, 0xe3, 0xba, 0x69,
    0xd4, 0x72, 0xe8, 0x82, 0x67, 0xfb, 0x50
};
const unsigned char expected_ciphertext_192[] = {
    0x19, 0xc3, 0x5b, 0x0d, 0x21, 0x12, 0xea, 0x54,
    0x75, 0x8c, 0xc9, 0x6a, 0xd4, 0x48, 0x1b, 0xce,
    0x29, 0x2b, 0xb0, 0x45, 0xc0, 0x6b, 0xd3, 0x41,
    0x16, 0x61, 0x73, 0x0c, 0x04, 0xc5, 0x25
};
const unsigned char expected_ciphertext_256[] = {
    0x2b, 0xa3, 0x32, 0x9d, 0xe2, 0x76, 0x46, 0x3f,
    0x15, 0xfa, 0xa8, 0x15, 0x81, 0x6e, 0x0d, 0x7e,
    0xf8, 0x78, 0x56, 0xfd, 0x2e, 0xfd, 0x80, 0x9c,
    0xa7, 0xef, 0x35, 0x9c, 0xe1, 0x22, 0x1b
};


static int test_aescfb8(gnutls_cipher_algorithm_t cipher,
    const unsigned char* key_data, size_t key_data_sz,
    const unsigned char* expected_ciphertext, size_t expected_ciphertext_sz)
{
    int ret;
    unsigned char ciphertext[sizeof(plaintext_data)];
    unsigned char decrypted[sizeof(plaintext_data)];
    unsigned char plaintext[sizeof(plaintext_data)];

    /* Create gnutls_datum_t structures for key and IV */
    gnutls_datum_t key = {
        .data = (unsigned char *)key_data,
        .size = key_data_sz
    };

    gnutls_datum_t iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };

    /* Create a fresh IV for decryption (GnuTLS modifies the IV during
     * operation) */
    gnutls_datum_t decrypt_iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };

    /* Copy plaintext to a non-const buffer for GnuTLS */
    memcpy(plaintext, plaintext_data, sizeof(plaintext_data));

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-CFB8 */
    gnutls_cipher_hd_t encrypt_handle;
    if ((ret = gnutls_cipher_init(&encrypt_handle, cipher, &key, &iv)) < 0) {
        print_gnutls_error("initializing cipher for encryption", ret);
        return 1;
    }

    if ((ret = gnutls_cipher_encrypt(encrypt_handle, plaintext,
            sizeof(plaintext))) < 0) {
        print_gnutls_error("encrypting", ret);
        gnutls_cipher_deinit(encrypt_handle);
        return 1;
    }

    /* Copy the encrypted data to our ciphertext buffer */
    memcpy(ciphertext, plaintext, sizeof(plaintext));

    gnutls_cipher_deinit(encrypt_handle);

    if (compare("Encryption", ciphertext, expected_ciphertext,
            sizeof(ciphertext)) != 0) {
        return 1;
    }

    /********** DECRYPTION TEST **********/
    /* Decrypt using AES-CFB8 */
    gnutls_cipher_hd_t decrypt_handle;
    if ((ret = gnutls_cipher_init(&decrypt_handle, cipher, &key,
            &decrypt_iv)) < 0) {
        print_gnutls_error("initializing cipher for decryption", ret);
        return 1;
    }

    /* Copy ciphertext to a buffer for decryption */
    memcpy(decrypted, ciphertext, sizeof(ciphertext));

    if ((ret = gnutls_cipher_decrypt(decrypt_handle, decrypted,
            sizeof(decrypted))) < 0) {
        print_gnutls_error("decrypting", ret);
        gnutls_cipher_deinit(decrypt_handle);
        return 1;
    }

    gnutls_cipher_deinit(decrypt_handle);

    if (compare("Decryption", decrypted, plaintext_data,
            sizeof(decrypted)) != 0) {
        return 1;
    }

    return 0;
}

int main(void)
{
    int ret;
    int fips_mode;

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    /* Check if FIPS mode is enabled */
    fips_mode = gnutls_fips140_mode_enabled();
    if (fips_mode != 0) {
        printf("This test can be run only when FIPS140 mode is not enabled\n");
        return 0; /* Skip test */
    }

    ret = test_aescfb8(GNUTLS_CIPHER_AES_128_CFB8, key_128, sizeof(key_128),
        expected_ciphertext_128, sizeof(expected_ciphertext_128));
    if (ret == 0) {
        ret = test_aescfb8(GNUTLS_CIPHER_AES_192_CFB8, key_192, sizeof(key_192),
            expected_ciphertext_192, sizeof(expected_ciphertext_192));
    }
    if (ret == 0) {
        ret = test_aescfb8(GNUTLS_CIPHER_AES_256_CFB8, key_256, sizeof(key_256),
            expected_ciphertext_256, sizeof(expected_ciphertext_256));
    }
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}

