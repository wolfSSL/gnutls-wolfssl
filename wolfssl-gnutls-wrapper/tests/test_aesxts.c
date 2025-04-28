
#include <gnutls/crypto.h>

#include "test_util.h"


const unsigned char key_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x2a, 0x0b, 0x7d, 0xc2, 0x5a, 0x00, 0xbc, 0x65,
    0xd5, 0x25, 0x0b, 0x80, 0x7c, 0x0f, 0x23, 0x85,
};
const unsigned char key_256[] = {
    0x00, 0xa9, 0x9e, 0x4e, 0x75, 0x84, 0x69, 0xc5,
    0x5c, 0xb4, 0xb8, 0xf8, 0xb9, 0x48, 0x7f, 0xde,
    0x7d, 0xd2, 0xbd, 0x5a, 0xb2, 0x45, 0xee, 0x38,
    0x3f, 0x4d, 0x82, 0x0e, 0xe1, 0x46, 0xd9, 0x23,
    0x1a, 0xe8, 0x2b, 0xa6, 0xf2, 0xdb, 0xde, 0x0a,
    0xfb, 0x29, 0xd5, 0x28, 0x34, 0x99, 0x04, 0xb2,
    0xfd, 0x33, 0x39, 0xc4, 0xa8, 0x8c, 0x6b, 0x21,
    0x1f, 0x4d, 0x6c, 0x8c, 0xa2, 0xb8, 0xe1, 0x4f
};
const unsigned char bad_key_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
const unsigned char bad_key_256[] = {
    0x00, 0xa9, 0x9e, 0x4e, 0x75, 0x84, 0x69, 0xc5,
    0x5c, 0xb4, 0xb8, 0xf8, 0xb9, 0x48, 0x7f, 0xde,
    0x7d, 0xd2, 0xbd, 0x5a, 0xb2, 0x45, 0xee, 0x38,
    0x3f, 0x4d, 0x82, 0x0e, 0xe1, 0x46, 0xd9, 0x23,
    0x00, 0xa9, 0x9e, 0x4e, 0x75, 0x84, 0x69, 0xc5,
    0x5c, 0xb4, 0xb8, 0xf8, 0xb9, 0x48, 0x7f, 0xde,
    0x7d, 0xd2, 0xbd, 0x5a, 0xb2, 0x45, 0xee, 0x38,
    0x3f, 0x4d, 0x82, 0x0e, 0xe1, 0x46, 0xd9, 0x23
};

const unsigned char iv_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const unsigned char plaintext_data[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};

const unsigned char expected_ciphertext_128[] = {
    0xc7, 0xfb, 0x5e, 0x76, 0xf1, 0x43, 0x20, 0x29,
    0x48, 0xb2, 0x43, 0x51, 0x47, 0x7e, 0x7a, 0x1f,
    0x69, 0xdb, 0x0a, 0x68, 0xde, 0x4d, 0x7d, 0x0b,
    0x7c, 0x04, 0x40, 0x42, 0x51, 0x27, 0x95, 0x85
};
const unsigned char expected_ciphertext_256[] = {
    0x79, 0xe8, 0x65, 0x70, 0x75, 0xed, 0x55, 0xb8,
    0xf5, 0x3c, 0xec, 0x50, 0x6d, 0x50, 0xdf, 0xf7,
    0x92, 0x05, 0x1c, 0xe1, 0xba, 0x3a, 0x75, 0x10,
    0x63, 0x0c, 0x15, 0x43, 0x3e, 0x9b, 0xa6, 0xd6
};


static int test_aesxts(gnutls_cipher_algorithm_t cipher,
    const unsigned char* key_data, size_t key_data_sz,
    const unsigned char* bad_key_data, size_t bad_key_data_sz,
    const unsigned char* expected_ciphertext, size_t expected_ciphertext_sz)
{
    int ret;
    unsigned char ciphertext[sizeof(plaintext_data)];
    unsigned char decrypted[sizeof(plaintext_data)];
    unsigned char plaintext[sizeof(plaintext_data)];
    gnutls_cipher_hd_t encrypt_handle;
    gnutls_cipher_hd_t decrypt_handle;
    /* Create gnutls_datum_t structures for key and IV */
    gnutls_datum_t key = {
        .data = (unsigned char *)key_data,
        .size = key_data_sz
    };
    gnutls_datum_t iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };
    gnutls_datum_t bad_key = {
        .data = (unsigned char *)bad_key_data,
        .size = bad_key_data_sz
    };
    /* Create a fresh IV for decryption (GnuTLS modifies the IV during
     * operation) */
    gnutls_datum_t decrypt_iv = {
        .data = (unsigned char *)iv_data,
        .size = sizeof(iv_data)
    };

    /* Copy plaintext to a non-const buffer for GnuTLS */
    memcpy(plaintext, plaintext_data, sizeof(plaintext_data));

    /* Try bad key - same data for both keys or key too small. */
    ret = gnutls_cipher_init(&encrypt_handle, cipher, &bad_key, &iv);
    if (gnutls_fips140_mode_enabled() && ret == 0) {
        print_gnutls_error("initializing cipher with bad key", ret);
        return 1;
    }
    if (!gnutls_fips140_mode_enabled() && ret != 0) {
        print_gnutls_error("initializing cipher with bad key", ret);
        return 1;
    }

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-XTS */
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
    /* Decrypt using AES-XTS */
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

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_aesxts(GNUTLS_CIPHER_AES_128_XTS, key_128, sizeof(key_128),
        bad_key_128, sizeof(bad_key_128), expected_ciphertext_128,
        sizeof(expected_ciphertext_128));
    if (ret == 0) {
        ret = test_aesxts(GNUTLS_CIPHER_AES_256_XTS, key_256, sizeof(key_256),
            bad_key_256, sizeof(bad_key_256), expected_ciphertext_256,
            sizeof(expected_ciphertext_256));
    }
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}

