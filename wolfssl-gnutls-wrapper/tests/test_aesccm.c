
#include <gnutls/crypto.h>

#include "test_util.h"


/* Test vectors for AES-CCM based on NIST SP 800-38C */
const unsigned char key_128_data[] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};
const unsigned char key_256_data[] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
};


/* Using 7-byte nonce for AES-CCM */
const unsigned char nonce_data[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
};

const unsigned char plaintext_data[] = {
    0x20, 0x21, 0x22, 0x23
};

/* Optional additional authenticated data (AAD) */
const unsigned char aad_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

const unsigned char ciphertext_128_data[] = {
    0x71, 0x62, 0x01, 0x5b, 0xba, 0x03, 0xbf, 0x8c,
    0xe0, 0xd6, 0x00, 0xa4, 0x48, 0x6f, 0xcc, 0xb3
};
const unsigned char ciphertext_256_data[] = {
    0x8a, 0xb1, 0xa8, 0x74, 0x21, 0xd3, 0xf7, 0xd7,
    0xe5, 0x5e, 0xc1, 0xfb, 0xae, 0x46, 0x93, 0xf5
};
const unsigned char ciphertext_8_128_data[] = {
    0x71, 0x62, 0x01, 0x5b, 0xd0, 0xad, 0x86, 0xfd,
    0x33, 0xc2, 0x69, 0x86
};
const unsigned char ciphertext_8_256_data[] = {
    0x8a, 0xb1, 0xa8, 0x74, 0x65, 0xee, 0x91, 0xc1,
    0x83, 0xbd, 0x74, 0x7f
};


static int test_aesccm(gnutls_cipher_algorithm_t cipher,
    const unsigned char* key_data, size_t key_data_sz,
    const unsigned char* ciphertext_data, size_t ciphertext_data_sz)
{
    int ret;
    unsigned char ciphertext[ciphertext_data_sz];
    unsigned char decrypted[sizeof(plaintext_data)];
    size_t ciphertext_sz;
    size_t decrypted_sz;
    gnutls_aead_cipher_hd_t encrypt_handle;
    gnutls_aead_cipher_hd_t decrypt_handle;

    /* Create gnutls_datum_t structures for key */
    gnutls_datum_t key = {
        .data = (unsigned char *)key_data,
        .size = key_data_sz
    };

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-128-CCM */
    if ((ret = gnutls_aead_cipher_init(&encrypt_handle, cipher, &key)) != 0) {
        print_gnutls_error("initializing cipher for encryption", ret);
        return 1;
    }

    /* Encrypt the plaintext */
    ciphertext_sz = sizeof(ciphertext);
    if ((ret = gnutls_aead_cipher_encrypt(encrypt_handle, nonce_data,
            sizeof(nonce_data), aad_data, sizeof(aad_data), ciphertext_data_sz -
            sizeof(plaintext_data), plaintext_data, sizeof(plaintext_data),
            ciphertext, &ciphertext_sz)) < 0) {
        print_gnutls_error("encrypting", ret);
        gnutls_aead_cipher_deinit(encrypt_handle);
        return 1;
    }

    gnutls_aead_cipher_deinit(encrypt_handle);

    if (compare_sz("Encryption", ciphertext, ciphertext_sz, ciphertext_data,
            ciphertext_data_sz) != 0) {
        return 1;
    }

    /********** DECRYPTION TEST **********/
    /* Decrypt using AES-128-CCM */
    if ((ret = gnutls_aead_cipher_init(&decrypt_handle, cipher, &key)) < 0) {
        print_gnutls_error("initializing cipher for decryption", ret);
        return 1;
    }

    /* Decrypt the ciphertext (including appended tag) */
    decrypted_sz = sizeof(decrypted);
    if ((ret = gnutls_aead_cipher_decrypt(decrypt_handle, nonce_data,
            sizeof(nonce_data), aad_data, sizeof(aad_data), ciphertext_data_sz -
            sizeof(plaintext_data), ciphertext, ciphertext_sz, decrypted,
            &decrypted_sz)) < 0) {
        print_gnutls_error("decrypting", ret);
        gnutls_aead_cipher_deinit(decrypt_handle);
        return 1;
    }

    gnutls_aead_cipher_deinit(decrypt_handle);

    if (compare_sz("Decryption", decrypted, decrypted_sz, plaintext_data,
            sizeof(decrypted)) != 0) {
        return 1;
    }

    return 0;
}

int main()
{
    int ret;

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_aesccm(GNUTLS_CIPHER_AES_128_CCM, key_128_data,
        sizeof(key_128_data), ciphertext_128_data, sizeof(ciphertext_128_data));
    if (ret == 0) {
        ret = test_aesccm(GNUTLS_CIPHER_AES_256_CCM, key_256_data,
            sizeof(key_256_data), ciphertext_256_data,
            sizeof(ciphertext_256_data));
    }
    if (ret == 0) {
        ret = test_aesccm(GNUTLS_CIPHER_AES_128_CCM_8, key_128_data,
            sizeof(key_128_data), ciphertext_8_128_data,
            sizeof(ciphertext_8_128_data));
    }
    if (ret == 0) {
        ret = test_aesccm(GNUTLS_CIPHER_AES_256_CCM_8, key_256_data,
            sizeof(key_256_data), ciphertext_8_256_data,
            sizeof(ciphertext_8_256_data));
    }
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}

