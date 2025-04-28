
#include <gnutls/crypto.h>

#include "test_util.h"


/* Test vectors for AES-GCM based on NIST SP 800-38D */
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


const unsigned char nonce_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b
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

const unsigned char ciphertext_128_data[] = {
    0x30, 0x0e, 0x85, 0xb4, 0x96, 0x28, 0x11, 0xd4,
    0x09, 0xe5, 0x6a, 0x97, 0xd1, 0x1a, 0xa3, 0xbd,
    0xa5, 0x17, 0x8b, 0xa1, 0x53, 0xda, 0xf8, 0x4e,
    0x9b, 0xbd, 0xfa, 0x0b, 0x79, 0x99, 0xdb, 0x66,
    0x67, 0xec, 0xd6, 0x9d, 0x4f, 0x1f, 0x71, 0xfe,
    0x52, 0x50, 0xc8, 0xe0, 0x6d, 0xc9, 0xdc, 0x07
};
const unsigned char ciphertext_192_data[] = {
    0xa0, 0xd5, 0x12, 0xdf, 0x57, 0x7b, 0x0f, 0xde,
    0xca, 0x5a, 0xed, 0xc1, 0x49, 0xf2, 0xe6, 0x42,
    0xa5, 0xd7, 0xe0, 0xda, 0x9e, 0x43, 0x81, 0x47,
    0x01, 0xde, 0xb7, 0x49, 0xc0, 0xa1, 0x53, 0x29,
    0xe3, 0x09, 0xf3, 0xe2, 0xd3, 0xe6, 0xbf, 0xec,
    0x1f, 0xa8, 0x70, 0x9d, 0xb4, 0xc3, 0xcf, 0x10
};
const unsigned char ciphertext_256_data[] = {
    0x54, 0xb8, 0x0d, 0x59, 0x6c, 0xfa, 0x15, 0x06,
    0x1e, 0x63, 0x60, 0xbe, 0x57, 0xdb, 0x65, 0x8e,
    0x57, 0x61, 0xb2, 0x1d, 0xc6, 0x6c, 0x74, 0x65,
    0x98, 0x8a, 0x85, 0xbf, 0xd8, 0x04, 0x26, 0xac,
    0x4a, 0xb4, 0x89, 0x10, 0x6b, 0x1b, 0x99, 0x3d,
    0x92, 0xd0, 0xda, 0x54, 0x6d, 0x9b, 0x76, 0xa0
};


static int test_aesgcm(gnutls_cipher_algorithm_t cipher,
    const unsigned char* key_data, size_t key_data_sz,
    const unsigned char* ciphertext_data, size_t ciphertext_data_sz,
    const unsigned char* tag_data, size_t tag_data_sz)
{
    int ret;
    unsigned char ciphertext[sizeof(plaintext_data)];
    unsigned char decrypted[sizeof(plaintext_data)];
    unsigned char auth_tag[16]; // 16 bytes is a common tag length for GCM
    unsigned char plaintext[sizeof(plaintext_data)];

    /* Create gnutls_datum_t structures for key and IV */
    gnutls_datum_t key = {
        .data = (unsigned char *)key_data,
        .size = key_data_sz
    };

    gnutls_datum_t nonce = {
        .data = (unsigned char *)nonce_data,
        .size = sizeof(nonce_data)
    };

    /* Create a fresh IV for decryption */
    gnutls_datum_t decrypt_nonce = {
        .data = (unsigned char *)nonce_data,
        .size = sizeof(nonce_data)
    };

    memset(ciphertext, 0, sizeof(plaintext_data));
    memset(decrypted, 0, sizeof(plaintext_data));
    memset(auth_tag, 0, 16);
    memset(plaintext, 0, sizeof(plaintext_data));

    /* Copy plaintext to a non-const buffer for GnuTLS */
    memcpy(plaintext, plaintext_data, sizeof(plaintext_data));

    /********** ENCRYPTION TEST **********/
    /* Encrypt using AES-128-GCM */
    gnutls_cipher_hd_t encrypt_handle;
    if ((ret = gnutls_cipher_init(&encrypt_handle, cipher, &key, &nonce)) < 0) {
        print_gnutls_error("initializing cipher for encryption", ret);
        return 1;
    }

    /* Set the additional authenticated data (AAD) */
    if ((ret = gnutls_cipher_add_auth(encrypt_handle, aad_data,
            sizeof(aad_data))) < 0) {
        print_gnutls_error("adding AAD for encryption", ret);
        gnutls_cipher_deinit(encrypt_handle);
        return 1;
    }

    /* Encrypt the plaintext */
    if ((ret = gnutls_cipher_encrypt(encrypt_handle, plaintext,
            sizeof(plaintext))) < 0) {
        print_gnutls_error("encrypting", ret);
        gnutls_cipher_deinit(encrypt_handle);
        return 1;
    }

    /* Copy the encrypted data to our ciphertext buffer */
    memcpy(ciphertext, plaintext, sizeof(plaintext));

    /* Get the authentication tag */
    if ((ret = gnutls_cipher_tag(encrypt_handle, auth_tag,
            sizeof(auth_tag))) < 0) {
        print_gnutls_error("getting authentication tag", ret);
        gnutls_cipher_deinit(encrypt_handle);
        return 1;
    }

    gnutls_cipher_deinit(encrypt_handle);

    if (compare("Encryption", ciphertext, ciphertext_data,
            ciphertext_data_sz) != 0) {
        return 1;
    }
    if (compare("Tag generation", auth_tag, tag_data, tag_data_sz) != 0) {
        return 1;
    }

    /********** DECRYPTION TEST **********/
    /* Decrypt using AES-128-GCM */
    gnutls_cipher_hd_t decrypt_handle;
    if ((ret = gnutls_cipher_init(&decrypt_handle, cipher, &key,
            &decrypt_nonce)) < 0) {
        print_gnutls_error("initializing cipher for decryption", ret);
        return 1;
    }

    /* Set the additional authenticated data (AAD) for decryption */
    if ((ret = gnutls_cipher_add_auth(decrypt_handle, aad_data,
            sizeof(aad_data))) < 0) {
        print_gnutls_error("adding AAD for decryption", ret);
        gnutls_cipher_deinit(decrypt_handle);
        return 1;
    }

    /* Set the authentication tag */
    if ((ret = gnutls_cipher_tag(decrypt_handle, auth_tag,
            sizeof(auth_tag))) < 0) {
        print_gnutls_error("setting authentication tag for verification", ret);
        gnutls_cipher_deinit(decrypt_handle);
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

    printf("Test completed.\n");
    return 0;
}

static int test_aesgcm_aead(gnutls_cipher_algorithm_t cipher,
    const unsigned char* key_data, size_t key_data_sz,
    const unsigned char* ciphertext_data, size_t ciphertext_data_sz)
{
    int ret;
    unsigned char ciphertext[sizeof(plaintext_data) + 16];
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

int main(void) {
    int ret;

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_aesgcm(GNUTLS_CIPHER_AES_128_GCM, key_128, sizeof(key_128),
        ciphertext_128_data, sizeof(ciphertext_128_data) - 16,
        ciphertext_128_data + sizeof(ciphertext_128_data) - 16, 16);
    if (ret == 0) {
        ret = test_aesgcm_aead(GNUTLS_CIPHER_AES_128_GCM, key_128,
            sizeof(key_128), ciphertext_128_data, sizeof(ciphertext_128_data));
    }
    if (ret == 0) {
        ret = test_aesgcm(GNUTLS_CIPHER_AES_192_GCM, key_192, sizeof(key_192),
            ciphertext_192_data, sizeof(ciphertext_192_data) - 16,
            ciphertext_192_data + sizeof(ciphertext_192_data) - 16, 16);
    }
    if (ret == 0) {
        ret = test_aesgcm_aead(GNUTLS_CIPHER_AES_192_GCM, key_192,
            sizeof(key_192), ciphertext_192_data, sizeof(ciphertext_192_data));
    }
    if (ret == 0) {
        ret = test_aesgcm(GNUTLS_CIPHER_AES_256_GCM, key_256, sizeof(key_256),
            ciphertext_256_data, sizeof(ciphertext_256_data) - 16,
            ciphertext_256_data + sizeof(ciphertext_256_data) - 16, 16);
    }
    if (ret == 0) {
        ret = test_aesgcm_aead(GNUTLS_CIPHER_AES_256_GCM, key_256,
            sizeof(key_256), ciphertext_256_data, sizeof(ciphertext_256_data));
    }
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}
