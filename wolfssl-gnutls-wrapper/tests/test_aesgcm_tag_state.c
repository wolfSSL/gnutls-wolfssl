/* AES-GCM tag after a one-shot decrypt on the same AEAD handle.
 *
 * GnuTLS calls the provider's tag callback to obtain the tag it compares with
 * the received one. If a one-shot gnutls_aead_cipher_decrypt() leaves the
 * handle in a state where the callback takes the tag as input, a following
 * gnutls_aead_cipher_decryptv2() with no ciphertext accepts any tag over any
 * AAD.
 *
 * Expected values from pyca/cryptography AESGCM: key 0^16, nonce 01 00^11,
 * AAD 'A' x 20; plaintext 'M' x 32, and the empty plaintext.
 */
#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "test_util.h"

static const unsigned char ct_tag[48] = {
    0x47, 0x60, 0x91, 0xab, 0x06, 0x70, 0x21, 0x40, 0xb7, 0x78, 0x73, 0x0e,
    0x6b, 0x7a, 0x2c, 0x15, 0x7b, 0x67, 0x6e, 0xfc, 0x7a, 0xad, 0x73, 0x27,
    0xe5, 0x86, 0x1c, 0x69, 0x27, 0x63, 0xc0, 0x66, 0x7e, 0x46, 0x77, 0x35,
    0xc6, 0x67, 0x19, 0x2e, 0xc6, 0x94, 0xff, 0xa4, 0x74, 0x3e, 0xc6, 0x96
};
static const unsigned char aad_tag[16] = {
    0x0e, 0xea, 0x6f, 0x5e, 0xa5, 0x99, 0xa4, 0x4a, 0xd5, 0xa3, 0x94, 0xfe,
    0xec, 0x67, 0x9d, 0xb9
};

int main(void)
{
    unsigned char key_data[16] = { 0 }, nonce[12] = { 1 }, aad[20], msg[32];
    unsigned char out[48], pt[48], tag[16], zero[16] = { 0 };
    unsigned char evil[] = "attacker header";
    gnutls_datum_t key = { key_data, sizeof(key_data) };
    gnutls_aead_cipher_hd_t h;
    giovec_t a = { aad, sizeof(aad) }, e = { evil, sizeof(evil) - 1 };
    size_t len, tag_len;
    int ret;

    printf("Testing AES-GCM tags after a one-shot decrypt...\n");

    memset(aad, 'A', sizeof(aad));
    memset(msg, 'M', sizeof(msg));
    if ((ret = gnutls_global_init()) != 0 ||
        (ret = gnutls_aead_cipher_init(&h, GNUTLS_CIPHER_AES_128_GCM, &key)) != 0) {
        print_gnutls_error("initializing", ret);
        return 1;
    }

    len = sizeof(out);
    ret = gnutls_aead_cipher_encrypt(h, nonce, sizeof(nonce), aad, sizeof(aad),
        16, msg, sizeof(msg), out, &len);
    if (ret != 0 || compare_sz("AES-GCM encrypt", out, len, ct_tag,
            sizeof(ct_tag)) != 0) {
        return 1;
    }

    /* One-shot decrypt, then a forged empty message on the same handle. */
    len = sizeof(pt);
    ret = gnutls_aead_cipher_decrypt(h, nonce, sizeof(nonce), aad, sizeof(aad),
        16, ct_tag, sizeof(ct_tag), pt, &len);
    if (ret != 0) {
        print_gnutls_error("one-shot decrypt", ret);
        return 1;
    }
    ret = gnutls_aead_cipher_decryptv2(h, nonce, sizeof(nonce), &e, 1, NULL, 0,
        zero, sizeof(zero));
    if (ret == 0) {
        printf("FAILURE - forged tag accepted after a one-shot decrypt\n");
        return 1;
    }

    /* The correct tag over the AAD alone must still verify. */
    len = sizeof(pt);
    gnutls_aead_cipher_decrypt(h, nonce, sizeof(nonce), aad, sizeof(aad), 16,
        ct_tag, sizeof(ct_tag), pt, &len);
    ret = gnutls_aead_cipher_decryptv2(h, nonce, sizeof(nonce), &a, 1, NULL, 0,
        (void *)aad_tag, sizeof(aad_tag));
    if (ret != 0) {
        print_gnutls_error("correct tag after a one-shot decrypt", ret);
        return 1;
    }

    /* An empty encryption after a decrypt returns the tag over the AAD. */
    len = sizeof(pt);
    gnutls_aead_cipher_decrypt(h, nonce, sizeof(nonce), aad, sizeof(aad), 16,
        ct_tag, sizeof(ct_tag), pt, &len);
    memset(tag, 0xaa, sizeof(tag));
    tag_len = sizeof(tag);
    ret = gnutls_aead_cipher_encryptv2(h, nonce, sizeof(nonce), &a, 1, NULL, 0,
        tag, &tag_len);
    if (ret != 0 || compare_sz("AES-GCM tag of the AAD alone", tag, tag_len,
            aad_tag, sizeof(aad_tag)) != 0) {
        return 1;
    }

    gnutls_aead_cipher_deinit(h);
    gnutls_global_deinit();
    printf("\nAll AES-GCM tag tests completed successfully!\n");
    return 0;
}
