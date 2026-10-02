/* gnutls_privkey_decrypt_data2() gives the exact plaintext size. A message of
 * any other length, or a ciphertext that does not decrypt, must fail and leave
 * the caller's buffer unchanged: TLS RSA key exchange prefills it with a
 * random premaster and ignores the error.
 */
#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include "test_util.h"

#define BUF_LEN 48

/* How the ciphertext is damaged before decryption. */
#define CT_INTACT   0
#define CT_CORRUPT  1
#define CT_TRUNCATE 2

static int decrypt_len(gnutls_privkey_t priv, gnutls_pubkey_t pub,
    size_t msg_len, int damage, int expect_ok)
{
    unsigned char msg[64], buf[BUF_LEN], prefill[BUF_LEN];
    gnutls_datum_t m = { msg, msg_len }, c = { NULL, 0 };
    size_t i;
    int ret;

    memset(msg, 'P', sizeof(msg));
    ret = gnutls_pubkey_encrypt_data(pub, 0, &m, &c);
    if (ret != 0) {
        print_gnutls_error("encrypting", ret);
        return 1;
    }
    if (damage == CT_CORRUPT) {
        c.data[c.size / 2] ^= 0x01;
    } else if (damage == CT_TRUNCATE) {
        c.size--;
    }

    for (i = 0; i < sizeof(prefill); i++) {
        prefill[i] = (unsigned char)(0xa0 + i);
    }
    memcpy(buf, prefill, sizeof(buf));
    ret = gnutls_privkey_decrypt_data2(priv, 0, &c, buf, sizeof(buf));
    gnutls_free(c.data);
    printf("message %zu bytes%s into %d-byte buffer: %s\n", msg_len,
        damage == CT_CORRUPT ? " (corrupted)" :
        damage == CT_TRUNCATE ? " (truncated)" : "", BUF_LEN,
        ret == 0 ? "decrypted" : gnutls_strerror(ret));

    if (expect_ok) {
        if (ret != 0) {
            printf("FAILURE - exact-length message did not decrypt\n");
            return 1;
        }
        if (memcmp(buf, msg, sizeof(buf)) != 0) {
            printf("FAILURE - decrypted data does not match\n");
            return 1;
        }
        return 0;
    }
    if (ret >= 0) {
        printf("FAILURE - reported as decrypted\n");
        return 1;
    }
    if (memcmp(buf, prefill, sizeof(buf)) != 0) {
        printf("FAILURE - output buffer changed on failure\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    gnutls_privkey_t priv;
    gnutls_pubkey_t pub;
    int ret;

    printf("Testing RSA decrypt_data2 with a mismatched length...\n");

    if ((ret = gnutls_global_init()) != 0 ||
        (ret = gnutls_privkey_init(&priv)) != 0 ||
        (ret = gnutls_privkey_generate(priv, GNUTLS_PK_RSA, 2048, 0)) != 0 ||
        (ret = gnutls_pubkey_init(&pub)) != 0 ||
        (ret = gnutls_pubkey_import_privkey(pub, priv, 0, 0)) != 0) {
        print_gnutls_error("setting up the key", ret);
        return 1;
    }

    if (decrypt_len(priv, pub, BUF_LEN, CT_INTACT, 1) != 0 ||
        decrypt_len(priv, pub, 16, CT_INTACT, 0) != 0 ||
        decrypt_len(priv, pub, 47, CT_INTACT, 0) != 0 ||
        decrypt_len(priv, pub, 64, CT_INTACT, 0) != 0 ||
        decrypt_len(priv, pub, BUF_LEN, CT_CORRUPT, 0) != 0 ||
        decrypt_len(priv, pub, BUF_LEN, CT_TRUNCATE, 0) != 0) {
        return 1;
    }

    gnutls_pubkey_deinit(pub);
    gnutls_privkey_deinit(priv);
    gnutls_global_deinit();
    printf("\nAll RSA decrypt_data2 tests completed successfully!\n");
    return 0;
}
