/* Concurrent EC key generation and ECDSA signing from several threads.
 *
 * The provider shares one DRBG across the process. If two threads use it at
 * once its state is corrupted and they can draw the same output: the same
 * private key, or the same ECDSA nonce (which reveals the key). Nothing fails
 * visibly, so this test records every private scalar and every r value and
 * checks that none repeats; with a working DRBG a repeat has negligible
 * probability.
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include "test_util.h"

#define NUM_THREADS     8
#define VALUE_MAX       72

struct value {
    unsigned char data[VALUE_MAX];
    unsigned int len;
};

static int iterations;
/* One slot per thread and iteration, compared only after all threads joined
 * so that the test adds no synchronization of its own. */
static struct value *priv_values;
static struct value *r_values;

static int record(struct value *v, const gnutls_datum_t *d)
{
    if (d->size == 0 || d->size > VALUE_MAX) {
        return 1;
    }
    memcpy(v->data, d->data, d->size);
    v->len = d->size;
    return 0;
}

static int keygen_and_sign(int slot)
{
    gnutls_privkey_t privkey = NULL;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_datum_t msg = { (unsigned char *)"test message", 12 };
    gnutls_datum_t sig = { NULL, 0 };
    gnutls_datum_t k = { NULL, 0 };
    gnutls_datum_t r = { NULL, 0 };
    gnutls_datum_t s = { NULL, 0 };
    int ret;

    if ((ret = gnutls_privkey_init(&privkey)) < 0 ||
        (ret = gnutls_privkey_generate(privkey, GNUTLS_PK_ECDSA,
            GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0)) < 0 ||
        (ret = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0, &msg,
            &sig)) < 0 ||
        (ret = gnutls_pubkey_init(&pubkey)) < 0 ||
        (ret = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0)) < 0 ||
        (ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_ECDSA_SHA256, 0,
            &msg, &sig)) < 0 ||
        (ret = gnutls_privkey_export_ecc_raw2(privkey, NULL, NULL, NULL, &k,
            0)) < 0 ||
        (ret = gnutls_decode_rs_value(&sig, &r, &s)) < 0) {
        print_gnutls_error("generating, signing or verifying", ret);
        ret = 1;
    }
    else if (record(&priv_values[slot], &k) != 0 ||
             record(&r_values[slot], &r) != 0) {
        fprintf(stderr, "Unexpected private key or r size\n");
        ret = 1;
    }
    else {
        ret = 0;
    }

    gnutls_free(k.data);
    gnutls_free(r.data);
    gnutls_free(s.data);
    gnutls_free(sig.data);
    gnutls_pubkey_deinit(pubkey);
    gnutls_privkey_deinit(privkey);
    return ret;
}

static void *thread_main(void *arg)
{
    int id = *(int *)arg;
    long failed = 0;
    int i;

    for (i = 0; i < iterations; i++) {
        failed += keygen_and_sign(id * iterations + i);
    }

    return (void *)failed;
}

static int value_cmp(const void *a, const void *b)
{
    const struct value *x = a;
    const struct value *y = b;

    if (x->len != y->len) {
        return x->len < y->len ? -1 : 1;
    }
    return memcmp(x->data, y->data, x->len);
}

static int count_repeats(struct value *values, int n)
{
    int repeats = 0;
    int i;

    qsort(values, n, sizeof(*values), value_cmp);
    for (i = 1; i < n; i++) {
        /* Slots of failed operations are empty and counted as failures. */
        if (values[i].len != 0 &&
                value_cmp(&values[i], &values[i - 1]) == 0) {
            repeats++;
        }
    }

    return repeats;
}

int main(int argc, char *argv[])
{
    pthread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    int failed = 0;
    int priv_repeats;
    int r_repeats;
    int ret;
    int i;

    iterations = (argc > 1 && strcmp(argv[1], "-fast") == 0) ? 250 : 1000;

    printf("Testing concurrent EC key generation and ECDSA signing "
        "(%d threads x %d)...\n", NUM_THREADS, iterations);

    ret = gnutls_global_init();
    if (ret != 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    priv_values = calloc(NUM_THREADS * iterations, sizeof(*priv_values));
    r_values = calloc(NUM_THREADS * iterations, sizeof(*r_values));
    if (priv_values == NULL || r_values == NULL) {
        fprintf(stderr, "Allocating memory failed\n");
        return 1;
    }

    for (i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (pthread_create(&threads[i], NULL, thread_main, &ids[i]) != 0) {
            fprintf(stderr, "Creating thread %d failed\n", i);
            return 1;
        }
    }
    for (i = 0; i < NUM_THREADS; i++) {
        void *res;

        pthread_join(threads[i], &res);
        failed += (int)(long)res;
    }

    priv_repeats = count_repeats(priv_values, NUM_THREADS * iterations);
    r_repeats = count_repeats(r_values, NUM_THREADS * iterations);
    printf("operations failed: %d, repeated private keys: %d, "
        "repeated ECDSA r values: %d\n", failed, priv_repeats, r_repeats);

    free(priv_values);
    free(r_values);
    gnutls_global_deinit();

    if (failed != 0 || priv_repeats != 0 || r_repeats != 0) {
        printf("FAILURE - concurrent key generation and signing\n");
        return 1;
    }

    printf("SUCCESS - concurrent key generation and signing\n");
    return 0;
}
