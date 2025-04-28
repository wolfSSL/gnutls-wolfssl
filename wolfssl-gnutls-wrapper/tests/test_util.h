
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>


void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s:\n    ", label);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", data[i]);
        if (i != len - 1)
            printf(",");
        if ((i+1) % 8 == 0 && i != len - 1)
            printf("\n    ");
        else if (i != len - 1)
            printf(" ");
    }
    printf("\n");
}

int compare_sz(const char* op, const unsigned char* output, size_t sz,
    const unsigned char* expected, size_t exp_sz)
{
    print_hex("Output", output, sz);

    if (sz != exp_sz) {
        printf("FAILURE - %s result size does not match expected size: "
            "%ld != %ld\n", op, sz, exp_sz);
        return 1;
    }

    if (memcmp(output, expected, sz) == 0) {
        printf("SUCCESS - %s using wolfSSL provider completed correctly\n", op);
    } else {
        print_hex("Expected", expected, exp_sz);
        printf("FAILURE - %s result does not match expected value\n", op);
        return 1;
    }

    return 0;
}

int compare(const char* op, const unsigned char* output,
    const unsigned char* expected, size_t sz)
{
    return compare_sz(op, output, sz, expected, sz);
}

void print_gnutls_error(const char* op, int ret)
{
    fprintf(stderr, "Error %s: %s (%d)\n", op, gnutls_strerror(ret), ret);
}

