
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gnutls/crypto.h>

#include "test_util.h"

#define RANDOM_FILENAME     "random"
#define RANDOM_SZ           64

int test_rnd_write(const char* filename, unsigned char* buf, size_t sz)
{
    int ret;
    FILE* fp;

    fp = fopen(filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return 1;
    }

    fwrite(buf, 1, sz, fp);
    fclose(fp);
}

int test_rnd_read(const char* filename, unsigned char* buf, size_t sz)
{
    int ret;
    FILE* fp;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return 1;
    }

    sz = fread(buf, 1, sz, fp);
    fclose(fp);
}

int test_rnd_fork_level(gnutls_rnd_level_t level)
{
    int ret;
    pid_t pid;

    pid = fork();

    if (pid == 0) {
        unsigned char buf[RANDOM_SZ];

        /* Child */
        ret = gnutls_rnd(level, buf, sizeof(buf));
        if (ret != 0) {
            print_gnutls_error("getting random", ret);
            exit(1);
        }

        (void)test_rnd_write(RANDOM_FILENAME, buf, sizeof(buf));
        gnutls_global_deinit();
        exit(0);
    } else {
        int status;
        unsigned char buf_parent[RANDOM_SZ];
        unsigned char buf_child[RANDOM_SZ];

        /* Parent */
        ret = gnutls_rnd(level, buf_parent, RANDOM_SZ);
        if (ret != 0) {
            print_gnutls_error("getting random", ret);
            exit(1);
        }

        waitpid(pid, &status, 0);
        if (WEXITSTATUS(status) != 0) {
            return 1;
        }

        if (test_rnd_read(RANDOM_FILENAME, buf_child, RANDOM_SZ) != 0) {
            return 1;
        }

        print_hex("PARENT", buf_parent, RANDOM_SZ);
        print_hex("CHILD", buf_child, RANDOM_SZ);
        if (memcmp(buf_parent, buf_child, RANDOM_SZ) == 0) {
            fprintf(stderr, "Fork testing failed\n");
            return 1;
        }

        printf("Fork test PASSED\n");

        return 0;
    }
}

int test_rnd_fork(void)
{
    int ret;

    ret = test_rnd_fork_level(GNUTLS_RND_NONCE);
    if (ret == 0) {
        ret = test_rnd_fork_level(GNUTLS_RND_RANDOM);
    }
    if (ret == 0) {
        ret = test_rnd_fork_level(GNUTLS_RND_KEY);
    }

    return ret;
}

int main(void)
{
    int ret;

    /* Initialize GnuTLS */
    if ((ret = gnutls_global_init()) < 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    ret = test_rnd_fork();
    if (ret == 0) {
        printf("Test completed.\n");
    }

    gnutls_global_deinit();

    return ret;
}

