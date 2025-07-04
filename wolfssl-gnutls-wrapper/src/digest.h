#ifdef ENABLE_WOLFSSL
int wolfssl_digest_register(void);
int wolfssl_digest_fast(gnutls_digest_algorithm_t algorithm,
    const void *text, size_t textsize, void *digest);
#endif
