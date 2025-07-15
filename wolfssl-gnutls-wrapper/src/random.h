#include <wolfssl/wolfcrypt/random.h>
#ifdef ENABLE_WOLFSSL
extern WC_RNG priv_rng;
extern WC_RNG pub_rng;
extern pid_t pid;
extern int rng_ready;
int wolfssl_ensure_rng(void);
#endif
