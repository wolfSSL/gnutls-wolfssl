#include <wolfssl/options.h>
#include "gnutls_compat.h"

#include "pk.h"
#include "logging.h"
#include "mac.h"
#include "random.h"
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>

#ifdef ENABLE_WOLFSSL
/**
 * Copy a wolfSSL mp_int object to a GnuTLS bigint object.
 *
 * GnuTLS bigint object is allocated.
 * Supports numbers up to 8192 bits.
 *
 * If bigint is implemented with mp_int then allocate and init-copy.
 *
 * @param [in]  mp  wolfSSL mp_int object.
 * @param [out] bi  GnuTLS bigint object.
 *
 * @return  0 on success.
 * @return  GNUTLS_E_INTERNAL_ERROR when encoding mp_int fails.
 * @return  GnuTLS error code on failure.
 */
int mp_int_to_bigint(mp_int *mp, bigint_t *bi)
{
    int ret;
    unsigned char data[1024];
    int size = mp_unsigned_bin_size(mp);

    /* Encode mp_int as a big-endian byte array. */
    ret = mp_to_unsigned_bin(mp, data);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_to_unsigned_bin", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Decode byte array into newly allocated GnuTLS bigint. */
    ret = _gnutls_mpi_init_scan(bi, data, size);
    return ret;
}

/**
 * Copy a GnuTLS bigint object to an mp_int object.
 *
 * Internally allocates an array for encoding.
 *
 * If bigint is implemented with mp_int then init-copy.
 *
 * @param [in]  bi  GnuTLS bigint object.
 * @param [out] mp  wolfSSL_mp_int object.
 * @return  0 on success.
 * @return  GnuTLS error on failure.
 */
int bigint_to_mp_int(bigint_t bi, mp_int *mp)
{
    int ret;
    gnutls_datum_t datum = { .data = NULL, .size = 0 };

    /* Initialize the mp_int. */
    ret = mp_init(mp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Encode the bigint as a big-endian byte array.
     * Data is allocated. */
    ret = _gnutls_mpi_dprint(bi, &datum);
    if (ret != 0) {
        WGW_ERROR("_gnutls_mpi_print: %d", ret);
        return ret;
    }

    /* Decode the byte array into wolfSSL mp_int. */
    ret = mp_read_unsigned_bin(mp, datum.data, datum.size);
    /* Dispose of the allocated data. */
    gnutls_free(datum.data);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_read_unsigned_bin", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**************** Algorithm specific helper functions ****************/

/** Maximum number of RSA key fields stored in valid GnuTLS parameters. */
#define RSA_MAX_PARAMS      8
/** Minimum number of RSA key fields stored in valid GnuTLS parameters. */
#define RSA_MIN_PRIV_PARAMS 5

/**
 * Get the MGF id for the hash type.
 *
 * @param [in]  hash_type  Hash type.
 * @param [out] mgf        MGF identifier.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when hash not supported.
 */
static int rsa_hash_to_mgf(int hash_type, int *mgf)
{
    /* Get wolfSSL MGF for wolfSSL hash identifier. */
    switch (hash_type) {
        case WC_HASH_TYPE_SHA:
            WGW_LOG("using MGF1SHA1");
            *mgf = WC_MGF1SHA1;
            break;
        case WC_HASH_TYPE_SHA224:
            WGW_LOG("using MGF1SHA224");
            *mgf = WC_MGF1SHA224;
            break;
        case WC_HASH_TYPE_SHA256:
            WGW_LOG("using MGF1SHA256");
            *mgf = WC_MGF1SHA256;
            break;
        case WC_HASH_TYPE_SHA384:
            WGW_LOG("using MGF1SHA384");
            *mgf = WC_MGF1SHA384;
            break;
        case WC_HASH_TYPE_SHA512:
            WGW_LOG("using MGF1SHA512");
            *mgf = WC_MGF1SHA512;
            break;
        default:
            /* MGF with hash not supported. */
            WGW_ERROR("Unsupported hash algorithm: %d", hash_type);
            return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

/**
 * Load the wolfSSL RSA object with data from the GnuTLS parameters.
 *
 * @param [in, out] rsa     wolfSSL RSA object.
 * @param [in]      params  GnuTLS PK parameters.
 * @param [in]      priv    Whether to load all private key parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing RSA key fails.
 * @return  GnuTLS error on failure.
 */
static int rsa_load_params(RsaKey *rsa, const gnutls_pk_params_st *params,
    int priv)
{
    int ret;

    /* Initialize the RSA object. */
    ret = wc_InitRsaKey(rsa, NULL);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitRsaKey", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Load the modulus. */
    ret = bigint_to_mp_int(params->params[RSA_MODULUS], &rsa->n);
    if (ret == 0) {
        /* Load the public exponent. */
        ret = bigint_to_mp_int(params->params[RSA_PUB], &rsa->e);
    }
    if ((ret == 0) && priv) {
        /* Load the private exponent if a private key. */
        ret = bigint_to_mp_int(params->params[RSA_PRIV], &rsa->d);
    }
    if ((ret == 0) && priv) {
        /* Load the first prime p if a private key. */
        ret = bigint_to_mp_int(params->params[RSA_PRIME1], &rsa->p);
    }
    if ((ret == 0) && priv) {
        /* Load the second prime q if a private key. */
        ret = bigint_to_mp_int(params->params[RSA_PRIME2], &rsa->q);
    }
    if ((ret == 0) && priv && (params->params[RSA_COEF] != NULL)) {
        /* Load the CRT coefficient if a private key and available. */
        ret = bigint_to_mp_int(params->params[RSA_COEF], &rsa->u);
    }
    if ((ret == 0) && priv && (params->params[RSA_E1] != NULL)) {
        /* Load the first CRT exponent if a private key and available. */
        ret = bigint_to_mp_int(params->params[RSA_E1], &rsa->dP);
    }
    if ((ret == 0) && priv && (params->params[RSA_E2] != NULL)) {
        /* Load the second CRT exponent if a private key and available. */
        ret = bigint_to_mp_int(params->params[RSA_E2], &rsa->dQ);
    }
    if ((ret == 0) && priv) {
        /* Set type to private if a private key - default is public. */
        rsa->type = RSA_PRIVATE;
    }

    if (ret != 0) {
        /* Dispose of the RSA key if loading failed. */
        wc_FreeRsaKey(rsa);
    }
    return ret;
}

/**
 * Store the wolfSSL RSA key/parameters into GnuTLS parameters.
 *
 * Updates the number of parameters stored so that GnuTLS parameter freeing
 * sees all allocated bigints.
 *
 * @param [in]      rsa     wolfSSL RsaKey object.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GnuTLS error on failure.
 */
static int rsa_store_params(RsaKey *rsa, gnutls_pk_params_st *params)
{
    int ret;

    /* Start with no allocated parameters. */
    params->params_nr = 0;

    /* Store the modulus. */
    ret = mp_int_to_bigint(&rsa->n, &params->params[RSA_MODULUS]);
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the public exponent. */
        ret = mp_int_to_bigint(&rsa->e, &params->params[RSA_PUB]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the private exponent. */
        ret = mp_int_to_bigint(&rsa->d, &params->params[RSA_PRIV]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the first prime p. */
        ret = mp_int_to_bigint(&rsa->p, &params->params[RSA_PRIME1]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the second prime q. */
        ret = mp_int_to_bigint(&rsa->q, &params->params[RSA_PRIME2]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the CRT coefficient. */
        ret = mp_int_to_bigint(&rsa->u, &params->params[RSA_COEF]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the first CRT exponent. */
        ret = mp_int_to_bigint(&rsa->dP, &params->params[RSA_E1]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the second CRT exponent. */
        ret = mp_int_to_bigint(&rsa->dQ, &params->params[RSA_E2]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
    }

    return ret;
}

/**
 * Load the wolfSSL DH object with data from the GnuTLS parameters.
 *
 * @param [in, out] dh      wolfSSL DH object.
 * @param [in]      params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing DH key fails.
 * @return  GnuTLS error on failure.
 */
static int dh_load_params(DhKey *dh, const gnutls_pk_params_st *params)
{
    int ret;

    /* Initialize the DH object. */
    ret = wc_InitDhKey(dh);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_InitDhKey", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Load the prime. */
    ret = bigint_to_mp_int(params->params[DH_P], &dh->p);
    if (ret == 0) {
        /* Load the generator. */
        ret = bigint_to_mp_int(params->params[DH_G], &dh->g);
    }

    if (ret != 0) {
        /* Dispose of the DH key if loading failed. */
        wc_FreeDhKey(dh);
    }
    return ret;
}

/**
 * Store all the wolfSSL DH parameters in the GnuTLS parameters.
 *
 * @param [in]      dh      wolfSSL DH parameters.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GnuTLS error on failure.
 */
static int dh_store_params(const DhParams* dh, gnutls_pk_params_st *params)
{
    int ret;

    /* Start with no allocated parameters. */
    params->params_nr = 0;

    /* Store the prime. */
    ret = _gnutls_mpi_init_scan(&params->params[DH_P], dh->p, dh->p_len);
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the generator. */
        ret = _gnutls_mpi_init_scan(&params->params[DH_G], dh->g, dh->g_len);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the generating prime. */
        ret = _gnutls_mpi_init_scan(&params->params[DH_Q], dh->q, dh->q_len);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
    }

    return ret;
}

/**
 * Checks whether the GnuTLS algorithm identifier is a ECC signature algorithm.
 *
 * @param [in] a  GnuTLS algorithm identifier.
 * @return  1 when algorithm is an ECC signature algorithm.
 * @return  0 when algorithm is not an ECC signature algorithm.
 */
#define IS_ALGO_ECC_SIG(a)                  \
    (((a) == GNUTLS_PK_ECDSA)   ||          \
     ((a) == GNUTLS_PK_EDDSA_ED25519) ||    \
     ((a) == GNUTLS_PK_EDDSA_ED448))

/**
 * Convert the GnuTLS curve to a wolfSSL curve id and length in bytes.
 *
 * @param [in] curve       GnuTLS curve.
 * @param [in] curve_id    wolfSSL curve id.
 * @param [in] curve_size  Size of curve in bytes.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when curve not supported.
 */
static int ecc_curve_to_id_size(int curve, int *curve_id, int *curve_size)
{
    switch (curve) {
#if !defined(HAVE_FIPS)
#if ECC_MIN_KEY_SZ <= 192
        case GNUTLS_ECC_CURVE_SECP192R1:
            WGW_LOG("SECP192R1 - 24 bytes");
            *curve_id = ECC_SECP192R1;
            *curve_size = 24;
            break;
#endif
#if ECC_MIN_KEY_SZ <= 224
        case GNUTLS_ECC_CURVE_SECP224R1:
            WGW_LOG("SECP224R1 - 28 bytes");
            *curve_id = ECC_SECP224R1;
            *curve_size = 28;
            break;
#endif
#endif
        case GNUTLS_ECC_CURVE_SECP256R1:
            WGW_LOG("SECP256R1 - 32 bytes");
            *curve_id = ECC_SECP256R1;
            *curve_size = 32;
            break;
        case GNUTLS_ECC_CURVE_SECP384R1:
            WGW_LOG("SECP384R1 - 48 bytes");
            *curve_id = ECC_SECP384R1;
            *curve_size = 48;
            break;
        case GNUTLS_ECC_CURVE_SECP521R1:
            WGW_LOG("SECP521R1 - 66 bytes");
            *curve_id = ECC_SECP521R1;
            *curve_size = 66;
            break;
        default:
            /* Curve not supported with this configuration. */
            WGW_ERROR("Curve not supported: %d", curve);
            return GNUTLS_E_INVALID_REQUEST;
    }

    return 0;
}

#ifndef ecc_get_k
#define ecc_get_k(key)  &(key)->k
#endif

/**
 * Load the wolfSSL ECC object with data from the GnuTLS parameters.
 *
 * @param [in, out] ecc     wolfSSL ECC object.
 * @param [in]      params  GnuTLS PK parameters.
 * @param [in]      priv    Whether to load all private key parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing ECC key fails.
 * @return  GnuTLS error on failure.
 */
static int ecc_load_params(ecc_key *ecc, const gnutls_pk_params_st *params,
    int priv)
{
    int ret;
    int curve_id;
    int curve_size;

    /* Get the curve id and size for GnuTLS curve. */
    ret = ecc_curve_to_id_size(params->curve, &curve_id, &curve_size);
    if (ret != 0) {
        return ret;
    }

    /* Initialize the RSA object. */
    ret = wc_ecc_init(ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Set the curve parameters. */
    ret = wc_ecc_set_curve(ecc, curve_size, curve_id);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_set_curve", ret);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Load the x-ordinate of the public key. */
    ret = bigint_to_mp_int(params->params[ECC_X], ecc->pubkey.x);
    if (ret == 0) {
        /* Load the y-ordinate of the public key. */
        ret = bigint_to_mp_int(params->params[ECC_Y], ecc->pubkey.y);
    }
    if (ret == 0) {
        /* Set the z-orfinate to 1. */
        ret = mp_set(ecc->pubkey.z, 1);
        if (ret != 0) {
            return GNUTLS_E_INTERNAL_ERROR;
        }
    }
    if ((ret == 0) && priv) {
        /* Load the prime value if a private key. */
        ret = bigint_to_mp_int(params->params[ECC_K], ecc_get_k(ecc));
    }
    if (ret == 0) {
        /* Set the key type. */
        if (priv) {
            ecc->type = ECC_PRIVATEKEY;
        } else {
            ecc->type = ECC_PUBLICKEY;
        }
    }

    return ret;
}

/**
 * Store the wolfSSL ECC key into GnuTLS parameters.
 *
 * Updates the number of parameters stored so that GnuTLS parameter freeing
 * sees all allocated bigints.
 *
 * @param [in]      ecc     wolfSSL ECC object.
 * @param [in, out] params  GnuTLS parameters.
 * @return  0 on success.
 * @return  GnuTLS error on failure.
 */
static int ecc_store_key(ecc_key *ecc, gnutls_pk_params_st *params)
{
    int ret;

    /* Start with no allocated parameters. */
    params->params_nr = 0;

    /* Store the x-ordinate of the public key. */
    ret = mp_int_to_bigint(ecc->pubkey.x, &params->params[ECC_X]);
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the y-ordinate of the public key. */
        ret = mp_int_to_bigint(ecc->pubkey.y, &params->params[ECC_Y]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Store the private value. */
        ret = mp_int_to_bigint(ecc_get_k(ecc), &params->params[ECC_K]);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
    }

    return ret;
}

#ifdef HAVE_ED25519
/**
 * Load the wolfSSL Ed25519 object with private data from the GnuTLS parameters.
 *
 * @param [in, out] ed25519  wolfSSL Ed25519 object.
 * @param [in]      params   GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing Ed25519 key fails.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER if public key does not match.
 * @return  GnuTLS_E_INTERNAL_ERROR on other failures to import.
 */
static int ed25519_load_priv_params(ed25519_key *ed25519,
    const gnutls_pk_params_st *params)
{
    int ret;

    /* Initialize Ed25519 private key */
    ret = wc_ed25519_init(ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Check whether the private key contains public key as well. */
    if (params->raw_priv.size == ED25519_PRV_KEY_SIZE) {
        /* Load both private that has public appended. */
        ret = wc_ed25519_import_private_key(params->raw_priv.data,
            params->raw_priv.size, NULL, 0, ed25519);
    } else {
        /* Load both private and public separately. */
        ret = wc_ed25519_import_private_key(params->raw_priv.data,
            params->raw_priv.size, params->raw_pub.data, params->raw_pub.size,
            ed25519);
    }
    /* Check for bad public key error to return specific GnuTLS error. */
    if (ret == PUBLIC_KEY_E) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }
    /* Return general error for other error returns. */
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        wc_ed25519_free(ed25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**
 * Load the wolfSSL Ed25519 object with public data from the GnuTLS parameters.
 *
 * @param [in, out] ed25519  wolfSSL Ed25519 object.
 * @param [in]      params   GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GnuTLS_E_INTERNAL_ERROR on other failures to import.
 */
static int ed25519_load_pub_params(ed25519_key *ed25519,
    const gnutls_pk_params_st *params)
{
    int ret;

    /* Initialize Ed25519 private key */
    ret = wc_ed25519_init(ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Load the public key. */
    ret = wc_ed25519_import_public(params->raw_pub.data, params->raw_pub.size,
        ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private", ret);
        wc_ed25519_free(ed25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}
#endif

#ifdef HAVE_ED448
/**
 * Load the wolfSSL Ed448 object with private data from the GnuTLS parameters.
 *
 * @param [in, out] ed448   wolfSSL Ed448 object.
 * @param [in]      params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing Ed448 key fails.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER if public key does not match.
 * @return  GnuTLS_E_INTERNAL_ERROR on other failures to import.
 */
static int ed448_load_priv_params(ed448_key *ed448,
    const gnutls_pk_params_st *params)
{
    int ret;

    /* Initialize Ed448 private key */
    ret = wc_ed448_init(ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Check whether the private key contains public key as well. */
    if (params->raw_priv.size == ED448_PRV_KEY_SIZE) {
        /* Load both private that has public appended. */
        ret = wc_ed448_import_private_key(params->raw_priv.data,
            params->raw_priv.size, NULL, 0, ed448);
    } else {
        /* Load both private and public separately. */
        ret = wc_ed448_import_private_key(params->raw_priv.data,
            params->raw_priv.size, params->raw_pub.data, params->raw_pub.size,
            ed448);
    }
    /* Check for bad public key error to return specific GnuTLS error. */
    if (ret == PUBLIC_KEY_E) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }
    /* Return general error for other error returns. */
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        wc_ed448_free(ed448);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}

/**
 * Load the wolfSSL Ed448 object with public data from the GnuTLS parameters.
 *
 * @param [in, out] ed448  wolfSSL Ed448 object.
 * @param [in]      params   GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GnuTLS_E_INTERNAL_ERROR on other failures to import.
 */
static int ed448_load_pub_params(ed448_key *ed448,
    const gnutls_pk_params_st *params)
{
    int ret;

    /* Initialize Ed448 private key */
    ret = wc_ed448_init(ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Load the public key. */
    ret = wc_ed448_import_public(params->raw_pub.data, params->raw_pub.size,
        ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private", ret);
        wc_ed448_free(ed448);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    return 0;
}
#endif

/**************** Implementations of PK functions ****************/

/**
 * Encrypt using RSA PKCS#1 v1.5 with public key.
 *
 * @param [out] ciphertext  Encrypted data.
 * @param [in]  plaintext   Data to encrypt.
 * @param [in]  params      GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM when RSA PKCS#1 v1.5
 *          encryption is not allowed.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_encrypt_rsa(gnutls_datum_t *ciphertext,
    const gnutls_datum_t *plaintext, const gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Check whether RSA PKCS#1.5 encryption is allowed. */
    if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
        WGW_LOG("PKCS#1 RSA encryption disabled");
        return GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM;
    }

    /* Initialize and load the public RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 0);
    if (ret != 0) {
        return ret;
    }

    /* Get the maximum encryption size and allocate for ciphertext output. */
    ciphertext->size = wc_RsaEncryptSize(&rsa);
    ciphertext->data = gnutls_malloc(ciphertext->size);
    if (ciphertext->data == NULL) {
        WGW_ERROR("Allocating memory for ciphertext");
        /* Ensure output datum is empty on error. */
        ciphertext->size = 0;
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Encrypt using RSA PKCS#1 v1.5 padding */
    ret = wc_RsaPublicEncrypt(plaintext->data, plaintext->size,
        ciphertext->data, ciphertext->size, &rsa, &priv_rng);
    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPublicEncrypt", ret);
        /* Dispose of allocated buffer for ciphertext. */
        gnutls_free(ciphertext->data);
        /* Ensure output datum is empty on error. */
        ciphertext->data = NULL;
        ciphertext->size = 0;
        return GNUTLS_E_ENCRYPTION_FAILED;
    }

    /* Set the actual size into output datum. */
    ciphertext->size = ret;

    return 0;
}

/**
 * Encrypt using RSA PKCS#1 OAEP with public key.
 *
 * @param [out] ciphertext  Encrypted data.
 * @param [in]  plaintext   Data to encrypt.
 * @param [in]  params      GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_encrypt_rsa_oaep(gnutls_datum_t *ciphertext,
    const gnutls_datum_t *plaintext, const gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;
    int hash_type;
    int mgf;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Get the hash and MGF based on GnuTLS digest. */
    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        params->spki.rsa_oaep_dig);
    ret = rsa_hash_to_mgf(hash_type, &mgf);
    if (ret != 0) {
        return ret;
    }

    /* Initialize and load the public RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 0);
    if (ret != 0) {
        return ret;
    }

    /* Get the maximum encryption size and allocate for ciphertext output. */
    ciphertext->size = wc_RsaEncryptSize(&rsa);
    ciphertext->data = gnutls_malloc(ciphertext->size);
    if (ciphertext->data == NULL) {
        WGW_ERROR("Allocating memory for ciphertext");
        /* Ensure output datum is empty on error. */
        ciphertext->size = 0;
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Encrypt using RSA PKCS#1 OAEP. */
    ret = wc_RsaPublicEncrypt_ex(plaintext->data, plaintext->size,
        ciphertext->data, ciphertext->size, &rsa, &priv_rng, WC_RSA_OAEP_PAD,
        hash_type, mgf, params->spki.rsa_oaep_label.data,
        params->spki.rsa_oaep_label.size);
    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPublicEncrypt_ex", ret);
        /* Dispose of allocated buffer for ciphertext. */
        gnutls_free(ciphertext->data);
        /* Ensure output datum is empty on error. */
        ciphertext->data = NULL;
        ciphertext->size = 0;
        return GNUTLS_E_ENCRYPTION_FAILED;
    }

    /* Set the actual size into output datum. */
    ciphertext->size = ret;

    return 0;
}

/**
 * Encrypt with public key.
 *
 * @param [in]  algo        GnuTLS PK algorithm.
 * @param [out] ciphertext  Encrypted data.
 * @param [in]  plaintext   Data to encrypt.
 * @param [in]  params      GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM when RSA PKCS#1 v1.5
 *          encryption is not allowed and requested.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when encryption fails.
 * @return  GNUTLS_E_LIB_IN_ERROR_STATE when library is an error state.
 * @return  GNUTLS_E_INVALID_REQUEST when algorithm is not supported.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_encrypt(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *ciphertext, const gnutls_datum_t *plaintext,
    const gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    /* Map algorithm to OAEP if PKI specifies. */
    if (algo == GNUTLS_PK_RSA && params->spki.pk == GNUTLS_PK_RSA_OAEP) {
        algo = GNUTLS_PK_RSA_OAEP;
    }

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
            /* RSA PKCS#1 v1.5 encryption. */
            ret = wolfssl_pk_encrypt_rsa(ciphertext, plaintext, params);
            break;

        case GNUTLS_PK_RSA_OAEP:
            /* RSA PKCS#1 OAEP encryption. */
            ret = wolfssl_pk_encrypt_rsa_oaep(ciphertext, plaintext, params);
            break;

        default:
            /* No other public key encryption algorithms supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

/**
 * Decrypt ciphertext using RSA PKCS#1 v1.5 with private key.
 *
 * @param [out] plaintext        Decrypted data.
 * @param [in]  ciphertext       Encrypted data to decrypt.
 * @param [in]  params           GnuTLS PK parameters.
 * @param [in]  alloc_plaintext  Whether the plaintext needs to be allocated.
 * @return  GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM when RSA PKCS#1 v1.5
 *          encryption is not allowed.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_decrypt_rsa(gnutls_datum_t *plaintext,
    const gnutls_datum_t *ciphertext, const gnutls_pk_params_st *params,
    int alloc_plaintext)
{
    int ret;
    RsaKey rsa;
    unsigned char out[1024];
    unsigned char *plain;
    word32 plain_size;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Check whether RSA PKCS#1.5 encryption is allowed. */
    if (!_gnutls_config_is_rsa_pkcs1_encrypt_allowed()) {
        WGW_LOG("PKCS#1 RSA encryption disabled");
        return GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM;
    }

    /* Initialize and load the private RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

#if !defined(HAVE_FIPS)
    /* Set a random against the RSA key for blinding. */
    ret = wc_RsaSetRNG(&rsa, &priv_rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSetRNG", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_RANDOM_FAILED;
    }
#endif

    /* Get the maximum decryption size. */
    plain_size = wc_RsaEncryptSize(&rsa);
    if (alloc_plaintext) {
        /* Allocate for plaintext output. */
        plaintext->data = gnutls_malloc(plain_size);
        if (plaintext->data == NULL) {
            WGW_ERROR("Allocating memory for plaintext");
            /* Ensure output datum is empty on error. */
            plaintext->size = 0;
            wc_FreeRsaKey(&rsa);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }
    /* Set plain to valid buffer. */
    if ((!alloc_plaintext) &&
            (plaintext->size < (unsigned int)wc_RsaEncryptSize(&rsa))) {
        plain = out;
    } else {
        plain = plaintext->data;
    }

    PRIVATE_KEY_UNLOCK();

    /* Decrypt using RSA PKCS#1 v1.5 padding */
    ret = wc_RsaPrivateDecrypt(ciphertext->data, ciphertext->size, plain,
        plain_size, &rsa);

    PRIVATE_KEY_LOCK();

    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPrivateDecrypt", ret);
        if (alloc_plaintext) {
            /* Dispose of allocated buffer for plaintext. */
            gnutls_free(plaintext->data);
            /* Ensure output datum is empty on error. */
            plaintext->data = NULL;
            plaintext->size = 0;
        }
        return GNUTLS_E_DECRYPTION_FAILED;
    }

    /* Check if returning through another buffer. */
    if (plain != plaintext->data) {
        /* Ensure the output buffer is big enough. */
        if ((unsigned int)ret > plaintext->size) {
            WGW_ERROR("Decrypted data too big for plaintext buffer: %d > %d",
                ret, plaintext->size);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        /* Copy the decrypted data into output buffer. */
        XMEMCPY(plaintext->data, plain, ret);
    }
    /* Set the actual size into output datum. */
    plaintext->size = ret;

    return 0;
}

/**
 * Decrypt ciphertext using RSA PKCS#1 OAEP with private key.
 *
 * @param [out] plaintext        Decrypted data.
 * @param [in]  ciphertext       Encrypted data to decrypt.
 * @param [in]  params           GnuTLS PK parameters.
 * @param [in]  alloc_plaintext  Whether the plaintext needs to be allocated.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_ENCRYPTION_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_decrypt_rsa_oaep(gnutls_datum_t *plaintext,
    const gnutls_datum_t *ciphertext, const gnutls_pk_params_st *params,
    int alloc_plaintext)
{
    int ret;
    RsaKey rsa;
    int hash_type;
    int mgf;
    unsigned char out[1024];
    unsigned char *plain;
    word32 plain_size;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Get the hash and MGF based on GnuTLS digest. */
    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        params->spki.rsa_oaep_dig);
    ret = rsa_hash_to_mgf(hash_type, &mgf);
    if (ret != 0) {
        return ret;
    }

    /* Initialize and load the private RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

#if !defined(HAVE_FIPS)
    /* Set a random against the RSA key for blinding. */
    ret = wc_RsaSetRNG(&rsa, &priv_rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSetRNG", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_RANDOM_FAILED;
    }
#endif

    /* Get the maximum decryption size. */
    plain_size = wc_RsaEncryptSize(&rsa);
    if (alloc_plaintext) {
        /* Allocate for plaintext output. */
        plaintext->data = gnutls_malloc(plain_size);
        if (plaintext->data == NULL) {
            WGW_ERROR("Allocating memory for plaintext");
            /* Ensure output datum is empty on error. */
            plaintext->size = 0;
            wc_FreeRsaKey(&rsa);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }
    /* Set plain to valid buffer. */
    if ((!alloc_plaintext) &&
            (plaintext->size < (unsigned int)wc_RsaEncryptSize(&rsa))) {
        plain = out;
    } else {
        plain = plaintext->data;
    }

    PRIVATE_KEY_UNLOCK();

    /* Decrypt using RSA PKCS#1 OAEP. */
    ret = wc_RsaPrivateDecrypt_ex(ciphertext->data, ciphertext->size,
        plain, plain_size, &rsa, WC_RSA_OAEP_PAD, hash_type, mgf,
        params->spki.rsa_oaep_label.data, params->spki.rsa_oaep_label.size);

    PRIVATE_KEY_LOCK();

    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPublicDecrypt_ex", ret);
        if (alloc_plaintext) {
            /* Dispose of allocated buffer for plaintext. */
            gnutls_free(plaintext->data);
            /* Ensure output datum is empty on error. */
            plaintext->data = NULL;
            plaintext->size = 0;
        }
        return GNUTLS_E_DECRYPTION_FAILED;
    }

    /* Check if returning through another buffer. */
    if (plain != plaintext->data) {
        /* Ensure the output buffer is big enough. */
        if ((unsigned int)ret > plaintext->size) {
            WGW_ERROR("Decrypted data too big for plaintext buffer: %d > %d",
                ret, plaintext->size);
            return GNUTLS_E_DECRYPTION_FAILED;
        }
        /* Copy the decrypted data into output buffer. */
        XMEMCPY(plaintext->data, plain, ret);
    }
    /* Set the actual size into output datum. */
    plaintext->size = ret;

    return 0;
}

/**
 * Decrypt with private key.
 *
 * @param [in]  algo        GnuTLS PK algorithm.
 * @param [out] ciphertext  Encrypted data.
 * @param [in]  plaintext   Data to encrypt.
 * @param [in]  params      GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM when RSA PKCS#1 v1.5
 *          encryption is not allowed and requested.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_DECRYPTION_FAILED when encryption fails.
 * @return  GNUTLS_E_LIB_IN_ERROR_STATE when library is an error state.
 * @return  GNUTLS_E_INVALID_REQUEST when algorithm is not supported.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_decrypt(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *plaintext, const gnutls_datum_t *ciphertext,
    const gnutls_pk_params_st *pk_params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    /* Map algorithm to OAEP if PKI specifies. */
    if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP) {
        algo = GNUTLS_PK_RSA_OAEP;
    }

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
            /* RSA PKCS#1 v1.5 decryption. */
            ret = wolfssl_pk_decrypt_rsa(plaintext, ciphertext, pk_params, 1);
            break;

        case GNUTLS_PK_RSA_OAEP:
            /* RSA PKCS#1 OAEP decryption. */
            ret = wolfssl_pk_decrypt_rsa_oaep(plaintext, ciphertext, pk_params,
                1);
            break;

        default:
            /* No other public key encryption algorithms supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

/**
 * Decrypt with private key.
 *
 * @param [in]  algo            GnuTLS PK algorithm.
 * @param [out] ciphertext      Encrypted data.
 * @param [in]  plaintext       Data to encrypt. Assumed to valid pointer.
 * @param [in]  plaintext_size  Length of data to encrypt in bytes.
 * @param [in]  params          GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_UNSUPPORTED_ENCRYPTION_ALGORITHM when RSA PKCS#1 v1.5
 *          encryption is not allowed and requested.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_DECRYPTION_FAILED when encryption fails.
 * @return  GNUTLS_E_LIB_IN_ERROR_STATE when library is an error state.
 * @return  GNUTLS_E_INVALID_REQUEST when algorithm is not supported.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_decrypt2(gnutls_pk_algorithm_t algo,
    const gnutls_datum_t *ciphertext, unsigned char *plaintext,
    size_t plaintext_size, const gnutls_pk_params_st *pk_params)
{
    int ret;
    gnutls_datum_t plain;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    /* Map algorithm to OAEP if PKI specifies. */
    if (algo == GNUTLS_PK_RSA && pk_params->spki.pk == GNUTLS_PK_RSA_OAEP) {
        algo = GNUTLS_PK_RSA_OAEP;
    }

    /* Put the plaintext buffer and size into a GnuTLS datum. */
    plain.data = plaintext;
    plain.size = plaintext_size;

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
            /* RSA PKCS#1 v1.5 decryption. */
            ret = wolfssl_pk_decrypt_rsa(&plain, ciphertext, pk_params, 0);
            break;

        case GNUTLS_PK_RSA_OAEP:
            /* RSA PKCS#1 OAEP decryption. */
            ret = wolfssl_pk_decrypt_rsa_oaep(&plain, ciphertext, pk_params, 0);
            break;

        default:
            /* No other public key encryption algorithms supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

/**
 * Sign using RSA PKCS#1 v1.5 with private key.
 *
 * @param [out] signature  Signature data.
 * @param [in]  vdata      Data to sign.
 * @param [in]  params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_SIGN_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_sign_rsa(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;


    /* Initialize and load the private RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Get the maximum encryption size and allocate for signature output. */
    signature->size = wc_RsaEncryptSize(&rsa);
    signature->data = gnutls_malloc(signature->size);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature");
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Decrypt using RSA PKCS#1 v1.5. */
    ret = wc_RsaSSL_Sign(vdata->data, vdata->size, signature->data,
        signature->size, &rsa, &priv_rng);

    PRIVATE_KEY_LOCK();

    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSSL_Sign", ret);
        /* Dispose of allocated buffer for signature. */
        gnutls_free(signature->data);
        /* Ensure output datum is empty on error. */
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    signature->size = ret;

    return 0;
}

/**
 * Sign using RSA PKCS#1 PSS with private key.
 *
 * @param [out] signature    Signature data.
 * @param [in]  vdata        Data to sign.
 * @param [in]  params       GnuTLS PK parameters.
 * @param [in]  sign_params  GnuTLS signature parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_SIGN_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_sign_rsa_pss(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;
    RsaKey rsa;
    int hash_type;
    int mgf;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Get the hash and MGF based on GnuTLS digest. */
    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        sign_params->rsa_pss_dig);
    ret = rsa_hash_to_mgf(hash_type, &mgf);
    if (ret != 0) {
        return ret;
    }


    /* Initialize and load the private RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Get the maximum encryption size and allocate for signature output. */
    signature->size = wc_RsaEncryptSize(&rsa);
    signature->data = gnutls_malloc(signature->size);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature");
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Decrypt using RSA PKCS#1 PSS. */
    ret = wc_RsaPSS_Sign_ex(vdata->data, vdata->size, signature->data,
        signature->size, hash_type, mgf, sign_params->salt_size, &rsa,
        &priv_rng);

    PRIVATE_KEY_LOCK();

    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_Sign_ex", ret);
        /* Dispose of allocated buffer for signature. */
        gnutls_free(signature->data);
        /* Ensure output datum is empty on error. */
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Set the actual size into output datum. */
    signature->size = ret;

    return 0;
}

/**
 * Sign using ECDSA with private key.
 *
 * @param [out] signature    Signature data.
 * @param [in]  vdata        Data to sign.
 * @param [in]  params       GnuTLS PK parameters.
 * @param [in]  sign_params  GnuTLS signature parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_SIGN_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_sign_ecc(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;
    ecc_key ecc;
    word32 len;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Initialize and load the private ECC key from GnuTLS PK parameters. */
    ret = ecc_load_params(&ecc, pk_params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Get the maximum signture size and allocate for signature output. */
    len = signature->size = wc_ecc_sig_size_calc(wc_ecc_size(&ecc));
    signature->data = gnutls_malloc(signature->size);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature");
        wc_ecc_free(&ecc);
        return GNUTLS_E_MEMORY_ERROR;
    }

#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K)
    /* Check whether signature is to be deterministic. */
    if ((sign_params->flags & GNUTLS_PK_FLAG_REPRODUCIBLE) != 0) {
        int hash_type;
        WGW_LOG("signing determinitically");
        /* Get wolfSSL hash type from GnuTLS signing parameters. */
        hash_type = get_hash_type((gnutls_mac_algorithm_t)
            sign_params->dsa_dig);
        /* Make the ecc object sign deterministically and indicate hash used. */
        wc_ecc_set_deterministic_ex(&ecc, 1, hash_type);
    }
#else
    (void)sign_params;
#endif

    PRIVATE_KEY_UNLOCK();

    /* Sign hash using ECDSA. */
    ret = wc_ecc_sign_hash(vdata->data, vdata->size, signature->data, &len,
        &priv_rng, &ecc);

    PRIVATE_KEY_LOCK();

    /* No longer need ECC key. */
    wc_ecc_free(&ecc);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_sign_hash", ret);
        /* Dispose of allocated buffer for signature. */
        gnutls_free(signature->data);
        /* Ensure output datum is empty on error. */
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Set the actual size into output datum. */
    signature->size = len;

    return 0;
}

#ifdef HAVE_ED25519
/**
 * Sign using EdDSA with Ed25519 private key.
 *
 * @param [out] signature  Signature data.
 * @param [in]  vdata      Data to sign.
 * @param [in]  params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_SIGN_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_sign_ed25519(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;
    word32 len = ED25519_SIG_SIZE;

    WGW_FUNC_ENTER();

    /* Initialize and load the private Ed25519 key from GnuTLS PK parameters. */
    ret = ed25519_load_priv_params(&ed25519, params);
    if (ret != 0) {
        return ret;
    }

    /* Allocate for signature output. */
    signature->data = gnutls_malloc(len);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature: %d", len);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Sign message using EdDSA. */
    ret = wc_ed25519_sign_msg(vdata->data, vdata->size, signature->data, &len,
        &ed25519);

    PRIVATE_KEY_LOCK();

    /* No longer need Ed25519 key. */
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_sign_msg", ret);
        /* Dispose of allocated buffer for signature. */
        gnutls_free(signature->data);
        /* Ensure output datum is empty on error. */
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Set the signature size into output datum. */
    signature->size = len;

    return 0;
}
#endif

#ifdef HAVE_ED448
/**
 * Sign using EdDSA with Ed448 private key.
 *
 * @param [out] signature  Signature data.
 * @param [in]  vdata      Data to sign.
 * @param [in]  params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_SIGN_FAILED when encryption fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_sign_ed448(gnutls_datum_t *signature,
    const gnutls_datum_t *vdata, const gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;
    word32 len = ED448_SIG_SIZE;

    WGW_FUNC_ENTER();

    /* Initialize and load the private Ed448 key from GnuTLS PK parameters. */
    ret = ed448_load_priv_params(&ed448, params);
    if (ret != 0) {
        return ret;
    }

    /* Allocate for signature output. */
    signature->data = gnutls_malloc(len);
    if (signature->data == NULL) {
        WGW_ERROR("Allocating memory for signature: %d", len);
        wc_ed448_free(&ed448);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Sign message using EdDSA. */
    ret = wc_ed448_sign_msg(vdata->data, vdata->size, signature->data, &len,
        &ed448, NULL, 0);

    PRIVATE_KEY_LOCK();

    /* No longer need Ed448 key. */
    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_sign_msg", ret);
        /* Dispose of allocated buffer for signature. */
        gnutls_free(signature->data);
        /* Ensure output datum is empty on error. */
        signature->data = NULL;
        signature->size = 0;
        return GNUTLS_E_PK_SIGN_FAILED;
    }

    /* Set the signature size into output datum. */
    signature->size = len;

    return 0;
}
#endif

/**
 * Sign with private key.
 *
 * @param [in]  algo       GnuTLS PK algorithm.
 * @param [out] signature  Signature data.
 * @param [in]  vdata      Data to sign.
 * @param [in]  params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_MEMORY_ERROR when dynamic memory allocation fails.
 * @return  GNUTLS_E_SIGN_FAILED when encryption fails.
 * @return  GNUTLS_E_LIB_IN_ERROR_STATE when library is an error state.
 * @return  GNUTLS_E_INVALID_REQUEST when algorithm is not supported.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_sign(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *signature, const gnutls_datum_t *vdata,
    const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    /* For ECC, make sure the curve PK algorithm matches algorithm.  */
    if (IS_ALGO_ECC_SIG(algo) &&
            (gnutls_ecc_curve_get_pk(pk_params->curve) != algo)) {
        WGW_ERROR("ECC curve does not match algorithm: %d %d\n", algo,
            pk_params->curve);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
            /* RSA PKCS#1 v1.5 signing. */
            ret = wolfssl_pk_sign_rsa(signature, vdata, pk_params);
            break;
        case GNUTLS_PK_RSA_PSS:
            /* RSA PKCS#1 PSS signing. */
            ret = wolfssl_pk_sign_rsa_pss(signature, vdata, pk_params,
                sign_params);
            break;

        case GNUTLS_PK_ECDSA:
            /* ECDSA signing. */
            ret = wolfssl_pk_sign_ecc(signature, vdata, pk_params, sign_params);
            break;

#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            /* Ed25519 signing. */
            ret = wolfssl_pk_sign_ed25519(signature, vdata, pk_params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            /* Ed448 signing. */
            ret = wolfssl_pk_sign_ed448(signature, vdata, pk_params);
            break;
#endif

        default:
            /* No other public key encryption algorithms supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

/**
 * Verify using RSA PKCS#1 v1.5 with public key.
 *
 * @param [in] vdata      Data to verify.
 * @param [in] signature  Signature data.
 * @param [in] params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_SIG_VERIFY_FAILED when verification fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_verify_rsa(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;
    unsigned char verify[1024];

    WGW_FUNC_ENTER();

    /* Initialize and load the public RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 0);
    if (ret != 0) {
        return ret;
    }

    /* Decrypt RSA signature. */
    ret = wc_RsaSSL_Verify(signature->data, signature->size, verify,
        sizeof(verify), &rsa);
    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaSSL_Verify", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    /* Compare length of decrypted data with verification data. */
    if (ret != (int)vdata->size) {
        WGW_ERROR("Decrypted data size size bad: %d %d", ret, vdata->size);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    /* Compare decrypted data with verification data. */
    if (XMEMCMP(verify, vdata->data, ret) != 0) {
        WGW_ERROR("Decrypted data doesn't match");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

/**
 * Verify using RSA PKCS#1 PSS with public key.
 *
 * @param [in] vdata        Data to verify.
 * @param [in] signature    Signature data.
 * @param [in] params       GnuTLS PK parameters.
 * @param [in] sign_params  GnuTLS signature parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_SIG_VERIFY_FAILED when verification fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_verify_rsa_pss(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;
    RsaKey rsa;
    int hash_type;
    int mgf;
    unsigned char verify[1024];

    WGW_FUNC_ENTER();

    /* Check salt size match verification data size when fixed salt length. */
    if ((sign_params->flags & GNUTLS_PK_FLAG_RSA_PSS_FIXED_SALT_LENGTH) &&
            (sign_params->salt_size != vdata->size)) {
        WGW_ERROR("Fixed salt length doesn't match hash size");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    /* Get the hash and MGF based on GnuTLS digest. */
    hash_type = get_hash_type((gnutls_mac_algorithm_t)
        sign_params->rsa_pss_dig);
    ret = rsa_hash_to_mgf(hash_type, &mgf);
    if (ret != 0) {
        return ret;
    }

    /* Initialize and load the public RSA key from GnuTLS PK parameters. */
    ret = rsa_load_params(&rsa, params, 0);
    if (ret != 0) {
        return ret;
    }

    /* Decrypt signature and check hash, MGF and salt. */
    ret = wc_RsaPSS_Verify_ex(signature->data,
        signature->size, verify, sizeof(verify), hash_type, mgf,
        sign_params->salt_size, &rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_Verify_ex", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    /* Check padding valid and verification data matches decrypted signature. */
    ret = wc_RsaPSS_CheckPadding(vdata->data, vdata->size, verify, ret,
        hash_type);
    /* No longer need RSA key. */
    wc_FreeRsaKey(&rsa);
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("wc_RsaPSS_CheckPadding", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

/**
 * Parse DER length field.
 *
 * @param [in]     sig_data  Signature data.
 * @param [in]     sig_len   Signature data length.
 * @param [in,out] idx       Current index (updated on success).
 * @param [out]    len       Parsed length value.
 * @return  0 on success.
 * @return  Negative on parsing error.
 */
static int parse_der_length(const byte* sig_data, word32 sig_len,
        word32* idx, word32* len)
{
    if (*idx >= sig_len)
        return -1;

    *len = sig_data[(*idx)++];

    if (*len & 0x80) {
        /* Long form length */
        word32 num_bytes = *len & 0x7F;

        if (num_bytes == 0 || num_bytes > 4 || *idx + num_bytes > sig_len)
            return -1;

        *len = 0;
        while (num_bytes--) {
            *len = (*len << 8) | sig_data[(*idx)++];
        }
    }

    return 0;
}

/**
 * Parse a lenient DER-encoded ECDSA signature to extract r and s.
 *
 * This handles potentially malformed DER where INTEGER values are raw bytes
 * without proper sign-bit handling (as generated by some XML-DSig implementations).
 *
 * @param [in]  sig_data  Signature data (DER SEQUENCE).
 * @param [in]  sig_len   Signature data length.
 * @param [out] r         mp_int to hold r value.
 * @param [out] s         mp_int to hold s value.
 * @return  0 on success.
 * @return  Negative on parsing error.
 */
static int parse_lenient_der_ecdsa_signature(const byte* sig_data, word32 sig_len,
    mp_int* r, mp_int* s)
{
    word32 idx = 0;
    word32 len;

    /* Parse SEQUENCE tag */
    if (idx >= sig_len || sig_data[idx++] != 0x30) {
        WGW_ERROR("Invalid DER SEQUENCE tag");
        return -1;
    }

    /* Parse SEQUENCE length */
    if (parse_der_length(sig_data, sig_len, &idx, &len) != 0)
        return -1;

    /* Parse first INTEGER (r) tag */
    if (idx >= sig_len || sig_data[idx++] != 0x02) {
        WGW_ERROR("Invalid DER INTEGER tag for r");
        return -1;
    }

    /* Parse r length */
    if (parse_der_length(sig_data, sig_len, &idx, &len) != 0)
        return -1;

    /* Skip leading zero byte if present (sign byte) */
    if (len <= 0)
        return -1;

    if (idx < sig_len && sig_data[idx] == 0x00) {
        idx++;
        len--;
    }

    /* Read r value */
    if (idx + len > sig_len) return -1;
    if (mp_read_unsigned_bin(r, sig_data + idx, len) != 0) {
        WGW_ERROR("Failed to read r value");
        return -1;
    }
    idx += len;

    /* Parse second INTEGER (s) tag */
    if (idx >= sig_len || sig_data[idx++] != 0x02) {
        WGW_ERROR("Invalid DER INTEGER tag for s");
        return -1;
    }

    /* Parse s length */
    if (parse_der_length(sig_data, sig_len, &idx, &len) != 0)
        return -1;

    /* Skip leading zero byte if present (sign byte) */
    if (len > 0 && idx < sig_len && sig_data[idx] == 0x00) {
        idx++;
        len--;
    }

    /* Read s value */
    if (idx + len > sig_len) return -1;
    if (mp_read_unsigned_bin(s, sig_data + idx, len) != 0) {
        WGW_ERROR("Failed to read s value");
        return -1;
    }

    return 0;
}

/**
 * Verify using ECDSA with public key.
 *
 * @param [in] vdata      Data to verify.
 * @param [in] signature  Signature data.
 * @param [in] params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_SIG_VERIFY_FAILED when verification fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_verify_ecc(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *params)
{
    int ret;
    ecc_key ecc;
    int res;

    WGW_FUNC_ENTER();

    /* Initialize and load the public ECC key from GnuTLS PK parameters. */
    ret = ecc_load_params(&ecc, params, 0);
    if (ret != 0) {
        return ret;
    }

    /* Try standard verification first with DER-encoded signature. */
    ret = wc_ecc_verify_hash(signature->data, signature->size, vdata->data,
        vdata->size, &res, &ecc);

    /* If DER parsing failed (e.g., malformed DER from XML-DSig),
     * try lenient parsing and verification */
    if (ret == ASN_ECC_KEY_E || ret == ASN_PARSE_E) {
        mp_int r, s;

        WGW_LOG("Standard DER parsing failed (%d), trying lenient parser", ret);

        /* Initialize mp_int for r and s */
        ret = mp_init(&r);
        if (ret != 0) {
            wc_ecc_free(&ecc);
            WGW_WOLFSSL_ERROR("mp_init(r)", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        ret = mp_init(&s);
        if (ret != 0) {
            mp_clear(&r);
            wc_ecc_free(&ecc);
            WGW_WOLFSSL_ERROR("mp_init(s)", ret);
            return GNUTLS_E_PK_SIG_VERIFY_FAILED;
        }

        /* Parse potentially malformed DER to extract r and s */
        ret = parse_lenient_der_ecdsa_signature(signature->data, signature->size, &r, &s);
        if (ret == 0) {
            /* Verify using extracted r and s */
            ret = wc_ecc_verify_hash_ex(&r, &s, vdata->data, vdata->size, &res, &ecc);
            if (ret < 0) {
                WGW_WOLFSSL_ERROR("wc_ecc_verify_hash_ex", ret);
            } else {
                WGW_LOG("Lenient parser succeeded, verification result: %d", res);
            }
        } else {
            WGW_ERROR("Lenient DER parsing failed");
            ret = -1;
        }

        /* Clean up */
        mp_clear(&r);
        mp_clear(&s);
    }

    /* No longer need ECC key. */
    wc_ecc_free(&ecc);

    /* When the process fails - return signature failure. */
    if (ret < 0) {
        WGW_WOLFSSL_ERROR("ECDSA verification failed", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    /* When verification result is fail - return signature failure. */
    if (!res) {
        WGW_ERROR("Failed verification\n");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}

#ifdef HAVE_ED25519
/**
 * Verify using Ed25519 with public key.
 *
 * @param [in] vdata      Data to verify.
 * @param [in] signature  Signature data.
 * @param [in] params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_SIG_VERIFY_FAILED when verification fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_verify_ed25519(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;
    int res;

    WGW_FUNC_ENTER();

    /* Initialize and load the public Ed25519 key from GnuTLS PK parameters. */
    ret = ed25519_load_pub_params(&ed25519, params);
    if (ret != 0) {
        return ret;
    }

    /* Verify the signature against data using EdDSA. */
    ret = wc_ed25519_verify_msg(signature->data, signature->size, vdata->data,
        vdata->size, &res, &ed25519);
    /* No longer need Ed25519 key. */
    wc_ed25519_free(&ed25519);
    /* When the process fails - return signature failure. */
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_verify_msg", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    /* When verification result is fail - return signature failure. */
    if (!res) {
        WGW_ERROR("Failed verification\n");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}
#endif

#ifdef HAVE_ED448
/**
 * Verify using Ed448 with public key.
 *
 * @param [in] vdata      Data to verify.
 * @param [in] signature  Signature data.
 * @param [in] params     GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_SIG_VERIFY_FAILED when verification fails.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_verify_ed448(const gnutls_datum_t *vdata,
    const gnutls_datum_t *signature, const gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;
    int res;

    WGW_FUNC_ENTER();

    /* Initialize and load the public Ed448 key from GnuTLS PK parameters. */
    ret = ed448_load_pub_params(&ed448, params);
    if (ret != 0) {
        return ret;
    }

    /* Verify the signature against data using EdDSA. */
    ret = wc_ed448_verify_msg(signature->data, signature->size, vdata->data,
        vdata->size, &res, &ed448, NULL, 0);
    /* No longer need Ed448 key. */
    wc_ed448_free(&ed448);
    /* When the process fails - return signature failure. */
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_verify_msg", ret);
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }
    /* When verification result is fail - return signature failure. */
    if (!res) {
        WGW_ERROR("Failed verification\n");
        return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

    return 0;
}
#endif

/**
 * Verify with public key.
 *
 * @param [in] algo         GnuTLS PK algorithm.
 * @param [in] vdata        Data to verify.
 * @param [in] signature    Signature data.
 * @param [in] pk_params    GnuTLS PK parameters.
 * @param [in] sign_params  GnuTLS signature parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_SIG_VERIFY_FAILED when verification fails.
 * @return  GNUTLS_E_LIB_IN_ERROR_STATE when library is an error state.
 * @return  Other GnuTLS error on failure.
 */
static int wolfssl_pk_verify(gnutls_pk_algorithm_t algo,
    const gnutls_datum_t *vdata, const gnutls_datum_t *signature,
    const gnutls_pk_params_st *pk_params,
    const gnutls_x509_spki_st *sign_params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    /* For ECC, make sure the curve PK algorithm matches algorithm.  */
    if (IS_ALGO_ECC_SIG(algo) &&
            (gnutls_ecc_curve_get_pk(pk_params->curve) != algo)) {
        WGW_ERROR("ECC curve does not match algorithm: %d %d\n", algo,
            pk_params->curve);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
            /* RSA PKCS#1 v1.5 verification. */
            ret = wolfssl_pk_verify_rsa(vdata, signature, pk_params);
            break;
        case GNUTLS_PK_RSA_PSS:
            /* RSA PKCS#1 PSS verification. */
            ret = wolfssl_pk_verify_rsa_pss(vdata, signature, pk_params,
                sign_params);
            break;
        case GNUTLS_PK_ECDSA:
            /* ECDSA verification. */
            ret = wolfssl_pk_verify_ecc(vdata, signature, pk_params);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            /* Ed25519 verification. */
            ret = wolfssl_pk_verify_ed25519(vdata, signature, pk_params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            /* Ed448 verification. */
            ret = wolfssl_pk_verify_ed448(vdata, signature, pk_params);
            break;
#endif
        default:
            /* No other public key encryption algorithms supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

/**
 * Verify the private ECC key.
 *
 * @param [in] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER when private or public key are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_verify_priv_params_ecc(const gnutls_pk_params_st *params)
{
    int ret;
    ecc_key ecc;

    WGW_FUNC_ENTER();

    /* Initialize and load the private ECC key from GnuTLS PK parameters. */
    ret = ecc_load_params(&ecc, params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Explicit check of ECC private key. */
    ret = wc_ecc_check_key(&ecc);
    /* No longer need ECC key. */
    wc_ecc_free(&ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }

    return 0;
}

#ifdef HAVE_ED25519
/**
 * Verify the private Ed2519 key.
 *
 * @param [in] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER when private or public key are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_verify_priv_params_ed25519(
    const gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;

    WGW_FUNC_ENTER();

    /* Initialize and load the private Ed25519 key from GnuTLS PK parameters. */
    ret = ed25519_load_priv_params(&ed25519, params);
    /* No longer need Ed25519 key. */
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        /* ret will be GNUTLS_E_ILLEGAL_PARAMETER when invalid key. */
        return ret;
    }

    return 0;
}
#endif

#ifdef HAVE_ED448
/**
 * Verify the private Ed2519 key.
 *
 * @param [in] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER when private or public key are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_verify_priv_params_ed448(
    const gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;

    WGW_FUNC_ENTER();

    /* Initialize and load the private Ed448 key from GnuTLS PK parameters. */
    ret = ed448_load_priv_params(&ed448, params);
    /* No longer need Ed448 key. */
    wc_ed448_free(&ed448);
    if (ret != 0) {
        /* ret will be GNUTLS_E_ILLEGAL_PARAMETER when invalid key. */
        return ret;
    }

    return 0;
}
#endif

/**
 * Verify the private key.
 *
 * @param [in] algo    GnuTLS PK algorithm.
 * @param [in] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER when private or public key are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_verify_priv_params(gnutls_pk_algorithm_t algo,
    const gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_ECDSA:
            /* Verify ECC private key. */
            ret = wolfssl_pk_verify_priv_params_ecc(params);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            /* Verify Ed25519 private key. */
            ret = wolfssl_pk_verify_priv_params_ed25519(params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            /* Verify Ed448 private key. */
            ret = wolfssl_pk_verify_priv_params_ed448(params);
            break;
#endif
        default:
            /* No validation done for other key types. */
            /* TODO: Explicitly check RSA keys? */
            ret = 0;
    }

    return ret;
}

/**
 * Verify the public ECC key.
 *
 * @param [in] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER when private or public key are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_verify_pub_params_ecc(const gnutls_pk_params_st *params)
{
    int ret;
    ecc_key ecc;

    WGW_FUNC_ENTER();

    /* Initialize and load the public ECC key from GnuTLS PK parameters. */
    ret = ecc_load_params(&ecc, params, 0);
    if (ret != 0) {
        return ret;
    }

    /* Explicit check of ECC public key. */
    ret = wc_ecc_check_key(&ecc);
    /* No longer need ECC key. */
    wc_ecc_free(&ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
        return GNUTLS_E_ILLEGAL_PARAMETER;
    }

    return 0;
}

/**
 * Verify the public key.
 *
 * @param [in] algo    GnuTLS PK algorithm.
 * @param [in] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_ILLEGAL_PARAMETER when private or public key are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_verify_pub_params(gnutls_pk_algorithm_t algo,
    const gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
#endif
            /* No validation required for RSA or Ed keys. */
            ret = 0;
            break;
        case GNUTLS_PK_ECDSA:
            /* Verify ECC public key. */
            ret = wolfssl_pk_verify_pub_params_ecc(params);;
            break;
        default:
            /* Algorithm not supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            ret = GNUTLS_E_INVALID_REQUEST;
    }

    return ret;
}

/**
 * Generate DH parameters.
 *
 * @param [in]      bits    Number of bits in prime.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when bit size is not supported.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_params_dh(unsigned int bits,
    gnutls_pk_params_st *params)
{
    const DhParams* dh = NULL;

    WGW_FUNC_ENTER();

    /* Use predefined parameters based on bits size */
    switch (bits) {
        case 2048:
#ifdef HAVE_FFDHE_2048
            WGW_LOG("2048");
            /* Get predefined 2048-bit parameters. */
            dh = wc_Dh_ffdhe2048_Get();
#endif
            break;
        case 3072:
#ifdef HAVE_FFDHE_3072
            WGW_LOG("3072");
            /* Get predefined 3072-bit parameters. */
            dh = wc_Dh_ffdhe3072_Get();
#endif
            break;
        case 4096:
#ifdef HAVE_FFDHE_4096
            WGW_LOG("4096");
            /* Get predefined 4096-bit parameters. */
            dh = wc_Dh_ffdhe4096_Get();
#endif
            break;
        case 6144:
#ifdef HAVE_FFDHE_6144
            WGW_LOG("6144");
            /* Get predefined 6144-bit parameters. */
            dh = wc_Dh_ffdhe6144_Get();
#endif
            break;
        case 8192:
#ifdef HAVE_FFDHE_8192
            WGW_LOG("8192");
            /* Get predefined 8192-bit parameters. */
            dh = wc_Dh_ffdhe8192_Get();
#endif
            break;
        default:
            /* Key size not supported. */
            WGW_ERROR("Unsupported DH key size: %d", bits);
            return GNUTLS_E_INVALID_REQUEST;
    }

    /* Store the parameters in the GnuTLS parameters. */
    return dh_store_params(dh, params);
}

/**
 * Generate DH parameters.
 *
 * Only DH parameter generation supported.
 * RSA/ECDSA/EDDSA do not require parameter generation.
 *
 * @param [in]      algo    GnuTLS PK algorithm.
 * @param [in]      level   For DH, number of bits in prime.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when bit size is not supported.
 * @return  GNUTLS_E_LIB_IN_ERROR_STATE when library is an error state.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_params(gnutls_pk_algorithm_t algo,
    unsigned int level, gnutls_pk_params_st *params)
{
    int ret = 0;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    /* Handle different key types */
    if (algo == GNUTLS_PK_DH) {
        ret = wolfssl_pk_generate_params_dh(level, params);
    }

    return ret;
}


/**
 * Generate an RSA private/public key pair.
 *
 * @param [in]      bits    Number of bits in key.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_FIPS140_OP_NOT_APPROVED when FIPS140 build
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing RSA key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_rsa(unsigned int bits,
    gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    WGW_LOG("bits: %d", bits);
#if defined(HAVE_FIPS)
    /* missing check for 1024, 1024 is not allowed */
    if (bits == 1024) {
        WGW_ERROR("Bits size not valid");
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
    }
#endif

#ifdef WC_RNG_SEED_CB
    /* Set the seed callback to get entropy. */
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) {
        WGW_ERROR("wc_InitRsaKey failed with code %d", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate RSA key */
    ret = wc_MakeRsaKey(&rsa, bits, WC_RSA_EXPONENT, &priv_rng);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_ERROR("RSA key generation failed with code %d", ret);
        wc_FreeRsaKey(&rsa);
#if defined(HAVE_FIPS)
        return GNUTLS_FIPS140_OP_NOT_APPROVED;
#else
        return GNUTLS_E_PK_GENERATION_ERROR;
#endif
    }

    /* Store RSA fields in the GnuTLS parameters. */
    ret = rsa_store_params(&rsa, params);
    /* RSA key object no longer needed. */
    wc_FreeRsaKey(&rsa);

    return ret;
}

/**
 * Generate a DH private/public key pair.
 *
 * @param [in]      bits    Number of bits in key.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_dh(unsigned int bits,
    gnutls_pk_params_st *params)
{
    int ret;
    DhKey dh;
    unsigned char *priv;
    word32 privSz;
    unsigned char *pub;
    word32 pubSz;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

#ifdef WC_RNG_SEED_CB
    /* Set the seed callback to get entropy. */
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Convert private key size to public key size. */
    if (bits == 256) {
        bits = 2048;
    } else if (bits == 276) {
        bits = 3072;
    } else if (bits == 336) {
        bits = 4096;
    } else if (bits == 376) {
        bits = 6144;
    } else if (bits == 512) {
        bits = 8192;
    }

    /* Generate/get the parameters for the bit size if bit size specified.
     * Otherwise, the parameters are already in GnuTLS's params.
     */
    if (bits != 0) {
        WGW_LOG("Get fixed parameters");
        ret = wolfssl_pk_generate_params_dh(bits, params);
        if (ret != 0) {
            return ret;
        }
    }
    /* Load the parameters from GnuTLS parameters into wolfSSL DH key. */
    WGW_LOG("Load DH parameters from params");
    ret = dh_load_params(&dh, params);
    if (ret != 0) {
        wc_FreeDhKey(&dh);
        return ret;
    }
    if (bits == 0) {
        /* If bits not passed in then still need it - calculate from prime. */
        bits = mp_count_bits(&dh.p);
    }

    /* Convert bits to bytes and allocate private key. */
    privSz = (bits + 7) / 8;
    priv = gnutls_malloc(privSz);
    if (priv == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_FreeDhKey(&dh);
        return GNUTLS_E_MEMORY_ERROR;
    }
    /* Convert bits to bytes and allocate public key. */
    pubSz = (bits + 7) / 8;
    pub = gnutls_malloc(pubSz);
    if (pub == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        gnutls_free(priv);
        wc_FreeDhKey(&dh);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate public/private key pair for DH. */
    ret = wc_DhGenerateKeyPair(&dh, &priv_rng, priv, &privSz, pub, &pubSz);

    PRIVATE_KEY_LOCK();

    /* No longer need DH key (private/public generated into buffers). */
    wc_FreeDhKey(&dh);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_DhGenerateKeyPair", ret);
        gnutls_free(pub);
        gnutls_free(priv);
        return ret;
    }

    /* Load the public key into the GnuTLS parameters. */
    ret = _gnutls_mpi_init_scan(&params->params[DH_Y], pub, pubSz);
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
        /* Load the private key into the GnuTLS parameters. */
        ret = _gnutls_mpi_init_scan(&params->params[DH_X], priv, privSz);
    }
    if (ret == 0) {
        /* Update allocated bigint count. */
        params->params_nr++;
    }

    /* Dispose of dynamically allocated data. */
    gnutls_free(pub);
    gnutls_free(priv);

    return ret;
}

/**
 * Generate an ECC private/public key pair.
 *
 * @param [in]      curve   GnuTLS curve.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_ecc(unsigned int curve,
    gnutls_pk_params_st *params)
{
    int ret;
    ecc_key ecc;
    int curve_id;
    int curve_size;

    WGW_FUNC_ENTER();

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Get the curve id and size for GnuTLS curve. */
    ret = ecc_curve_to_id_size(curve, &curve_id, &curve_size);
    if (ret != 0) {
        return ret;
    }

#ifdef WC_RNG_SEED_CB
    /* Set the seed callback to get entropy. */
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    /* Initialize ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate ECC key */
    ret = wc_ecc_make_key_ex(&priv_rng, curve_size, &ecc, curve_id);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_make_key_ex", ret);
        wc_ecc_free(&ecc);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Store the curve in the GnuTLS parameters. */
    params->curve = curve;
    /* Store the ECC key in the GnuTLS parameters. */
    ret = ecc_store_key(&ecc, params);
    /* wolfSSL ECC key no longer needed. */
    wc_ecc_free(&ecc);

    return ret;
}

#ifdef HAVE_ED25519
/**
 * Generate an Ed25519 private/public key pair.
 *
 * @param [in]      curve   GnuTLS curve.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_ECC_CURVE_INVALID when curve does not match algorithm.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_ed25519(unsigned int curve,
    gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;
    word32 privSz = ED25519_PRV_KEY_SIZE;
    word32 pubSz = ED25519_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    /* Check curve matches algorithm. */
    if (curve != GNUTLS_ECC_CURVE_ED25519) {
        return GNUTLS_ECC_CURVE_INVALID;
    }

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Initialize Ed25519 key */
    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate Ed25519 key */
    ret = wc_ed25519_make_key(&priv_rng, ED25519_KEY_SIZE, &ed25519);

    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_make_key", ret);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Set the curve into the GnuTLS parameters. */
    params->curve = curve;
    /* No allocated parameters - keys in raw fields. */
    params->params_nr = 0;

    /* Allocate memory in GnuTLS parameters for private value. */
    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_MEMORY_ERROR;
    }
    /* Allocate memory in GnuTLS parameters for public value. */
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_ed25519_free(&ed25519);
        /* Dispose of private value buffer. */
        gnutls_free(params->raw_priv.data);
        /* Ensure private values is empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Export public and private key into buffers. */
    ret = wc_ed25519_export_key(&ed25519, params->raw_priv.data, &privSz,
        params->raw_pub.data, &pubSz);
    /* wolfSSL Ed25519 object no longer needed. */
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_export_key", ret);
        /* Dispose of private and public value buffers. */
        gnutls_free(params->raw_priv.data);
        gnutls_free(params->raw_pub.data);
        /* Ensure private and public values are empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set sizes of private and public values into GnuTLS parameters. */
    params->raw_priv.size = ED25519_KEY_SIZE;   /* Private-only */
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

#ifdef HAVE_ED448
/**
 * Generate an Ed448 private/public key pair.
 *
 * @param [in]      curve   GnuTLS curve.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_ECC_CURVE_INVALID when curve does not match algorithm.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_ed448(unsigned int curve,
    gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;
    word32 privSz = ED448_PRV_KEY_SIZE;
    word32 pubSz = ED448_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    /* Check curve matches algorithm. */
    if (curve != GNUTLS_ECC_CURVE_ED448) {
        return GNUTLS_ECC_CURVE_INVALID;
    }

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Initialize Ed448 key */
    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate Ed448 key */
    ret = wc_ed448_make_key(&priv_rng, ED448_KEY_SIZE, &ed448);

    PRIVATE_KEY_LOCK();

    /* Random number generator no longer needed. */
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_make_key", ret);
        wc_ed448_free(&ed448);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Set the curve into the GnuTLS parameters. */
    params->curve = curve;
    /* No allocated parameters - keys in raw fields. */
    params->params_nr = 0;

    /* Allocate memory in GnuTLS parameters for private value. */
    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_ed448_free(&ed448);
        return GNUTLS_E_MEMORY_ERROR;
    }
    /* Allocate memory in GnuTLS parameters for public value. */
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_ed448_free(&ed448);
        /* Dispose of private value buffer. */
        gnutls_free(params->raw_priv.data);
        /* Ensure private values is empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Export public and private key into buffers. */
    ret = wc_ed448_export_key(&ed448, params->raw_priv.data, &privSz,
        params->raw_pub.data, &pubSz);
    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_export_key", ret);
        /* Dispose of private and public value buffers. */
        gnutls_free(params->raw_priv.data);
        gnutls_free(params->raw_pub.data);
        /* Ensure private and public values are empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set sizes of private and public values into GnuTLS parameters. */
    params->raw_priv.size = ED448_KEY_SIZE;     /* Private-only */
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

#ifdef HAVE_CURVE25519
/**
 * Generate an X25519 private/public key pair.
 *
 * @param [in]      curve   GnuTLS curve.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_ECC_CURVE_INVALID when curve does not match algorithm.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_x25519(unsigned int curve,
    gnutls_pk_params_st *params)
{
    int ret;
    curve25519_key x25519;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    /* Check curve matches algorithm. */
    if (curve != GNUTLS_ECC_CURVE_X25519) {
        return GNUTLS_ECC_CURVE_INVALID;
    }

    /* Initialize a new random for generation. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Initialize X25519 key */
    ret = wc_curve25519_init(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate X25519 key */
    ret = wc_curve25519_make_key(&priv_rng, CURVE25519_KEYSIZE, &x25519);

    PRIVATE_KEY_LOCK();

    /* Random number generator no longer needed. */
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_make_key", ret);
        wc_curve25519_free(&x25519);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Set the curve into the GnuTLS parameters. */
    params->curve = curve;
    /* No allocated parameters - keys in raw fields. */
    params->params_nr = 0;

    /* Allocate memory in GnuTLS parameters for private value. */
    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_curve25519_free(&x25519);
        return GNUTLS_E_MEMORY_ERROR;
    }
    /* Allocate memory in GnuTLS parameters for public value. */
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_curve25519_free(&x25519);
        /* Dispose of private value buffer. */
        gnutls_free(params->raw_priv.data);
        /* Ensure private values is empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Export public and private key into buffers. */
    ret = wc_curve25519_export_key_raw_ex(&x25519, params->raw_priv.data,
        &privSz, params->raw_pub.data, &pubSz, EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_export_key_raw", ret);
        /* Dispose of private and public value buffers. */
        gnutls_free(params->raw_priv.data);
        gnutls_free(params->raw_pub.data);
        /* Ensure private and public values are empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set sizes of private and public values into GnuTLS parameters. */
    params->raw_priv.size = privSz;
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

#ifdef HAVE_CURVE448
/**
 * Generate an X448 private/public key pair.
 *
 * @param [in]      curve   GnuTLS curve.
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_ECC_CURVE_INVALID when curve does not match algorithm.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys_x448(unsigned int curve,
    gnutls_pk_params_st *params)
{
    int ret;
    curve448_key x448;
    word32 privSz = CURVE448_KEY_SIZE;
    word32 pubSz = CURVE448_PUB_KEY_SIZE;

    WGW_FUNC_ENTER();

    /* Check curve matches algorithm. */
    if (curve != GNUTLS_ECC_CURVE_X448) {
        return GNUTLS_ECC_CURVE_INVALID;
    }

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Initialize X448 key */
    ret = wc_curve448_init(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    PRIVATE_KEY_UNLOCK();

    /* Generate X448 key */
    ret = wc_curve448_make_key(&priv_rng, CURVE448_KEY_SIZE, &x448);

    /* Random number generator no longer needed. */
    PRIVATE_KEY_LOCK();

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_make_key", ret);
        wc_curve448_free(&x448);
        return GNUTLS_E_PK_GENERATION_ERROR;
    }

    /* Set the curve into the GnuTLS parameters. */
    params->curve = curve;
    /* No allocated parameters - keys in raw fields. */
    params->params_nr = 0;

    /* Allocate memory in GnuTLS parameters for private value. */
    params->raw_priv.data = gnutls_malloc(privSz);
    if (params->raw_priv.data == NULL) {
        WGW_ERROR("Allocating memory for private key: %d", privSz);
        wc_curve448_free(&x448);
        return GNUTLS_E_MEMORY_ERROR;
    }
    /* Allocate memory in GnuTLS parameters for public value. */
    params->raw_pub.data = gnutls_malloc(pubSz);
    if (params->raw_pub.data == NULL) {
        WGW_ERROR("Allocating memory for public key: %d", pubSz);
        wc_curve448_free(&x448);
        /* Dispose of private value buffer. */
        gnutls_free(params->raw_priv.data);
        /* Ensure private values is empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        return GNUTLS_E_MEMORY_ERROR;
    }

    /* Export public and private key into buffers. */
    ret = wc_curve448_export_key_raw_ex(&x448, params->raw_priv.data, &privSz,
        params->raw_pub.data, &pubSz, EC448_LITTLE_ENDIAN);
    wc_curve448_free(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_export_key_raw_ex", ret);
        /* Dispose of private and public value buffers. */
        gnutls_free(params->raw_priv.data);
        gnutls_free(params->raw_pub.data);
        /* Ensure private and public values are empty on error. */
        params->raw_priv.data = NULL;
        params->raw_priv.size = 0;
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set sizes of private and public values into GnuTLS parameters. */
    params->raw_priv.size = privSz;
    params->raw_pub.size = pubSz;

    return ret;
}
#endif

/**
 * Generate an X448 private/public key pair.
 *
 * @param [in]      algo       GnuTLS PK algorithm.
 * @param [in]      level      GnuTLS curve or size of prime in bits.
 * @param [in, out] params     GnuTLS PK parameters.
 * @param [in]      ephemeral  Key pair is ephemenral - random can be weaker.
 *                             Ignored.
 * @return  0 on success.
 * @return  GNUTLS_FIPS140_OP_NOT_APPROVED when FIPS140 build
 * @return  GNUTLS_ECC_CURVE_INVALID when curve does not match algorithm.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing key fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_generate_keys(gnutls_pk_algorithm_t algo,
    unsigned int level, gnutls_pk_params_st *params,
    unsigned ephemeral)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check that the library is not in an error state. */
    if (_gnutls_have_lib_error()) {
        return GNUTLS_E_LIB_IN_ERROR_STATE;
    }

    (void)ephemeral;

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
        case GNUTLS_PK_RSA:
            /* Generate an RSA key. */
            ret = wolfssl_pk_generate_keys_rsa(level, params);
            break;

        case GNUTLS_PK_DH:
            /* Generate a DH key. */
            ret = wolfssl_pk_generate_keys_dh(level, params);
            break;

        case GNUTLS_PK_ECDSA:
            /* Generate an ECC key. */
            ret = wolfssl_pk_generate_keys_ecc(level, params);
            break;

#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            /* Generate an Ed25519 key. */
            ret = wolfssl_pk_generate_keys_ed25519(level, params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            /* Generate an Ed448 key. */
            ret = wolfssl_pk_generate_keys_ed448(level, params);
            break;
#endif

#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
            /* Generate an X25519 key. */
            ret = wolfssl_pk_generate_keys_x25519(level, params);
            break;
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
            /* Generate an X448 key. */
            ret = wolfssl_pk_generate_keys_x448(level, params);
            break;
#endif

        default:
            /* Algorithm not supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            return GNUTLS_E_ALGO_NOT_SUPPORTED;
    }

    /* Store the algorithm into the GnuTLS parameters. */
    params->algo = algo;

    return ret;
}

/**
 * Fixup RSA key by generating missing CRT parameters.
 *
 * @param [in, out] params  GnuTLS PK parameters.
 * @return  0 on success.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when P is 0.
 * @return  GNUTLS_E_INTERNAL_ERROR when a calculation fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_fixup_rsa_calc_exp(gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;
    mp_int tmp;

    WGW_FUNC_ENTER();

    /* Clear out all extra parameters in case they were left over. */
    _gnutls_mpi_zrelease(&params->params[RSA_COEF]);
    _gnutls_mpi_zrelease(&params->params[RSA_E1]);
    _gnutls_mpi_zrelease(&params->params[RSA_E2]);

    /* Set the number of allocated parameters to exclude CRT parameter. */
    params->params_nr = RSA_MIN_PRIV_PARAMS;

    /* Load the wolfSSL RSA key with data from the GnuTLS parameters. */
    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Ensure P is valid for inversion. */
    if (mp_iszero(&rsa.p)) {
        WGW_ERROR("First prime is 0 - can't invert");
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    /* Calculate coefficient (u). */
    ret = mp_invmod(&rsa.q, &rsa.p, &rsa.u);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_invmod", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    /* Store coefficient in GnuTLS parameters. */
    ret = mp_int_to_bigint(&rsa.u, &params->params[RSA_COEF]);
    if (ret != 0) {
        wc_FreeRsaKey(&rsa);
        return ret;
    }
    /* Update allocated bigint count. */
    params->params_nr++;

    /* Initialize mp_int for use as a temporary in calculations */
    ret = mp_init(&tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Calculate first exponent (dP). */
    ret = mp_sub_d(&rsa.p, 1, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_mod(&rsa.dP, &rsa.d, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_invmod", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    /* Store first exponent in GnuTLS parameters. */
    ret = mp_int_to_bigint(&rsa.dP, &params->params[RSA_E1]);
    if (ret != 0) {
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return ret;
    }
    /* Update allocated bigint count. */
    params->params_nr++;

    /* Calculate second exponent (dQ). */
    ret = mp_sub_d(&rsa.q, 1, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    ret = mp_mod(&rsa.dQ, &rsa.d, &tmp);
    mp_free(&tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_invmod", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    /* Store second exponent in GnuTLS parameters. */
    ret = mp_int_to_bigint(&rsa.dQ, &params->params[RSA_E2]);
    wc_FreeRsaKey(&rsa);
    if (ret != 0) {
        return ret;
    }
    /* Update allocated bigint count. */
    params->params_nr++;

    return 0;
}

/**
 * Check that the product of the two primes is the modulus.
 *
 * @param [in] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when count of bits of q + u < p.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when multiplying p and q fails.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when is not equal to product of p and q.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing the temporary mp_int
 *          fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_fixup_rsa_check_p_q(gnutls_pk_params_st *params)
{
    int ret;
    RsaKey rsa;
    mp_int tmp;

    WGW_FUNC_ENTER();

    /* Load the RSA key from the GnuTLS parameters. */
    ret = rsa_load_params(&rsa, params, 1);
    if (ret != 0) {
        return ret;
    }

    /* Check q, u and p are about the right sizes. */
    if (mp_count_bits(&rsa.q) + mp_count_bits(&rsa.u) < mp_count_bits(&rsa.p)) {
        WGW_ERROR("q and c smaller than p");
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    /* Initialize a temporary to use in calculations. */
    ret = mp_init(&tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Calculate product of p and q. */
    ret = mp_mul(&rsa.p, &rsa.q, &tmp);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("mp_init", ret);
        mp_free(&tmp);
        wc_FreeRsaKey(&rsa);
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    /* Compare p * q to n. */
    ret = mp_cmp(&rsa.n, &tmp);
    mp_free(&tmp);
    wc_FreeRsaKey(&rsa);
    if (ret != MP_EQ) {
        WGW_ERROR("p * q != n");
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    return 0;
}

/**
 * Fill in CRT parameters if not available and check p * q = n.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when P is 0.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when count of bits of q + u < p.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when multiplying p and q fails.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when is not equal to product of p and q.
 * @return  GNUTLS_E_INTERNAL_ERROR when a calculation fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing the temporary mp_int
 *          fails.
 */
static int wolfssl_pk_fixup_rsa(gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check we have the basic RSA private key parameters: n, e, d, p, q */
    if (params->params_nr < RSA_MIN_PRIV_PARAMS) {
        WGW_ERROR("Too few parameters for RSA private key");
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    /* Check we have CRT parameters. */
    if (params->params_nr < RSA_MAX_PARAMS) {
        WGW_LOG("RSA private key missing exp parameters");
        ret = wolfssl_pk_fixup_rsa_calc_exp(params);
        if (ret != 0) {
            return ret;
        }
    }

    /* Check p, q and u look about right and p * q equals n. */
    return wolfssl_pk_fixup_rsa_check_p_q(params);
}

/**
 * Check RSA key and PSS parameters.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when not all private key fields are set.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing the temporary mp_int
 *          fails.
 * @return  GNUTLS_E_PK_INVALID_PUBKEY_PARAMS when PSS parameters are invalid.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_fixup_rsa_pss(gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Check we have the basic RSA private key parameters: n, e, d, p, q */
    if (params->params_nr < RSA_MIN_PRIV_PARAMS) {
        WGW_ERROR("Too few parameters for RSA private key");
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }

    /* If we have digest for PSS check digest and salt size are valid. */
    if (params->spki.rsa_pss_dig != GNUTLS_DIG_UNKNOWN) {
        int bits;
        int hash_len = gnutls_hash_get_len(params->spki.rsa_pss_dig);
        mp_int n;

        /* Initialize a mp_int for the modulus. */
        ret = mp_init(&n);
        if (ret != 0) {
            WGW_WOLFSSL_ERROR("mp_init", ret);
            return GNUTLS_E_INTERNAL_ERROR;
        }
        /* Put modulus into mp_int. */
        ret = bigint_to_mp_int(params->params[RSA_MODULUS], &n);
        if (ret != 0) {
            mp_free(&n);
            return ret;
        }
        /* Count bits in modulus. */
        bits = mp_count_bits(&n);
        mp_free(&n);

        /* Check hash length plus salt size is valid for key size. */
        if (hash_len + (int)params->spki.salt_size + 2 > (bits + 7) / 8) {
            return GNUTLS_E_PK_INVALID_PUBKEY_PARAMS;
        }
    }

    return 0;
}

#ifdef HAVE_ED25519
/**
 * Check curve field and make public key from Ed25519 private key.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_ECC_UNSUPPORTED_CURVE when curve field is invalid.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when no private key data.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing dynamic memory fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when importing private key fails.
 */
static int wolfssl_pk_fixup_ed25519(gnutls_pk_params_st *params)
{
    int ret;
    ed25519_key ed25519;

    WGW_FUNC_ENTER();

    /* Check curve field of parameters is correct. */
    if (params->curve != GNUTLS_ECC_CURVE_ED25519) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_ED25519,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    /* Check we have a private key. */
    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    /* Check whether a public key buffer has been allocated. */
    if (params->raw_pub.data == NULL) {
        /* Allocate a public key buffer now. */
        params->raw_pub.data = gnutls_malloc(ED25519_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                ED25519_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize Ed25519 private key */
    ret = wc_ed25519_init(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_init", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Import private key only. */
    ret = wc_ed25519_import_private_only(params->raw_priv.data,
        params->raw_priv.size, &ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_import_private_key", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        wc_ed25519_free(&ed25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Make key into buffer in GnuTLS parameters. */
    ret = wc_ed25519_make_public(&ed25519, params->raw_pub.data,
        ED25519_PUB_KEY_SIZE);
    /* wolfSSL Ed25519 key no longer needed.  */
    wc_ed25519_free(&ed25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed25519_make_public", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set the public key size into GnuTLS parameters. */
    params->raw_pub.size = ED25519_PUB_KEY_SIZE;

    return 0;
}
#endif

#ifdef HAVE_ED448
/**
 * Check curve field and make public key from Ed448 private key.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_ECC_UNSUPPORTED_CURVE when curve field is invalid.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when no private key data.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing dynamic memory fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when importing private key fails.
 */
static int wolfssl_pk_fixup_ed448(gnutls_pk_params_st *params)
{
    int ret;
    ed448_key ed448;

    WGW_FUNC_ENTER();

    /* Check curve field of parameters is correct. */
    if (params->curve != GNUTLS_ECC_CURVE_ED448) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_ED448,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    /* Check we have a private key. */
    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    /* Check whether a public key buffer has been allocated. */
    if (params->raw_pub.data == NULL) {
        /* Allocate a public key buffer now. */
        params->raw_pub.data = gnutls_malloc(ED448_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                ED448_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize Ed448 private key */
    ret = wc_ed448_init(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_init", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Import private key only. */
    ret = wc_ed448_import_private_only(params->raw_priv.data,
        params->raw_priv.size, &ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_import_private_key", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        wc_ed448_free(&ed448);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Make key into buffer in GnuTLS parameters. */
    ret = wc_ed448_make_public(&ed448, params->raw_pub.data,
        ED448_PUB_KEY_SIZE);
    /* wolfSSL Ed448 key no longer needed.  */
    wc_ed448_free(&ed448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ed448_make_public", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set the public key size into GnuTLS parameters. */
    params->raw_pub.size = ED448_PUB_KEY_SIZE;

    return 0;
}
#endif

#ifdef HAVE_CURVE25519
/**
 * Check curve field and make public key from X25519 private key.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_ECC_UNSUPPORTED_CURVE when curve field is invalid.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when no private key data.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing dynamic memory fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when importing private key fails.
 */
static int wolfssl_pk_fixup_x25519(gnutls_pk_params_st *params)
{
    int ret;
    curve25519_key x25519;

    WGW_FUNC_ENTER();

    /* Check curve field of parameters is correct. */
    if (params->curve != GNUTLS_ECC_CURVE_X25519) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_X25519,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    /* Check we have a private key. */
    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    /* Check whether a public key buffer has been allocated. */
    if (params->raw_pub.data == NULL) {
        /* Allocate a public key buffer now. */
        params->raw_pub.data = gnutls_malloc(CURVE25519_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                CURVE25519_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize X25519 private key */
    ret = wc_curve25519_init(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Import private key only. */
    ret = wc_curve25519_import_private(params->raw_priv.data,
        params->raw_priv.size, &x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_import_private_key", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        wc_curve25519_free(&x25519);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Make key into buffer in GnuTLS parameters. */
    ret = wc_curve25519_make_pub(CURVE25519_PUB_KEY_SIZE, params->raw_pub.data,
        params->raw_priv.size, params->raw_priv.data);
    /* wolfSSL X25519 key no longer needed.  */
    wc_curve25519_free(&x25519);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_make_pub", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set the public key size into GnuTLS parameters. */
    params->raw_pub.size = CURVE25519_PUB_KEY_SIZE;

    return 0;
}
#endif

#ifdef HAVE_CURVE448
/**
 * Check curve field and make public key from X448 private key.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_ECC_UNSUPPORTED_CURVE when curve field is invalid.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when no private key data.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing dynamic memory fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when importing private key fails.
 */
static int wolfssl_pk_fixup_x448(gnutls_pk_params_st *params)
{
    int ret;
    curve448_key x448;

    WGW_FUNC_ENTER();

    /* Check curve field of parameters is correct. */
    if (params->curve != GNUTLS_ECC_CURVE_X448) {
        WGW_ERROR("Algorithm isn't curve: %d %d", GNUTLS_ECC_CURVE_X448,
            params->curve);
        return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
    }

    /* Check we have a private key. */
    if (params->raw_priv.data == NULL) {
        return GNUTLS_E_PK_INVALID_PRIVKEY;
    }
    /* Check whether a public key buffer has been allocated. */
    if (params->raw_pub.data == NULL) {
        /* Allocate a public key buffer now. */
        params->raw_pub.data = gnutls_malloc(CURVE448_PUB_KEY_SIZE);
        if (params->raw_pub.data == NULL) {
            WGW_ERROR("Allocating memory for public key: %d",
                CURVE448_PUB_KEY_SIZE);
            return GNUTLS_E_MEMORY_ERROR;
        }
    }

    /* Initialize X448 private key */
    ret = wc_curve448_init(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Import private key only. */
    ret = wc_curve448_import_private(params->raw_priv.data,
        params->raw_priv.size, &x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_import_private_key", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        wc_curve448_free(&x448);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Make key into buffer in GnuTLS parameters. */
    ret = wc_curve448_make_pub(CURVE448_PUB_KEY_SIZE, params->raw_pub.data,
        params->raw_priv.size, params->raw_priv.data);
    /* wolfSSL X448 key no longer needed.  */
    wc_curve448_free(&x448);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_make_pub", ret);
        /* Dispose of public value buffer. */
        gnutls_free(params->raw_pub.data);
        /* Ensure public value is empty on error. */
        params->raw_pub.data = NULL;
        params->raw_pub.size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Set the public key size into GnuTLS parameters. */
    params->raw_pub.size = CURVE448_PUB_KEY_SIZE;

    return 0;
}
#endif

/**
 * Check curve field and make public key from private key.
 *
 * @param [in, out] params  GnuTLS params.
 * @return  0 on success.
 * @return  GNUTLS_E_ECC_UNSUPPORTED_CURVE when curve field is invalid.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when no private key data.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GNUTLS_E_CRYPTO_INIT_FAILED when initializing dynamic memory fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when importing private key fails.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when P is 0.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when count of bits of q + u < p.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when multiplying p and q fails.
 * @return  GNUTLS_E_PK_INVALID_PRIVKEY when is not equal to product of p and q.
 * @return  GNUTLS_E_INTERNAL_ERROR when a calculation fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing the temporary mp_int
 *          fails.
 * @return  GNUTLS_E_PK_INVALID_PUBKEY_PARAMS when PSS parameters are invalid.
 */
static int wolfssl_pk_fixup(gnutls_pk_algorithm_t algo,
    gnutls_direction_t direction, gnutls_pk_params_st *params)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Only need to fixup when exporting. */
    if (direction != GNUTLS_IMPORT)
        return 0;

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_RSA:
            /* Fixup RSA key. */
            ret = wolfssl_pk_fixup_rsa(params);
            break;
        case GNUTLS_PK_RSA_PSS:
            /* Fixup RSA key that is for RSA-PSS. */
            ret = wolfssl_pk_fixup_rsa_pss(params);
            break;
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
            /* Fixup Ed25519 key. */
            ret = wolfssl_pk_fixup_ed25519(params);
            break;
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
            /* Fixup Ed448 key. */
            ret = wolfssl_pk_fixup_ed448(params);
            break;
#endif
#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
            /* Fixup X25519 key. */
            ret = wolfssl_pk_fixup_x25519(params);
            break;
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
            /* Fixup X448 key. */
            ret = wolfssl_pk_fixup_x448(params);
            break;
#endif
        default:
            /* Other algorithms don't need fixing. */
            ret = 0;
            break;
    }

    return ret;
}

/**
 * Derive shared secret from private key and peer's public key with DH.
 *
 * @param [out] out    Shared secret.
 * @param [in]  priv   Private key.
 * @param [in]  pub    Peer's public key.
 * @param [in]  nonce  Not used.
 * @param [in]  flags  Flags including:
 *                       PK_DERIVE_TLS13 - whether deriving for TLS13.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when nonce is NULL.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing a wolfSSL object fails.
 * @return  GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER when public key is invalid.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_derive_dh(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce, unsigned int flags)
{
    int ret;
    DhKey dh;
    word32 len;
    word32 bits;
    gnutls_datum_t private;
    gnutls_datum_t public;
    gnutls_datum_t q;

    WGW_FUNC_ENTER();

    /* Check nonce is not NULL. */
    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Get private key from PK parameters. */
    ret = _gnutls_mpi_dprint(priv->params[DH_X], &private);
    if (ret != 0) {
        WGW_ERROR("_gnutls_mpi_print: %d", ret);
        return ret;
    }
    /* Get public key from peer's PK parameters. */
    ret = _gnutls_mpi_dprint(pub->params[DH_Y], &public);
    if (ret != 0) {
        WGW_ERROR("_gnutls_mpi_print: %d", ret);
        gnutls_free(private.data);
        return ret;
    }

    WGW_LOG("Load DH parameters from params");
    /* Load the parameters into the DH key. */
    ret = dh_load_params(&dh, priv);
    if (ret != 0) {
        gnutls_free(public.data);
        gnutls_free(private.data);
        return ret;
    }

    /* Check for Q parameter and load if available. */
    if (priv->params[DH_Q] != NULL) {
        ret = _gnutls_mpi_dprint(priv->params[DH_Q], &q);
        if (ret != 0) {
            WGW_ERROR("_gnutls_mpi_print: %d", ret);
            wc_FreeDhKey(&dh);
            gnutls_free(public.data);
            gnutls_free(private.data);
            return ret;
        }
    } else {
        q.data = NULL;
        q.size = 0;
    }

    /* Check public key is valid for parameters. */
    ret = wc_DhCheckPubKey_ex(&dh, public.data, public.size, q.data, q.size);
    gnutls_free(q.data);
    if (ret != 0) {
        wc_FreeDhKey(&dh);
        gnutls_free(public.data);
        gnutls_free(private.data);
        return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

    /* Allocate buffer for shared secret. */
    bits = mp_count_bits(&dh.p);
    len = (bits + 7) / 8;
    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_FreeDhKey(&dh);
        gnutls_free(public.data);
        gnutls_free(private.data);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Check if shared secret is being used with TLS v1.3. */
    if (flags & PK_DERIVE_TLS13) {
        /* Encode with 0 front padding. */
#if !defined(HAVE_FIPS)
        ret = wc_DhAgree_ct(&dh, out->data, &len, private.data, private.size,
            public.data, public.size);
#else
        ret = wc_DhAgree(&dh, out->data, &len, private.data, private.size,
            public.data, public.size);
        /* Front pad if needed. */
        if ((ret == 0) && (len < (bits + 7) / 8)) {
            word32 offset = (bits + 7) / 8 - len;
            XMEMMOVE(out->data + offset, out->data, len);
            XMEMSET(out->data, 0, offset);
            len += offset;
        }
#endif
    } else {
        /* Don't front pad. */
        ret = wc_DhAgree(&dh, out->data, &len, private.data, private.size,
            public.data, public.size);
    }

    PRIVATE_KEY_LOCK();

    /* DH key, public and private data are no longer needed. */
    wc_FreeDhKey(&dh);
    gnutls_free(public.data);
    gnutls_free(private.data);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_DhAgree", ret);
        /* Dispose of shared secret value buffer. */
        gnutls_free(out->data);
        /* Ensure shared secret value is empty on error. */
        out->data = NULL;
        out->size = 0;
        return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

    /* Set shared secret length. */
    out->size = len;

    return 0;
}

/**
 * Derive shared secret from private key and peer's public key with ECDH.
 *
 * @param [out] out    Shared secret.
 * @param [in]  priv   Private key.
 * @param [in]  pub    Peer's public key.
 * @param [in]  nonce  Not used.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when nonce is NULL.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing a wolfSSL object fails.
 * @return  GNUTLS_E_PK_INVALID_PUBKEY when public key is invalid.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_derive_ecc(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce)
{
    int ret;
    ecc_key private;
    ecc_key public;
    word32 len;

    WGW_FUNC_ENTER();

    /* Check nonce is not NULL. */
    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0)
        return GNUTLS_E_RANDOM_FAILED;

    /* Initialize and load the private ECC key from GnuTLS PK parameters. */
    ret = ecc_load_params(&private, priv, 1);
    if (ret != 0) {
        return ret;
    }
    /* Set the random for use with blinding. */
    private.rng = &priv_rng;

    /* Initialize and load the public ECC key from peer's GnuTLS PK parameters.
     */
    ret = ecc_load_params(&public, pub, 0);
    if (ret != 0) {
        wc_ecc_free(&private);
        return ret;
    }

    /* Check the public key is valid for the curve. */
    ret = wc_ecc_check_key(&public);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_check_key", ret);
        wc_ecc_free(&public);
        wc_ecc_free(&private);
        return GNUTLS_E_PK_INVALID_PUBKEY;
    }

    /* Allocate memory for the shared secret. */
    len = private.dp->size;
    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_ecc_free(&public);
        wc_ecc_free(&private);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Calculate the shared secret. */
    ret = wc_ecc_shared_secret(&private, &public, out->data, &len);

    PRIVATE_KEY_LOCK();

    /* Random, private and public key no londer needed. */
    wc_ecc_free(&public);
    wc_ecc_free(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_ecc_shared_secret", ret);
        /* Dispose of shared secret value buffer. */
        gnutls_free(out->data);
        /* Ensure shared secret value is empty on error. */
        out->data = NULL;
        out->size = 0;
        return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

    /* Set shared secret length. */
    out->size = len;

    return 0;
}

#ifdef HAVE_CURVE25519
/**
 * Derive shared secret from private key and peer's public key with X25519.
 *
 * @param [out] out    Shared secret.
 * @param [in]  priv   Private key.
 * @param [in]  pub    Peer's public key.
 * @param [in]  nonce  Not used.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when nonce is NULL.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing a wolfSSL object fails.
 * @return  GNUTLS_E_PK_INVALID_PUBKEY when public key is invalid.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_derive_x25519(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce)
{
    int ret;
    curve25519_key private;
    curve25519_key public;
    word32 len = CURVE25519_KEYSIZE;

    WGW_FUNC_ENTER();

    /* Check nonce is not NULL. */
    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* Check the public key is valid. */
    ret = wc_curve25519_check_public(pub->raw_pub.data, pub->raw_pub.size,
        EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_check_public", ret);
        return GNUTLS_E_PK_INVALID_PUBKEY;
    }

    /* Initialize X25519 private key. */
    ret = wc_curve25519_init(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Initialize X25519 public key. */
    ret = wc_curve25519_init(&public);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_init", ret);
        wc_curve25519_free(&private);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Import the private key in little-endian order. */
    ret = wc_curve25519_import_private_ex(priv->raw_priv.data,
        priv->raw_priv.size, &private, EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_import_private", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Import the peer's public key in little-endian order. */
    ret = wc_curve25519_import_public_ex(pub->raw_pub.data, pub->raw_pub.size,
        &public, EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_import_public", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

#ifdef WOLFSSL_CURVE25519_BLINDING
    /* Initialize a new random for blinding. */
    if (wolfssl_ensure_rng() != 0) {
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_RANDOM_FAILED;
    }

    /* Set random into private key. */
    ret = wc_curve25519_set_rng(&private, &priv_rng);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_set_rng", ret);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }
#endif

    /* Allocate memory for the shared secret. */
    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_curve25519_free(&public);
        wc_curve25519_free(&private);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Calculate the shared secret. */
    ret = wc_curve25519_shared_secret_ex(&private, &public, out->data, &len,
        EC25519_LITTLE_ENDIAN);

    PRIVATE_KEY_LOCK();

    /* Random, private and public key no londer needed. */
    wc_curve25519_free(&public);
    wc_curve25519_free(&private);

    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve25519_shared_secret_ex", ret);
        /* Dispose of shared secret value buffer. */
        gnutls_free(out->data);
        /* Ensure shared secret value is empty on error. */
        out->data = NULL;
        out->size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->size = len;

    return 0;
}
#endif

#ifdef HAVE_CURVE448
/**
 * Derive shared secret from private key and peer's public key with X448.
 *
 * @param [out] out    Shared secret.
 * @param [in]  priv   Private key.
 * @param [in]  pub    Peer's public key.
 * @param [in]  nonce  Not used.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when nonce is NULL.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing a wolfSSL object fails.
 * @return  GNUTLS_E_PK_INVALID_PUBKEY when public key is invalid.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_derive_x448(gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce)
{
    int ret;
    curve448_key private;
    curve448_key public;
    word32 len = CURVE448_KEY_SIZE;

    WGW_FUNC_ENTER();

    /* Check nonce is not NULL. */
    if (nonce != NULL) {
        WGW_ERROR("Nonce is NULL");
        return GNUTLS_E_INVALID_REQUEST;
    }

    ret = wc_curve448_check_public(pub->raw_pub.data, pub->raw_pub.size,
        EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_check_public", ret);
        return GNUTLS_E_PK_INVALID_PUBKEY;
    }

    /* Initialize X448 private key */
    ret = wc_curve448_init(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Initialize X448 public key */
    ret = wc_curve448_init(&public);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_init", ret);
        wc_curve448_free(&private);
        return GNUTLS_E_CRYPTO_INIT_FAILED;
    }

    /* Import the private key in little-endian order. */
    ret = wc_curve448_import_private_ex(priv->raw_priv.data,
        priv->raw_priv.size, &private, EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_import_private_ex", ret);
        wc_curve448_free(&public);
        wc_curve448_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Import the peer's public key in little-endian order. */
    ret = wc_curve448_import_public_ex(pub->raw_pub.data, pub->raw_pub.size,
        &public, EC448_LITTLE_ENDIAN);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_import_public", ret);
        wc_curve448_free(&public);
        wc_curve448_free(&private);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    /* Allocate memory for the shared secret. */
    out->data = gnutls_malloc(len);
    if (out->data == NULL) {
        WGW_ERROR("Allocating memory for shared key: %d", len);
        wc_curve448_free(&public);
        wc_curve448_free(&private);
        return GNUTLS_E_MEMORY_ERROR;
    }

    PRIVATE_KEY_UNLOCK();

    /* Calculate the shared secret. */
    ret = wc_curve448_shared_secret_ex(&private, &public, out->data, &len,
        EC448_LITTLE_ENDIAN);

    PRIVATE_KEY_LOCK();

    /* Private and public key no londer needed. */
    wc_curve448_free(&public);
    wc_curve448_free(&private);
    if (ret != 0) {
        WGW_WOLFSSL_ERROR("wc_curve448_shared_secret_ex", ret);
        /* Dispose of shared secret value buffer. */
        gnutls_free(out->data);
        /* Ensure shared secret value is empty on error. */
        out->data = NULL;
        out->size = 0;
        return GNUTLS_E_INTERNAL_ERROR;
    }

    out->size = len;

    return 0;
}
#endif

/**
 * Derive shared secret from private key and peer's public key.
 *
 * @param [out] out    Shared secret.
 * @param [in]  priv   Private key.
 * @param [in]  pub    Peer's public key.
 * @param [in]  nonce  Not used.
 * @return  0 on success.
 * @return  GNUTLS_E_INVALID_REQUEST when nonce is NULL.
 * @return  GNUTLS_E_RANDOM_FAILED when random initialization fails.
 * @return  GNUTLS_E_INTERNAL_ERROR when initializing a wolfSSL object fails.
 * @return  GNUTLS_E_PK_INVALID_PUBKEY when public key is invalid.
 * @return  GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER when public key is invalid.
 * @return  GNUTLS_E_MEMORY_ERROR when allocating dynamic memory fails.
 * @return  GnuTLS error on other failure.
 */
static int wolfssl_pk_derive(gnutls_pk_algorithm_t algo, gnutls_datum_t *out,
    const gnutls_pk_params_st *priv, const gnutls_pk_params_st *pub,
    const gnutls_datum_t *nonce, unsigned int flags)
{
    int ret;

    WGW_FUNC_ENTER();

    /* Use GnuTLS algorithm identifier. */
    switch (algo) {
        case GNUTLS_PK_DH:
            /* Derive a secret with Diffie-Hellman. */
            ret = wolfssl_pk_derive_dh(out, priv, pub, nonce, flags);
            break;
        case GNUTLS_PK_EC:
            /* Derive a secret with Elliptic Curve Diffie-Hellman. */
            ret = wolfssl_pk_derive_ecc(out, priv, pub, nonce);
            break;
#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
            /* Derive a secret with Elliptic Curve X25519. */
            ret = wolfssl_pk_derive_x25519(out, priv, pub, nonce);
            break;
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
            /* Derive a secret with Elliptic Curve X448. */
            ret = wolfssl_pk_derive_x448(out, priv, pub, nonce);
            break;
#endif

        default:
            /* Algorithm not supported. */
            WGW_ERROR("Algorithm not supported: %d", algo);
            return GNUTLS_E_INTERNAL_ERROR;
    }

    return ret;
}

/**
 * Encapsulate a random secret using public key.
 *
 * This API is for ML-KEM.
 *
 * @param [in]  algo           GnuTLS PK algorithm.
 * @param [out] ciphertext     Encapsulated secret.
 * @param [out] shared_secret  Random secret that was encapsulated.
 * @param [in]  pub            Public key.
 * @return  GNUTLS_E_UNKNOWN_ALGORITHM when algorithm is not supported.
 */
static int wolfssl_pk_encaps(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *ciphertext, gnutls_datum_t *shared_secret,
    const gnutls_datum_t *pub)
{
    WGW_FUNC_ENTER();

    (void)algo;
    (void)ciphertext;
    (void)shared_secret;
    (void)pub;

    WGW_ERROR("Algorithm not supported: %d", algo);
    /* No algorithms supported at this time. */
    return GNUTLS_E_UNKNOWN_ALGORITHM;
}

/**
 * Decapsualtes ciphertext with private key to get shared secret.
 *
 * This API is for ML-KEM.
 *
 * @param [in]  algo           GnuTLS PK algorithm.
 * @param [out] shared_secret  Random secret that was encapsulated.
 * @param [in]  ciphertext     Encapsulated secret.
 * @param [in]  priv           Private key.
 * @return  GNUTLS_E_UNKNOWN_ALGORITHM when algorithm is not supported.
 */
static int wolfssl_pk_decaps(gnutls_pk_algorithm_t algo,
    gnutls_datum_t *shared_secret, const gnutls_datum_t *ciphertext,
    const gnutls_datum_t *priv)
{
    WGW_FUNC_ENTER();

    (void)algo;
    (void)shared_secret;
    (void)ciphertext;
    (void)priv;

    WGW_ERROR("Algorithm not supported: %d", algo);
    /* No algorithms supported at this time. */
    return GNUTLS_E_UNKNOWN_ALGORITHM;
}

/**
 * Returns whether curve is supported.
 *
 * @param [in] pk  GnuTLS curve.
 * @return  1 when curve supported.
 * @return  0 when curve not supported.
 */
static int wolfssl_pk_curve_exists(gnutls_ecc_curve_t curve)
{
    WGW_FUNC_ENTER();

    switch (curve) {
#ifdef HAVE_ED25519
        case GNUTLS_ECC_CURVE_ED25519:
#endif
#ifdef HAVE_CURVE25519
        case GNUTLS_ECC_CURVE_X25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_ECC_CURVE_ED448:
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_ECC_CURVE_X448:
#endif
#if ECC_MIN_KEY_SZ <= 192
        case GNUTLS_ECC_CURVE_SECP192R1:
#endif
#if ECC_MIN_KEY_SZ <= 224
        case GNUTLS_ECC_CURVE_SECP224R1:
#endif
        case GNUTLS_ECC_CURVE_SECP256R1:
        case GNUTLS_ECC_CURVE_SECP384R1:
        case GNUTLS_ECC_CURVE_SECP521R1:
            WGW_LOG("Curve exists: %d", curve);
            return 1;
        default:
            WGW_ERROR("Curve doesn't exist: %d", curve);
            return 0;
    }
}

/**
 * Returns whether public key algorithm is supported.
 *
 * @param [in] pk  GnuTLS public key algorithm.
 * @return  1 when public key algorithm supported.
 * @return  0 when public key algorithm not supported.
 */
static int wolfssl_pk_exists(gnutls_pk_algorithm_t pk)
{
    WGW_FUNC_ENTER();

    switch (pk) {
        case GNUTLS_PK_RSA:
        case GNUTLS_PK_DH:
        case GNUTLS_PK_ECDSA:
#ifdef HAVE_CURVE25519
        case GNUTLS_PK_ECDH_X25519:
#endif
        case GNUTLS_PK_RSA_PSS:
        case GNUTLS_PK_RSA_OAEP:
#ifdef HAVE_ED25519
        case GNUTLS_PK_EDDSA_ED25519:
#endif
#ifdef HAVE_CURVE448
        case GNUTLS_PK_ECDH_X448:
#endif
#ifdef HAVE_ED448
        case GNUTLS_PK_EDDSA_ED448:
#endif
            WGW_LOG("Algorithm exists: %d", pk);
            return 1;
        default:
            WGW_ERROR("Algorithm doesn't exist: %d", pk);
            return 0;
    }
}

/**
 * Returns whether signature algorithm is supported.
 *
 * @param [in] sign  GnuTLS signature algorithm.
 * @return  1 when signature algorithm supported.
 * @return  0 when signature algorithm not supported.
 */
static int wolfssl_pk_sign_exists(gnutls_sign_algorithm_t sign)
{
    WGW_FUNC_ENTER();

    switch (sign) {
        case GNUTLS_SIGN_RSA_RAW:

        case GNUTLS_SIGN_RSA_MD5:
        case GNUTLS_SIGN_RSA_SHA1:
        case GNUTLS_SIGN_RSA_SHA256:
        case GNUTLS_SIGN_RSA_SHA384:
        case GNUTLS_SIGN_RSA_SHA512:
        case GNUTLS_SIGN_RSA_SHA224:

        case GNUTLS_SIGN_RSA_SHA3_224:
        case GNUTLS_SIGN_RSA_SHA3_256:
        case GNUTLS_SIGN_RSA_SHA3_384:
        case GNUTLS_SIGN_RSA_SHA3_512:

        case GNUTLS_SIGN_RSA_PSS_SHA256:
        case GNUTLS_SIGN_RSA_PSS_SHA384:
        case GNUTLS_SIGN_RSA_PSS_SHA512:

        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
        case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:

        case GNUTLS_SIGN_ECDSA_SHA1:
        case GNUTLS_SIGN_ECDSA_SHA224:
        case GNUTLS_SIGN_ECDSA_SHA256:
        case GNUTLS_SIGN_ECDSA_SHA384:
        case GNUTLS_SIGN_ECDSA_SHA512:
        case GNUTLS_SIGN_ECDSA_SHA3_224:
        case GNUTLS_SIGN_ECDSA_SHA3_256:
        case GNUTLS_SIGN_ECDSA_SHA3_384:
        case GNUTLS_SIGN_ECDSA_SHA3_512:

        case GNUTLS_SIGN_ECDSA_SECP256R1_SHA256:
        case GNUTLS_SIGN_ECDSA_SECP384R1_SHA384:
        case GNUTLS_SIGN_ECDSA_SECP521R1_SHA512:

#ifdef HAVE_ED25519
        case GNUTLS_SIGN_EDDSA_ED25519:
#endif
#ifdef HAVE_ED448
        case GNUTLS_SIGN_EDDSA_ED448:
#endif
            WGW_LOG("Signature exists: %d", sign);
            return 1;
        default:
            WGW_ERROR("Signature doesn't exist: %d", sign);
            return 0;
    }
}


/* structure containing function pointers for the pk implementation */
static const gnutls_crypto_pk_st wolfssl_pk_struct = {
    .encrypt = wolfssl_pk_encrypt,
    .decrypt = wolfssl_pk_decrypt,
    .decrypt2 = wolfssl_pk_decrypt2,
    .sign = wolfssl_pk_sign,
    .verify = wolfssl_pk_verify,
    .verify_priv_params = wolfssl_pk_verify_priv_params,
    .verify_pub_params = wolfssl_pk_verify_pub_params,
    .generate_params = wolfssl_pk_generate_params,
    .generate_keys = wolfssl_pk_generate_keys,
    .pk_fixup_private_params = wolfssl_pk_fixup,
    .derive = wolfssl_pk_derive,
    .encaps = wolfssl_pk_encaps,
    .decaps = wolfssl_pk_decaps,
    .curve_exists = wolfssl_pk_curve_exists,
    .pk_exists = wolfssl_pk_exists,
    .sign_exists = wolfssl_pk_sign_exists
};

/* register the pk algorithm with GnuTLS */
int wolfssl_pk_register(void)
{
    return 0;
}

const gnutls_crypto_pk_st *gnutls_get_pk_ops(void)
{
    WGW_FUNC_ENTER();

    return &wolfssl_pk_struct;
}

#endif
