/****************************************************************************\
*
* This file is part of the "Luna OpenSSL for PQC" project.
*
* The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
* following Web site for further details: https://mit-license.org/ ).
*
* Copyright © 2024 Thales Group
*
\****************************************************************************/

#include "lunaCommon.h"

/* TODO: bad style */
#define OPENSSL_NO_DYNAMIC_ENGINE 1
#define LUNA_CONFIG_OSSL_PROVIDER 1
#include "e_gem.c"

#define P11 (p11.std) /* gem engine convention */
#define P11_GET_COUNT() (luna_count_c_init)
#define P11_CHECK_COUNT(_count) ( (luna_have_c_init != 1) || ((_count) != luna_count_c_init) )
#define KEYCTX_CHECK_COUNT(_ctx)  ( P11_CHECK_COUNT((_ctx)->count_c_init) )
#define DIM LUNA_DIM /* array dimension */
#ifdef LUNA_OSSL_3_4
#define LUNA_RSAWRAP_KEYBITS 2048
#else
#define LUNA_RSAWRAP_KEYBITS 1024
#endif

#define CK_INVALID_X 0x7FFFFFFFUL
#define CKM_INVALID CK_INVALID_X
#define CKK_INVALID CK_INVALID_X
#define CKP_INVALID CK_INVALID_X

#define CKR_LUNA_OQS_BASE 0x7FFFFF00UL
#define CKR_OBJECT_COUNT_TOO_SMALL (CKR_LUNA_OQS_BASE + 1)
#define CKR_OBJECT_COUNT_TOO_LARGE (CKR_LUNA_OQS_BASE + 2)
#define CKR_OBJECT_ENCODING_FAILED (CKR_LUNA_OQS_BASE + 3)
#define CKR_OBJECT_DECODING_FAILED (CKR_LUNA_OQS_BASE + 4)

#define CKK_EC_EDWARDS          0x00000040UL
//#define CKK_EC_EDWARDS_OLD       (CKK_VENDOR_DEFINED + 0x12)
#define CKM_EC_EDWARDS_KEY_PAIR_GEN    0x00001055UL
#define CKM_EDDSA                      0x00001057UL

#define CKK_EC_MONTGOMERY       0x00000041UL
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x00001056UL

#define LUNA_ASSERT(_expr) \
    ((!(_expr)) ? (fprintf(stderr, "LUNA_ASSERT: %s: %u: %s.\n", __FILE__, __LINE__, #_expr), (exit(-1), -1)) : 0)

/* forward reference */
static void luna_init_ecdh(void);
/* NOTE: OQS is conditionally compiled, on windows for example */
#ifdef LUNA_OQS
static void luna_init_pqc(void);
static void luna_fini_pqc(void);
#endif

/* engine interface that is private to luna provider */
static ENGINE *e_init = NULL;

/* query provider is useable */
int luna_prov_is_running(void)
{
    if ( ! ossl_prov_is_running() )
        return 0;
    LUNA_PRINTF(("e_init = %p\n", e_init));
    return e_init != NULL;
}

int luna_prov_engine_init(void)
{
    LUNA_ASSERT(e_init == NULL); /* initialize once */
    /* init engine */
    ENGINE *e = ENGINE_gem();
    if (e == NULL)
        return 0;
    if (luna_init_engine(e) != 1) {
        luna_destroy_engine(e);
        return 0;
    }
    e_init = e;
    LUNA_PRINTF(("e_init = %p\n", e_init));
    luna_init_ecdh();
#ifdef LUNA_OQS
    luna_init_pqc();
#endif
    return e_init != NULL;
}

void luna_prov_engine_fini(void)
{
    /* NOTE: maybe not safe to call upon application exit (atexit) */
    if (luna_get_flag_exit() != 0)
        return;
#ifdef LUNA_OQS
    luna_fini_pqc();
#endif
    luna_finish_engine(e_init);
    luna_destroy_engine(e_init);
    e_init = NULL;
}

/* query key is useable */
int luna_prov_rsa_check_key(OSSL_LIB_CTX *ctx, const RSA *rsa, int operation)
{
    LUNA_PRINTF(("\n"));
    const int rc_check = ( (operation & (EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_ENCRYPT)) == 0 ) ?
            luna_prov_rsa_check_private(rsa) : luna_prov_rsa_check_public(rsa);
    if (luna_prov_check_is_software(rc_check)) {
#ifdef LUNA_OSSL_3_4
        return ossl_rsa_check_key_size(rsa, 1);
#else
        return ossl_rsa_check_key(ctx, rsa, operation);
#endif
    } else if (luna_prov_check_is_hardware(rc_check)) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}

int luna_prov_ec_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect)
{
    LUNA_PRINTF(("\n"));
    const int rc_check = protect ?
            luna_prov_ec_check_private(ec) : luna_prov_ec_check_public(ec);
    if (luna_prov_check_is_software(rc_check)) {
#ifdef LUNA_OSSL_3_4
        const EC_GROUP *grp = EC_KEY_get0_group(ec);
        return ossl_ec_check_security_strength(grp, 1);
#else
        return ossl_ec_check_key(ctx, ec, protect);
#endif
    } else if (luna_prov_check_is_hardware(rc_check)) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}

int luna_prov_dsa_check_key(OSSL_LIB_CTX *ctx, const DSA *dsa, int sign)
{
    LUNA_PRINTF(("\n"));
    const int rc_check = sign ?
            luna_prov_dsa_check_private(dsa) : luna_prov_dsa_check_public(dsa);
    if (luna_prov_check_is_software(rc_check)) {
#ifdef LUNA_OSSL_3_4
        return ossl_dsa_check_key(dsa, 1);
#else
        return ossl_dsa_check_key(ctx, dsa, sign);
#endif
    } else if (luna_prov_check_is_hardware(rc_check)) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}

int luna_prov_rsa_check_private(const RSA *rsa)
{
    if (rsa == NULL)
        return LUNA_CHECK_ERROR;
    return luna_rsa_check_private((RSA*)rsa);
}

int luna_prov_ec_check_private(const EC_KEY *ec)
{
    if (ec == NULL)
        return LUNA_CHECK_ERROR;
    return luna_ecdsa_check_private((EC_KEY*)ec);
}

int luna_prov_dsa_check_private(const DSA *dsa)
{
    if (dsa == NULL)
        return LUNA_CHECK_ERROR;
    return luna_dsa_check_private((DSA*)dsa);
}

int luna_prov_check_is_software(int rc_check)
{
    int rc = (rc_check == LUNA_CHECK_IS_SOFTWARE);
    return rc;
}

int luna_prov_check_is_hardware(int rc_check)
{
    int rc = (rc_check == LUNA_CHECK_IS_HARDWARE);
    return rc;
}

int luna_prov_rsa_check_public(const RSA *rsa)
{
    if (rsa == NULL)
        return LUNA_CHECK_ERROR;
    return luna_rsa_check_public((RSA*)rsa);
}

int luna_prov_ec_check_public(const EC_KEY *ec)
{
    if (ec == NULL)
        return LUNA_CHECK_ERROR;
    return luna_ecdsa_check_public((EC_KEY*)ec);
}

int luna_prov_dsa_check_public(const DSA *dsa)
{
    if (dsa == NULL)
        return LUNA_CHECK_ERROR;
    return luna_dsa_check_public((DSA*)dsa);
}

/* RSA wrapper functions */
int luna_prov_RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb)
{
    LUNA_PRINTF(("\n"));
    /* for keygen, the engine does not redirect to software so we must redirect here */
    if ( ! luna_get_enable_rsa_gen_key_pair() )
       return RSA_generate_multi_prime_key(rsa, bits, primes, e, cb);
    /* luna supports 2 primes only */
    LUNA_PRINTF(("bits = %d, primes = %d\n", bits, primes));
    if (primes != 2)
        return 0;
    int flagSessionObject = luna_get_token_object() ? 0 : 1;
    return luna_rsa_keygen_ex(rsa, bits, e, cb, flagSessionObject);
}

static int luna_prov_encode_pkcs1(unsigned char **out, size_t *out_len, int type,
                        const unsigned char *m, size_t m_len)
{
    size_t di_prefix_len, dig_info_len;
    const unsigned char *di_prefix;
    unsigned char *dig_info;

    LUNA_PRINTF(("\n"));
    if (type == NID_undef) {
        ERR_raise(ERR_LIB_RSA, RSA_R_UNKNOWN_ALGORITHM_TYPE);
        return 0;
    }
    di_prefix = ossl_rsa_digestinfo_encoding(type, &di_prefix_len);
    if (di_prefix == NULL) {
        ERR_raise(ERR_LIB_RSA,
                  RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
        return 0;
    }
    if (di_prefix_len > LUNA_PROV_MAX_BUFFER || m_len > LUNA_PROV_MAX_BUFFER) {
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    dig_info_len = di_prefix_len + m_len;
    dig_info = OPENSSL_malloc(dig_info_len);
    if (dig_info == NULL) {
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(dig_info, di_prefix, di_prefix_len);
    memcpy(dig_info + di_prefix_len, m, m_len);

    *out = dig_info;
    *out_len = dig_info_len;
    return 1;
}

#define SSL_SIG_LENGTH  36

int luna_prov_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
    LUNA_PRINTF(("\n"));
    int encrypt_len, ret = 0;
    size_t encoded_len = 0;
    unsigned char *tmps = NULL;
    const unsigned char *encoded = NULL;
    int rsasize =RSA_size(rsa);

    if (rsasize < 1)
        goto err;

#ifndef FIPS_MODULE
    //if (rsa->meth->rsa_sign != NULL)
    //    return rsa->meth->rsa_sign(type, m, m_len, sigret, siglen, rsa);
#endif /* FIPS_MODULE */

    /* Compute the encoded digest. */
    if (type == NID_md5_sha1) {
        /*
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         */
        if (m_len != SSL_SIG_LENGTH) {
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MESSAGE_LENGTH);
            return 0;
        }
        encoded_len = SSL_SIG_LENGTH;
        encoded = m;
    } else {
        if (!luna_prov_encode_pkcs1(&tmps, &encoded_len, type, m, m_len))
            goto err;
        encoded = tmps;
    }

    if (encoded_len + RSA_PKCS1_PADDING_SIZE > (size_t)rsasize) {
        ERR_raise(ERR_LIB_RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto err;
    }

    encrypt_len = luna_rsa_priv_enc((int)encoded_len, encoded, sigret, rsa, RSA_PKCS1_PADDING);
    if (encrypt_len <= 0)
        goto err;

    *siglen = encrypt_len;
    ret = 1;

err:
    OPENSSL_clear_free(tmps, encoded_len);
    return ret;
}

static int LUNAPROV_digest_sz_from_nid(int nid);

static int luna_prov_rsa_verify(int type, const unsigned char *m, unsigned int m_len,
                    unsigned char *rm, size_t *prm_len,
                    const unsigned char *sigbuf, size_t siglen, RSA *rsa)
{
    int len, ret = 0;
    size_t decrypt_len, encoded_len = 0;
    unsigned char *decrypt_buf = NULL, *encoded = NULL;
    int rsasize = RSA_size(rsa);

    LUNA_PRINTF(("\n"));
    if ( (rsasize < 1) || (siglen != (size_t)rsasize) ) {
        ERR_raise(ERR_LIB_RSA, RSA_R_WRONG_SIGNATURE_LENGTH);
        return 0;
    }

    /* Recover the encoded digest. */
    decrypt_buf = OPENSSL_malloc(siglen);
    if (decrypt_buf == NULL) {
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    len = luna_rsa_pub_dec((int)siglen, sigbuf, decrypt_buf, rsa, RSA_PKCS1_PADDING);
    if (len <= 0)
        goto err;
    decrypt_len = len;

    /* no worries about md5 here */

    {
        /*
         * If recovering the digest, extract a digest-sized output from the end
         * of |decrypt_buf| for |encode_pkcs1|, then compare the decryption
         * output as in a standard verification.
         */
        if (rm != NULL) {
            len = LUNAPROV_digest_sz_from_nid(type);

            if (len <= 0)
                goto err;
            m_len = (unsigned int)len;
            if (m_len > decrypt_len) {
                ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH);
                goto err;
            }
            m = decrypt_buf + decrypt_len - m_len;
        }

        /* Construct the encoded digest and ensure it matches. */
        if (!luna_prov_encode_pkcs1(&encoded, &encoded_len, type, m, m_len))
            goto err;

        if (encoded_len != decrypt_len
                || memcmp(encoded, decrypt_buf, encoded_len) != 0) {
            ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        /* Output the recovered digest. */
        if (rm != NULL) {
            memcpy(rm, m, m_len);
            *prm_len = m_len;
        }
    }

    ret = 1;

err:
    OPENSSL_clear_free(encoded, encoded_len);
    OPENSSL_clear_free(decrypt_buf, siglen);
    return ret;
}

int luna_prov_RSA_verify(int type, const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, unsigned int siglen, RSA *rsa)
{
    LUNA_PRINTF(("\n"));
    return luna_prov_rsa_verify(type, m, m_len, NULL, NULL, sigbuf, siglen, rsa);
}

int luna_prov_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    LUNA_PRINTF(("\n"));
    return luna_rsa_priv_enc(flen, from, to, rsa, padding);
}

int luna_prov_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    LUNA_PRINTF(("\n"));
    return luna_rsa_priv_dec(flen, from, to, rsa, padding);
}

int luna_prov_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding)
{
    LUNA_PRINTF(("\n"));
    return luna_rsa_pub_dec(flen, from, to, rsa, padding);
}

int luna_prov_rsa_priv_enc_pkcs(void *xparams, int flen, const unsigned char *from,
        size_t tolen, unsigned char *to, RSA *rsa, int padding)
{
    LUNA_PRINTF(("\n"));
    return luna_rsa_priv_enc_pkcs(xparams, flen, from,
            tolen, to, rsa, padding);
}

int luna_prov_rsa_priv_dec_x509(void *xparams, int flen, const unsigned char *from,
        size_t tolen, unsigned char *to, RSA *rsa, int padding)
{
    LUNA_PRINTF(("\n"));
    return luna_rsa_priv_dec_x509(xparams, flen, from,
            tolen, to, rsa, padding);
}

/* EC wrapper functions */
int luna_prov_EC_KEY_generate_key_ex(EC_KEY *key, int lunaflags)
{
    LUNA_PRINTF(("lunaflags = 0x%X\n", lunaflags));
    /* for keygen, the engine does not redirect to software so we must redirect here */
    if ( ( lunaflags & LUNA_PROV_FLAGS_SOFTWARE_OBJECT ) ||
            ( ! luna_get_enable_ec_gen_key_pair() ) ) {
        return EC_KEY_generate_key(key);
    }
    /* keygen in hardware */
    int flagSessionObject;
    int flagDerive;
    /* first, check for override (CKA_TOKEN) */
    if (lunaflags & LUNA_PROV_FLAGS_SESSION_OBJECT) {
        flagSessionObject = 1;
        flagDerive = 1;
    } else {
        /* second, check for config (CKA_TOKEN) */
        if (luna_get_token_object()) {
           flagSessionObject = 0;
           flagDerive = 0;
        } else {
           flagSessionObject = 1;
           flagDerive = 1;
        }
    }
    return luna_ec_keygen_hw_ex(key, flagSessionObject, flagDerive);
}

int luna_prov_ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen,
                  unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
                  const BIGNUM *r, EC_KEY *eckey)
{
    LUNA_PRINTF(("\n"));
    return luna_ecdsa_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
}

int luna_prov_ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
                 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    LUNA_PRINTF(("\n"));
    return luna_ecdsa_verify(type, dgst, dgst_len, sigbuf, sig_len, eckey);
}

/* DSA wrapper functions */
int luna_prov_DSA_generate_key(DSA *dsa)
{
    LUNA_PRINTF(("\n"));
    /* for keygen, the engine does not redirect to software so we must redirect here */
    if ( ! luna_get_enable_dsa_gen_key_pair() )
        return DSA_generate_key(dsa);
    int flagSessionObject = luna_get_token_object() ? 0 : 1;
    return luna_dsa_keygen_ex(dsa, flagSessionObject);
}

int luna_prov_ossl_dsa_sign_int(int type, const unsigned char *dgst, int dlen,
                      unsigned char *sig, unsigned int *siglen, DSA *dsa)
{
    LUNA_PRINTF(("\n"));
    DSA_SIG *s = luna_dsa_do_sign(dgst, dlen, dsa);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_DSA_SIG(s, &sig);
    DSA_SIG_free(s);
    return 1;
}

int luna_prov_DSA_verify(int type, const unsigned char *dgst, int dgst_len,
               const unsigned char *sigbuf, int siglen, DSA *dsa)
{
    LUNA_PRINTF(("\n"));
    DSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen;
    int ret = -1;

    s = DSA_SIG_new();
    if (s == NULL)
        return ret;
    if (d2i_DSA_SIG(&s, &p, siglen) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_DSA_SIG(s, &der);
    if (derlen != siglen || memcmp(sigbuf, der, derlen))
        goto err;
    ret = luna_dsa_do_verify(dgst, dgst_len, s, dsa);
 err:
    if (der != NULL)
       OPENSSL_free(der);
    DSA_SIG_free(s);
    return ret;
}

/* forward reference */
static EVP_PKEY *luna_init_wrapping_pkey_deferred(int bits);

/* software wrapping keypair */
static EVP_PKEY *luna_wrapping_pkey = NULL;
static int luna_wrapping_error = 0;
static CK_ULONG luna_wrapping_handle = 0;
static unsigned luna_wrapping_count_c_init = 0;

/* key identifiers */
typedef enum luna_prov_ctxtype_e {
    LUNA_PROV_CTXTYPE_ZERO=0,
    LUNA_PROV_CTXTYPE_OQS=0x100,
    LUNA_PROV_CTXTYPE_ECXGEN=0x200,
    LUNA_PROV_CTXTYPE_EDDSA=0x300,
    LUNA_PROV_CTXTYPE_ECXEXCH=0x400
} luna_prov_ctxtype;

typedef enum luna_prov_subtype_e {
    LUNA_PROV_SUBTYPE_ZERO=0,
    LUNA_PROV_SUBTYPE_OQS=0x10000,
    LUNA_PROV_SUBTYPE_x25519=0x20000,
    LUNA_PROV_SUBTYPE_x448,
    LUNA_PROV_SUBTYPE_ed25519,
    LUNA_PROV_SUBTYPE_ed448
} luna_prov_subtype;

/* luna provider key context */
typedef struct luna_prov_key_ctx_st {
    // firstly, magic value
    int magic;
    // luna pkcs11 handles
    unsigned long hPublic;
    unsigned long hPrivate;
    unsigned char bTokenObject;
    // luna optimizations
    unsigned count_c_init;
    unsigned is_hardware;
    unsigned index_alg;
    // from oqs provider
    void *oqsxkey;
    char *alg_name;
    int is_kem;
    // state of the key
    luna_prov_key_reason reason;
    // key identifiers
    luna_prov_ctxtype ctxtype;
    luna_prov_subtype subtype;
    int sublen;
    // read/write mutex
    lunasys_mutex_t mu;
    volatile int readers;
    volatile int writers;
    volatile int want_writers;
} luna_prov_key_ctx;

typedef struct luna_prov_keyinfo_st {
    // firstly, magic value
    int magic;
    // oqs provider weak handles
    void *pubkey;
    size_t pubkeylen;
    void *privkey;
    size_t privkeylen;
    // luna session
    luna_context_t sess;
} luna_prov_keyinfo;

static CK_RV LunaUnwrapKeyBytes(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_OBJECT_HANDLE hObject, CK_BYTE *psecret, CK_ULONG secretLen);

static CK_RV LunaDeriveUnwrapKeyBytes(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_MECHANISM_PTR pMechDerive, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
    CK_BYTE *psecret, CK_ULONG secretLen);

/*****************************************************************************/

#ifdef LUNA_OQS

/* header based on Luna PQC SHIM toolkit */
#include "pqcdefs.h"

/* detect mlkem, mldsa */
#ifdef CKK_ML_KEM
#define CKK_MLKEM CKK_ML_KEM
#define CKP_MLKEM_512 CKP_ML_KEM_512_IPD
#define CKM_MLKEM_KEM_KEY_PAIR_GEN CKM_ML_KEM_KEY_PAIR_GEN
#define CKM_MLKEM_KEM_KEY_ENCAP CKM_ML_KEM_KEY_ENCAP
#define CKM_MLKEM_KEM_KEY_DECAP CKM_ML_KEM_KEY_DECAP
#define CKP_MLKEM_768 CKP_ML_KEM_768_IPD
#define CKP_MLKEM_1024 CKP_ML_KEM_1024_IPD
#define LUNA_OQS_MLKEM 1
#endif

#ifdef CKK_ML_DSA
#define CKK_MLDSA CKK_ML_DSA
#define CKP_MLDSA_44 CKP_ML_DSA_44_IPD
#define CKM_MLDSA_KEY_PAIR_GEN CKM_ML_DSA_KEY_PAIR_GEN
#define CKM_MLDSA CKM_ML_DSA
#define CKP_MLDSA_65 CKP_ML_DSA_65_IPD
#define CKP_MLDSA_87 CKP_ML_DSA_87_IPD
#define LUNA_OQS_MLDSA 1
#endif

/* detect sphincs */
#ifdef CKK_SPHINCS
#define LUNA_OQS_SPHINCS 1
#endif

/* detect falcon padded */
#ifdef CKK_FALCON_PADDED
#define LUNA_OQS_FALCON_PADDED 1
#else
#define CKK_FALCON_PADDED CKK_INVALID
#define CKP_FALCON_PADDED_512 CKP_INVALID
#define CKP_FALCON_PADDED_1024 CKP_INVALID
#define CKM_FALCON_PADDED_KEY_PAIR_GEN CKM_INVALID
#define CKM_FALCON_PADDED CKM_INVALID
#define LUNA_OQS_FALCON_PADDED 1
#endif

// algorithm table (algorithms redirected to HSM by luna-provider)
static struct {
    int flag_include;
    const char *alg_name;
    // keytypes
    CK_KEY_TYPE keytype;
    CK_KEY_PARAMS ckp_params;
    // mechanism type for keygen
    CK_ULONG typeGenerate;
    // mechanism type for sign, encap, decap
    CK_ULONG typeSign;
    CK_ULONG typeEncap;
    CK_ULONG typeDecap;
} algtab[] = {
    // index [0] is invalid
    { 0, "INVALID",
        CKK_INVALID, CKP_INVALID,
        CKM_INVALID,
        CKM_INVALID, CKM_INVALID, CKM_INVALID },
    // ecx/ed
    { 0, "x25519",
        CKK_EC_MONTGOMERY, CKP_INVALID,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        CKM_INVALID, CKM_ECDH1_DERIVE, CKM_ECDH1_DERIVE },
    { 0, "x448",
        CKK_EC_MONTGOMERY, CKP_INVALID,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        CKM_INVALID, CKM_ECDH1_DERIVE, CKM_ECDH1_DERIVE },
    { 0, "ed25519",
        CKK_EC_EDWARDS, CKP_INVALID,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        CKM_EDDSA, CKM_INVALID, CKM_INVALID },
    { 0, "ed448",
        CKK_EC_EDWARDS, CKP_INVALID,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        CKM_EDDSA, CKM_INVALID, CKM_INVALID },
    // kem
    { 0, "kyber512",
        CKK_KYBER, CKP_KYBER_512,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "kyber768",
        CKK_KYBER, CKP_KYBER_768,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "kyber1024",
        CKK_KYBER, CKP_KYBER_1024,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    // kem hybrid
    { 0, "p256_kyber512",
        CKK_KYBER, CKP_KYBER_512,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "x25519_kyber512",
        CKK_KYBER, CKP_KYBER_512,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "p256_kyber768",
        CKK_KYBER, CKP_KYBER_768,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "p384_kyber768",
        CKK_KYBER, CKP_KYBER_768,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "x25519_kyber768",
        CKK_KYBER, CKP_KYBER_768,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "x448_kyber768",
        CKK_KYBER, CKP_KYBER_768,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    { 0, "p521_kyber1024",
        CKK_KYBER, CKP_KYBER_1024,
        CKM_KYBER_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_KYBER_KEM_KEY_ENCAP, CKM_KYBER_KEM_KEY_DECAP },
    // sig
    { 0, "falcon512",
        CKK_FALCON, CKP_FALCON_512,
        CKM_FALCON_KEY_PAIR_GEN,
        CKM_FALCON, CKM_INVALID, CKM_INVALID },
    { 0, "falcon1024",
        CKK_FALCON, CKP_FALCON_1024,
        CKM_FALCON_KEY_PAIR_GEN,
        CKM_FALCON, CKM_INVALID, CKM_INVALID },
    { 0, "dilithium2",
        CKK_DILITHIUM, CKP_DILITHIUM_2,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },
    { 0, "dilithium3",
        CKK_DILITHIUM, CKP_DILITHIUM_3,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },
    { 0, "dilithium5",
        CKK_DILITHIUM, CKP_DILITHIUM_5,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },
    // sig hybrid
    { 0, "p256_falcon512",
        CKK_FALCON, CKP_FALCON_512,
        CKM_FALCON_KEY_PAIR_GEN,
        CKM_FALCON, CKM_INVALID, CKM_INVALID },
    { 0, "p521_falcon1024",
        CKK_FALCON, CKP_FALCON_1024,
        CKM_FALCON_KEY_PAIR_GEN,
        CKM_FALCON, CKM_INVALID, CKM_INVALID },
    { 0, "rsa3072_falcon512",
        CKK_FALCON, CKP_FALCON_512,
        CKM_FALCON_KEY_PAIR_GEN,
        CKM_FALCON, CKM_INVALID, CKM_INVALID },
    { 0, "p256_dilithium2",
        CKK_DILITHIUM, CKP_DILITHIUM_2,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },
    { 0, "p384_dilithium3",
        CKK_DILITHIUM, CKP_DILITHIUM_3,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },
    { 0, "p521_dilithium5",
        CKK_DILITHIUM, CKP_DILITHIUM_5,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },
    { 0, "rsa3072_dilithium2",
        CKK_DILITHIUM, CKP_DILITHIUM_2,
        CKM_DILITHIUM_KEY_PAIR_GEN,
        CKM_DILITHIUM, CKM_INVALID, CKM_INVALID },

#ifdef LUNA_OQS_MLKEM
    // mlkem
    { 0, "mlkem512",
        CKK_MLKEM, CKP_MLKEM_512,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "mlkem768",
        CKK_MLKEM, CKP_MLKEM_768,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "mlkem1024",
        CKK_MLKEM, CKP_MLKEM_1024,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    // mlkem hybrid ecp
    { 0, "p256_mlkem512",
        CKK_MLKEM, CKP_MLKEM_512,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "p384_mlkem768",
        CKK_MLKEM, CKP_MLKEM_768,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "p256_mlkem768",
        CKK_MLKEM, CKP_MLKEM_768,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "p521_mlkem1024",
        CKK_MLKEM, CKP_MLKEM_1024,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "p384_mlkem1024",
        CKK_MLKEM, CKP_MLKEM_1024,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    // mlkem hybrid ecx
    { 0, "x25519_mlkem512",
        CKK_MLKEM, CKP_MLKEM_512,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "x448_mlkem768",
        CKK_MLKEM, CKP_MLKEM_768,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
    { 0, "x25519_mlkem768",
        CKK_MLKEM, CKP_MLKEM_768,
        CKM_MLKEM_KEM_KEY_PAIR_GEN,
        CKM_INVALID, CKM_MLKEM_KEM_KEY_ENCAP, CKM_MLKEM_KEM_KEY_DECAP },
#endif /* LUNA_OQS_MLKEM */

#ifdef LUNA_OQS_MLDSA
    // mldsa
    { 0, LUNA_TN_ML_DSA_44,
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, LUNA_TN_ML_DSA_65,
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, LUNA_TN_ML_DSA_87,
        CKK_MLDSA, CKP_MLDSA_87,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    // mldsa hybrid
    { 0, "p256_mldsa44",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "rsa3072_mldsa44",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "p384_mldsa65",
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "p521_mldsa87",
        CKK_MLDSA, CKP_MLDSA_87,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    // mldsa composite
    { 0, "mldsa44_pss2048",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa44_rsa2048",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa44_ed25519",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa44_p256",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa44_bp256",
        CKK_MLDSA, CKP_MLDSA_44,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa65_pss3072",
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa65_rsa3072",
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa65_p256",
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa65_bp256",
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa65_ed25519",
        CKK_MLDSA, CKP_MLDSA_65,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa87_p384",
        CKK_MLDSA, CKP_MLDSA_87,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa87_bp384",
        CKK_MLDSA, CKP_MLDSA_87,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
    { 0, "mldsa87_ed448",
        CKK_MLDSA, CKP_MLDSA_87,
        CKM_MLDSA_KEY_PAIR_GEN,
        CKM_MLDSA, CKM_INVALID, CKM_INVALID },
#endif /* LUNA_OQS_MLDSA */

#ifdef LUNA_OQS_SPHINCS
    // sphincs
    { 0, "sphincssha2128fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_128F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "sphincssha2128ssimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_128S_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "sphincssha2192fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_192F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "sphincsshake128fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHAKE256_128F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    // sphincs hybrid
    { 0, "p256_sphincssha2128fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_128F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "p256_sphincssha2128ssimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_128S_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "p384_sphincssha2192fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_192F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "p256_sphincsshake128fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHAKE256_128F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "rsa3072_sphincssha2128fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_128F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "rsa3072_sphincssha2128ssimple",
        CKK_SPHINCS, CKP_SPHINCS_SHA256_128S_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
    { 0, "rsa3072_sphincsshake128fsimple",
        CKK_SPHINCS, CKP_SPHINCS_SHAKE256_128F_SIMPLE,
        CKM_SPHINCS_KEY_PAIR_GEN,
        CKM_SPHINCS, CKM_INVALID, CKM_INVALID },
#endif

#ifdef LUNA_OQS_FALCON_PADDED
    { 0, "falconpadded512",
        CKK_FALCON_PADDED, CKP_FALCON_PADDED_512,
        CKM_FALCON_PADDED_KEY_PAIR_GEN,
        CKM_FALCON_PADDED, CKM_INVALID, CKM_INVALID
    },
    { 0, "p256_falconpadded512",
        CKK_FALCON_PADDED, CKP_FALCON_PADDED_512,
        CKM_FALCON_PADDED_KEY_PAIR_GEN,
        CKM_FALCON_PADDED, CKM_INVALID, CKM_INVALID
    },
    { 0, "rsa3072_falconpadded512",
        CKK_FALCON_PADDED, CKP_FALCON_PADDED_512,
        CKM_FALCON_PADDED_KEY_PAIR_GEN,
        CKM_FALCON_PADDED, CKM_INVALID, CKM_INVALID
    },
    { 0, "falconpadded1024",
        CKK_FALCON_PADDED, CKP_FALCON_PADDED_1024,
        CKM_FALCON_PADDED_KEY_PAIR_GEN,
        CKM_FALCON_PADDED, CKM_INVALID, CKM_INVALID
    },
    { 0, "p521_falconpadded1024",
        CKK_FALCON_PADDED, CKP_FALCON_PADDED_1024,
        CKM_FALCON_PADDED_KEY_PAIR_GEN,
        CKM_FALCON_PADDED, CKM_INVALID, CKM_INVALID
    },
#endif /* LUNA_OQS_FALCON_PADDED */

};

static void luna_init_algorithm_table(const char *szInclude, const char *szExclude) {
    int i = 0;
    int flag_include = 0;
    const int flag_include_all = (strcmp(szInclude, "ALL") == 0);
    const int flag_exclude_none = (strcmp(szExclude, "NONE") == 0);
    LUNA_PRINTF(("szInclude = %s\n", szInclude));
    LUNA_PRINTF(("szExclude = %s\n", szExclude));
    for (i = 0; i < DIM(algtab); i++) {
        flag_include = flag_include_all;
        // check include list first
        if (! flag_include_all) {
            if (strstr(szInclude, algtab[i].alg_name) != NULL) {
                flag_include = 1;
            }
        }
        // check exclude list second
        if (! flag_exclude_none) {
            if (strstr(szExclude, algtab[i].alg_name) != NULL) {
                flag_include = 0;
            }
        }
        // apply
        algtab[i].flag_include = flag_include;
    }
}

#ifdef OQS_USE_OPENSSL
extern void OQS_randombytes_openssl(uint8_t *out, size_t outlen);
#endif
extern void OQS_randombytes_system(uint8_t *out, size_t outlen);

// do PQC RNG in liboqs
static void luna_pqc_rng_liboqs(uint8_t *out, size_t outlen) {
#ifdef OQS_USE_OPENSSL
    // TODO: OQS_randombytes_openssl(out, outlen);
    OQS_randombytes_system(out, outlen);
#else
    OQS_randombytes_system(out, outlen);
#endif
}

static int luna_pqc_rng_hw_is_error(void);
static CK_RV luna_pqc_rng_hw(uint8_t *out, size_t outlen);
static void luna_pqc_rng_hw_cleanse(void);

// do PQC RNG in provider
static void luna_pqc_rng(uint8_t *out, size_t outlen) {
    // avoid repeated RNG failures in hardware
    if ( luna_pqc_rng_hw_is_error() || (luna_pqc_rng_hw(out, outlen) != CKR_OK) ) {
        // fallback to software
        luna_pqc_rng_liboqs(out, outlen);
    }
}

static int luna_pqc_rng_active = 0;
static lunasys_mutex_t luna_pqc_rng_mu;

static void luna_init_pqc(void) {
    // populate algorithm table
    luna_init_algorithm_table(
        (g_config.IncludePqc != NULL ? g_config.IncludePqc : "ALL"),
        (g_config.ExcludePqc != NULL ? g_config.ExcludePqc : "NONE") );
    // hook PQC RNG
    LUNA_ASSERT(lunasys_mutex_init(&luna_pqc_rng_mu) == 0);
    if (luna_get_DelegateSwPqcKemEncapRngToHw()) {
        OQS_randombytes_custom_algorithm(luna_pqc_rng);
        luna_pqc_rng_active = 1;
    }
}

// undo actions of luna_init_pqc
static void luna_fini_pqc(void) {
    LUNA_PRINTF(("\n"));
    // unhook PQC RNG
    if (luna_pqc_rng_active) {
#ifdef OQS_USE_OPENSSL
        // TODO: LUNA_ASSERT(OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl) == OQS_SUCCESS);
        LUNA_ASSERT(OQS_randombytes_switch_algorithm(OQS_RAND_alg_system) == OQS_SUCCESS);
#else
        LUNA_ASSERT(OQS_randombytes_switch_algorithm(OQS_RAND_alg_system) == OQS_SUCCESS);
#endif
        lunasys_mutex_fini(&luna_pqc_rng_mu);
        luna_pqc_rng_active = 0;
    }
}

static CK_RV LunaLookupAlgName_range(const char *alg_name, unsigned index0, unsigned index1, unsigned *pindexFound,
    CK_KEY_TYPE *pkeytype, CK_KEY_PARAMS *pparams,
    CK_MECHANISM *ptypeGenerate,
    CK_MECHANISM *ptypeSign, CK_MECHANISM *ptypeEncap, CK_MECHANISM *ptypeDecap) {
    unsigned i = 0;
    if (alg_name == NULL)
        return CKR_GENERAL_ERROR;
    if ( (index0 > index1) || (index1 >= DIM(algtab)) )
        return CKR_GENERAL_ERROR;
    LUNA_PRINTF(("alg_name = %s, index0 = %u, index1 = %u\n",
            alg_name, index0, index1));
    for (i = index0; i <= index1; i++) {
        if (! algtab[i].flag_include)
            continue;
        if (!strcmp(alg_name, algtab[i].alg_name)) {
            if (pindexFound != NULL)
                *pindexFound = i;
            if (pkeytype != NULL)
                *pkeytype = algtab[i].keytype;
            if (pparams != NULL)
                *pparams = algtab[i].ckp_params;
            if (ptypeGenerate != NULL)
                ptypeGenerate->mechanism = algtab[i].typeGenerate;
            if (ptypeSign != NULL)
                ptypeSign->mechanism = algtab[i].typeSign;
            if (ptypeEncap != NULL)
                ptypeEncap->mechanism = algtab[i].typeEncap;
            if (ptypeDecap != NULL)
                ptypeDecap->mechanism = algtab[i].typeDecap;
            return CKR_OK;
        }
    }
    LUNA_PRINTF(("lookup failed: alg_name = %s\n", alg_name));
    return CKR_MECHANISM_INVALID;
}

static CK_RV LunaLookupAlgName(luna_prov_key_ctx *keyctx,
    CK_KEY_TYPE *pkeytype, CK_KEY_PARAMS *pparams,
    CK_MECHANISM *ptypeGenerate,
    CK_MECHANISM *ptypeSign, CK_MECHANISM *ptypeEncap, CK_MECHANISM *ptypeDecap) {
    LUNA_PRINTF(("keyctx->alg_name = %s\n", keyctx->alg_name));
    unsigned index0 = 1;
    unsigned index1 = (DIM(algtab) - 1);
    if (keyctx->index_alg != 0)
        index0 = index1 = keyctx->index_alg;
    return LunaLookupAlgName_range(keyctx->alg_name, index0, index1, &(keyctx->index_alg),
        pkeytype, pparams,
        ptypeGenerate,
        ptypeSign, ptypeEncap, ptypeDecap);
}

static CK_RV LunaFind(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_ATTRIBUTE *a, CK_ULONG n, CK_OBJECT_HANDLE *ph) {

#ifdef LUNA_OSSL_FIND_2_OBJECTS
   CK_OBJECT_HANDLE hObject[2] = {LUNA_INVALID_HANDLE, LUNA_INVALID_HANDLE};
#else
   CK_OBJECT_HANDLE hObject[1] = {LUNA_INVALID_HANDLE}; /* OPTIMIZE */
#endif

    CK_ULONG ulCount = 0;
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    CK_RV rv = P11->C_FindObjectsInit(session, a, n);
    if (rv != CKR_OK) {
        luna_context_set_last_error(&pkeyinfo->sess, rv);
        return rv;
    }
    rv = P11->C_FindObjects(session, hObject, DIM(hObject), &ulCount);
#ifdef LUNA_OSSL_CALL_FINAL
    (void)P11->C_FindObjectsFinal(session);
#endif
    if (rv != CKR_OK) {
        luna_context_set_last_error(&pkeyinfo->sess, rv);
        return rv;
    }
    if (ulCount < 1)
        return CKR_OBJECT_COUNT_TOO_SMALL;
    if (ulCount > 1)
        return CKR_OBJECT_COUNT_TOO_LARGE;
    *ph = hObject[0];
    return CKR_OK;
}

static void LUNA_OQS_refresh_subtype(luna_prov_key_ctx *keyctx) {
    const char *alg_name = keyctx->alg_name;
    // call strstr to detect ecx subtype for any case of {pure, hybrid, composite}
    if (strstr(alg_name, "x25519") != NULL) {
        keyctx->is_kem = 1;
        keyctx->subtype = LUNA_PROV_SUBTYPE_x25519;
        keyctx->sublen = 32;
    } else if (strstr(alg_name, "x448") != NULL) {
        keyctx->is_kem = 1;
        keyctx->subtype = LUNA_PROV_SUBTYPE_x448;
        keyctx->sublen = 56;
    } else if (strstr(alg_name, "ed25519") != NULL) {
        keyctx->is_kem = 0;
        keyctx->subtype = LUNA_PROV_SUBTYPE_ed25519;
        keyctx->sublen = 32;
    } else if (strstr(alg_name, "ed448") != NULL) {
        keyctx->is_kem = 0;
        keyctx->subtype = LUNA_PROV_SUBTYPE_ed448;
        keyctx->sublen = 57;
    } else {
        keyctx->is_kem = 0;
        keyctx->subtype = 0;
        keyctx->sublen = 0;
    }
}

/* callbacks for malloc and free */
static luna_prov_key_ctx *LUNA_OQS_malloc_from_any(void *oqsxkey, const char *alg_name,
        luna_prov_ctxtype ctxtype) {
    luna_prov_key_ctx *keyctx = (luna_prov_key_ctx*)OPENSSL_zalloc(sizeof(*keyctx));
    if (keyctx == NULL)
        return NULL;
    keyctx->alg_name = OPENSSL_strdup(alg_name);
    if (keyctx->alg_name == NULL) {
        OPENSSL_free(keyctx);
        return NULL;
    }

    keyctx->magic = LUNA_PROV_MAGIC_ZERO;
    keyctx->hPublic = 0;
    keyctx->hPrivate = 0;
    keyctx->bTokenObject = 0;

    // luna optimizations
    keyctx->count_c_init = 0;
    keyctx->is_hardware = 1; // assume hardware until proven otherwise
    keyctx->index_alg = 0;

    keyctx->oqsxkey = oqsxkey;
    keyctx->reason = LUNA_PROV_KEY_REASON_ZERO;
    LUNA_ASSERT(lunasys_mutex_init(&keyctx->mu) == 0);

    keyctx->ctxtype = ctxtype;
    keyctx->is_kem = 0;
    LUNA_OQS_refresh_subtype(keyctx);

    return keyctx;
}

luna_prov_key_ctx *LUNA_OQS_malloc_from_oqs(void *oqsxkey, const char *alg_name) {
    return LUNA_OQS_malloc_from_any(oqsxkey, alg_name, LUNA_PROV_CTXTYPE_OQS);
}

luna_prov_key_ctx *LUNA_OQS_malloc_from_ecxgen(void *oqsxkey, const char *alg_name) {
    return LUNA_OQS_malloc_from_any(oqsxkey, alg_name, LUNA_PROV_CTXTYPE_ECXGEN);
}

luna_prov_key_ctx *LUNA_OQS_malloc_from_eddsa(void *oqsxkey, const char *alg_name) {
    return LUNA_OQS_malloc_from_any(oqsxkey, alg_name, LUNA_PROV_CTXTYPE_EDDSA);
}

luna_prov_key_ctx *LUNA_OQS_malloc_from_eddsa_2(void *oqsxkey, const luna_prov_key_ctx *src_ctx) {
    return LUNA_OQS_malloc_from_eddsa(oqsxkey, src_ctx->alg_name);
}

luna_prov_key_ctx *LUNA_OQS_malloc_from_ecx(void *oqsxkey, const char *alg_name) {
    return LUNA_OQS_malloc_from_any(oqsxkey, alg_name, LUNA_PROV_CTXTYPE_ECXEXCH);
}

luna_prov_key_ctx *LUNA_OQS_malloc_from_ecx_2(void *oqsxkey, const luna_prov_key_ctx *src_ctx) {
    return LUNA_OQS_malloc_from_ecx(oqsxkey, src_ctx->alg_name);
}

void LUNA_OQS_free(luna_prov_key_ctx *keyctx) {
    if (keyctx == NULL)
        return;
    /* FIXME: this assumes that KEM keys are never persisted */
    /* FIXME: this assumes that SIG keys are always persisted */
    if ( (keyctx->is_kem) && (keyctx->bTokenObject == CK_TRUE) &&
            (keyctx->hPrivate != 0 || keyctx->hPublic != 0) ) {
        LUNA_PRINTF(("BUG: leaking token object!\n"));
    }

    lunasys_mutex_fini(&keyctx->mu);
    OPENSSL_free(keyctx->alg_name);
    memset(keyctx, 0, sizeof(*keyctx));
    OPENSSL_free(keyctx);
}

void LUNA_OQS_refresh_alg_name(luna_prov_key_ctx *keyctx, const char *alg_name) {
    char *p = OPENSSL_strdup(alg_name);
    if (p != NULL) {
        OPENSSL_free(keyctx->alg_name);
        keyctx->alg_name = p;
        LUNA_OQS_refresh_subtype(keyctx);
    }
}

// query the algorithm can be implemented is hsm
static int LUNA_OQS_QUERY_X(luna_prov_key_ctx *keyctx) {
    LUNA_PRINTF(("alg_name = %s\n", keyctx->alg_name));
    unsigned index0 = 1;
    unsigned index1 = (DIM(algtab) - 1);
    if (keyctx->index_alg != 0)
        index0 = index1 = keyctx->index_alg;
    CK_RV rvlookup = LunaLookupAlgName_range(keyctx->alg_name, index0, index1, &(keyctx->index_alg),
            NULL, NULL, NULL, NULL, NULL, NULL);
    return (rvlookup == CKR_OK ? LUNA_OQS_OK : LUNA_OQS_ERROR);
}

// query the classic part of the algorithm can be implemented in hsm
static int LUNA_OQS_QUERY_classic_keypair(luna_prov_key_ctx *keyctx) {
    int rc = LUNA_OQS_OK;
    CK_KEY_TYPE keytype = CKK_INVALID;
    struct {
        const char *alg_name;
        CK_KEY_TYPE keytype;
    } tab [] = {
            { "rsa3072", CKK_RSA },
            { "rsa2048", CKK_RSA },
            { "pss3072", CKK_RSA },
            { "pss2048", CKK_RSA },
            { "bp256", CKK_EC },
            { "p256", CKK_EC },
            { "p384", CKK_EC },
            { "p521", CKK_EC },
            /* NOTE: excluding these here means allow the pqc part in hsm but the ecx part in software */
            { "x25519", CKK_EC_MONTGOMERY },
            { "x448", CKK_EC_MONTGOMERY },
            /* NOTE: excluding these here means allow the pqc part in hsm but the ed part in software */
            { "ed25519", CKK_EC_EDWARDS },
            { "ed448", CKK_EC_EDWARDS },
    };
    int i = 0;
    for (i = 0; i < DIM(tab); i++) {
        if (strstr(keyctx->alg_name, tab[i].alg_name) != NULL) {
            keytype = tab[i].keytype;
            break;
        }
    }
    switch (keytype) {
    case CKK_RSA:
        if (luna_get_enable_rsa_gen_key_pair() != 1) {
            rc = LUNA_OQS_ERROR;
        }
        break;
    case CKK_EC:
        if (luna_get_enable_ec_gen_key_pair() != 1) {
            rc = LUNA_OQS_ERROR;
        }
        break;
    case CKK_EC_MONTGOMERY:
        if (luna_get_enable_em_gen_key_pair() != 1) {
            rc = LUNA_OQS_ERROR;
        }
        break;
    case CKK_EC_EDWARDS:
        if (luna_get_enable_ed_gen_key_pair() != 1) {
            rc = LUNA_OQS_ERROR;
        }
        break;
    case CKK_INVALID:
        /* is not a classic algorithm hence ok */
        rc = LUNA_OQS_OK;
        break;
    default:
        /* is a classic algorithm but not implemented hence NOT ok */
        rc = LUNA_OQS_ERROR;
        break;
    }
    return rc;
}

// query the pqc part and classic part of the algorithm can be generated in hsm
int LUNA_OQS_QUERY_any_keypair(luna_prov_key_ctx *keyctx) {
    /* test pqc keygen enabled, in general */
    if (luna_get_enable_pqc_gen_key_pair() != 1)
        return LUNA_OQS_ERROR;
    /* test classic keygen enabled, in general */
    if (LUNA_OQS_QUERY_classic_keypair(keyctx) != LUNA_OQS_OK)
        return LUNA_OQS_ERROR;
    /* test algorithm enabled, by user */
    return LUNA_OQS_QUERY_X(keyctx);
}

// query the pqc (kem) part of the key can be generated in hsm
int LUNA_OQS_QUERY_KEM_keypair(luna_prov_key_ctx *keyctx) {
    return LUNA_OQS_QUERY_any_keypair(keyctx);
}

static int _LUNA_OQS_findobject_helper_pre(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo,
        int *bFoundItHere);
static void _LUNA_OQS_findobject_helper_post(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo,
        int bFoundItHere);

// decode and find the key in hsm
// FIXME: some callers only need to decode the key (optimization)
static int LUNA_OQS_findobject(luna_prov_key_ctx *keyctx) {
    int rc = 0;
    int bFoundItHere = 0;
    luna_prov_keyinfo keyinfo;
    LUNA_OQS_READKEY_LOCK(keyctx, &keyinfo);
    rc = _LUNA_OQS_findobject_helper_pre(keyctx, &keyinfo, &bFoundItHere);
    if (rc) {
        _LUNA_OQS_findobject_helper_post(keyctx, &keyinfo, bFoundItHere);
    }
    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return rc;
}

// query if public key exists as a blob (outside the hsm)
static int luna_prov_key_reason_pubkey(luna_prov_key_reason reason) {
    int rc = ( (reason == LUNA_PROV_KEY_REASON_SET_PARAMS) || /* confirmed */
         (reason == LUNA_PROV_KEY_REASON_FROM_DATA) || /* TODO: unconfirmed */
         /* NOTE: the provider calls LUNA_OQS_WRITEKEY_LOCK that updates the 'reason' field,
          * so it is no longer necessary to check for reason == LUNA_PROV_KEY_REASON_GEN.
          */
         (reason == LUNA_PROV_KEY_REASON_FROM_ENCODING) ); /* confirmed */
    return rc;
}

// query the pqc part of the encapsulation (public key op) can be done in hsm
static int LUNA_OQS_QUERY_any_public_op(luna_prov_key_ctx *keyctx) {
    // check the algorithm list
    if (LUNA_OQS_QUERY_X(keyctx) != LUNA_OQS_OK)
        return LUNA_OQS_ERROR;
    // decode and find the key in hsm
    if (keyctx->magic == LUNA_PROV_MAGIC_ZERO)
        (void)LUNA_OQS_findobject(keyctx);
    // check the public key handle
    if (keyctx->hPublic == 0)
        return LUNA_OQS_ERROR;
    // success, meaning we MUST do the crypto op in hsm (or fail trying)
    return LUNA_OQS_OK;
}

int LUNA_OQS_QUERY_KEM_encaps(luna_prov_key_ctx *keyctx) {
    int rc = LUNA_OQS_QUERY_any_public_op(keyctx);
    if (rc == LUNA_OQS_OK) {
        // this checks "can we stuff the public key in the mechanism parameters"
        if ( (keyctx->hPublic == 0) && (luna_prov_key_reason_pubkey(keyctx->reason) == 0) )
            return LUNA_OQS_ERROR;
    }
    return rc;
}

// query the pqc part of the decapsulation (private key op) can be done in hsm
static int LUNA_OQS_QUERY_any_private_op(luna_prov_key_ctx *keyctx) {
    // NOTE: check the algorithm list is irrelevant when the keyctx indicates hardware key!
    // decode and find the key in hsm
    if (keyctx->magic == LUNA_PROV_MAGIC_ZERO)
        (void)LUNA_OQS_findobject(keyctx);
    // check the private key handle
    if ( (keyctx->is_hardware == 0) && (keyctx->hPrivate == 0) )
        return LUNA_OQS_ERROR;
    // success, meaning we MUST do the crypto op in hsm (or fail trying)
    return LUNA_OQS_OK;
}

int LUNA_OQS_QUERY_KEM_decaps(luna_prov_key_ctx *keyctx) {
    return LUNA_OQS_QUERY_any_private_op(keyctx);
}

// query the pqc (sig) part of the algorithm can be generated in hsm
int LUNA_OQS_QUERY_SIG_keypair(luna_prov_key_ctx *keyctx) {
    return LUNA_OQS_QUERY_any_keypair(keyctx);
}

// query the pqc part of the signature (private key op) can be done in hsm
int LUNA_OQS_QUERY_SIG_sign(luna_prov_key_ctx *keyctx) {
    return LUNA_OQS_QUERY_any_private_op(keyctx);
}

// query the pqc part of the verify (public key op) can be done in hsm
int LUNA_OQS_QUERY_SIG_verify(luna_prov_key_ctx *keyctx) {
    // check the engine/provider configuration for public crypto
    if (g_postconfig.DisablePublicCrypto)
        return LUNA_OQS_ERROR;
    return LUNA_OQS_QUERY_any_public_op(keyctx);
}

static CK_RV LunaPqcFind(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo);
static CK_RV LunaPqcGen(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo, int is_kem, int is_ecx);
static void _LUNA_OQS_WRITEKEY(luna_prov_key_ctx *keyctx, luna_prov_key_reason reason);
static void _LUNA_OQS_READKEY(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo);
static void LUNA_OQS_READKEY_NDX_LOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo, int ndx_in);
static void luna_sprintf_base64url(char *obuf, unsigned char *in, unsigned inlen);
static void _LUNA_debug_ex(const char *prefix, const char *prefix2, const CK_BYTE* p, size_t n);
static int luna_prov_is_ecdh_len(size_t len);

static void LunaTranslateFM2FW(luna_prov_key_ctx *keyctx,
    CK_KEY_TYPE *pkeytype, CK_KEY_PARAMS *pparams,
    CK_MECHANISM *ptypeGenerate,
    CK_MECHANISM *ptypeSign, CK_MECHANISM *ptypeEncap, CK_MECHANISM *ptypeDecap);

#include "lunaPqcKem.c"

/* luna oqs callback functions */
static int LUNA_OQS_keypair(luna_prov_key_ctx *keyctx, luna_prov_key_bits *keybits) {
    const int is_kem = keybits->is_kem;
    const int is_ecx = 0;
    // check keyctx already initialized
    if (keyctx->magic != LUNA_PROV_MAGIC_ZERO)
        return LUNA_OQS_ERROR;

    LUNA_OQS_READKEY_LOCK(keyctx, NULL);

    // initially, keyctx error
    keyctx->magic = LUNA_PROV_MAGIC_ERROR;

    luna_prov_keyinfo keyinfo;
    _LUNA_OQS_READKEY(keyctx, &keyinfo);

    // find in hsm
    // FIXME: if kem (or sig) keys are session objects then they cannot be found, so this can be optimized out
    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        rv = LunaPqcFind(keyctx, &keyinfo);
        if ( (rv == CKR_OBJECT_COUNT_TOO_SMALL && keyctx->reason == LUNA_PROV_KEY_REASON_ZERO)
          || (rv == CKR_OBJECT_DECODING_FAILED && keyctx->reason == LUNA_PROV_KEY_REASON_ZERO)
           ) {
            _LUNA_OQS_WRITEKEY(keyctx, LUNA_PROV_KEY_REASON_GEN);
            rv = LunaPqcGen(keyctx, &keyinfo, is_kem, is_ecx);
        }

        // get public key
        if (rv == CKR_OK && keyctx->reason == LUNA_PROV_KEY_REASON_GEN) {
            rv = LunaPqcExportPublic(keyctx, &keyinfo);
        }

        // set last error but do not close context
        luna_context_set_last_error(&keyinfo.sess, rv);
    }

    // finally
    if (rv == CKR_OK) {
        keyctx->magic = LUNA_PROV_MAGIC_OK;
    }

    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
}

int LUNA_OQS_KEM_keypair(luna_prov_key_ctx *keyctx, luna_prov_key_bits *keybits) {
    LUNA_PRINTF(("alg_name = %s\n", keyctx->alg_name));
    return LUNA_OQS_keypair(keyctx, keybits);
}

static int _LUNA_OQS_findobject_internal(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo);

// decode and find the key in hsm, for ops such as sign, verify, encaps, decaps
static int _LUNA_OQS_findobject_helper_pre(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo,
        int *bFoundItHere) {
    int rc = 1;
    if ( (keyctx->magic == LUNA_PROV_MAGIC_ZERO)
            || ((keyctx->magic == LUNA_PROV_MAGIC_OK) && P11_CHECK_COUNT(keyctx->count_c_init)) ) {
        *bFoundItHere = (keyctx->magic == LUNA_PROV_MAGIC_ZERO) ? 1 : 0;
        // force another find object
        keyctx->magic = LUNA_PROV_MAGIC_ZERO;
        (void)_LUNA_OQS_findobject_internal(keyctx, keyinfo);
    }
    if (keyctx->magic != LUNA_PROV_MAGIC_OK) {
        rc = 0;
    }
    return rc;
}

#define LUNA_KEYCTX_LEN_SECRET(_k) ( ((_k)->sublen == 56) ? 56 : 32 )

int LUNA_OQS_KEM_encaps(luna_prov_key_ctx *keyctx,
    unsigned char *out, size_t *outlen,
    unsigned char *secret, size_t *secretlen)
{
    LUNA_PRINTF(("alg_name = %s, magic = 0x%X\n", keyctx->alg_name, keyctx->magic));
    const CK_ULONG length_shared_secret = LUNA_KEYCTX_LEN_SECRET(keyctx);
    void *pd = 0;
    CK_ULONG dlen = 0;
    int bFoundItHere = 0;

    luna_prov_keyinfo keyinfo;
    LUNA_OQS_READKEY_LOCK(keyctx, &keyinfo);
    if (!_LUNA_OQS_findobject_helper_pre(keyctx, &keyinfo, &bFoundItHere)) {
        LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
        return LUNA_OQS_ERROR; // callback failure (bad key state)
    }

    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    // NOTE: KEM_encaps implies that the public key bytes were previously copied from peer, so
    // calling _LUNA_OQS_findobject_helper_post here to populate public key bytes from hardware
    // would be a major mistake. We assert this fact, unlike the other ops (KEM_decaps, SIG_sign, SIG_verify).
    LUNA_ASSERT(bFoundItHere == 0);
    if (out == NULL || secret == NULL) {
        // query length only
        dlen = *outlen;
        if (rv == CKR_OK)
            rv = LunaPqcKemEncap(keyctx, &keyinfo, NULL, &dlen, NULL, length_shared_secret);
        LUNA_PRINTF(("rv1 = 0x%lx\n", rv));
        if (rv == CKR_OK) { // best to not side-effect size on error
            *outlen = dlen;
            *secretlen = length_shared_secret;
        }
        // set last error but do not close context
        luna_context_set_last_error(&keyinfo.sess, rv);
        LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
        return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
    }

    dlen = *outlen;
    if (length_shared_secret > *secretlen)
        rv = CKR_GENERAL_ERROR; // callback failure (buffer too small)
    if (rv == CKR_OK)
        rv = LunaPqcKemEncap(keyctx, &keyinfo, &pd, &dlen, secret, length_shared_secret);
    LUNA_PRINTF(("rv2 = 0x%lx\n", rv));
    if (rv == CKR_OK) { // best to not side-effect size on error
        memcpy(out, pd, dlen);
        OPENSSL_free(pd);
        *outlen = dlen;
        *secretlen = length_shared_secret;
    }
    // set last error but do not close context
    luna_context_set_last_error(&keyinfo.sess, rv);
    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
}

int LUNA_OQS_KEM_decaps(luna_prov_key_ctx *keyctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    const CK_ULONG length_shared_secret = LUNA_KEYCTX_LEN_SECRET(keyctx);
    if (out == NULL) {
        // query length only
        *outlen = length_shared_secret;
        return LUNA_OQS_OK;
    }

    int bFoundItHere = 0;
    LUNA_PRINTF(("alg_name = %s, magic = 0x%X\n", keyctx->alg_name, keyctx->magic));
    luna_prov_keyinfo keyinfo;
    LUNA_OQS_READKEY_LOCK(keyctx, &keyinfo);
    if (!_LUNA_OQS_findobject_helper_pre(keyctx, &keyinfo, &bFoundItHere)) {
        LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
        return LUNA_OQS_ERROR; // callback failure (bad key state)
    }

    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK && bFoundItHere) {
        _LUNA_OQS_findobject_helper_post(keyctx, &keyinfo, bFoundItHere);
    }
    if (length_shared_secret > *outlen)
        rv = CKR_GENERAL_ERROR; // callback failure (buffer too small)
    if (rv == CKR_OK)
        rv = LunaPqcKemDecap(keyctx, &keyinfo, out, length_shared_secret, in, inlen);
    LUNA_PRINTF(("rv2 = 0x%lx\n", rv));
    if (rv == CKR_OK) // best to not side-effect size on error
        *outlen = length_shared_secret;
    // set last error but do not close context
    luna_context_set_last_error(&keyinfo.sess, rv);
    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
}

#include "lunaPqcSig.c"

int LUNA_OQS_SIG_keypair(luna_prov_key_ctx *keyctx, luna_prov_key_bits *keybits)
{
    LUNA_PRINTF(("alg_name = %s\n", keyctx->alg_name));
    return LUNA_OQS_keypair(keyctx, keybits);
}

static int _LUNA_OQS_findobject_internal(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo)
{
    // check keyctx already initialized
    if (keyctx->magic != LUNA_PROV_MAGIC_ZERO)
        return LUNA_OQS_ERROR;

    // initially, keyctx error
    keyctx->magic = LUNA_PROV_MAGIC_ERROR;

    // find in hsm
    CK_RV rv = (luna_open_context(&pkeyinfo->sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        rv = LunaPqcFind(keyctx, pkeyinfo);
        // set last error but do not close context
        luna_context_set_last_error(&pkeyinfo->sess, rv);
    }

    // finally
    if (rv == CKR_OK) {
        keyctx->magic = LUNA_PROV_MAGIC_OK;
    }

    return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
}

int LUNA_OQS_SIG_sign_ndx(luna_prov_key_ctx *keyctx,
    unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen,
    int ndx_in)
{
    int bFoundItHere = 0;
    LUNA_PRINTF(("alg_name = %s, magic = 0x%X\n", keyctx->alg_name, keyctx->magic));
    luna_prov_keyinfo keyinfo;
    LUNA_OQS_READKEY_NDX_LOCK(keyctx, &keyinfo, ndx_in);
    if (!_LUNA_OQS_findobject_helper_pre(keyctx, &keyinfo, &bFoundItHere)) {
        LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
        return LUNA_OQS_ERROR; // callback failure (bad key state)
    }

    CK_ULONG dlen = 0;
    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK && bFoundItHere) {
        _LUNA_OQS_findobject_helper_post(keyctx, &keyinfo, bFoundItHere);
    }
    if (sig == NULL) {
        // query length only
        dlen = *siglen;
        if (rv == CKR_OK)
            rv = LunaPqcSigSign(keyctx, &keyinfo, NULL, &dlen, tbs, tbslen);
        LUNA_PRINTF(("rv1 = 0x%lx\n", rv));
        if (rv == CKR_OK) // best to not side-effect size on error
            *siglen = dlen;
        // set last error but do not close context
        luna_context_set_last_error(&keyinfo.sess, rv);
        LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
        return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
    }

    dlen = *siglen;
    if (rv == CKR_OK)
        rv = LunaPqcSigSign(keyctx, &keyinfo, sig, &dlen, tbs, tbslen);
    LUNA_PRINTF(("rv2 = 0x%lx\n", rv));
    if (rv == CKR_OK) // best to not side-effect size on error
        *siglen = dlen;
    // set last error but do not close context
    luna_context_set_last_error(&keyinfo.sess, rv);
    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
}

int LUNA_OQS_SIG_verify_ndx(luna_prov_key_ctx *keyctx,
    const unsigned char *tbs, size_t tbslen,
    const unsigned char *sig, size_t siglen,
    int ndx_in)
{
    int bFoundItHere = 0;
    LUNA_PRINTF(("alg_name = %s, magic = 0x%X\n", keyctx->alg_name, keyctx->magic));
    luna_prov_keyinfo keyinfo;
    LUNA_OQS_READKEY_NDX_LOCK(keyctx, &keyinfo, ndx_in);
    if (!_LUNA_OQS_findobject_helper_pre(keyctx, &keyinfo, &bFoundItHere)) {
        LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
        return LUNA_OQS_ERROR; // callback failure (bad key state)
    }

    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK && bFoundItHere) {
        _LUNA_OQS_findobject_helper_post(keyctx, &keyinfo, bFoundItHere);
    }
    if (rv == CKR_OK)
        rv = LunaPqcSigVerify(keyctx, &keyinfo, tbs, tbslen, sig, siglen);
    LUNA_PRINTF(("rv = 0x%lx\n", rv));
    // set last error but do not close context
    luna_context_set_last_error(&keyinfo.sess, rv);
    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return (rv == CKR_OK) ? LUNA_OQS_OK : LUNA_OQS_ERROR;
}

#include "oqs_prov.h"

/*
 * callbacks to notify about events related to keypair changes
 */

/* debug print */
#ifndef NDEBUG
static void _LUNA_debug_ex(const char *prefix, const char *prefix2, const unsigned char* p, size_t n) {
    if (getenv("LUNAPROV") == NULL)
        return;
    if (p == NULL) {
        printf("LUNA: DEBUG: %s: %s: %u: NULL\n", prefix, prefix2, (unsigned)n);
        return;
    }
    printf("LUNA: DEBUG: %s: %s: %u: %02X %02X %02X %02X - %02X %02X ... %02X %02X\n",
            (char*)prefix, (char*)prefix2, (unsigned)n,
            /* show the length (if applicable for hybrid keys, big-endian format) */
            (CK_BYTE)p[0], (CK_BYTE)p[1], (CK_BYTE)p[2], (CK_BYTE)p[3],
            /* show four more bytes of detail */
            (CK_BYTE)p[4], (CK_BYTE)p[5], (CK_BYTE)p[n-2], (CK_BYTE)p[n-1]);
}

static void _LUNA_OQS_debug(luna_prov_key_ctx *keyctx, const char *prefix) {
    LUNA_ASSERT(keyctx != NULL);
    LUNA_ASSERT(keyctx->oqsxkey != NULL);
    if (getenv("LUNAPROV")) {
        if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_OQS) {
            OQSX_KEY *oqsxkey = (OQSX_KEY *)keyctx->oqsxkey;
            if (oqsxkey->privkey != NULL) {
                _LUNA_debug_ex(prefix, "privkey", oqsxkey->privkey, oqsxkey->privkeylen);
            }
            if (oqsxkey->pubkey != NULL) {
                _LUNA_debug_ex(prefix, "pubkey", oqsxkey->pubkey, oqsxkey->pubkeylen);
            }

        } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_ECXGEN) {
            /* TODO: for debug: PROV_ECX_GEN_CTX *oqsxkey = (PROV_ECX_GEN_CTX *)keyctx->oqsxkey; */

        } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_EDDSA) {
            PROV_EDDSA_CTX *oqsxkey = (PROV_EDDSA_CTX *)keyctx->oqsxkey;
            ECX_KEY *eckey = oqsxkey->key;
            if (eckey != NULL) {
                if (eckey->privkey != NULL) {
                    _LUNA_debug_ex(prefix, "privkey", eckey->privkey, keyctx->sublen);
                }
                _LUNA_debug_ex(prefix, "pubkey", eckey->pubkey, keyctx->sublen);
            }

        } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_ECXEXCH) {
            PROV_ECX_CTX *oqsxkey = (PROV_ECX_CTX *)keyctx->oqsxkey;
            ECX_KEY *eckey = oqsxkey->key;
            if (eckey != NULL) {
                if (eckey->privkey != NULL) {
                    _LUNA_debug_ex(prefix, "privkey", eckey->privkey, keyctx->sublen);
                }
                _LUNA_debug_ex(prefix, "pubkey", eckey->pubkey, keyctx->sublen);
            }
        }
    }
}
#else
static void _LUNA_debug_ex(const char *prefix, const char *prefix2, const unsigned char* p, size_t n) {
}
static void _LUNA_OQS_debug(luna_prov_key_ctx *keyctx, const char *prefix) {
}
#endif

/* writing the key buffer, including re-allocating the key buffer */
static void _LUNA_OQS_WRITEKEY(luna_prov_key_ctx *keyctx, luna_prov_key_reason reason) {
    keyctx->reason = reason;
    _LUNA_OQS_debug(keyctx, "write");
}

void LUNA_OQS_WRITEKEY_LOCK(luna_prov_key_ctx *keyctx, luna_prov_key_reason reason) {
    lunasys_mutex_enter(&keyctx->mu);
    LUNA_PRINTF(("reason = %d\n", (int)reason));
    keyctx->want_writers++;
    while (keyctx->writers || keyctx->readers) {
        lunasys_mutex_exit(&keyctx->mu);
        luna_sleep_milli(10); /* FIXME: condition variable */
        lunasys_mutex_enter(&keyctx->mu);
    }
    keyctx->writers++;
    keyctx->want_writers--;
    LUNA_ASSERT(keyctx->writers == 1);
    LUNA_ASSERT(keyctx->readers == 0);
    _LUNA_OQS_WRITEKEY(keyctx, reason);
    lunasys_mutex_exit(&keyctx->mu);
}

void LUNA_OQS_WRITEKEY_UNLOCK(luna_prov_key_ctx *keyctx) {
    lunasys_mutex_enter(&keyctx->mu);
    keyctx->writers--;
    LUNA_PRINTF(("\n"));
    lunasys_mutex_exit(&keyctx->mu);
}

/* reading the key buffer */
static void _LUNA_OQS_READKEY_NDX(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo, int ndx_in) {
    LUNA_ASSERT(keyctx != NULL && keyctx->oqsxkey != NULL);
    LUNA_ASSERT(keyinfo != NULL);
    LUNA_ASSERT(ndx_in >= -1);
    memset(keyinfo, 0, sizeof(*keyinfo));
    if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_OQS) {
        OQSX_KEY *oqsxkey = (OQSX_KEY *)keyctx->oqsxkey;
        LUNA_PRINTF(("ndx_in = %d, numkeys = %u.\n", ndx_in, (unsigned)oqsxkey->numkeys));
        LUNA_ASSERT( (ndx_in >= -1) && (ndx_in < (int)oqsxkey->numkeys) );
        if (oqsxkey->numkeys > 1) {
            /* NOTE: oqsxkey refers to both the classic key and the PQC key */
            /* NOTE: whereas keyinfo refers to just the PQC key */
            LUNA_ASSERT(oqsxkey->numkeys == 2);

            if (oqsxkey->keytype == KEY_TYPE_CMP_SIG) {
                const int ndx = (ndx_in == -1) ? 0 : ndx_in;

                /* composite pqc; reference function oqsx_key_set_composites */
                int i;
                int privlen = 0;
                int publen = 0;
                const OQSX_KEY *key = oqsxkey;
                for (i = 0; i < key->numkeys; i++) {
                    if (key->privkey) {
                        if (ndx == i) {
                            keyinfo->privkey = (char *)key->privkey + privlen;
                            keyinfo->privkeylen = key->privkeylen_cmp[i];
                        }
                        privlen += key->privkeylen_cmp[i];
                    }
                    if (key->pubkey) {
                        if (ndx == i) {
                            keyinfo->pubkey = (char *)key->pubkey + publen;
                            keyinfo->pubkeylen = key->pubkeylen_cmp[i];
                        }
                        publen += key->pubkeylen_cmp[i];
                    }
                }

            } else {
                /* TODO: for more than 2 keys: const int ndx = (ndx_in == -1) ? (oqsxkey->numkeys - 1) : ndx_in; */

                /* hybrid pqc; reference function oqsx_key_set_composites */
                /* private key appears first */
                if (oqsxkey->privkey) {
                    int classic_privkey_len = 0, offset = 0;
                    DECODE_UINT32(classic_privkey_len, oqsxkey->privkey);
                    /* assumes composites already set: keyinfo->privkey = oqsxkey->comp_privkey[1]; */
                    offset = SIZE_OF_UINT32 + classic_privkey_len;
                    keyinfo->privkey = LUNA_POINTER_ADD(oqsxkey->privkey, offset);
                    LUNA_ASSERT(oqsxkey->privkeylen > offset);
                    keyinfo->privkeylen = (oqsxkey->privkeylen - offset);
                }

                /* public key appears second */
                if (oqsxkey->pubkey) {
                    int classic_pubkey_len = 0, offset = 0;
                    DECODE_UINT32(classic_pubkey_len, oqsxkey->pubkey);
                    /* assumes composites already set: keyinfo->pubkey = oqsxkey->comp_pubkey[1]; */
                    offset = SIZE_OF_UINT32 + classic_pubkey_len;
                    keyinfo->pubkey = LUNA_POINTER_ADD(oqsxkey->pubkey, offset);
                    LUNA_ASSERT(oqsxkey->pubkeylen > offset);
                    keyinfo->pubkeylen = (oqsxkey->pubkeylen - offset);
                }
            }

        } else {
            /* pure pqc */
            LUNA_ASSERT(oqsxkey->numkeys == 1);
            /* private key appears first */
            keyinfo->privkey = oqsxkey->privkey;
            keyinfo->privkeylen = oqsxkey->privkeylen;
            /* public key appears second */
            keyinfo->pubkey = oqsxkey->pubkey;
            keyinfo->pubkeylen = oqsxkey->pubkeylen;
        }

    } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_ECXGEN) {
        /* TODO: PROV_ECX_GEN_CTX *oqsxkey = (PROV_ECX_GEN_CTX *)keyctx->oqsxkey; */

    } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_EDDSA) {
        PROV_EDDSA_CTX *oqsxkey = (PROV_EDDSA_CTX *)keyctx->oqsxkey;
        ECX_KEY *eckey = oqsxkey->key;
        LUNA_ASSERT(eckey != NULL);
        keyinfo->privkey = eckey->privkey;
        keyinfo->privkeylen = keyctx->sublen;
        keyinfo->pubkey = eckey->pubkey;
        keyinfo->pubkeylen = keyctx->sublen;

    } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_ECXEXCH) {
        PROV_ECX_CTX *oqsxkey = (PROV_ECX_CTX *)keyctx->oqsxkey;
        ECX_KEY *eckey = oqsxkey->key;
        LUNA_ASSERT(eckey != NULL);
        keyinfo->privkey = eckey->privkey;
        keyinfo->privkeylen = keyctx->sublen;
        keyinfo->pubkey = eckey->pubkey;
        keyinfo->pubkeylen = keyctx->sublen;
    }

    // NOTE: set ok flag in the keyinfo, though no code seems to check it,
    // implying this function must always succeed
    keyinfo->magic = LUNA_PROV_MAGIC_OK;
    luna_context_t tmp_ctx = LUNA_CONTEXT_T_INIT;
    memcpy(&keyinfo->sess, &tmp_ctx, sizeof(tmp_ctx));
    _LUNA_OQS_debug(keyctx, "read");
}

void _LUNA_OQS_READKEY(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo) {
    _LUNA_OQS_READKEY_NDX(keyctx, keyinfo, -1);
}

static void LUNA_OQS_READKEY_NDX_LOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo, int ndx_in) {
    lunasys_mutex_enter(&keyctx->mu);
    LUNA_PRINTF(("\n"));
    while (keyctx->writers || keyctx->want_writers) {
        lunasys_mutex_exit(&keyctx->mu);
        luna_sleep_milli(10); /* FIXME: condition variable */
        lunasys_mutex_enter(&keyctx->mu);
    }
    keyctx->readers++;
    LUNA_ASSERT(keyctx->writers == 0);
    LUNA_ASSERT(keyctx->want_writers == 0);
    if (keyinfo != NULL)
        _LUNA_OQS_READKEY_NDX(keyctx, keyinfo, ndx_in);
    lunasys_mutex_exit(&keyctx->mu);
}

void LUNA_OQS_READKEY_LOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo) {
    LUNA_OQS_READKEY_NDX_LOCK(keyctx, keyinfo, -1);
}

void LUNA_OQS_READKEY_UNLOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo) {
    lunasys_mutex_enter(&keyctx->mu);
    keyctx->readers--;
    LUNA_PRINTF(("\n"));
    lunasys_mutex_exit(&keyctx->mu);
    if (keyinfo != NULL) {
        luna_close_context(&keyinfo->sess);
    }
}

#endif // LUNA_OQS

/*****************************************************************************/

/* init wrapping keypair in software */
/* NOTE: deferred because default provider is not available at luna provider init time */
static EVP_PKEY *luna_init_wrapping_pkey_deferred(int bits) {
    LUNA_PRINTF(("\n"));
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL)
        return NULL;
    RSA *rsa = RSA_generate_key(bits, 0x010001, NULL, NULL);
    if (rsa == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

/*
 * digest wrapper functions
 */

#ifdef LUNAPROV_ENABLE_MD_WRAPPER

/* table of supported (builtin) digests */
static LUNAPROV_EVP_MD digtab[] = {
        { NID_sha1, 160, "sha-1", "sha_1", "sha1", NULL, NULL, NULL },
        { NID_sha224, 224, "sha2-224", "sha2_224", "sha-224", "sha_224", "sha224", NULL },
        { NID_sha256, 256, "sha2-256", "sha2_256", "sha-256", "sha_256", "sha256", NULL },
        { NID_sha384, 384, "sha2-384", "sha2_384", "sha-384", "sha_384", "sha384", NULL },
        { NID_sha512, 512, "sha2-512", "sha2_512", "sha-512", "sha_512", "sha512", NULL },
#if defined(LUNA_OSSL_SHA3)
        { NID_sha3_224, 224, "sha3-224", "sha3_224", NULL, NULL, NULL, NULL },
        { NID_sha3_256, 256, "sha3-256", "sha3_256", NULL, NULL, NULL, NULL },
        { NID_sha3_384, 384, "sha3-384", "sha3_384", NULL, NULL, NULL, NULL },
        { NID_sha3_512, 512, "sha3-512", "sha3_512", NULL, NULL, NULL, NULL },
#endif /* LUNA_OSSL_SHA3 */
    };

/* lookup digest; return non-null on success */
static const LUNAPROV_EVP_MD *LUNAPROV_digest_lookup_mdname(const char *mdname)
{
    if (mdname == NULL || mdname[0] == '\0') {
        LUNA_PRINTF(("mdname is null\n"));
        return NULL;
    }
    LUNA_PRINTF(("mdname = %s\n", mdname));
    for (int i = 0; i < DIM(digtab); i++) {
        LUNA_ASSERT(digtab[i].mdname != NULL);
        if ( !OPENSSL_strcasecmp(mdname, digtab[i].mdname) )
            return &digtab[i];
        if ( (digtab[i].alias1 != NULL) && (!OPENSSL_strcasecmp(mdname, digtab[i].alias1)) )
            return &digtab[i];
        if ( (digtab[i].alias2 != NULL) && (!OPENSSL_strcasecmp(mdname, digtab[i].alias2)) )
            return &digtab[i];
        if ( (digtab[i].alias3 != NULL) && (!OPENSSL_strcasecmp(mdname, digtab[i].alias3)) )
            return &digtab[i];
        if ( (digtab[i].alias4 != NULL) && (!OPENSSL_strcasecmp(mdname, digtab[i].alias4)) )
            return &digtab[i];
    }
    return NULL;
}

static const LUNAPROV_EVP_MD *LUNAPROV_digest_lookup_nid(int nid)
{
    if (nid == NID_undef || nid < 0) {
        LUNA_PRINTF(("nid is invalid\n"));
        return NULL;
    }
    LUNA_PRINTF(("nid = %d\n", nid));
    for (int i = 0; i < DIM(digtab); i++) {
        LUNA_ASSERT(digtab[i].nid != NID_undef && digtab[i].nid >= 0);
        if ( nid == digtab[i].nid )
            return &digtab[i];
    }
    return NULL;
}

/* return 0 on error */
static int LUNAPROV_digest_sz_from_nid(int nid)
{
    LUNA_PRINTF(("\n"));
    const LUNAPROV_EVP_MD *md = LUNAPROV_digest_lookup_nid(nid);
    if (md == NULL)
        return 0;
    return (md->bits/8);
}

static LUNAPROV_EVP_MD *_LUNAPROV_EVP_MD_alloc(LUNAPROV_EVP_MD *src)
{
    LUNAPROV_EVP_MD *md = (LUNAPROV_EVP_MD *) OPENSSL_zalloc(sizeof(LUNAPROV_EVP_MD));
    if (md == NULL)
        return NULL;
    md->nid = src->nid;
    md->bits = src->bits;
    /* mdname is a pointer to a global string, so no need to duplicate */
    md->mdname = src->mdname;
    /* the remaining members can be null */
    return md;
}

/* find digest by name; return non-null on success */
LUNAPROV_EVP_MD *LUNAPROV_EVP_MD_fetch(void *libctx, const char *mdname, const char *params)
{
    LUNA_PRINTF(("\n"));
    /* check null algorithm */
    if ( (mdname == NULL) || (mdname[0] == '\0') ) {
        LUNA_PRINTF(("mdname is null\n"));
        return NULL;
    }
    LUNA_PRINTF(("mdname = %s\n", mdname));
    /* check null libctx */
    if (libctx == NULL) {
        LUNA_PRINTF(("libctx is null\n"));
        return NULL;
    }
    /* check unrecognized param(s) */
    if (params != NULL) {
        LUNA_PRINTF(("BUG: params is non-null\n"));
    }
    const LUNAPROV_EVP_MD *md0 = LUNAPROV_digest_lookup_mdname(mdname);
    if (md0 == NULL)
        return NULL;
    /* returned md is a duplicate */
    LUNAPROV_EVP_MD *md1 = (LUNAPROV_EVP_MD*)md0;
    LUNAPROV_EVP_MD *ret_md = _LUNAPROV_EVP_MD_alloc(md1);
    if (ret_md == NULL)
        return NULL;
    ret_md->tmp_md = EVP_MD_fetch(libctx, ret_md->mdname, params);
    ret_md->ref_count = 1;
    return ret_md;
}

const EVP_MD *LUNAPROV_EVP_MD_get_tmp_md(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    if (md == NULL)
        return NULL;
    return md->tmp_md;
}

void LUNAPROV_EVP_MD_free(LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    if (md == NULL)
        return;
    // FIXME:atomic reference counting?
    md->ref_count--;
    if (md->ref_count > 0)
        return;
    if (md->tmp_md != NULL)
        EVP_MD_free(md->tmp_md);
    OPENSSL_cleanse(md, sizeof(*md));
    OPENSSL_free(md);
    return;
}

int LUNAPROV_EVP_MD_is_a(const LUNAPROV_EVP_MD *md, const char *mdname)
{
    LUNA_PRINTF(("\n"));
    int rc = (md != NULL && md == LUNAPROV_digest_lookup_mdname(mdname));
    return rc;
}

int LUNAPROV_EVP_MD_get_size(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    int rc = (md == NULL ? -1 : (md->bits/8));
    return rc;
}

int LUNAPROV_EVP_MD_get_nid(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    int rc = (md == NULL ? NID_undef : md->nid);
    return rc;
}

int LUNAPROV_EVP_MD_up_ref(LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    if (md == NULL)
        return 0;
    // FIXME:atomic reference counting?
    md->ref_count++;
    return 1;
}

const char *LUNAPROV_EVP_MD_get0_name(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    const char *rc = (md == NULL ? NULL : md->mdname);
    return rc;
}

int LUNAPROV_ossl_digest_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md, int sha1_allowed)
{
    LUNA_PRINTF(("\n"));
    int nid = LUNAPROV_EVP_MD_get_nid(md);
    if (nid == NID_sha1 && !sha1_allowed)
        nid = -1;
    return nid;
}

int LUNAPROV_ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md, int sha1_allowed)
{
    LUNA_PRINTF(("\n"));
    return LUNAPROV_ossl_digest_get_approved_nid_with_sha1(ctx, md, sha1_allowed);
}

const OSSL_PARAM *LUNAPROV_EVP_MD_gettable_ctx_params(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    if (md == NULL || md->tmp_md == NULL)
        return NULL;
    return EVP_MD_gettable_ctx_params(md->tmp_md);
}

const OSSL_PARAM *LUNAPROV_EVP_MD_settable_ctx_params(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    if (md == NULL || md->tmp_md == NULL)
        return NULL;
    return EVP_MD_settable_ctx_params(md->tmp_md);
}

LUNAPROV_EVP_MD_CTX *LUNAPROV_EVP_MD_CTX_new(void)
{
    LUNA_PRINTF(("\n"));
    LUNAPROV_EVP_MD_CTX *ctx = (LUNAPROV_EVP_MD_CTX *) OPENSSL_zalloc(sizeof(LUNAPROV_EVP_MD_CTX));
    if (ctx == NULL)
        return NULL;
    ctx->tmp_ctx = EVP_MD_CTX_new();
    return ctx;
}

void LUNAPROV_EVP_MD_CTX_free(LUNAPROV_EVP_MD_CTX *ctx)
{
    LUNA_PRINTF(("\n"));
    if (ctx == NULL)
        return;
    if (ctx->mddata != NULL) {
        OPENSSL_cleanse(ctx->mddata, ctx->mdsize);
        OPENSSL_free(ctx->mddata);
    }
    if (ctx->tmp_ctx != NULL)
        EVP_MD_CTX_free(ctx->tmp_ctx);
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    OPENSSL_free(ctx);
}

int LUNAPROV_EVP_MD_CTX_copy_ex(LUNAPROV_EVP_MD_CTX *out, const LUNAPROV_EVP_MD_CTX *in)
{
    LUNA_PRINTF(("\n"));
    if (in == NULL)
        return 0;
    out->digest = in->digest;
    if (out->mddata != NULL) {
        OPENSSL_cleanse(out->mddata, out->mdsize);
        OPENSSL_free(out->mddata);
    }
    out->mddata = OPENSSL_memdup(in->mddata, in->mdsize);
    out->mdsize = in->mdsize;
    EVP_MD_CTX_copy_ex(out->tmp_ctx, in->tmp_ctx);
    return 1;
}

int LUNAPROV_EVP_DigestInit_ex2(LUNAPROV_EVP_MD_CTX *ctx, const LUNAPROV_EVP_MD *md, const OSSL_PARAM params[])
{
    LUNA_PRINTF(("\n"));
    LUNA_ASSERT(ctx != NULL);
    LUNA_ASSERT(md != NULL);
    LUNA_ASSERT(params == NULL);
    LUNA_ASSERT(ctx->digest == NULL);
    ctx->digest = md;
    return 1;
}

int LUNAPROV_EVP_DigestUpdate(LUNAPROV_EVP_MD_CTX *ctx, const void *data, size_t datalen)
{
    LUNA_PRINTF(("\n"));
    LUNA_ASSERT(ctx != NULL);
    LUNA_ASSERT(data != NULL);
    LUNA_ASSERT(datalen != 0);
    /* accumulate the data */
    if (ctx->mddata) {
        unsigned char *newdata = OPENSSL_malloc(ctx->mdsize + datalen);
        if (newdata == NULL)
            return 0;
        memcpy(newdata, ctx->mddata, ctx->mdsize);
        memcpy(newdata + ctx->mdsize, data, datalen);
        OPENSSL_cleanse(ctx->mddata, ctx->mdsize);
        OPENSSL_free(ctx->mddata);
        ctx->mddata = newdata;
        ctx->mdsize += datalen;
    } else {
        ctx->mddata = OPENSSL_malloc(datalen);
        if (ctx->mddata == NULL)
            return 0;
        ctx->mdsize = datalen;
        memcpy(ctx->mddata, data, ctx->mdsize);
    }
    return 1;
}

int LUNAPROV_EVP_DigestFinal_ex(LUNAPROV_EVP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen)
{
    LUNA_PRINTF(("\n"));
    LUNA_ASSERT(out != NULL);
    int ret = 0;
    int sz = 0;

    if (ctx->digest == NULL)
        return 0;

    sz = LUNAPROV_EVP_MD_get_size(ctx->digest);
    if (sz < 0)
        return 0;

    switch (LUNAPROV_EVP_MD_get_nid(ctx->digest)) {
    case NID_sha1:
        ret = EVP_Q_digest(NULL, "SHA1", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha224:
        ret = EVP_Q_digest(NULL, "SHA224", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha256:
        ret = EVP_Q_digest(NULL, "SHA256", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha384:
        ret = EVP_Q_digest(NULL, "SHA384", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha512:
        ret = EVP_Q_digest(NULL, "SHA512", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
#if defined(LUNA_OSSL_SHA3)
    case NID_sha3_224:
        ret = EVP_Q_digest(NULL, "SHA3_224", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha3_256:
        ret = EVP_Q_digest(NULL, "SHA3_256", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha3_384:
        ret = EVP_Q_digest(NULL, "SHA3_384", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
    case NID_sha3_512:
        ret = EVP_Q_digest(NULL, "SHA3_512", NULL, ctx->mddata, ctx->mdsize, out, NULL);
        break;
#endif /* LUNA_OSSL_SHA3 */
    default:
        ret = 0;
        break;
    }

    if (outlen != NULL) {
        *outlen = sz;
    }

    return ret;
}

int LUNAPROV_EVP_MD_CTX_get_params(LUNAPROV_EVP_MD_CTX *ctx, OSSL_PARAM params[])
{
    LUNA_PRINTF(("\n"));
    if (ctx == NULL || ctx->tmp_ctx == NULL)
        return 0;
    return EVP_MD_CTX_get_params(ctx->tmp_ctx, params);
}

int LUNAPROV_EVP_MD_CTX_set_params(LUNAPROV_EVP_MD_CTX *ctx, const OSSL_PARAM params[])
{
    LUNA_PRINTF(("\n"));
    if (ctx == NULL || ctx->tmp_ctx == NULL)
        return 0;
    return EVP_MD_CTX_set_params(ctx->tmp_ctx, params);
}

#else /* LUNAPROV_ENABLE_MD_WRAPPER */

#define MD_NID_CASE(name, sz)                                                  \
    case NID_##name:                                                           \
        return sz;

static int LUNAPROV_digest_sz_from_nid(int nid)
{
    LUNA_PRINTF(("\n"));
    switch (nid) {
    MD_NID_CASE(sha1, SHA_DIGEST_LENGTH)
    MD_NID_CASE(sha224, SHA224_DIGEST_LENGTH)
    MD_NID_CASE(sha256, SHA256_DIGEST_LENGTH)
    MD_NID_CASE(sha384, SHA384_DIGEST_LENGTH)
    MD_NID_CASE(sha512, SHA512_DIGEST_LENGTH)
    MD_NID_CASE(sha3_224, SHA224_DIGEST_LENGTH)
    MD_NID_CASE(sha3_256, SHA256_DIGEST_LENGTH)
    MD_NID_CASE(sha3_384, SHA384_DIGEST_LENGTH)
    MD_NID_CASE(sha3_512, SHA512_DIGEST_LENGTH)
    default:
        return 0;
    }
}

LUNAPROV_EVP_MD *LUNAPROV_EVP_MD_fetch(void *libctx, const char *mdname, const char *params)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_fetch(libctx, mdname, params);
}

const EVP_MD *LUNAPROV_EVP_MD_get_tmp_md(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return md;
}

void LUNAPROV_EVP_MD_free(LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    EVP_MD_free(md);
}

int LUNAPROV_EVP_MD_is_a(const LUNAPROV_EVP_MD *md, const char *mdname)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_is_a(md, mdname);
}

int LUNAPROV_EVP_MD_get_size(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_get_size(md);
}

int LUNAPROV_EVP_MD_get_nid(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_nid(md); /* aka EVP_MD_get_type */
}

int LUNAPROV_EVP_MD_up_ref(LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_up_ref(md);
}

const char *LUNAPROV_EVP_MD_get0_name(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_get0_name(md);
}

int LUNAPROV_ossl_digest_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md, int sha1_allowed)
{
    LUNA_PRINTF(("\n"));
#ifdef LUNA_OSSL_3_4
    int mdnid = ossl_digest_get_approved_nid(md);

#if (0) && !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (ossl_securitycheck_enabled(ctx)) {
        if (mdnid == NID_undef || (mdnid == NID_sha1 && !sha1_allowed))
            mdnid = -1; /* disallowed by security checks */
    }
#endif
    return mdnid;
#else
    return ossl_digest_get_approved_nid_with_sha1(ctx, md, sha1_allowed);
#endif
}

int LUNAPROV_ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md, int sha1_allowed)
{
    LUNA_PRINTF(("\n"));
#ifdef LUNA_OSSL_3_4
    return ossl_digest_rsa_sign_get_md_nid(md);
#else
    return ossl_digest_rsa_sign_get_md_nid(ctx, md, sha1_allowed);
#endif
}

int LUNAPROV_ossl_digest_is_allowed(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
#ifdef LUNA_OSSL_3_4
#if (0) && !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (ossl_securitycheck_enabled(ctx))
        return ossl_digest_get_approved_nid(md) != NID_undef;
# endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */
    return 1;
#else
    return ossl_digest_is_allowed(ctx, md);
#endif
}

const OSSL_PARAM *LUNAPROV_EVP_MD_gettable_ctx_params(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_gettable_ctx_params(md);
}

const OSSL_PARAM *LUNAPROV_EVP_MD_settable_ctx_params(const LUNAPROV_EVP_MD *md)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_settable_ctx_params(md);
}

LUNAPROV_EVP_MD_CTX *LUNAPROV_EVP_MD_CTX_new(void)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_CTX_new();
}

void LUNAPROV_EVP_MD_CTX_free(LUNAPROV_EVP_MD_CTX *ctx)
{
    LUNA_PRINTF(("\n"));
    EVP_MD_CTX_free(ctx);
}

int LUNAPROV_EVP_MD_CTX_copy_ex(LUNAPROV_EVP_MD_CTX *out, const LUNAPROV_EVP_MD_CTX *in)
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_CTX_copy_ex(out, in);
}

int LUNAPROV_EVP_DigestInit_ex2(LUNAPROV_EVP_MD_CTX *ctx, const LUNAPROV_EVP_MD *md, const OSSL_PARAM params[])
{
    LUNA_PRINTF(("\n"));
    return EVP_DigestInit_ex2(ctx, md, params);
}

int LUNAPROV_EVP_DigestUpdate(LUNAPROV_EVP_MD_CTX *ctx, const void *data, size_t datalen)
{
    LUNA_PRINTF(("\n"));
    return EVP_DigestUpdate(ctx, data, datalen);
}

int LUNAPROV_EVP_DigestFinal_ex(LUNAPROV_EVP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen)
{
    LUNA_PRINTF(("\n"));
    return EVP_DigestFinal_ex(ctx, out, outlen);
}

int LUNAPROV_EVP_MD_CTX_get_params(LUNAPROV_EVP_MD_CTX *ctx, OSSL_PARAM params[])
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_CTX_get_params(ctx, params);
}

int LUNAPROV_EVP_MD_CTX_set_params(LUNAPROV_EVP_MD_CTX *ctx, const OSSL_PARAM params[])
{
    LUNA_PRINTF(("\n"));
    return EVP_MD_CTX_set_params(ctx, params);
}

#endif /* LUNAPROV_ENABLE_MD_WRAPPER */

static int luna_prov_is_ecdh_len(size_t len)
{
    /* NOTE: p521, p384, p256, bp512, x448 */
    if (len == 66 || len == 48 || len == 32 || len == 64 || len == 56)
        return 1;
    return 0;
}

static void luna_init_ecdh(void) {
    // zeroize wrapping key (a new one will be generated)
    luna_wrapping_pkey = NULL;
    luna_wrapping_error = 0;
    luna_wrapping_handle = 0;
    luna_wrapping_count_c_init = 0;
}

static CK_RV LunaEcdhComputeKey(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_BYTE *psecret, CK_ULONG secretLen,
    const CK_BYTE *cipherText, CK_ULONG cipherTextLen, int flagCofactor) {
    CK_RV rv = CKR_OK;

    CK_OBJECT_HANDLE privateObjectHandle = keyctx->hPrivate;
    CK_OBJECT_HANDLE decapObjectHandle = 0;

    CK_ULONG valueLen = secretLen;
    CK_KEY_TYPE aesKeyType = CKK_GENERIC_SECRET; /* NOTE: CKK_AES is limited to 16, 24, 32 */
    char *decapLabel = "temp-luna-ecdh-compute";

    CK_ECDH1_DERIVE_PARAMS ecdh1DeriveParams;
    memset(&ecdh1DeriveParams, 0, sizeof(ecdh1DeriveParams));
    ecdh1DeriveParams.pPublicData = (CK_BYTE*)cipherText;
    ecdh1DeriveParams.ulPublicDataLen = cipherTextLen;
    ecdh1DeriveParams.pSharedData = NULL;
    ecdh1DeriveParams.ulSharedDataLen = 0;
    ecdh1DeriveParams.kdf = CKD_NULL;

    CK_MECHANISM decapMech;
    decapMech.mechanism = (flagCofactor ? CKM_ECDH1_COFACTOR_DERIVE : CKM_ECDH1_DERIVE);
    decapMech.pParameter = &ecdh1DeriveParams;
    decapMech.ulParameterLen = sizeof(ecdh1DeriveParams);

    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE decapTemplate[] = {
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_LABEL, decapLabel, strlen(decapLabel)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
        {CKA_MODIFIABLE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
    };

    // check for stale object handle
    if (rv == CKR_OK) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

#if 1
    // OPTIMIZATION: derive and wrap
    if (rv == CKR_OK) {
        rv = LunaDeriveUnwrapKeyBytes(keyctx, pkeyinfo,
                &decapMech, privateObjectHandle, decapTemplate, DIM(decapTemplate),
                psecret, secretLen);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("ECDH compute and wrap failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("ECDH compute and wrap was successful\n"));
        }
    }

#else
    // Perform the decapsulation using the private key
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    if (rv == CKR_OK) {
        rv = P11->C_DeriveKey(session, &decapMech, privateObjectHandle, decapTemplate, DIM(decapTemplate), &decapObjectHandle);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("ECDH compute failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("ECDH compute was successful: hObject=%lu\n", decapObjectHandle));
        }
    }

    // unwrap key and get key bytes
    if (rv == CKR_OK) {
        rv = LunaUnwrapKeyBytes(keyctx, pkeyinfo, decapObjectHandle, psecret, secretLen);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("ECDH unwrap failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("ECDH unwrap was successful\n"));
        }
    }

    if (decapObjectHandle != 0) {
        (void)P11->C_DestroyObject(session, decapObjectHandle);
        decapObjectHandle = 0;
    }
#endif

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

typedef struct LunaUnwrapKeyBytesOAEP_st {
    CK_MECHANISM_PTR pMechDerive;
    CK_OBJECT_HANDLE hBaseKey;
    CK_ATTRIBUTE_PTR pAttr;
    CK_ULONG nAttr;
} LunaUnwrapKeyBytesOAEP_st;

static CK_RV LunaUnwrapKeyBytesOAEP(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_OBJECT_HANDLE hObject, CK_BYTE *psecret, CK_ULONG secretLen,
    LunaUnwrapKeyBytesOAEP_st *px) {

    CK_RV rv = CKR_OK;
    const unsigned bits = LUNA_RSAWRAP_KEYBITS;
    CK_OBJECT_HANDLE hWrapper = 0;
    CK_BYTE *pWrapped = NULL;
    CK_ULONG ulWrapped = 0;
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    EVP_PKEY *pkey = luna_wrapping_pkey;
    if (pkey == NULL)
        rv = CKR_KEY_NEEDED;
    // import sw rsa public to hw
    if (rv == CKR_OK && (luna_wrapping_handle == 0 || luna_wrapping_count_c_init != luna_count_c_init)) {
        CK_ULONG ckoClass = CKO_PUBLIC_KEY;
        CK_ULONG ckkType = CKK_RSA;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_BYTE ckModulus[LUNA_RSAWRAP_KEYBITS / 8] = {0};
        CK_BYTE ckExponent[3] = { 0x01, 0x00, 0x01 };
        CK_ATTRIBUTE attr[] = {
            { CKA_TOKEN, &no, sizeof(no) }, /* session object ok here for PQC FM/SHIM */
            { CKA_CLASS, &ckoClass, sizeof(ckoClass) },
            { CKA_KEY_TYPE, &ckkType, sizeof(ckkType) },
            { CKA_WRAP, &yes, sizeof(yes) },
            { CKA_MODULUS, &ckModulus, sizeof(ckModulus) },
            { CKA_PUBLIC_EXPONENT, &ckExponent, sizeof(ckExponent) },
        };
        const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
        const BIGNUM *n = NULL;
        const BIGNUM *e = NULL;
        RSA_get0_key(rsa, &n, &e, NULL);
        int rctmp = 0;
        if ( ((rctmp = BN_num_bytes(e)) != sizeof(ckExponent)) || ((rctmp = BN_bn2bin(e, ckExponent)) != sizeof(ckExponent)) )
            rv = CKR_GENERAL_ERROR;
        if ( ((rctmp = BN_num_bytes(n)) != sizeof(ckModulus)) || ((rctmp = BN_bn2bin(n, ckModulus)) != sizeof(ckModulus)) )
            rv = CKR_GENERAL_ERROR;
        if (rv == CKR_OK) {
            rv = P11->C_CreateObject(session, attr, DIM(attr), &hWrapper);
            if (rv == CKR_OK) {
                luna_wrapping_handle = hWrapper;
                luna_wrapping_count_c_init = luna_count_c_init;
            }
        }
    } else {
        hWrapper = luna_wrapping_handle;
    }
    // hw wrap the tls key
    if (rv == CKR_OK) {
        CK_MECHANISM mechWrap = { CKM_RSA_PKCS_OAEP, 0, 0 };
        CK_RSA_PKCS_OAEP_PARAMS oaepParams;
        CK_RSA_PKCS_OAEP_PARAMS *params = &oaepParams;
        mechWrap.mechanism = CKM_RSA_PKCS_OAEP;
        mechWrap.pParameter = &oaepParams;
        mechWrap.ulParameterLen = sizeof(oaepParams);
        params->hashAlg = CKM_SHA256;
        params->mgf = CKG_MGF1_SHA256;
        params->source = CKZ_DATA_SPECIFIED;
        params->pSourceData = 0;
        params->ulSourceDataLen = 0;
        ulWrapped = (bits / 8);
        pWrapped = (CK_BYTE*)OPENSSL_malloc(ulWrapped);
        if (px == NULL) {
            rv = P11->C_WrapKey(session, &mechWrap, hWrapper, hObject, pWrapped, &ulWrapped);
        } else {
            rv = p11.ext.CA_DeriveKeyAndWrap(session,
                    px->pMechDerive, px->hBaseKey, px->pAttr, px->nAttr,
                    &mechWrap, hWrapper, pWrapped, &ulWrapped);
        }
    }
    // sw unwrap the tls key
    if (rv == CKR_OK) {
        struct _temp_evp {
            int nid;
            EVP_PKEY *pkey;
            EVP_MD_CTX *mctx;
            EVP_PKEY_CTX *pkctx;
            size_t cipherlen;
            unsigned char *cipher;
            size_t outlen;
            unsigned char *out;
            size_t labellen;
            unsigned char label[256];
        } evp = { NID_sha256, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, {0} };
            evp.pkey = pkey;
            const EVP_MD *oaep_md = EVP_get_digestbynid(evp.nid);
            const EVP_MD *mgf1_md = EVP_get_digestbynid(evp.nid);
               evp.out = NULL;
               evp.outlen = 0;
               evp.pkctx = EVP_PKEY_CTX_new(evp.pkey, NULL);
               if (evp.pkctx == NULL)
                  goto err;
               if (EVP_PKEY_decrypt_init(evp.pkctx) <= 0)
                  goto err;
               if (EVP_PKEY_CTX_set_rsa_padding(evp.pkctx, RSA_PKCS1_OAEP_PADDING) <= 0)
                  goto err;
               if (EVP_PKEY_CTX_set_rsa_oaep_md(evp.pkctx, oaep_md) <= 0)
                  goto err;
               if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp.pkctx, mgf1_md) <= 0)
                  goto err;
               evp.labellen = 0;
               evp.cipher = pWrapped;
               evp.cipherlen = ulWrapped;
               if (EVP_PKEY_decrypt(evp.pkctx, NULL, &evp.outlen, evp.cipher, evp.cipherlen) <= 0) {
                  LUNA_PRINTF((LUNA_FUNC_NAME ": EVP_PKEY_decrypt failed \n"));
                  goto err;
               }
               evp.out = OPENSSL_malloc(evp.outlen);
               if (evp.out == NULL) {
                   LUNA_PRINTF((LUNA_FUNC_NAME ": OPENSSL_malloc failed \n"));
                   goto err;
               }
               if (EVP_PKEY_decrypt(evp.pkctx, evp.out, &evp.outlen, evp.cipher, evp.cipherlen) <= 0) {
                  LUNA_PRINTF((LUNA_FUNC_NAME ": EVP_PKEY_decrypt failed \n"));
                  goto err;
               }
               if (evp.outlen != secretLen) {
                  LUNA_PRINTF((LUNA_FUNC_NAME ": memcmp failed: outlen = %u \n", (unsigned)evp.outlen));
                  goto err;
               }
               // evp success
               memcpy(psecret, evp.out, secretLen);
               // evp clean
               OPENSSL_free(evp.out);
               EVP_PKEY_CTX_free(evp.pkctx);
               goto clean;
               err:
               rv = CKR_GENERAL_ERROR;
               if (evp.out)
                   OPENSSL_free(evp.out);
               if (evp.pkctx)
                   EVP_PKEY_CTX_free(evp.pkctx);
    }
    clean:
    // clean
    if (pWrapped != NULL) {
        memset(pWrapped, 0, ulWrapped);
        OPENSSL_free(pWrapped);
    }
    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaUnwrapKeyBytes_prep(void) {
    /* generate the software wrapping keypair once, shortly after the provider is initialized */
    if (luna_wrapping_pkey == NULL && luna_wrapping_error == 0) {
        luna_wrapping_pkey = luna_init_wrapping_pkey_deferred(LUNA_RSAWRAP_KEYBITS);
        if (luna_wrapping_pkey == NULL)
            luna_wrapping_error = 1;
        luna_wrapping_handle = 0;
        luna_wrapping_count_c_init = 0;
    }

    if (luna_wrapping_error != 0)
        return CKR_GENERAL_ERROR;

    return CKR_OK;
}

static CK_RV LunaUnwrapKeyBytes(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_OBJECT_HANDLE hObject, CK_BYTE *psecret, CK_ULONG secretLen) {

    if (LunaUnwrapKeyBytes_prep() != CKR_OK)
        return CKR_GENERAL_ERROR;

    return LunaUnwrapKeyBytesOAEP(keyctx, pkeyinfo, hObject, psecret, secretLen, NULL);
}

static CK_RV LunaDeriveUnwrapKeyBytes(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_MECHANISM_PTR pMechDerive, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
    CK_BYTE *psecret, CK_ULONG secretLen) {

    if (LunaUnwrapKeyBytes_prep() != CKR_OK)
        return CKR_GENERAL_ERROR;

    LunaUnwrapKeyBytesOAEP_st foo;
    foo.pMechDerive = pMechDerive;
    foo.hBaseKey = hBaseKey;
    foo.pAttr = pAttr;
    foo.nAttr = nAttr;
    return LunaUnwrapKeyBytesOAEP(keyctx, pkeyinfo, 0, psecret, secretLen, &foo);
}

/* derive key (ECDH) */
int luna_prov_ECDH_compute_key_ex(
    void *out, size_t outlen,
    const EC_KEY *peer_key0,
    const EC_KEY *eckey0,
    void *(*KDF) (const void *in, size_t inlen, void *out, size_t *outlen))
{
    EC_KEY *peer_key = (EC_KEY *)peer_key0;
    EC_KEY *eckey = (EC_KEY *)eckey0;
    LUNA_ASSERT(out != NULL);
    LUNA_ASSERT(luna_prov_is_ecdh_len(outlen));
    LUNA_ASSERT(peer_key != NULL);
    LUNA_ASSERT(eckey != NULL);
    LUNA_ASSERT(KDF == NULL);

    switch (luna_ecdsa_check_private(eckey)) {
    case 0: /* hardware */
        break;
    case 1: /* software */
        {
            const EC_POINT *ppubkey = EC_KEY_get0_public_key(peer_key);
            return ECDH_compute_key(out, outlen, ppubkey, eckey, KDF);
        }
    default: /* error */
        return 0;
    }

    luna_prov_key_ctx keyctx;
    luna_prov_keyinfo keyinfo;
    CK_ULONG buflen = (CK_ULONG)outlen;
    CK_BYTE *buf = NULL;
    memset(&keyctx, 0, sizeof(keyctx));
    memset(&keyinfo, 0, sizeof(keyinfo));

    CK_RV rv = CKR_OK;
    CK_BYTE *px = NULL;
    int pxlen = 0;
    const int oRawEcPoint = 0;

    if (! oRawEcPoint) {
        /* convert ecPoint from openssl form to luna octet form (same as CKA_EC_POINT) */
        pxlen = LUNA_i2o_ECPublicKey(peer_key, &px, NULL, NULL);
        if (pxlen <= 0)
            rv = CKR_GENERAL_ERROR;
    } else {
        /* convert ecPoint from openssl form to luna raw form */
        pxlen = i2o_ECPublicKey(peer_key, &px);
        if (pxlen <= 0)
            rv = CKR_GENERAL_ERROR;
    }

    /* allocate buf */
    if (rv == CKR_OK) {
        buf = (CK_BYTE*)OPENSSL_zalloc(buflen);
        if (buf == NULL)
            rv = CKR_GENERAL_ERROR;
    }

    /* derive in hardware */
    if (rv == CKR_OK) {
        rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
        if (rv == CKR_OK) {
            int flagCofactor = 0;
            if (EC_KEY_get_flags(eckey) & EC_FLAG_COFACTOR_ECDH)
                flagCofactor = 1;
            /* NOTE: copy 'count_c_init' otherwise error with message "key handle is stale" */
            keyctx.count_c_init = keyinfo.sess.count_c_init;
            /* FIXME: OPTIMIZATION: I suspect eckey was duplicated however the cached hsm object handles were not; libssl is to blame? */
            keyctx.hPrivate = luna_find_ecdsa_handle_FAST(&keyinfo.sess, eckey, 1);
            if (keyctx.hPrivate == 0)
                rv = CKR_GENERAL_ERROR;
            if (rv == CKR_OK)
                rv = LunaEcdhComputeKey(&keyctx, &keyinfo, buf, buflen, px, pxlen, flagCofactor);
            luna_close_context_w_err(&keyinfo.sess, (rv != CKR_OK), rv);
        }
    }

    /* copy computed key */
    if (rv == CKR_OK)
        memcpy(out, buf, buflen);

    /* cleanse */
    if (buf) {
        OPENSSL_cleanse(buf, buflen);
        OPENSSL_free(buf);
    }
    if (px)
        OPENSSL_free(px);

    return (rv == CKR_OK ? (int)buflen : 0);
}

int luna_prov_EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx)
{
    int r = 0;
    BIGNUM *a1, *a2, *a3, *b1, *b2, *b3;
    BN_CTX *ctx_new = NULL;

    /* compare the field types */
    if (EC_GROUP_get_field_type(a) != EC_GROUP_get_field_type(b))
        return 1;
    /* compare the curve name (if present in both) */
    if (EC_GROUP_get_curve_name(a) && EC_GROUP_get_curve_name(b) &&
        EC_GROUP_get_curve_name(a) != EC_GROUP_get_curve_name(b))
        return 1;
#if 0
    /* FIXME: structure of 'a' is undefined, and, there is no way to query flags */
    if (a->meth->flags & EC_FLAGS_CUSTOM_CURVE)
        return 0;
#endif

    if (ctx == NULL)
        ctx_new = ctx = BN_CTX_new();
    if (ctx == NULL)
        return -1;

    BN_CTX_start(ctx);
    a1 = BN_CTX_get(ctx);
    a2 = BN_CTX_get(ctx);
    a3 = BN_CTX_get(ctx);
    b1 = BN_CTX_get(ctx);
    b2 = BN_CTX_get(ctx);
    b3 = BN_CTX_get(ctx);
    if (b3 == NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx_new);
        return -1;
    }

    /*
     * XXX This approach assumes that the external representation of curves
     * over the same field type is the same.
     */
    if (!EC_GROUP_get_curve(a, a1, a2, a3, ctx) ||
        !EC_GROUP_get_curve(b, b1, b2, b3, ctx))
        r = 1;

    /* return 1 if the curve parameters are different */
    if (r || BN_cmp(a1, b1) != 0 || BN_cmp(a2, b2) != 0 || BN_cmp(a3, b3) != 0)
        r = 1;

#if 0
    /* FIXME: the generator is different when testing "openssl s_client" */
    /* XXX EC_POINT_cmp() assumes that the methods are equal */
    /* return 1 if the generators are different */
    if (r || EC_POINT_cmp(a, EC_GROUP_get0_generator(a),
                          EC_GROUP_get0_generator(b), ctx) != 0)
        r = 1;
#endif

    if (!r) {
        const BIGNUM *ao, *bo, *ac, *bc;
        /* compare the orders */
        ao = EC_GROUP_get0_order(a);
        bo = EC_GROUP_get0_order(b);
        if (ao == NULL || bo == NULL) {
            /* return an error if either order is NULL */
            r = -1;
            goto end;
        }
        if (BN_cmp(ao, bo) != 0) {
            /* return 1 if orders are different */
            r = 1;
            goto end;
        }
        /*
         * It gets here if the curve parameters and generator matched.
         * Now check the optional cofactors (if both are present).
         */
        ac = EC_GROUP_get0_cofactor(a);
        bc = EC_GROUP_get0_cofactor(b);
        /* Returns 1 (mismatch) if both cofactors are specified and different */
        if (!BN_is_zero(ac) && !BN_is_zero(bc) && BN_cmp(ac, bc) != 0)
            r = 1;
        /* Returns 0 if the parameters matched */
    }
end:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx_new);
    return r;
}


/* ECX/ED wrapper functions */

#ifdef LUNA_OQS
static
int luna_prov_ecx_public_from_private_sw(struct ecx_gen_ctx *gctx,
        ECX_KEY *key, unsigned char *privkey) {
    switch (gctx->type) {
    case ECX_KEY_TYPE_X25519:
        privkey[0] &= 248;
        privkey[X25519_KEYLEN - 1] &= 127;
        privkey[X25519_KEYLEN - 1] |= 64;
        LUNA_PRINTF(("ossl_x25519_public_from_private\n"));
        ossl_x25519_public_from_private(key->pubkey, privkey); /* 32 bytes */
        break;
    case ECX_KEY_TYPE_X448:
        privkey[0] &= 252;
        privkey[X448_KEYLEN - 1] |= 128;
        LUNA_PRINTF(("ossl_x448_public_from_private\n"));
        ossl_x448_public_from_private(key->pubkey, privkey); /* 56 bytes */
        break;
    case ECX_KEY_TYPE_ED25519:
        LUNA_PRINTF(("ossl_ed25519_public_from_private\n"));
        if (!ossl_ed25519_public_from_private(gctx->libctx, key->pubkey, privkey, /* 32 bytes */
                                              gctx->propq))
            goto err;
        break;
    case ECX_KEY_TYPE_ED448:
        LUNA_PRINTF(("ossl_ed448_public_from_private\n"));
        if (!ossl_ed448_public_from_private(gctx->libctx, key->pubkey, privkey, /* 57 bytes */
                                            gctx->propq))
            goto err;
        break;
    }
    return 1;

err:
    return 0;
}

static
int luna_prov_ecx_dhkem_derive_private_sw(struct ecx_gen_ctx *gctx,
        ECX_KEY *ecx, unsigned char *privout) {
    if (!ossl_ecx_dhkem_derive_private(ecx,
            privout, gctx->dhkem_ikm, gctx->dhkem_ikmlen))
        return 0;
    return luna_prov_ecx_public_from_private_sw(gctx,
            ecx, privout);
}

static
int luna_prov_ecx_sig_derive_private_sw(struct ecx_gen_ctx *gctx,
        ECX_KEY *ecx, unsigned char *privout) {
    if (RAND_priv_bytes_ex(gctx->libctx, privout, ecx->keylen, 0) <= 0)
        return 0;
    return luna_prov_ecx_public_from_private_sw(gctx,
            ecx, privout);
}

static
int ECX_KEY_TYPE_is_kem(struct ecx_gen_ctx *gctx) {
    const int t = gctx->type;
    int rc = ( (t == ECX_KEY_TYPE_X25519) || (t == ECX_KEY_TYPE_X448) );
    return rc;
}

static
int ECX_KEY_TYPE_is_sig(struct ecx_gen_ctx *gctx) {
    const int t = gctx->type;
    int rc = ( (t == ECX_KEY_TYPE_ED25519) || (t == ECX_KEY_TYPE_ED448) );
    return rc;
}

static
int ECX_KEY_TYPE_privkeylen(struct ecx_gen_ctx *gctx) {
    switch (gctx->type) {
    case ECX_KEY_TYPE_X25519:
        return 32; /* X25519_KEYLEN */
    case ECX_KEY_TYPE_X448:
        return 56; /* X448_KEYLEN */
    case ECX_KEY_TYPE_ED25519:
        return 32; /* ED25519_KEYLEN */
    case ECX_KEY_TYPE_ED448:
        return 57; /* ED448_KEYLEN */
    }
    return 0;
}

static
int ECX_KEY_TYPE_pubkeylen(struct ecx_gen_ctx *gctx) {
    /* public key len same as private key len */
    int rc = ECX_KEY_TYPE_privkeylen(gctx);
    return rc;
}

static int luna_prov_query_ecx(luna_prov_key_ctx *keyctx) {
    int rc_query = LUNA_OQS_QUERY_X(keyctx);
    return (rc_query == LUNA_OQS_OK ? 1 : 0);
}

int luna_prov_ecx_sig_derive_private(struct ecx_gen_ctx *gctx,
        ECX_KEY *ecx, unsigned char *privout) {

    luna_prov_key_ctx *keyctx = gctx->lunakeyctx;
    // need to check if this is for kem or for sig
    const int is_kem = ECX_KEY_TYPE_is_kem(gctx);
    const int is_sig = ECX_KEY_TYPE_is_sig(gctx);
    const int is_ecx = 1;
    if (is_kem) {
        if ( (luna_get_enable_em_gen_key_pair() != 1)
                || (luna_prov_query_ecx(keyctx) != 1) ) {
            // in software
            return luna_prov_ecx_sig_derive_private_sw(gctx,
                    ecx, privout);
        }
    } else if (is_sig) {
        if ( (luna_get_enable_ed_gen_key_pair() != 1)
                || (luna_prov_query_ecx(keyctx) != 1) ) {
            // in software
            return luna_prov_ecx_sig_derive_private_sw(gctx,
                    ecx, privout);
        }
    } else {
        LUNA_PRINTF(("BUG: neither kem nor sig\n"));
        return 0;
    }

    // in hardware
    // check keyctx already initialized
    if (keyctx->magic != LUNA_PROV_MAGIC_ZERO)
        return 0;

    luna_prov_keyinfo keyinfo;
    LUNA_OQS_READKEY_LOCK(keyctx, &keyinfo);

    // initially, keyctx error
    keyctx->magic = LUNA_PROV_MAGIC_ERROR;

    // NOTE: custom keyinfo, not retrieved during LUNA_OQS_READKEY_LOCK
    keyinfo.privkey = ecx->privkey;
    keyinfo.privkeylen = ECX_KEY_TYPE_privkeylen(gctx);
    keyinfo.pubkey = ecx->pubkey;
    keyinfo.pubkeylen = ECX_KEY_TYPE_pubkeylen(gctx);

    // find in hsm
    // FIXME: if kem (or sig) keys are session objects then they cannot be found, so this can be optimized out
    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        rv = LunaPqcFind(keyctx, &keyinfo);
        if ( (rv == CKR_OBJECT_COUNT_TOO_SMALL && keyctx->reason == LUNA_PROV_KEY_REASON_ZERO)
          || (rv == CKR_OBJECT_DECODING_FAILED && keyctx->reason == LUNA_PROV_KEY_REASON_ZERO)
           ) {
            _LUNA_OQS_WRITEKEY(keyctx, LUNA_PROV_KEY_REASON_GEN);
            rv = LunaPqcGen(keyctx, &keyinfo, is_kem, is_ecx);
        }

        // get public key
        if (rv == CKR_OK && keyctx->reason == LUNA_PROV_KEY_REASON_GEN) {
            rv = LunaEcxExportPublic(keyctx, &keyinfo);
        }

        // set last error but do not close context
        luna_context_set_last_error(&keyinfo.sess, rv);
    }

    // finally
    if (rv == CKR_OK) {
        keyctx->magic = LUNA_PROV_MAGIC_OK;
        _LUNA_debug_ex("luna_prov_ecx_sig_derive_private", "privout", privout, keyinfo.privkeylen);
    }

    LUNA_OQS_READKEY_UNLOCK(keyctx, &keyinfo);
    return (rv == CKR_OK) ? 1 : 0;
}

int luna_prov_ecx_dhkem_derive_private(struct ecx_gen_ctx *gctx,
        ECX_KEY *ecx, unsigned char *privout) {
    // need to check if this is for kem or for sig
    const int is_kem = ECX_KEY_TYPE_is_kem(gctx);
    const int is_sig = ECX_KEY_TYPE_is_sig(gctx);
    const int is_ecx = 1;
    if (is_kem) {
        if (luna_get_enable_em_gen_key_pair() != 1) {
            // in software
            return luna_prov_ecx_dhkem_derive_private_sw(gctx,
                    ecx, privout);
        }
    } else if (is_sig) {
        if (luna_get_enable_ed_gen_key_pair() != 1) {
            // in software
            return luna_prov_ecx_dhkem_derive_private_sw(gctx,
                    ecx, privout);
        }
    } else {
        LUNA_PRINTF(("BUG: neither kem nor sig\n"));
        return 0;
    }
    // in hardware
    LUNA_PRINTF(("BUG: NOT IMPLEMENTED\n"));
    return 0; // FIXME:FIXME:
}

// implement BASE64URL, not BASE64
static const char *bstr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void luna_sprintf_base64url(char *obuf, unsigned char *input, unsigned inlen) {
    unsigned i = 0;
    unsigned o = 0;
    unsigned remain = 0;
    unsigned ondx = 0;

    obuf[0] = 0;
    if (input == NULL)
        return;

    while (i < inlen) {
        remain = (inlen - i);
        switch (remain) {
        case 1:
            obuf[ondx++] = bstr[((input[i] >> 2) & 0x3f)];
            obuf[ondx++] = bstr[((input[i] << 4) & 0x30)];
            break;
        case 2:
            obuf[ondx++] = bstr[((input[i] >> 2) & 0x3f)];
            obuf[ondx++] = bstr[((input[i] << 4) & 0x30) + ((input[i + 1] >> 4) & 0x0f)];
            obuf[ondx++] = bstr[((input[i + 1] << 2) & 0x3c)];
            break;
        default:
            obuf[ondx++] = bstr[((input[i] >> 2) & 0x3f)];
            obuf[ondx++] = bstr[((input[i] << 4) & 0x30) + ((input[i + 1] >> 4) & 0x0f)];
            obuf[ondx++] = bstr[((input[i + 1] << 2) & 0x3c) + ((input[i + 2] >> 6) & 0x03)];
            obuf[ondx++] = bstr[(input[i + 2] & 0x3f)];
            break;
        }
        o += 4;
        i += 3;
    }
    obuf[ondx] = 0;
    LUNA_PRINTF(("obuf = \"%s\" (%u)\n", obuf, ondx));
}

#define ECX_LEN_32 32
#if (ECX_LEN_32 != LUNA_PQC_PRIVATEBLOB_BYTES_32)
#error "ECX_LEN_32: assertion failed"
#endif

int luna_prov_ecx_check_private(const ECX_KEY *ecx)
{
    if (ecx == NULL || ecx->privkey == NULL) {
        LUNA_PRINTF(("ecx NULL\n"));
        return LUNA_CHECK_ERROR;
    }
    unsigned char *privkey = ecx->privkey;
    CK_ATTRIBUTE aPublic[] = {
            {CKA_LABEL, 0, 0}, // first
            {CKA_ID, 0, 0} // second
    };
    CK_ATTRIBUTE aPrivate[] = {
            {CKA_LABEL, 0, 0}, // first
            {CKA_ID, 0, 0} // second
    };
    luna_prov_keyinfo keyinfo;
    memset(&keyinfo, 0, sizeof(keyinfo));
    keyinfo.privkey = privkey;
    keyinfo.privkeylen = ECX_LEN_32;
    _LUNA_debug_ex("luna_prov_ecx_check_private", "privkey", keyinfo.privkey, keyinfo.privkeylen);
    CK_RV rv = LunaPqcDecodeTemplateV2(NULL, &keyinfo,
        aPublic, aPrivate);
    if (rv == CKR_OK) {
        LunaPqcCleanTemplate(NULL, aPublic, aPrivate);
        LUNA_PRINTF(("LUNA_CHECK_IS_HARDWARE\n"));
        return LUNA_CHECK_IS_HARDWARE;
    }
    /* NOTE: possibly the key is not populated yet. If so then likely this function should not be called. */
    /* TODO: add more checks for malformed key, if possible */
    if ( (privkey[0] == 0 && privkey[1] == 0 && privkey[2] == 0 && privkey[3] == 0)
            ) {
        LUNA_PRINTF(("LUNA_CHECK_ERROR\n"));
        return LUNA_CHECK_ERROR;
    }
    LUNA_PRINTF(("LUNA_CHECK_IS_SOFTWARE\n"));
    return LUNA_CHECK_IS_SOFTWARE;
}

/* return 1 on success, 0 on failure */
int luna_prov_ecx_public_from_private(ECX_KEY *ecx)
{
    LUNA_PRINTF(("\n"));
    const int rc_check = luna_prov_ecx_check_private(ecx);
    switch (rc_check) {
    case LUNA_CHECK_IS_SOFTWARE:
        /* public key is derived from proper private key - leave public alone */
        return 1;
    case LUNA_CHECK_IS_HARDWARE:
        /* public key is derived from pseudo private key - obfuscate public somehow */
        {
            const int pubkeylen = ECX_LEN_32;
            _LUNA_debug_ex("uri", "pubkey", ecx->pubkey, pubkeylen);
            if (luna_RAND_bytes(ecx->pubkey, pubkeylen) != 1) {
                ecx->pubkey[0] ^= 0x5a;
                ecx->pubkey[pubkeylen-1] ^= 0xa5;
                return 0;
            }
            _LUNA_debug_ex("rand", "pubkey", ecx->pubkey, pubkeylen);
            if (luna_prov_ecx_fix_public(ecx) == 0)
                return 0;
            _LUNA_debug_ex("hsm", "pubkey", ecx->pubkey, pubkeylen);
        }
        return 1;
    case LUNA_CHECK_ERROR:
    default:
        return 0;
    }
    return 0;
}

int luna_prov_ed25519_sign(luna_prov_key_ctx *keyctx,
                        unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    LUNA_PRINTF(("\n"));
    int rc = LUNA_OQS_SIG_sign_ndx(keyctx,
        sig, siglen,
        tbs, tbslen,
        0);
    return (rc == LUNA_OQS_OK) ? 1: 0;
}

int luna_prov_ed448_sign(luna_prov_key_ctx *keyctx,
                        unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    LUNA_PRINTF(("\n"));
    int rc = LUNA_OQS_SIG_sign_ndx(keyctx,
        sig, siglen,
        tbs, tbslen,
        0);
    return (rc == LUNA_OQS_OK) ? 1: 0;
}

// fix public key if it is found in hardware
int luna_prov_ecx_fix_public(ECX_KEY *ecx) {
    LUNA_PRINTF(("\n"));
    const int rc_check = luna_prov_ecx_check_private(ecx);
    if (rc_check != LUNA_CHECK_IS_HARDWARE)
        return 0;

    luna_prov_key_ctx *keyctx = NULL;
    if (ecx->type == ECX_KEY_TYPE_ED25519) {
        keyctx = LUNA_OQS_malloc_from_eddsa(NULL, "ed25519");
    } else if (ecx->type == ECX_KEY_TYPE_ED448) {
        keyctx = LUNA_OQS_malloc_from_eddsa(NULL, "ed448");
    } else if (ecx->type == ECX_KEY_TYPE_X25519) {
        keyctx = LUNA_OQS_malloc_from_ecx(NULL, "x25519");
    } else if (ecx->type == ECX_KEY_TYPE_X448) {
        keyctx = LUNA_OQS_malloc_from_ecx(NULL, "x448");
    } else {
        return 0;
    }

    if (keyctx == NULL)
        return 0;

    // initially, keyctx error
    keyctx->magic = LUNA_PROV_MAGIC_ERROR;

    // NOTE: custom keyinfo, not retrieved during LUNA_OQS_READKEY_LOCK
    luna_prov_keyinfo keyinfo;
    memset(&keyinfo, 0, sizeof(keyinfo));
    keyinfo.privkey = ecx->privkey;
    keyinfo.privkeylen = keyctx->sublen;
    keyinfo.pubkey = ecx->pubkey;
    keyinfo.pubkeylen = keyctx->sublen;

    // find in hsm
    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        rv = LunaPqcFind(keyctx, &keyinfo);

        // get public key bytes
        if (rv == CKR_OK) {
            rv = LunaEcxExportPublic(keyctx, &keyinfo);
        }

        luna_close_context_w_err(&keyinfo.sess, (rv != CKR_OK), rv);
    }

    // finally
    LUNA_OQS_free(keyctx);

    return (rv == CKR_OK) ? 1 : 0;
}

// compute key as in x25519/x448
int luna_prov_ecx_compute_key(luna_prov_key_ctx *keyctx,
                         unsigned char *secret, size_t *secretlen, size_t outlen) {
    PROV_ECX_CTX *oqsxkey = (PROV_ECX_CTX *)keyctx->oqsxkey;
    ECX_KEY *peerkey = oqsxkey->peerkey;
    LUNA_ASSERT(peerkey != NULL);
    unsigned char *in = peerkey->pubkey;
    unsigned inlen = keyctx->sublen;
    // reuse LUNA_OQS_KEM_decaps, because this op uses the private key
    // FIXME:FIXME:other ecdh options? cofactor?
    int rc = LUNA_OQS_KEM_decaps (keyctx,
        secret, secretlen,
        in, inlen);
    return rc == LUNA_OQS_OK ? 1 : 0;
}

#endif // LUNA_OQS

int luna_getenv_LUNAPROV_rc = 0;

// query environment variable, faster
void luna_getenv_LUNAPROV_init(void) {
    if (luna_getenv_LUNAPROV_rc == 0) {
        if (getenv("LUNAPROV") != NULL) {
            luna_getenv_LUNAPROV_rc = 1;
        } else {
            luna_getenv_LUNAPROV_rc = -1;
        }
    }
}

#ifdef LUNA_OQS

// translate from FM codes to FW codes (main firmware)
static void LunaTranslateFM2FW(luna_prov_key_ctx *keyctx, CK_KEY_TYPE *pkeytype,
        CK_KEY_PARAMS *pparams, CK_MECHANISM *ptypeGenerate,
        CK_MECHANISM *ptypeSign, CK_MECHANISM *ptypeEncap,
        CK_MECHANISM *ptypeDecap) {

    int isMechMlkem = 0;
    int isMechMldsa = 0;

    LUNA_PRINTF(("alg_name = %s\n", keyctx->alg_name));
    // check key type
    if (pkeytype != NULL) {
        if (*pkeytype == CKK_ML_KEM) {
            *pkeytype = 0x00000049UL; /* TODO: hardcoded */
        } else if (*pkeytype == CKK_ML_DSA) {
            *pkeytype = 0x0000004aUL; /* TODO: hardcoded */
        }
    }

    // check mech for generate
    if (ptypeGenerate != NULL) {
        if (ptypeGenerate->mechanism == CKM_ML_KEM_KEY_PAIR_GEN) {
            ptypeGenerate->mechanism = 0x0000000fUL; /* TODO: hardcoded */
            isMechMlkem = 1;
        } else if (ptypeGenerate->mechanism == CKM_ML_DSA_KEY_PAIR_GEN) {
            ptypeGenerate->mechanism = 0x0000001CUL; /* TODO: hardcoded */
            isMechMldsa = 1;
        }
    }

    // check mech for sign
    if (ptypeSign != NULL) {
        if (ptypeSign->mechanism == CKM_ML_DSA) {
            ptypeSign->mechanism = 0x0000001DUL; /* TODO: hardcoded */
            isMechMldsa = 1;
        }
    }

    // check mech for encap
    if (ptypeEncap != NULL) {
        if (ptypeEncap->mechanism == CKM_MLKEM_KEM_KEY_ENCAP) {
            ptypeEncap->mechanism = 0x00000017UL; /* TODO: hardcoded */
            isMechMlkem = 1;
        }
    }

    // check mech for decap
    if (ptypeDecap != NULL) {
        if (ptypeDecap->mechanism == CKM_MLKEM_KEM_KEY_DECAP) {
            ptypeDecap->mechanism = 0x00000017UL; /* TODO: hardcoded */
            isMechMlkem = 1;
        }
    }

    // finally, check params
    if (pparams != NULL) {
        if (isMechMlkem) {
            switch (*pparams) {
            case CKP_ML_KEM_512:
            case CKP_ML_KEM_512_IPD:
                *pparams = 1; /* TODO: hardcoded */
                break;
            case CKP_ML_KEM_768:
            case CKP_ML_KEM_768_IPD:
                *pparams = 2; /* TODO: hardcoded */
                break;
            case CKP_ML_KEM_1024:
            case CKP_ML_KEM_1024_IPD:
                *pparams = 3; /* TODO: hardcoded */
                break;
            default:
                *pparams = 0;
                break;
            }
        }

        if (isMechMldsa) {
            switch (*pparams) {
            case CKP_ML_DSA_44:
            case CKP_ML_DSA_44_IPD:
                *pparams = 1; /* TODO: hardcoded */
                break;
            case CKP_ML_DSA_65:
            case CKP_ML_DSA_65_IPD:
                *pparams = 2; /* TODO: hardcoded */
                break;
            case CKP_ML_DSA_87:
            case CKP_ML_DSA_87_IPD:
                *pparams = 3; /* TODO: hardcoded */
                break;
            default:
                *pparams = 0;
                break;
            }
        }
    }
}

// get the public key bytes from hardware in case we need to (or prefer to) do public key crypto op in software
static void _LUNA_OQS_findobject_helper_post(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo,
        int bFoundItHere) {
    if (! bFoundItHere)
        return;
    if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_ECXEXCH) {
        // openssl computes public key bytes from private key bytes,
        // so we MUST get the real public key bytes from hardware
        (void)LunaEcxExportPublic(keyctx, keyinfo);
    } else if (keyctx->ctxtype == LUNA_PROV_CTXTYPE_EDDSA) {
        // openssl computes public key bytes from private key bytes,
        // so we MUST get the real public key bytes from hardware
        (void)LunaEcxExportPublic(keyctx, keyinfo);
    }
    // LUNA_PROV_CTXTYPE_OQS no issue
    // LUNA_PROV_CTXTYPE_ECXGEN no issue
}

// query misc
int luna_prov_get_DelegateHwPqcKemEncapToSw(void) {
    return luna_get_DelegateHwPqcKemEncapToSw();
}

//
// get RNG from hardware
//

// sticky error flag
static int luna_pqc_rng_hw_error = 0;

// query there is an error and we should bypass hardware
static int luna_pqc_rng_hw_is_error(void) {
    return luna_pqc_rng_hw_error;
}

// get RNG from pkcs11
static CK_RV luna_pqc_rng_hw_pkcs11(uint8_t *out, size_t outlen) {
    luna_prov_keyinfo keyinfo;
    memset(&keyinfo, 0, sizeof(keyinfo));
    CK_RV rv = (luna_open_context(&keyinfo.sess) == 1) ? CKR_OK : CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        CK_SESSION_HANDLE session = keyinfo.sess.hSession;
        rv = P11->C_GenerateRandom(session, out, outlen);
        luna_close_context_w_err(&keyinfo.sess, (rv != CKR_OK), rv);
    }
    if (rv != CKR_OK) {
        luna_pqc_rng_hw_error = 1;
    }
    return rv;
}

// statistics
static struct {
    unsigned big;
    unsigned reset;
    unsigned error;
    unsigned copy;
    unsigned cache;
    unsigned liboqs;
    unsigned hwm;
} cnt = { 0, 0, 0, 0, 0, 0, 0 };

// size of RNG cache for small requests (32-bytes)
#define LUNA_PQC_RNG_SMALL (32)
#define LUNA_PQC_RNG_CACHE (LUNA_PQC_RNG_SMALL * 40 * 2)

static struct {
    volatile int dirty;
    volatile size_t offset;
    CK_BYTE bytes[LUNA_PQC_RNG_CACHE];
} rcache = { 1, 0, {0} }; /* must be static */

static void luna_pqc_rng_hw_cleanse(void) {
    memset(rcache.bytes, 0, sizeof(rcache.bytes));
}

// get RNG from cache
static CK_RV luna_pqc_rng_hw_cache_locked(uint8_t *out, size_t outlen) {
    // check request is larger than cache
    if (outlen > LUNA_PQC_RNG_CACHE) {
        cnt.big++;
        return luna_pqc_rng_hw_pkcs11(out, outlen);
    }
    const size_t offset0 = rcache.offset;
    const size_t offset1 = offset0 + outlen;
    if ( rcache.dirty || (offset1 > LUNA_PQC_RNG_CACHE) ) {
        // reset the cache
        cnt.reset++;
        rcache.dirty = 1;
        CK_RV rv = luna_pqc_rng_hw_pkcs11(rcache.bytes, LUNA_PQC_RNG_CACHE);
        if (rv != CKR_OK) {
            cnt.error++;
            return rv;
        }
        rcache.dirty = 0;
        rcache.offset = outlen;
        memcpy(out, &(rcache.bytes[0]), outlen);
    } else {
        // just copy from cache
        cnt.copy++;
        rcache.dirty = 0;
        rcache.offset = offset1;
        memcpy(out, &(rcache.bytes[offset0]), outlen);
    }
    return CKR_OK;
}

static CK_RV luna_pqc_rng_hw_cache(uint8_t *out, size_t outlen) {
    lunasys_mutex_enter(&luna_pqc_rng_mu);
    luna_pqc_rng_hw_cache_locked(out, outlen);
    lunasys_mutex_exit(&luna_pqc_rng_mu);
}

static CK_RV luna_pqc_rng_hw_int(uint8_t *out, size_t outlen) {
    // frequent small requests require the cache for performance
    if (outlen <= LUNA_PQC_RNG_SMALL) {
        cnt.cache++;
        return luna_pqc_rng_hw_cache(out, outlen);
    }
    cnt.liboqs++;
    return (luna_pqc_rng_liboqs(out, outlen), CKR_OK);
}

static CK_RV luna_pqc_rng_hw(uint8_t *out, size_t outlen) {
    CK_RV rv = luna_pqc_rng_hw_int(out, outlen);
    if (outlen > cnt.hwm)
        cnt.hwm = outlen;
#if 0
    fprintf(stderr, "big = %u, reset = %u, error = %u, copy = %u, cache = %u, liboqs = %u, hwm = %u.\n",
            cnt.big, cnt.reset, cnt.error, cnt.copy, cnt.cache, cnt.liboqs, cnt.hwm);
#endif
    return rv;
}

// set parameter by converting from provider internal format to external format
int LUNA_PARAM_set_encoded_public_key(void *oqsxk_, OSSL_PARAM *p, const void *val, size_t len) {
    OQSX_KEY *oqsxk = (OQSX_KEY *)oqsxk_;
    if (oqsxk->keytype != KEY_TYPE_ECX_HYB_KEM)
        return OSSL_PARAM_set_octet_string(p, val, len);
    // special case of reverse keyshare for KEY_TYPE_ECX_HYB_KEM
    const size_t sublen = oqsxk->lunakeyctx->sublen;
    if ( (sublen > len) || (sublen < 1) ) {
        LUNA_PRINTF(("BUG: sublen = %lu, len = %lu\n", sublen, len));
        return 0;
    }
    unsigned char *srcbuf = (unsigned char *)val;
    unsigned char *tmpbuf = OPENSSL_zalloc(len);
    memcpy(tmpbuf, srcbuf+sublen, (len-sublen));
    memcpy(tmpbuf+(len-sublen), srcbuf, sublen);
    int rc = OSSL_PARAM_set_octet_string(p, tmpbuf, len);
    OPENSSL_free(tmpbuf);
    return rc;
}

// get parameter by converting from external format to provider internal format
int LUNA_PARAM_get_encoded_public_key(void *oqsxk_, const OSSL_PARAM *p, void **val_ptr, size_t max_len, size_t *used_len) {
    OQSX_KEY *oqsxk = (OQSX_KEY *)oqsxk_;
    int rc = OSSL_PARAM_get_octet_string(p, val_ptr, max_len, used_len);
    if ( (rc <= 0) || (oqsxk->keytype != KEY_TYPE_ECX_HYB_KEM) )
        return rc;
    // special case of reverse keyshare for KEY_TYPE_ECX_HYB_KEM
    const size_t sublen = oqsxk->lunakeyctx->sublen;
    const size_t len = *used_len;
    if ( (sublen > len) || (sublen < 1) ) {
        LUNA_PRINTF(("BUG: sublen = %lu, len = %lu\n", sublen, len));
        return 0;
    }
    unsigned char *srcbuf = (unsigned char *)*val_ptr;
    unsigned char *tmpbuf = OPENSSL_zalloc(len);
    memcpy(tmpbuf, srcbuf+(len-sublen), sublen);
    memcpy(tmpbuf+sublen, srcbuf, (len-sublen));
    memcpy(*val_ptr, tmpbuf, len);
    OPENSSL_free(tmpbuf);
    return rc;
}

#endif /* LUNA_OQS */

/* for find object by uri */
LUNA_FIND_CTX *LUNA_FIND_CTX_new(const char *uri) {
    LUNA_PRINTF(("uri=%s\n", uri));
    LUNA_FIND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->uri = OPENSSL_strdup(uri);
    if (ctx->uri == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    luna_context_t *psess = OPENSSL_zalloc(sizeof(*psess));
    if (psess == NULL) {
        OPENSSL_free(ctx->uri);
        OPENSSL_free(ctx);
        return NULL;
    }
    if (luna_open_context(psess) != 1) {
        OPENSSL_free(psess);
        OPENSSL_free(ctx->uri);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->psess = psess;
    ctx->magic = 1;
    return ctx;
}

void LUNA_FIND_CTX_free(LUNA_FIND_CTX *ctx) {
    LUNA_PRINTF(("\n"));
    if (ctx == NULL)
        return;
    if (ctx->uri != NULL) {
        OPENSSL_free(ctx->uri);
    }
    ctx->uri = NULL;
    if (ctx->psess != NULL) {
        luna_close_context(ctx->psess);
        OPENSSL_free(ctx->psess);
    }
    ctx->psess = NULL;
    ctx->magic = 0;
    // TODO: free multiple pkeys
    OPENSSL_free(ctx);
}

int LUNA_FIND_CTX_next(LUNA_FIND_CTX *ctx) {
    int rc = 0;
    EVP_PKEY *pkey = NULL;
    LUNA_PRINTF(("count = %d\n", ctx->count));
    switch (ctx->count) {
    case 0:
        // load PKEY (private key required and public key optional)
        pkey = luna_load_anykey(NULL, ctx->uri, NULL, NULL, 0);
        break;
    case 1:
        // load PUBKEY (public key required)
        pkey = luna_load_anykey(NULL, ctx->uri, NULL, NULL, 1);
        break;
    default:
        pkey = NULL;
        break;
    }
    if (pkey != NULL) {
        ctx->current = &ctx->pkeys[ctx->count];
        ctx->current->pkey = pkey;
        ctx->count++;
        rc = 1;
    }
    LUNA_PRINTF(("rc = %d\n", rc));
    return rc;
}

static struct {
    const char *sn;
    const char *tls_name;
    const char *ln;
} sntab[] = {
        { LUNA_SN_ML_DSA_87, LUNA_TN_ML_DSA_87, LUNA_LN_ML_DSA_87 },
        { LUNA_SN_ML_DSA_65, LUNA_TN_ML_DSA_65, LUNA_LN_ML_DSA_65 },
        { LUNA_SN_ML_DSA_44, LUNA_TN_ML_DSA_44, LUNA_LN_ML_DSA_44 }
};

const char *luna_short_name(const char *txt) {
    if (txt == NULL)
        return NULL;
    const char *sn = txt;
    for (int i = 0; i < DIM(sntab); i++) {
        // fix error message "key2any_encode:passed a null parameter"
        if ( !strcmp(txt, sntab[i].tls_name) || !strcmp(txt, sntab[i].ln) ) {
            sn = sntab[i].sn;
            break;
        }
    }
    LUNA_PRINTF(("txt = %s, sn = %s\n", txt, sn));
    return sn;
}

const char *luna_tls_name(const char *txt) {
    if (txt == NULL)
        return NULL;
    const char *tls_name = txt;
    for (int i = 0; i < DIM(sntab); i++) {
        // fix error message "oqs_sig_sign:reason(12)"
        if ( !strcmp(txt, sntab[i].sn) || !strcmp(txt, sntab[i].ln) ) {
            tls_name = sntab[i].tls_name;
            break;
        }
    }
    LUNA_PRINTF(("txt = %s, tls_name = %s\n", txt, tls_name));
    return tls_name;
}

