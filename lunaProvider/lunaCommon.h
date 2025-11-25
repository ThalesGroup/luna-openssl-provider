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

#ifndef _LUNACOMMON_H
#define _LUNACOMMON_H

/* openssl headers */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/core.h>
#include <openssl/types.h>
#include <openssl/bio.h>

/* prov headers */
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_util.h"
#include "prov/securitycheck.h"
#include "prov/seeding.h"
#ifdef LUNA_OQS
#include "prov/ecx.h"
#endif

/* TODO: generated when building openssl */
#include "prov/der_rsa.h"
#include "prov/der_dsa.h"
#include "prov/der_ec.h"
#include "prov/der_ecx.h"

/* internal headers */
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "internal/packet.h"
/* coverity #include "internal/constant_time.h" */
#include "internal/cryptlib.h"
#include "internal/param_build_set.h"

/* crypto (internal) headers */
#include "crypto/rsa.h"
#include "crypto/dsa.h"
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "crypto/ecx.h"

#ifndef FIPS_MODULE
# ifndef OPENSSL_NO_SM2
#  include "crypto/sm2.h"
# endif
#endif

/* NOTE: OQS is conditionally compiled, on windows for example */
#ifdef LUNA_OQS
#include "oqs_prov.h"
#endif // LUNA_OQS

/* detect openssl 3.2 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30200000L)
#define LUNA_OSSL_3_2 (1)
#endif

#ifndef LUNA_OSSL_3_2
#ifndef OSSL_DISPATCH_END
#define OSSL_DISPATCH_END { 0, NULL }
#endif
#endif

/* detect openssl 3.4 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30400000L)
#define LUNA_OSSL_3_4 (1)
#endif

/* detect openssl 3.0.7 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30000070L)
#define LUNA_OSSL_3_0_7 (1)
#define LUNA_FIPS (1)
#endif

/* detect openssl 3.5.0 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30500000L)
#define LUNA_OSSL_3_5 (1)
#endif

/* luna dispatch functions */
extern const OSSL_DISPATCH luna_rsa_signature_functions[];
extern const OSSL_DISPATCH luna_rsa_asym_cipher_functions[];
extern const OSSL_DISPATCH luna_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH luna_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH luna_ec_signature_functions[];
extern const OSSL_DISPATCH luna_ec_keymgmt_functions[];
extern const OSSL_DISPATCH luna_ecdh_keyexch_functions[];
extern const OSSL_DISPATCH luna_dsa_signature_functions[];
extern const OSSL_DISPATCH luna_dsa_keymgmt_functions[];
#ifdef LUNA_OQS
extern const OSSL_DISPATCH luna_ed25519_signature_functions[];
extern const OSSL_DISPATCH luna_ed448_signature_functions[];
extern const OSSL_DISPATCH luna_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH luna_ed448_keymgmt_functions[];
extern const OSSL_DISPATCH luna_x25519_keymgmt_functions[];
extern const OSSL_DISPATCH luna_x448_keymgmt_functions[];
extern const OSSL_DISPATCH luna_x25519_keyexch_functions[];
extern const OSSL_DISPATCH luna_x448_keyexch_functions[];
#endif

/* minimal definitions shared outside luna-provider */
#include "luna_prov_minimal.h"

/* misc */
#define LUNA_PROV_DIGEST_LENGTH_MAX 64 /* TODO:EVP_MAX_MD_SIZE */

/* luna query provider is useable */
int luna_prov_is_running(void);
int luna_prov_engine_init(void);
void luna_prov_engine_fini(void);

/* luna query key is useable */
int luna_prov_rsa_check_key(OSSL_LIB_CTX *ctx, const RSA *rsa, int operation);
int luna_prov_ec_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect);
int luna_prov_dsa_check_key(OSSL_LIB_CTX *ctx, const DSA *dsa, int sign);

/* luna query key is hardware key or software key or other (e.g., malformed) */
int luna_prov_rsa_check_private(const RSA *rsa);
int luna_prov_ec_check_private(const EC_KEY *ec);
int luna_prov_dsa_check_private(const DSA *dsa);

int luna_prov_check_is_software(int rc_check);
int luna_prov_check_is_hardware(int rc_check);

int luna_prov_rsa_check_public(const RSA *rsa);
int luna_prov_ec_check_public(const EC_KEY *ec);
int luna_prov_dsa_check_public(const DSA *dsa);

/* RSA wrapper functions */
int luna_prov_RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes, BIGNUM *e_value, BN_GENCB *cb);
int luna_prov_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int luna_prov_RSA_verify(int type, const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int luna_prov_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
                        RSA *rsa, int padding);
int luna_prov_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
                        RSA *rsa, int padding);
int luna_prov_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding);
int luna_prov_rsa_priv_enc_pkcs(void *xparams, int flen, const unsigned char *from,
        size_t tolen, unsigned char *to, RSA *rsa, int padding);
int luna_prov_rsa_priv_dec_x509(void *xparams, int flen, const unsigned char *from,
        size_t tolen, unsigned char *to, RSA *rsa, int padding);

/* EC wrapper functions */
int luna_prov_EC_KEY_generate_key_ex(EC_KEY *key, int lunaflags);
int luna_prov_ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen,
                  unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
                  const BIGNUM *r, EC_KEY *eckey);
int luna_prov_ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
                 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

/* DSA wrapper functions */
int luna_prov_DSA_generate_key(DSA *dsa);
int luna_prov_ossl_dsa_sign_int(int type, const unsigned char *dgst, int dlen,
                      unsigned char *sig, unsigned int *siglen, DSA *dsa);
int luna_prov_DSA_verify(int type, const unsigned char *dgst, int dgst_len,
               const unsigned char *sigbuf, int siglen, DSA *dsa);

/* ECDH wrapper functions */
int luna_prov_ECDH_compute_key_ex(void *out, size_t outlen, const EC_KEY *peer_key,
                     const EC_KEY *eckey,
                     void *(*KDF) (const void *in, size_t inlen, void *out,
                                   size_t *outlen));
int luna_prov_EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);

#ifdef LUNA_OQS
/* ECX/ED wrapper functions */
typedef struct ecx_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    ECX_KEY_TYPE type;
    int selection;
    unsigned char *dhkem_ikm;
    size_t dhkem_ikmlen;
    /* added for luna hsm */
    luna_prov_key_ctx *lunakeyctx;
} PROV_ECX_GEN_CTX;

int luna_prov_ecx_dhkem_derive_private(struct ecx_gen_ctx *gctx,
        ECX_KEY *ecx, unsigned char *privout);

int luna_prov_ecx_sig_derive_private(struct ecx_gen_ctx *gctx,
        ECX_KEY *ecx, unsigned char *privout);

int luna_prov_ecx_check_private(const ECX_KEY *ecx);

int luna_prov_ecx_public_from_private(ECX_KEY *ecx);

int luna_prov_ecx_fix_public(ECX_KEY *ecx);

#define EDDSA_MAX_CONTEXT_STRING_LEN 255
#define EDDSA_PREHASH_OUTPUT_LEN 64

typedef struct {
    OSSL_LIB_CTX *libctx;
    ECX_KEY *key;

    /* The Algorithm Identifier of the signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* id indicating the EdDSA instance */
    int instance_id;

    unsigned int dom2_flag : 1;
    unsigned int prehash_flag : 1;

    /* indicates that a non-empty context string is required, as in Ed25519ctx */
    unsigned int context_string_flag : 1;

    unsigned char context_string[EDDSA_MAX_CONTEXT_STRING_LEN];
    size_t context_string_len;

    /* added for luna hsm */
    luna_prov_key_ctx *lunakeyctx;
} PROV_EDDSA_CTX;

int luna_prov_ed25519_sign(luna_prov_key_ctx *keyctx,
        unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen);

int luna_prov_ed448_sign(luna_prov_key_ctx *keyctx,
        unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen);

typedef struct {
    size_t keylen;
    ECX_KEY *key;
    ECX_KEY *peerkey;
    /* added for luna hsm */
    luna_prov_key_ctx *lunakeyctx;
} PROV_ECX_CTX;

int luna_prov_ecx_compute_key(luna_prov_key_ctx *keyctx,
                         unsigned char *secret, size_t *secretlen, size_t outlen);
#endif

/*
 * digest wrapper functions
 *
 * allow the provider to have finer control of its digest implementation; e.g.,
 *   1. use hardware or software?
 *   2. if software then low-level (opensl SHAxxx) or high-level (openssl EVP)?
 *   3. use single-part or multi-part?
 *   4. accumulate the input data or not?
 *
 * currently, the best option seems to be:
 *   software, low-level, single-part, accumulate
 */

/* TODO:revisit this later for full pqc hybrid in hardware:#define LUNAPROV_ENABLE_MD_WRAPPER 1 */

#ifdef LUNAPROV_ENABLE_MD_WRAPPER
typedef struct lunaprov_evp_md_st {
    int nid;
    int bits;
    const char *mdname;
    /* the rest is optional */
    const char *alias1;
    const char *alias2;
    const char *alias3;
    const char *alias4;
    EVP_MD *tmp_md;
    volatile int ref_count;
} LUNAPROV_EVP_MD;
#else
#define LUNAPROV_EVP_MD EVP_MD
#endif

LUNAPROV_EVP_MD *LUNAPROV_EVP_MD_fetch(void *libctx, const char *mdname, const char *params);
void LUNAPROV_EVP_MD_free(LUNAPROV_EVP_MD *md);
int LUNAPROV_EVP_MD_is_a(const LUNAPROV_EVP_MD *md, const char *mdname);
int LUNAPROV_EVP_MD_get_size(const LUNAPROV_EVP_MD *md);
int LUNAPROV_EVP_MD_get_nid(const LUNAPROV_EVP_MD *md);
int LUNAPROV_EVP_MD_up_ref(LUNAPROV_EVP_MD *md);
const char *LUNAPROV_EVP_MD_get0_name(const LUNAPROV_EVP_MD *md);
const OSSL_PARAM *LUNAPROV_EVP_MD_gettable_ctx_params(const LUNAPROV_EVP_MD *md);
const OSSL_PARAM *LUNAPROV_EVP_MD_settable_ctx_params(const LUNAPROV_EVP_MD *md);
int LUNAPROV_ossl_digest_get_approved_nid_with_sha1(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md, int sha1_allowed);
int LUNAPROV_ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md, int sha1_allowed);
int LUNAPROV_ossl_digest_is_allowed(OSSL_LIB_CTX *ctx, const LUNAPROV_EVP_MD *md);
const EVP_MD *LUNAPROV_EVP_MD_get_tmp_md(const LUNAPROV_EVP_MD *md);

#ifdef LUNAPROV_ENABLE_MD_WRAPPER
typedef struct lunaprov_evp_md_ctx_st {
    const LUNAPROV_EVP_MD *digest;
    unsigned char *mddata;
    size_t mdsize;
    EVP_MD_CTX *tmp_ctx;
} LUNAPROV_EVP_MD_CTX;
#else
#define LUNAPROV_EVP_MD_CTX EVP_MD_CTX
#endif

LUNAPROV_EVP_MD_CTX *LUNAPROV_EVP_MD_CTX_new(void);
void LUNAPROV_EVP_MD_CTX_free(LUNAPROV_EVP_MD_CTX *mdctx);
int LUNAPROV_EVP_MD_CTX_copy_ex(LUNAPROV_EVP_MD_CTX *out, const LUNAPROV_EVP_MD_CTX *in);
int LUNAPROV_EVP_DigestInit_ex2(LUNAPROV_EVP_MD_CTX *ctx, const LUNAPROV_EVP_MD *md, const OSSL_PARAM params[]);
int LUNAPROV_EVP_DigestUpdate(LUNAPROV_EVP_MD_CTX *ctx, const void *data, size_t count);
int LUNAPROV_EVP_DigestFinal_ex(LUNAPROV_EVP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen);
int LUNAPROV_EVP_MD_CTX_get_params(LUNAPROV_EVP_MD_CTX *ctx, OSSL_PARAM params[]);
int LUNAPROV_EVP_MD_CTX_set_params(LUNAPROV_EVP_MD_CTX *ctx, const OSSL_PARAM params[]);


/* for coverity misc */
#define LUNA_PROV_MAX_BUFFER ((64 * 1024) - 16) /* somewhat less than 64kB */

#endif


