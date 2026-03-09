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

#ifndef _LUNA_PROV_MINIMAL_H
#define _LUNA_PROV_MINIMAL_H

/* magic values */
#define LUNA_PROV_MAGIC_ZERO 0
#define LUNA_PROV_MAGIC_ERROR (-1)
#define LUNA_PROV_MAGIC_OK 0x60cafe06

/* debugging */
#ifdef NDEBUG
#define LUNA_PRINTF(a_)
#else
#define LUNA_PRINTF(a_) if (luna_getenv_LUNAPROV()) { printf("LUNA: %s: ", __func__); printf a_; }
#endif

/* luna provider key reason (i.e., was it generated new, or, read from a file old) */
typedef enum luna_prov_key_reason_en {
    LUNA_PROV_KEY_REASON_ZERO = 0,
    LUNA_PROV_KEY_REASON_GEN = 1,
    LUNA_PROV_KEY_REASON_SET_PARAMS = 2,
    LUNA_PROV_KEY_REASON_FROM_DATA = 3,
    LUNA_PROV_KEY_REASON_FROM_ENCODING = 4,
    LUNA_PROV_KEY_REASON_CREATE = 5
} luna_prov_key_reason;

/* forward reference to luna key context */
typedef struct luna_prov_key_ctx_st luna_prov_key_ctx;

/* forward reference to luna key info */
typedef struct luna_prov_keyinfo_st luna_prov_keyinfo;

/* luna provider flags (i.e., override CKA_TOKEN, etc) */
enum luna_prov_flags_en {
    LUNA_PROV_FLAGS_ZERO = 0x0,
    LUNA_PROV_FLAGS_SESSION_OBJECT = 0x10000,
    LUNA_PROV_FLAGS_SOFTWARE_OBJECT = 0x20000
};

#define LUNA_PROV_PKEY_PARAM_FLAGS "luna-prov-pkey-param-flags"

/* luna provider key bits */
typedef struct luna_prov_key_bits_st {
    int ok;
    int ndx;
    int is_kem;
    int is_hybrid;
    int is_composite;
    int is_delegated;
} luna_prov_key_bits;

/*
 * callback functions from OQS to LUNA
 *
 * return 0 on success, -1 for general error, other specific error
 */

#define LUNA_OQS_ERROR -1
#define LUNA_OQS_OK 0

/* callbacks for malloc and free */
luna_prov_key_ctx *LUNA_OQS_malloc_from_oqs(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_ecxgen(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_eddsa(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_eddsa_2(void *oqsxkey, const luna_prov_key_ctx *src_ctx);
luna_prov_key_ctx *LUNA_OQS_malloc_from_ecx(void *oqsxkey, const char *alg_name);
luna_prov_key_ctx *LUNA_OQS_malloc_from_ecx_2(void *oqsxkey, const luna_prov_key_ctx *src_ctx);
void LUNA_OQS_free(luna_prov_key_ctx *keyctx);
void LUNA_OQS_refresh_alg_name(luna_prov_key_ctx *keyctx, const char *alg_name);

/* callbacks to query luna capability */
int LUNA_OQS_QUERY_KEM_keypair(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_KEM_encaps(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_KEM_decaps(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_SIG_keypair(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_SIG_sign(luna_prov_key_ctx *keyctx);
int LUNA_OQS_QUERY_SIG_verify(luna_prov_key_ctx *keyctx);

/* callbacks for key encapsulation */
int LUNA_OQS_KEM_keypair(luna_prov_key_ctx *keyctx,
    luna_prov_key_bits *keybits);
int LUNA_OQS_KEM_encaps(luna_prov_key_ctx *keyctx,
    unsigned char *out, size_t *outlen,
    unsigned char *secret, size_t *secretlen);
int LUNA_OQS_KEM_decaps(luna_prov_key_ctx *keyctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);

/* callbacks for sign and verify */
int LUNA_OQS_SIG_keypair(luna_prov_key_ctx *keyctx,
    luna_prov_key_bits *keybits);
int LUNA_OQS_SIG_sign_ndx(luna_prov_key_ctx *keyctx,
    unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen,
    int ndx_in);
int LUNA_OQS_SIG_verify_ndx(luna_prov_key_ctx *keyctx,
    const unsigned char *tbs, size_t tbslen,
    const unsigned char *sig, size_t siglen,
    int ndx_in);

/* callbacks to notify about events related to keypair changes */
void LUNA_OQS_WRITEKEY_LOCK(luna_prov_key_ctx *keyctx, luna_prov_key_reason reason);
void LUNA_OQS_WRITEKEY_UNLOCK(luna_prov_key_ctx *keyctx);
void LUNA_OQS_READKEY_LOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo);
void LUNA_OQS_READKEY_UNLOCK(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *keyinfo);

/* misc */
#define LUNA_POINTER_ADD(_vp, _ofs)  ( (void*) ( ((unsigned char*)(_vp)) + (_ofs) ) )

/* query environment variable, faster */
void luna_getenv_LUNAPROV_init(void);
extern int luna_getenv_LUNAPROV_rc;
#define luna_getenv_LUNAPROV() (luna_getenv_LUNAPROV_rc == 1)

/* query misc */
int luna_prov_get_DelegateHwPqcKemEncapToSw(void);

/* for reverse keyshare */
int LUNA_PARAM_set_encoded_public_key(void *oqsxk, OSSL_PARAM *p, const void *val, size_t len);
int LUNA_PARAM_get_encoded_public_key(void *oqsxk, const OSSL_PARAM *p, void **val, size_t max_len, size_t *used_len);

/* algorithm names, according to openssl (as of openssl 3.5.1) */
#define LUNA_SN_ML_DSA_44 "id-ml-dsa-44" /* short name (aka internal name) */
#define LUNA_LN_ML_DSA_44 "ML-DSA-44" /* long name (aka external name) */
#define LUNA_ZN_ML_DSA_44 "MLDSA44" /* alternate external name */
#define LUNA_TN_ML_DSA_44 "mldsa44" /* IANA name (aka TLS name) */
#define LUNA_OID_ML_DSA_44 "2.16.840.1.101.3.4.3.17" /* oid name */

#define LUNA_SN_ML_DSA_65 "id-ml-dsa-65"
#define LUNA_LN_ML_DSA_65 "ML-DSA-65"
#define LUNA_ZN_ML_DSA_65 "MLDSA65"
#define LUNA_TN_ML_DSA_65 "mldsa65"
#define LUNA_OID_ML_DSA_65 "2.16.840.1.101.3.4.3.18"

#define LUNA_SN_ML_DSA_87 "id-ml-dsa-87"
#define LUNA_LN_ML_DSA_87 "ML-DSA-87"
#define LUNA_ZN_ML_DSA_87 "MLDSA87"
#define LUNA_TN_ML_DSA_87 "mldsa87"
#define LUNA_OID_ML_DSA_87 "2.16.840.1.101.3.4.3.19"

/* concatenate names: long + alternate + oid + short */
#define LUNA_PROV_NAMES_ML_DSA_XX(xx) LUNA_LN_ML_DSA_##xx ":" LUNA_ZN_ML_DSA_##xx ":" LUNA_OID_ML_DSA_##xx ":" LUNA_SN_ML_DSA_##xx
#define LUNA_PROV_NAMES_ML_DSA_44 LUNA_PROV_NAMES_ML_DSA_XX(44)
#define LUNA_PROV_NAMES_ML_DSA_65 LUNA_PROV_NAMES_ML_DSA_XX(65)
#define LUNA_PROV_NAMES_ML_DSA_87 LUNA_PROV_NAMES_ML_DSA_XX(87)

#if 0
/* name to be used for encoding/decoding (legacy is TLS name) */
#define LUNA_EN_ML_DSA_44 LUNA_TN_ML_DSA_44
#define LUNA_EN_ML_DSA_65 LUNA_TN_ML_DSA_65
#define LUNA_EN_ML_DSA_87 LUNA_TN_ML_DSA_87
#else
/* should be long name instead */
#define LUNA_EN_ML_DSA_44 LUNA_LN_ML_DSA_44
#define LUNA_EN_ML_DSA_65 LUNA_LN_ML_DSA_65
#define LUNA_EN_ML_DSA_87 LUNA_LN_ML_DSA_87
#endif

/* translate to short name, if possible */
const char *luna_short_name(const char *txt);
const char *luna_tls_name(const char *txt);

#endif // _LUNA_PROV_MINIMAL_H

