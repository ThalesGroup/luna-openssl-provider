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

#ifndef header_e_gem_compat_h
#define header_e_gem_compat_h

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/* Configure based on the openssl version number */
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL)

   /* Definitions for openssl version 1.1.0 and above */
   #define LUNA_OPENSSL_VERSION_TEXT OPENSSL_VERSION_TEXT
   #define LUNA_RAND_OpenSSL() RAND_OpenSSL()
   #define LUNA_EC_KEY_METHOD EC_KEY_METHOD
   #define LUNA_EC_KEY_OpenSSL() EC_KEY_OpenSSL()
   #define LUNA_EC_KEY_new_method(_eng) EC_KEY_new_method(_eng)

   /* key structure is hidden; i.e., RSA, DSA */
   #define LUNA_NO_RSA_STRUCTURE 1

   /* key structure is hidden; i.e., EC_KEY */
   #define LUNA_NO_EC_KEY_STRUCTURE 1

   /* return value is not void; i.e., rand_seed, rand_add */
   #define LUNA_RAND_RETURN_VALUE 1

   /* EC_KEY_* functions instead of ECDSA_* functions */
   #define LUNA_EC_KEY_FUNCTIONS 1

   /* EC_KEY_METHOD* functions instead of ECDSA_METHOD* functions */
   #define LUNA_EC_KEY_METHOD_FUNCTIONS 1

   /* key structure is hidden; i.e., EC_KEY_SIG */
   #define LUNA_NO_EC_KEY_SIG_STRUCTURE 1

   /* asn1 structure is hidden; i.e., ASN1_OBJECT */
   #define LUNA_NO_ASN1_STRUCTURE 1

   /* pkey structure is hidden; i.e., EVP_PKEY */
   #define LUNA_NO_PKEY_STRUCTURE 1

   #ifdef LUNA_OSSL_PKEY_METHS
      #define LUNA_RSA_USE_EVP_PKEY_METHS 1
      /* intended for 3.0.0 only, however, it seems that we should include these for 1.1.1 too */
      #define LUNA_DSA_USE_EVP_PKEY_METHS 1
      #define LUNA_RSA_USE_EVP_ASN1_METHS 1 /* for rsa keygen issues */
      #define LUNA_DSA_USE_EVP_ASN1_METHS 1 /* for dsa keygen issues */
      #if 1
      /* for EC not appearing in capabilities */
      #define LUNA_EC_USE_EVP_PKEY_METHS 1
      #define LUNA_EC_USE_EVP_ASN1_METHS 1
      #endif
   #endif

#else /* OPENSSL_VERSION_NUMBER */

   /* Definitions for openssl version older than 1.1.0 */
   #define LUNA_OPENSSL_VERSION_TEXT OPENSSL_VERSION_PTEXT
   #define LUNA_RAND_OpenSSL() RAND_SSLeay()
   #define LUNA_EC_KEY_METHOD ECDSA_METHOD
   #define LUNA_EC_KEY_OpenSSL() ECDSA_OpenSSL()
   #define LUNA_EC_KEY_new_method(_eng) EC_KEY_new()

   #if (OPENSSL_VERSION_NUMBER >= 0x10002000L)

      /* key structure is hidden; i.e., EC_KEY */
      /* FIXME: not 100% true: #define LUNA_NO_EC_KEY_STRUCTURE 1 */

      /* FIXME: it would be nice to define LUNA_RSA_USE_EVP_PKEY_METHS for openssl 1.0.2 */
      /* FIXME: however, this assumes the run-time version of libcrypto is compatible with the compile-time version of engine */

   #endif

#endif /* OPENSSL_VERSION_NUMBER */



#ifdef LUNA_NO_RSA_STRUCTURE

#define LUNA_RSA_METH_SET_DEFAULT(_dest) { \
   const RSA_METHOD *method = RSA_PKCS1_OpenSSL(); \
   RSA_meth_set0_app_data((_dest), NULL); \
   RSA_meth_set_init((_dest), RSA_meth_get_init(method)); \
   RSA_meth_set_finish((_dest), RSA_meth_get_finish(method)); \
   RSA_meth_set_sign((_dest), NULL); \
   RSA_meth_set_verify((_dest), NULL); \
   RSA_meth_set_keygen((_dest), NULL); \
   RSA_meth_set_multi_prime_keygen((_dest), NULL); \
   RSA_meth_set_mod_exp((_dest), RSA_meth_get_mod_exp(method)); \
   RSA_meth_set_bn_mod_exp((_dest), RSA_meth_get_bn_mod_exp(method)); \
   RSA_meth_set_pub_dec((_dest), luna_rsa_pub_dec); \
      saved_rsa_pub_dec = RSA_meth_get_pub_dec(method); \
   RSA_meth_set_pub_enc((_dest), luna_rsa_pub_enc); \
      saved_rsa_pub_enc = RSA_meth_get_pub_enc(method); \
   RSA_meth_set_priv_enc((_dest), luna_rsa_priv_enc); \
      saved_rsa_priv_enc = RSA_meth_get_priv_enc(method); \
   RSA_meth_set_priv_dec((_dest), luna_rsa_priv_dec); \
      saved_rsa_priv_dec = RSA_meth_get_priv_dec(method); \
   }

#define LUNA_RSA_METH_SET_KEYGEN_EX(_dest, _src) { \
   RSA_meth_set_keygen((_dest), (_src)); \
   }

#define LUNA_RSA_METH_OR_FLAGS(_meth, _value) { \
   RSA_meth_set_flags((_meth), RSA_meth_get_flags(_meth) | (_value)); \
   }

#define LUNA_RSA_METH_GET_FLAGS(_meth) RSA_meth_get_flags((RSA_METHOD *)(_meth))

#define LUNA_DSA_METH_SET_DEFAULT(_dest) { \
   const DSA_METHOD *method = DSA_OpenSSL(); \
   DSA_meth_set_mod_exp((_dest), DSA_meth_get_mod_exp(method)); \
   DSA_meth_set_bn_mod_exp((_dest), DSA_meth_get_bn_mod_exp(method)); \
   DSA_meth_set_sign((_dest), luna_dsa_do_sign); \
      saved_dsa_do_sign = DSA_meth_get_sign(method); \
   DSA_meth_set_sign_setup((_dest), luna_dsa_sign_setup); \
      saved_dsa_sign_setup = DSA_meth_get_sign_setup(method); \
   DSA_meth_set_verify((_dest), luna_dsa_do_verify); \
      saved_dsa_do_verify = DSA_meth_get_verify(method); \
   }

#define LUNA_DSA_METH_SET_KEYGEN_EX(_dest, _src) { \
   DSA_meth_set_keygen((_dest), (_src)); \
   }

#define LUNA_DSA_METH_OR_FLAGS(_meth, _value) { \
   DSA_meth_set_flags((_meth), DSA_meth_get_flags(_meth) | (_value)); \
   }

static BIGNUM *LUNA_RSA_GET_n(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_e(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_d(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_p(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_q(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_dmp1(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_dmq1(RSA *rsa);
static BIGNUM *LUNA_RSA_GET_iqmp(RSA *rsa);
#define LUNA_RSA_GET_FLAGS(_rsa) (RSA_test_flags(_rsa, 0xffffffff))
#define LUNA_RSA_OR_FLAGS(_rsa, _flags) { RSA_set_flags((_rsa), (_flags)); }

static BIGNUM *LUNA_DSA_GET_p(DSA *dsa);
static BIGNUM *LUNA_DSA_GET_q(DSA *dsa);
static BIGNUM *LUNA_DSA_GET_g(DSA *dsa);
static BIGNUM *LUNA_DSA_GET_pub_key(DSA *dsa);
static BIGNUM *LUNA_DSA_GET_priv_key(DSA *dsa);
#define LUNA_DSA_GET_FLAGS(_dsa) (DSA_test_flags(_dsa, 0xffffffff))
#define LUNA_DSA_OR_FLAGS(_dsa, _flags) { DSA_set_flags((_dsa), (_flags)); }
static BIGNUM *LUNA_DSA_SIG_GET_r(const DSA_SIG *sig);
static BIGNUM *LUNA_DSA_SIG_GET_s(const DSA_SIG *sig);

#else /* LUNA_NO_RSA_STRUCTURE */

#define LUNA_RSA_METH_SET_DEFAULT(_dest) { \
   const RSA_METHOD *method = RSA_PKCS1_SSLeay(); \
   (_dest)->rsa_mod_exp = method->rsa_mod_exp; \
   (_dest)->bn_mod_exp = method->bn_mod_exp; \
   (_dest)->rsa_pub_dec = luna_rsa_pub_dec; \
      saved_rsa_pub_dec = method->rsa_pub_dec; \
   (_dest)->rsa_pub_enc = luna_rsa_pub_enc; \
      saved_rsa_pub_enc = method->rsa_pub_enc; \
   (_dest)->rsa_priv_enc = luna_rsa_priv_enc; \
      saved_rsa_priv_enc = method->rsa_priv_enc; \
   (_dest)->rsa_priv_dec = luna_rsa_priv_dec; \
      saved_rsa_priv_dec = method->rsa_priv_dec; \
   }

#define LUNA_RSA_METH_SET_KEYGEN_EX(_dest, _src) { \
   (_dest)->rsa_keygen = (_src); \
   }

#define LUNA_RSA_METH_OR_FLAGS(_meth, _value) { \
   (_meth)->flags |= (_value); \
   }

#define LUNA_DSA_METH_SET_DEFAULT(_dest) { \
   const DSA_METHOD *method = DSA_OpenSSL(); \
   (_dest)->dsa_mod_exp = method->dsa_mod_exp; \
   (_dest)->bn_mod_exp = method->bn_mod_exp; \
   (_dest)->dsa_do_sign = luna_dsa_do_sign; \
      saved_dsa_do_sign = method->dsa_do_sign; \
   (_dest)->dsa_sign_setup = luna_dsa_sign_setup; \
      saved_dsa_sign_setup = method->dsa_sign_setup; \
   (_dest)->dsa_do_verify = luna_dsa_do_verify; \
      saved_dsa_do_verify = method->dsa_do_verify; \
   }

#define LUNA_DSA_METH_SET_KEYGEN_EX(_dest, _src) { \
   (_dest)->dsa_keygen = (_src); \
   }

#define LUNA_DSA_METH_OR_FLAGS(_meth, _value) { \
   (_meth)->flags |= (_value); \
   }

#define LUNA_RSA_GET_n(_rsa) ((_rsa)->n)
#define LUNA_RSA_GET_e(_rsa) ((_rsa)->e)
#define LUNA_RSA_GET_d(_rsa) ((_rsa)->d)
#define LUNA_RSA_GET_p(_rsa) ((_rsa)->p)
#define LUNA_RSA_GET_q(_rsa) ((_rsa)->q)
#define LUNA_RSA_GET_dmp1(_rsa) ((_rsa)->dmp1)
#define LUNA_RSA_GET_dmq1(_rsa) ((_rsa)->dmq1)
#define LUNA_RSA_GET_iqmp(_rsa) ((_rsa)->iqmp)
#define LUNA_RSA_GET_FLAGS(_rsa) ((_rsa)->flags)
#define LUNA_RSA_OR_FLAGS(_rsa, _flags) { (_rsa)->flags |= (_flags); }

#define LUNA_DSA_GET_p(_dsa) ((_dsa)->p)
#define LUNA_DSA_GET_q(_dsa) ((_dsa)->q)
#define LUNA_DSA_GET_g(_dsa) ((_dsa)->g)
#define LUNA_DSA_GET_pub_key(_dsa) ((_dsa)->pub_key)
#define LUNA_DSA_GET_priv_key(_dsa) ((_dsa)->priv_key)
#define LUNA_DSA_GET_FLAGS(_dsa) ((_dsa)->flags)
#define LUNA_DSA_OR_FLAGS(_dsa, _flags) { (_dsa)->flags |= (_flags); }
#define LUNA_DSA_SIG_GET_r(_sig) ((_sig)->r)
#define LUNA_DSA_SIG_GET_s(_sig) ((_sig)->s)

#endif /* LUNA_NO_RSA_STRUCTURE */



#ifdef LUNA_EC_KEY_FUNCTIONS
#define LUNA_ENGINE_set_ECDSA(_eng, _meth) ENGINE_set_EC((_eng), (_meth))
#define LUNA_EC_KEY_get_ex_data(_key, _ex) EC_KEY_get_ex_data((_key), (_ex))
#define LUNA_EC_KEY_set_ex_data(_key, _ex, _val) EC_KEY_set_ex_data((_key), (_ex), (_val))
#define LUNA_EC_KEY_get_ex_new_index(_name) EC_KEY_get_ex_new_index(0, (_name), 0, 0, 0)
#else /* LUNA_EC_KEY_FUNCTIONS */
#define LUNA_ENGINE_set_ECDSA(_eng, _meth) ENGINE_set_ECDSA((_eng), (_meth))
#define LUNA_EC_KEY_get_ex_data(_key, _ex) ECDSA_get_ex_data((_key), (_ex))
#define LUNA_EC_KEY_set_ex_data(_key, _ex, _val) ECDSA_set_ex_data((_key), (_ex), (_val))
#define LUNA_EC_KEY_get_ex_new_index(_name) ECDSA_get_ex_new_index(0, (_name), 0, 0, 0)
#endif /* LUNA_EC_KEY_FUNCTIONS */



#ifdef LUNA_NO_EC_KEY_STRUCTURE

#ifdef LUNA_EC_KEY_METHOD_FUNCTIONS
#define LUNA_EC_KEY_METH_SET_DEFAULT(_dest) { \
   const LUNA_EC_KEY_METHOD *method = LUNA_EC_KEY_OpenSSL(); \
   EC_KEY_METHOD_set_sign((_dest), luna_ecdsa_sign, luna_ecdsa_sign_setup, luna_ecdsa_do_sign); \
      EC_KEY_METHOD_get_sign(method, &saved_ecdsa_sign, &saved_ecdsa_sign_setup, &saved_ecdsa_do_sign); \
   EC_KEY_METHOD_set_verify((_dest), luna_ecdsa_verify, luna_ecdsa_do_verify); \
      EC_KEY_METHOD_get_verify(method, NULL, &saved_ecdsa_do_verify); \
   EC_KEY_METHOD_set_keygen((_dest), luna_ecdsa_keygen); \
      EC_KEY_METHOD_get_keygen(method, &saved_ecdsa_keygen); \
   EC_KEY_METHOD_set_compute_key((_dest), luna_ecdsa_compute_key); \
      EC_KEY_METHOD_get_compute_key(method, &saved_ecdsa_compute_key); \
   }
#define LUNA_EC_KEY_METH_OR_FLAGS(_meth, _flags) { \
   /* FIXME: EC_KEY_METHOD_set_flags((_meth), (_flags)); */ \
   }
#else /* LUNA_EC_KEY_METHOD_FUNCTIONS */
#define LUNA_EC_KEY_METH_SET_DEFAULT(_dest) { \
   const LUNA_EC_KEY_METHOD *method = LUNA_EC_KEY_OpenSSL(); \
   ECDSA_METHOD_set_sign_setup((_dest), luna_ecdsa_sign_setup); \
   ECDSA_METHOD_set_sign((_dest), luna_ecdsa_do_sign); \
      /* FIXME: ECDSA_METHOD_get_sign(method, &saved_ecdsa_sign, &saved_ecdsa_sign_setup, &saved_ecdsa_do_sign); */ \
   ECDSA_METHOD_set_verify((_dest), luna_ecdsa_do_verify); \
      /* FIXME: ECDSA_METHOD_get_verify(method, NULL, &saved_ecdsa_do_verify); */ \
   /* FIXME: ECDSA_METHOD_set_keygen((_dest), luna_ecdsa_keygen); */ \
      /* FIXME: ECDSA_METHOD_get_keygen(method, &saved_ecdsa_keygen); */ \
   /* FIXME: ECDSA_METHOD_set_compute_key((_dest), luna_ecdsa_compute_key); */ \
      /* FIXME: ECDSA_METHOD_get_compute_key(method, &saved_ecdsa_compute_key); */ \
   }
#define LUNA_EC_KEY_METH_OR_FLAGS(_meth, _flags) { \
   ECDSA_METHOD_set_flags((_meth), (_flags)); \
   }
#endif /* LUNA_EC_KEY_METHOD_FUNCTIONS */

#ifdef LUNA_EC_KEY_FUNCTIONS
#define LUNA_EC_KEY_GET_FLAGS(_dsa) EC_KEY_get_flags(_dsa)
#define LUNA_EC_KEY_OR_FLAGS(_dsa, _flags) { EC_KEY_set_flags((_dsa), (_flags)); }
#else /* LUNA_EC_KEY_FUNCTIONS */
#define LUNA_EC_KEY_GET_FLAGS(_dsa) EC_KEY_get_flags(_dsa)
#define LUNA_EC_KEY_OR_FLAGS(_dsa, _flags) { EC_KEY_set_flags((_dsa), (_flags)); }
#endif /* LUNA_EC_KEY_FUNCTIONS */

#else /* LUNA_NO_EC_KEY_STRUCTURE */

#include <openssl/ec_lcl.h> /* internal */
#include <openssl/ecs_locl.h> /* internal */

#define LUNA_EC_KEY_METH_SET_DEFAULT(_dest) { \
   const LUNA_EC_KEY_METHOD *method = LUNA_EC_KEY_OpenSSL(); \
   (_dest)->ecdsa_do_sign = luna_ecdsa_do_sign;  \
      saved_ecdsa_do_sign = method->ecdsa_do_sign; \
   (_dest)->ecdsa_sign_setup = luna_ecdsa_sign_setup; \
      saved_ecdsa_sign_setup = method->ecdsa_sign_setup; \
   (_dest)->ecdsa_do_verify = luna_ecdsa_do_verify; \
      saved_ecdsa_do_verify = method->ecdsa_do_verify; \
   }
#define LUNA_EC_KEY_METH_OR_FLAGS(_meth, _flags) { (_meth)->flags |= (_flags); }

#define LUNA_EC_KEY_GET_FLAGS(_dsa) ((_dsa)->flags)
#define LUNA_EC_KEY_OR_FLAGS(_dsa, _flags) { (_dsa)->flags |= (_flags); }

#endif /* LUNA_NO_EC_KEY_STRUCTURE */



#ifdef LUNA_NO_EC_KEY_SIG_STRUCTURE
static BIGNUM *LUNA_EC_KEY_SIG_GET_r(const ECDSA_SIG *sig);
static BIGNUM *LUNA_EC_KEY_SIG_GET_s(const ECDSA_SIG *sig);
#else /* LUNA_NO_EC_KEY_SIG_STRUCTURE */
#define LUNA_EC_KEY_SIG_GET_r(_sig) ((_sig)->r)
#define LUNA_EC_KEY_SIG_GET_s(_sig) ((_sig)->s)
#endif /* LUNA_NO_EC_KEY_SIG_STRUCTURE */



/* Common functions that are not inline */
static int LUNA_RSA_SET_n_e_d(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d);
static int LUNA_RSA_SET_p_q(RSA *rsa, BIGNUM *p, BIGNUM *q);
static int LUNA_RSA_SET_dmp1_dmq1_iqmp(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
static int LUNA_DSA_SET_p_q_g(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g);
static int LUNA_DSA_SET_pub_priv(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key);
static int LUNA_DSA_SIG_SET_r_s(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
static int LUNA_EC_KEY_SIG_SET_r_s(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
static void *LUNA_OPENSSL_zalloc(size_t num);
static void LUNA_OPENSSL_free(void *ptr);
static EVP_MD_CTX *LUNA_EVP_MD_CTX_new(void);
static void LUNA_EVP_MD_CTX_free(EVP_MD_CTX *pctx);
static RSA_METHOD *LUNA_RSA_meth_new(const char *name, int flags);
static void LUNA_RSA_meth_free(RSA_METHOD *meth);
static DSA_METHOD *LUNA_DSA_meth_new(const char *name, int flags);
static void LUNA_DSA_meth_free(DSA_METHOD *meth);
static LUNA_EC_KEY_METHOD *LUNA_EC_KEY_meth_new(const char *name, int flags);
static void LUNA_EC_KEY_meth_free(LUNA_EC_KEY_METHOD *meth);
static const EC_GROUP *LUNA_EC_KEY_get0_group(const EC_KEY *key);
static const BIGNUM *LUNA_EC_GROUP_get0_order(const EC_GROUP *group, BIGNUM **p_alloc);
static const BIGNUM *LUNA_EC_KEY_get0_private_key(const EC_KEY *key);
static const EC_POINT *LUNA_EC_KEY_get0_public_key(const EC_KEY *key);
static int LUNA_EC_KEY_set_private_key(EC_KEY *key, BIGNUM *priv_key);

/* Extra functions that are required by sautil */
static int LUNA_ASN1_OBJECT_GET_length(ASN1_OBJECT *asn1);
static const unsigned char *LUNA_ASN1_OBJECT_GET_data(ASN1_OBJECT *asn1);

/* Extra functions to get the key without incrementing reference count */
static RSA *LUNA_EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
static DSA *LUNA_EVP_PKEY_get0_DSA(EVP_PKEY *pkey);
static EC_KEY *LUNA_EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

/* Extra functions that are required by engine, sautil, etc */
static size_t LUNA_EC_GROUP_get_field_len(const EC_GROUP *group);
static int LUNA_o2i_ECPublicKey(EC_KEY **dsa, const unsigned char *in, const size_t inlen);
static int LUNA_i2o_ECPublicKey(const EC_KEY *dsa, unsigned char **pout, unsigned char **pout2, int *plen2);
static int LUNA_RSA_copy_from_pkey(RSA *rsa, const EVP_PKEY *pkey);
static int LUNA_DSA_copy_from_pkey(DSA *dsa, const EVP_PKEY *pkey);
static int LUNA_EC_copy_from_pkey(EC_KEY *dsa, const EVP_PKEY *pkey);

/* Sanity test */
/* NOTE: do not try combinations that fail in mysterious ways (openssl internal errors) */
#if defined(LUNA_RSA_USE_EVP_ASN1_METHS) && !defined(LUNA_RSA_USE_EVP_PKEY_METHS)
#error "rsa sanity test failed"
#endif
#if defined(LUNA_DSA_USE_EVP_ASN1_METHS) && !defined(LUNA_DSA_USE_EVP_PKEY_METHS)
#error "dsa sanity test failed"
#endif
#if defined(LUNA_EC_USE_EVP_ASN1_METHS) && !defined(LUNA_EC_USE_EVP_PKEY_METHS)
#error "ec sanity test failed"
#endif

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

#endif /* header_e_gem_compat_h */
