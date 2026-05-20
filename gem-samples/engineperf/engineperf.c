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

#define OPENSSL_SUPPRESS_DEPRECATED
#include "engineperf.h"
#include "e_gem.h"
#include "e_gem_compat.h"

/* if set then do unusually high stressing; eg continue testing despite errors, which hinders debugging */
#undef ENGINEPERF_STRESS

/* assert version is 1.0.0 or higher */
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
#error "BUG: this application requires openssl version 1.0.0 or higher"
#endif

/* It is no longer necessary to set locking callbacks in a multi-threaded environment. */
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#define ENGINEPERF_NO_LOCKING_CALLBACKS 1
#endif

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/* For CodeWarrior */
#if 0
}
#endif

/*****************************************************************************/

static void engineperf_exit(int exitcode);
static void engineperf_err_flush(void);
static int engineperf_SHA256(const unsigned char *d, size_t n, unsigned char *md);
static int engineperf_FIPS_mode(void);
static int engineperf_FIPS_mode_set(int r);

/* defines... */

#define LOCAL_APP_NAME "engineperf"
#define LOCAL_APP_VERSION "v4.1.0-101"
#define LOCAL_APP_COPYRIGHT "2009-2026"
#define LOCAL_MAX_STRING (255)  /* bytes */
#define LOCAL_MAX_BUFFER (8192) /* bytes */
#define LOCAL_MAX_THREAD (15)   /* 15 = apache worker model */
#define LOCAL_MAX_RAND (512)    /* 512 = something apache does */
#define LOCAL_DEFAULT_THREADS (1)
#define LOCAL_DEFAULT_SECONDS (5)
#undef TRY_PKCS11SO_ENGINE
/*#define TRY_PKCS11SO_ENGINE  (1)*/
#define ENGINE_LUNACA3_ID "gem" /* lowercase is the convention */
#define LOCAL_XOR_2WAY(_a, _b) ((_a) ^ (_b))

/* typedefs... */

/* crypto flavor */
typedef enum crypto_flavor_e {
   crypto_flavor_null = 0,
   crypto_flavor_priv_enc,    /* private encrypt followed by public decrypt (user-defined padding, raw data) */
   crypto_flavor_priv_dec,    /* public encrypt followed by private decrypt (user-defined padding, raw data) */
   crypto_flavor_oaep_sha1,   /* public encrypt followed by private decrypt (RSA PKCS OAEP padding, SHA1 MGF) */
   crypto_flavor_sign,        /* sign followed by verify (RSA_PKCS1/DSA/EC, user-supplied digest) */
   crypto_flavor_digest_sign, /* EVP PKEY digest sign followed by digest verify (RSA_PKCS1/DSA/EC, user-defined digest) */
   crypto_flavor_pkcs_pss,    /* EVP PKEY PKCS PSS sign followed by verify (RSA PKCS PSS padding, user-defined MGF) */
   crypto_flavor_pkcs_oaep,   /* EVP PKEY PKCS OAEP encrypt followed by decrypt (RSA PKCS OAEP padding, user-defined MGF) */
   crypto_flavor_last         /* end of list */
} crypto_flavor_t;

#define IS_EVP_FLAVOR(_flavor) ( ((_flavor) >= crypto_flavor_digest_sign) && ((_flavor) <= crypto_flavor_pkcs_oaep) )
#define IS_EVP_TESTCASE(_flavor, _pkey) ( ((_pkey) != NULL) && IS_EVP_FLAVOR(_flavor) )

/* command line */
typedef struct engineperf_s {
   int foo;
   int have_enginearg;
   int have_login;
   int want_software;
   int want_haGet;
   int want_haRecover;
   int want_no_cleanup;
   int load_private;
   int want_pkcs11;
   int pk11_slot;
   int error_login;
   int only_rsasign;
   int want_fips;
   int want_engine_impl;
   int want_mgf1_vary;
   int want_rsa_oaep_label;

   /* normally select one of these */
   int want_engine;
   int want_provider;

   unsigned threads;
   unsigned seconds;
   unsigned set_default;
   char enginearg[LOCAL_MAX_STRING + 1];
   char login[LOCAL_MAX_STRING + 1];
   char providers[LOCAL_MAX_STRING + 1];
} engineperf_t;

#define ENGINEPERF_T_INIT \
   { 0 }

/* performance gathering */
typedef struct luna_perf_s {
   int foo;
   LUNA_TIME_UNIT_T min;
   LUNA_TIME_UNIT_T max;
   LUNA_TIME_UNIT_T payload;
} luna_perf_t;

#define LUNA_PERF_T_INIT \
   { 0, 0, 0, 0 }

/* stop watch */
typedef struct luna_stopwatch_s {
   int foo;
   LUNA_TIME_UNIT_T t0;
   LUNA_TIME_UNIT_T t1;
   LUNA_TIME_UNIT_T seconds;
} luna_stopwatch_t;

#define LUNA_STOPWATCH_T_INIT \
   { 0, 0, 0, 0 }

static void luna_stopwatch_start2(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T seconds);
static void luna_stopwatch_stop(luna_stopwatch_t *lsw);
static int luna_stopwatch_update(luna_stopwatch_t *lsw);
static LUNA_TIME_UNIT_T luna_stopwatch_usec(luna_stopwatch_t *lsw);

#if !defined(LUNA_OSSL3)
typedef struct { int dummy; } OSSL_PROVIDER;
#endif

/* foo_key_t */
typedef struct foo_key_s {
   int foo;
   ENGINE *e;
   OSSL_PROVIDER *prov;
   unsigned sig_size;
#ifndef OPENSSL_NO_RSA
   RSA *rsa;
   EVP_PKEY *pkey_rsa;
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
   DSA *dsa;
   EVP_PKEY *pkey_dsa;
#endif /* OPENSSL_NO_DSA */
#ifdef LUNA_OSSL_ECDSA
   EC_KEY *ec;
   EVP_PKEY *pkey_ec;
#endif /* LUNA_OSSL_ECDSA */
} foo_key_t;

#define FOO_KEY_T_INIT \
   { 0 }

static void luna_stopwatch_report(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T report_size, LUNA_TIME_UNIT_T loops,
                                  int want_hz, const char *context);

static void luna_stopwatch_report_wrapper(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T report_size, LUNA_TIME_UNIT_T loops,
                                          int want_hz, int want_verify, const char *keytype, foo_key_t *fkey,
                                          crypto_flavor_t flavor);

/* foo_thread_t */
typedef void (*foo_thread_f)(void *context);

typedef struct foo_thread_s {
   int foo;
   volatile int have_init;
   volatile int want_loops;
   volatile int want_fini;
   volatile int have_fini;
   volatile int want_hush;
   volatile LUNA_TIME_UNIT_T loops;
   foo_key_t *fkey;
   int want_verify;
   const char *keytype;
   crypto_flavor_t flavor;
   foo_thread_f f;
} foo_thread_t;

#define FOO_THREAD_T_INIT \
   { 0 }

static int foo_thread_init(foo_thread_t *pt, foo_thread_f f, foo_key_t *fkey, int want_verify, const char *keytype,
                           crypto_flavor_t flavor);
static void foo_thread_msleep(unsigned millisecs);
static void engineperf_mt_init(void);
static void engineperf_mt_fini(void);

/* misc for coverity */
static char *engineperf_strncpy(char *dest, const char *src, size_t n);
static int engineperf_sscanf_s(const char *str, const char *format, char *dest, size_t maxlen);

/* data... */

static engineperf_t local_param = ENGINEPERF_T_INIT;

/* functions... */

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_preferred_id"

/* get preferred engine id */
static const char *engineperf_preferred_id(void) {
#ifdef TRY_PKCS11SO_ENGINE
   if (local_param.want_pkcs11) {
      return "pkcs11";
   }
#endif /* #ifdef TRY_PKCS11SO_ENGINE */

   return ENGINE_LUNACA3_ID;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_engine_get"

/* get reference to engine */
static ENGINE *engineperf_engine_get(void) {
   ENGINE *e = NULL;

   static int loaded_engines = 0;
   static int loaded_error = 0;

   if (loaded_error) {
      return NULL;
   }

   if (!loaded_engines) {
      ENGINE_load_builtin_engines();
      loaded_engines = 1;
   }

   /* ENGINE_by_id: increment structural reference count */
   if ((e = ENGINE_by_id(engineperf_preferred_id())) == NULL) {
      e = ENGINE_by_id("dynamic");
      if (e != NULL) {
         if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engineperf_preferred_id(), 0) ||
             !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
         }
      }

      if (e == NULL) {
         loaded_error = 1;
         return NULL;
      }
   }

   return e; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_engine_load"

/* load openssl engine */
static const char *engineperf_engine_load(ENGINE **eout) {
   ENGINE *e = NULL;
   int rc = 0;
   const char *eid = NULL;

   e = engineperf_engine_get();
   if (e == NULL) {
      return "ENGINE_by_id failed";
   }

   eid = ENGINE_get_id(e);
   if ((eid == NULL) || (strcmp(eid, ENGINE_LUNACA3_ID) && strcmp(eid, "pkcs11"))) {
      ENGINE_free(e);
      return "ENGINE_get_name failed";
   }

   fprintf(stdout, "NOTE: using engine id \"%s\". \n", (char *)eid);

   /* let the engine know this app is non-forking (DisableCheckFinalize=1). */
   if (strcmp(eid, ENGINE_LUNACA3_ID) == 0) {
      rc = ENGINE_ctrl_cmd_string(e, "DisableCheckFinalize", "1", 0);
      if (rc != 1) {
         fprintf(stderr, "WARNING: failed to set \"DisableCheckFinalize=1\". \n");
      }
   }

   /* let the engine know which slot number (PK11_CMD_SLOT=UINT). */
   if (strcmp(eid, "pkcs11") == 0) {
      char buf[64];
      sprintf(buf, "%u", (unsigned)local_param.pk11_slot);
      rc = ENGINE_ctrl_cmd_string(e, "SLOT", buf, 0);
      if (rc != 1) {
         fprintf(stderr, "WARNING: failed to set \"SLOT=%u\". \n", (unsigned)local_param.pk11_slot);
      }
   }

   /* ENGINE_set_default after engines configured */
   if (ENGINE_set_default(e, local_param.set_default) != 1) {
      ENGINE_free(e);
      return "ENGINE_set_default failed";
   }

   ENGINE_free(e);
   *eout = e;

   /* ENGINE_init: increment functional reference count AND increment structural reference count */
   if (ENGINE_init(e) != 1) {
      return "ENGINE_init failed";
   }

   return NULL; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_engine_unload"

/* unload openssl engine */
static const char *engineperf_engine_unload(ENGINE *eout) {
   /* ENGINE_finish: decrement functional reference count AND decrement structural reference count */
   if (ENGINE_finish(eout) != 1) {
      return "ENGINE_finish failed";
   }

   return NULL; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_engine_connect"

/* connect/disconnect to hsm */
static void engineperf_engine_connect(foo_key_t *fkey, int want_disconnect) {
   int rc = 0;
   char buf[LOCAL_MAX_STRING];

   memset(buf, 0, sizeof(buf));

   if (local_param.want_software) {
      return;
   }

   if (want_disconnect) {
      if (local_param.have_login) {
         rc = ENGINE_ctrl_cmd_string(fkey->e, "logout", local_param.login, 0);
      }
   } else {
      if (local_param.have_enginearg) {
         rc = ENGINE_ctrl_cmd_string(fkey->e, "enginearg", local_param.enginearg, 0);
      }

      if (local_param.have_login) {
         rc = ENGINE_ctrl_cmd_string(fkey->e, "login", local_param.login, 0);
      }
   }

   if (rc != 1) {
      return;
   }

   return;
}

#if defined(LUNA_OSSL3)

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_provider_load"

static OSSL_PROVIDER *fips = NULL;
static OSSL_PROVIDER *dflt = NULL; /* default provider */
static OSSL_PROVIDER *base = NULL;
static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *nullprov = NULL; /* null provider wipes out basic algorithms { RNG, SHA2, etc } */

/* load openssl3 provider */
static const char *engineperf_provider_load(OSSL_PROVIDER **prov) {
   OSSL_PROVIDER *luna = NULL;

   fprintf(stdout, "NOTE: using providers \"%s\". \n", (char *)local_param.providers);

   /* TODO: loading null provider (and setting libctx) is experimental */
   if (strstr(local_param.providers, "null") != NULL) {
      nullprov = OSSL_PROVIDER_load(NULL, "null");
      if (nullprov == NULL) {
         return "Failed to load null provider";
      }
      libctx = OSSL_LIB_CTX_new();
      if (libctx == NULL) {
         return "Failed to create library context";
      }
   }

   /* load multiple providers, lunaprov first */
   if (strstr(local_param.providers, "lunaprov") != NULL) {
      luna = OSSL_PROVIDER_load(libctx, "lunaprov");
      if (luna == NULL) {
         return "Failed to load lunaprov provider";
      }
      *prov = luna;
   }

   /* load fips provider */
   if (strstr(local_param.providers, "fips") != NULL) {
      fips = OSSL_PROVIDER_load(libctx, "fips");
      if (fips == NULL) {
         return "Failed to load fips provider";
      }
   }

   /* load default provider */
   if (strstr(local_param.providers, "default") != NULL) {
      dflt = OSSL_PROVIDER_load(libctx, "default");
      if (dflt == NULL) {
         return "Failed to load default provider";
      }
   }

   /* load base provider */
   if (strstr(local_param.providers, "base") != NULL) {
      base = OSSL_PROVIDER_load(libctx, "base");
      if (base == NULL) {
         return "Failed to load base provider";
      }
   }

   /* TODO: engineperf needs EVP_set_default_properties */
   if (luna != NULL) {
      if (EVP_set_default_properties(libctx, "?provider=lunaprov") <= 0) {
         return "Failed to load base provider";
      }
   }

   return NULL; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_provider_unload"

/* unload openssl3 provider */
static const char *engineperf_provider_unload(OSSL_PROVIDER *prov) {
   if (prov)
      OSSL_PROVIDER_unload(prov);
   if (fips)
      OSSL_PROVIDER_unload(fips);
   if (dflt)
      OSSL_PROVIDER_unload(dflt);
   if (base)
      OSSL_PROVIDER_unload(base);
   fips = dflt = base = NULL;
   return NULL; /* success */
}

#else /* LUNA_OSSL3 */

#define NO_PROVIDERS_SZ "providers not available in openssl version less than 3.0.0"

static const char *engineperf_provider_load(OSSL_PROVIDER **prov) {
   return NO_PROVIDERS_SZ;
}

static const char *engineperf_provider_unload(OSSL_PROVIDER *prov) {
   return NO_PROVIDERS_SZ;
}

#endif /* LUNA_OSSL3 */

/* return size of thing we are reporting */
static unsigned foo_key_report_size(foo_key_t *fkey, const char *keytype) {
   LUNA_TIME_UNIT_T report_size = 0;

   if (strcmp("RAND", keytype) == 0) {
      report_size = LUNA_MIN(LOCAL_MAX_RAND, LOCAL_MAX_BUFFER);
   }

#ifndef OPENSSL_NO_RSA
   if ((strcmp("RSA", keytype) == 0) || (strcmp("LOAD_RSA", keytype) == 0)) {
      if (fkey->rsa != NULL) {
         report_size = (unsigned)RSA_size(fkey->rsa);
      }
   }
#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
   if ((strcmp("DSA", keytype) == 0) || (strcmp("LOAD_DSA", keytype) == 0)) {
      if ((fkey->dsa != NULL) && (LUNA_DSA_GET_p(fkey->dsa) != NULL)) {
         /* report_size = (unsigned)DSA_size(fkey->dsa); */
         report_size = (unsigned)BN_num_bytes(LUNA_DSA_GET_p(fkey->dsa));
      }
   }
#endif /* OPENSSL_NO_DSA */

#ifdef LUNA_OSSL_ECDSA
   if ((strcmp("ECDSA", keytype) == 0) || (strcmp("LOAD_ECDSA", keytype) == 0)) {
      if (fkey->ec != NULL) {
         /* no matter; report curve name instead */
         report_size = (unsigned)ECDSA_size(fkey->ec);
      }
   }
#endif /* LUNA_OSSL_ECDSA */

   return report_size;
}

/* return name of thing we are reporting */
static const char *foo_key_report_name(foo_key_t *fkey, const char *keytype) {
   const char *report_name = "(null_report_name)";
   const char *sname = NULL;
   int nid = 0;

#ifdef LUNA_OSSL_ECDSA
   const EC_GROUP *group = NULL;
   if ((strcmp("ECDSA", keytype) == 0) || (strcmp("LOAD_ECDSA", keytype) == 0)) {
      if (fkey->ec == NULL) {
         return report_name;
      }

      group = EC_KEY_get0_group(fkey->ec);
      if (group == NULL) {
         fprintf(stderr, "EC_KEY_get0_group failed. \n");
         return report_name;
      }

      if (!EC_GROUP_check(group, NULL)) {
         fprintf(stderr, "EC_GROUP_check failed. \n");
         return report_name;
      }

      if ((nid = EC_GROUP_get_curve_name(group)) < 1) {
         fprintf(stderr, "EC_GROUP_get_curve_name failed. \n");
         return report_name;
      }

      sname = OBJ_nid2sn(nid);
      if (sname == NULL) {
         fprintf(stderr, "OBJ_nid2sn failed. \n");
         return report_name;
      }

      report_name = sname;
   }
#endif /* LUNA_OSSL_ECDSA */

   return report_name;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_signver3_setup"

/* setup test for sign and verify */
static unsigned engineperf_signver3_setup(foo_key_t *fkey, int want_verify, const char *keytype,
                                          crypto_flavor_t flavor) {
   const char *fn = "unknown.pem";
   BIO *f = NULL;
   unsigned sig_size = 0;

   if ((strcmp("RSA", keytype) == 0) || (strcmp("LOAD_RSA", keytype) == 0)) {
#ifndef TRY_PKCS11SO_ENGINE
      fn = "tmprsakey.pem";
#else /* TRY_PKCS11SO_ENGINE */
      fn = "pkcs11:Generated RSA Private Key"; /* FIXME: hardcoded label (via ckdemo). */
#endif /* TRY_PKCS11SO_ENGINE */
   }

   if ((strcmp("DSA", keytype) == 0) || (strcmp("LOAD_DSA", keytype) == 0)) {
      fn = "tmpdsakey.pem";
   }

   if ((strcmp("ECDSA", keytype) == 0) || (strcmp("LOAD_ECDSA", keytype) == 0)) {
      fn = "tmpecdsakey.pem";
   }

   if (strcmp("RAND", keytype) == 0) {
      sig_size = LUNA_MIN(LOCAL_MAX_RAND, LOCAL_MAX_BUFFER);
   }

#ifndef OPENSSL_NO_RSA
   if ((strcmp("RSA", keytype) == 0) || (strcmp("LOAD_RSA", keytype) == 0)) {
      if (fkey->rsa == NULL) {
         if (local_param.load_private == 0) {
            EVP_PKEY *pkey = NULL;

            if ((f = BIO_new(BIO_s_file())) == NULL) {
               fprintf(stderr, "BIO_new failed. \n");
               goto err;
            }

            if (BIO_read_filename(f, fn) <= 0) {
               fprintf(stderr, "BIO_read_filename failed. \n");
               goto err;
            }

            if ((pkey = PEM_read_bio_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
               fprintf(stderr, LUNA_FUNC_NAME ": PEM_read_bio_PrivateKey(RSA) failed. \n");
               goto err;
            }

            IF_DEBUG(fprintf(stderr, "PEM_read_bio_PrivateKey(RSA) ok. \n"););
            fkey->rsa = LUNA_EVP_PKEY_get0_RSA(pkey);
            fkey->pkey_rsa = pkey;

         } else {
            EVP_PKEY *pkey = NULL;

            IF_DEBUG(fprintf(stderr, "ENGINE_load_private_key(RSA, \"%s\")... \n", (char *)fn););
            pkey = (local_param.error_login) ? NULL : ENGINE_load_private_key(fkey->e, fn, NULL, NULL);
            if ((pkey == NULL) || (LUNA_EVP_PKEY_get0_RSA(pkey) == NULL)) {
               fprintf(stderr, LUNA_FUNC_NAME ": ENGINE_load_private_key failed. \n");
               local_param.error_login = 1; /* paranoia... avoiding repeated bad login */
               goto err;
            }

            IF_DEBUG(fprintf(stderr, "ENGINE_load_private_key(RSA) ok. \n"););
            fkey->rsa = LUNA_EVP_PKEY_get0_RSA(pkey);
            fkey->pkey_rsa = pkey;
         }
      }

      sig_size = (unsigned)RSA_size(fkey->rsa);
   }
#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
   if ((strcmp("DSA", keytype) == 0) || (strcmp("LOAD_DSA", keytype) == 0)) {
      if (fkey->dsa == NULL) {
         if (local_param.load_private == 0) {
            EVP_PKEY *pkey = NULL;

            if ((f = BIO_new(BIO_s_file())) == NULL) {
               fprintf(stderr, "BIO_new failed. \n");
               goto err;
            }

            if (BIO_read_filename(f, fn) <= 0) {
               fprintf(stderr, "BIO_read_filename failed. \n");
               goto err;
            }

            if ((pkey = PEM_read_bio_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
               fprintf(stderr, LUNA_FUNC_NAME ": PEM_read_bio_PrivateKey(DSA) failed. \n");
               goto err;
            }

            IF_DEBUG(fprintf(stderr, "PEM_read_bio_PrivateKey(DSA) ok. \n"););
            fkey->dsa = LUNA_EVP_PKEY_get0_DSA(pkey);
            fkey->pkey_dsa = pkey;

         } else {
            EVP_PKEY *pkey = NULL;

            IF_DEBUG(fprintf(stderr, "ENGINE_load_private_key(DSA)... \n"););
            pkey = (local_param.error_login) ? NULL : ENGINE_load_private_key(fkey->e, fn, NULL, NULL);
            if ((pkey == NULL) || (LUNA_EVP_PKEY_get0_DSA(pkey) == NULL)) {
               fprintf(stderr, LUNA_FUNC_NAME ": ENGINE_load_private_key failed. \n");
               local_param.error_login = 1; /* paranoia... avoiding repeated bad login */
               goto err;
            }

            IF_DEBUG(fprintf(stderr, "ENGINE_load_private_key(DSA) ok. \n"););
            fkey->dsa = LUNA_EVP_PKEY_get0_DSA(pkey);
            fkey->pkey_dsa = pkey;
         }
      }

      sig_size = (unsigned)DSA_size(fkey->dsa);
   }
#endif /* OPENSSL_NO_DSA */

#ifdef LUNA_OSSL_ECDSA
   if ((strcmp("ECDSA", keytype) == 0) || (strcmp("LOAD_ECDSA", keytype) == 0)) {
      if (fkey->ec == NULL) {
         if (local_param.load_private == 0) {
            EVP_PKEY *pkey = NULL;

            if ((f = BIO_new(BIO_s_file())) == NULL) {
               fprintf(stderr, "BIO_new failed. \n");
               goto err;
            }

            if (BIO_read_filename(f, fn) <= 0) {
               fprintf(stderr, "BIO_read_filename failed. \n");
               goto err;
            }

            if ((pkey = PEM_read_bio_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
               fprintf(stderr, LUNA_FUNC_NAME ": PEM_read_bio_PrivateKey(ECDSA) failed. \n");
               goto err;
            }

            IF_DEBUG(fprintf(stderr, "PEM_read_bio_PrivateKey(ECDSA) ok. \n"););
            fkey->ec = LUNA_EVP_PKEY_get0_EC_KEY(pkey);
            fkey->pkey_ec = pkey;

         } else {
            EVP_PKEY *pkey = NULL;

            IF_DEBUG(fprintf(stderr, "ENGINE_load_private_key(ECDSA)... \n"););
            pkey = (local_param.error_login) ? NULL : ENGINE_load_private_key(fkey->e, fn, NULL, NULL);
            if ((pkey == NULL) || (LUNA_EVP_PKEY_get0_EC_KEY(pkey) == NULL)) {
               fprintf(stderr, LUNA_FUNC_NAME ": ENGINE_load_private_key failed. \n");
               local_param.error_login = 1; /* paranoia... avoiding repeated bad login */
               goto err;
            }

            IF_DEBUG(fprintf(stderr, "ENGINE_load_private_key(ECDSA) ok. \n"););
            fkey->ec = LUNA_EVP_PKEY_get0_EC_KEY(pkey);
            fkey->pkey_ec = pkey;
         }
      }

      sig_size = (unsigned)ECDSA_size(fkey->ec);
   }
#endif /* LUNA_OSSL_ECDSA */

err:
   if (f != NULL) {
      BIO_free(f);
   }

   return sig_size;
}

static const unsigned char baPrefixSha256[] = {
   0x30, 0x31,
   0x30, 0x0d,
   0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
   0x05, 0x00,
   0x04, 0x20
   }; /* 19 bytes */

static int engineperf_vary_saltlen(const EVP_MD *md, foo_thread_t *have_pt, int verify, int want_vary);
static size_t engineperf_vary_label(unsigned char *buf, size_t max, foo_thread_t *have_pt, int want_vary);

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_signver3"

/* test sign and verify */
static void engineperf_signver3(foo_key_t *fkey, int want_verify_in, const char *keytype, crypto_flavor_t flavor,
                                foo_thread_t *have_pt) {
   const unsigned buflen = LOCAL_MAX_BUFFER;
   unsigned char *from = (unsigned char *)"sign this";
   const unsigned from_len = (unsigned)strlen((char*)from);
   unsigned char *buf = NULL;
   unsigned char *buf2 = NULL;
   unsigned sig_size = 0;
   int want_sign = 1;
   int want_hush = (have_pt != NULL) ? have_pt->want_hush : 0;
   LUNA_TIME_UNIT_T loops = 0;
   unsigned int siglen = 0;

   luna_stopwatch_t lsw = LUNA_STOPWATCH_T_INIT;

   /* engineperf uses sha256 by default, whereas openssl uses sha1 by default */
   unsigned char encoded[19 + 32] = {0};
   int encoded_len = 0;
   int nid = NID_undef;

   struct _temp_evp {
      int nid;
      int mgf1_nid;
      EVP_PKEY *pkey;
      EVP_MD_CTX *mctx;
      EVP_PKEY_CTX *pkctx;
      size_t cipherlen;
      unsigned char *cipher;
      size_t outlen;
      unsigned char *out;
      size_t labellen;
      unsigned char label[256];
   } evp = { NID_sha256, NID_sha512, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, {0} };

   const int want_verify = want_verify_in;
   int want_vary = 1;

   /* decide to vary the input parameters to crypto operations */
   switch (flavor) {
   case crypto_flavor_priv_enc:
      want_vary = want_verify_in ? 0 : 1;
      break;
   case crypto_flavor_priv_dec:
      want_vary = 1;
      break;
   case crypto_flavor_oaep_sha1:
      want_vary = 1;
      break;
   case crypto_flavor_sign:
      want_vary = want_verify_in ? 0 : 1;
      break;
   case crypto_flavor_digest_sign:
      want_vary = want_verify_in ? 0 : 1;
      break;
   case crypto_flavor_pkcs_pss:
      want_vary = want_verify_in ? 0 : 1;
      break;
   case crypto_flavor_pkcs_oaep:
   case crypto_flavor_null:
      want_vary = 1;
      break;
   default:
      want_vary = 1;
      fprintf(stderr, LUNA_FUNC_NAME ": WARNING: default case: flavor = %d \n", (int)flavor);
      break;
   }

   /* encode the input data if necessary */
   if (flavor == crypto_flavor_sign) {
      if (engineperf_SHA256(from, from_len, &encoded[0]) != 1)
         goto err;
      encoded_len = 32;
      nid = NID_sha256;
   } else {
      memcpy(&encoded[0], baPrefixSha256, sizeof(baPrefixSha256));
      if (engineperf_SHA256(from, from_len, &encoded[sizeof(baPrefixSha256)]) != 1)
         goto err;
      encoded_len = sizeof(baPrefixSha256) + 32;
      nid = NID_undef;
   }

   /* NOTE: sig_size shall be initialized once by the main thread! */
   sig_size = fkey->sig_size;
   if (sig_size < 1) {
      if (!want_hush)
         fprintf(stderr, LUNA_FUNC_NAME ": engineperf_signver3_setup failed \n");
      goto err;
   }

   buf = malloc(buflen);
   if (buf == NULL) {
      if (!want_hush)
         fprintf(stderr, LUNA_FUNC_NAME ": malloc failed \n");
      goto err;
   }

   buf2 = malloc(buflen);
   if (buf2 == NULL) {
      if (!want_hush)
         fprintf(stderr, LUNA_FUNC_NAME ": malloc failed \n");
      goto err;
   }

   luna_stopwatch_start2(&lsw, local_param.seconds);
   for (; (have_pt != NULL ? !have_pt->want_fini : !luna_stopwatch_update(&lsw)); loops++) {
      if (loops == 1) {
         /* loop #0 is slow due to cache effects; restart timer when loop #1 begins */
         luna_stopwatch_start2(&lsw, local_param.seconds);

         if (have_pt != NULL)
            have_pt->have_init = 1; /* signal have_init = 1 */
      }

      if (want_sign) {
         if (strcmp("RAND", keytype) == 0) {
            if (RAND_bytes(buf, sig_size) != 1) {
               if (!want_hush)
                  fprintf(stderr, LUNA_FUNC_NAME ": RAND_bytes failed \n");
               goto err;
            }
         }

#ifndef OPENSSL_NO_RSA
         if (strcmp("RSA", keytype) == 0) {
            evp.pkey = fkey->pkey_rsa;
            switch (flavor) {
               case crypto_flavor_priv_enc:
                  if (RSA_private_encrypt(encoded_len, encoded, buf, fkey->rsa, RSA_PKCS1_PADDING) < 1) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": RSA_private_encrypt failed \n");
                     goto err;
                  }
                  break;

               case crypto_flavor_priv_dec:
               case crypto_flavor_oaep_sha1:
                  if (RSA_public_encrypt(encoded_len, encoded, buf, fkey->rsa,
                     flavor == crypto_flavor_oaep_sha1 ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING) < 1) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": RSA_public_encrypt failed \n");
                     goto err;
                  }
                  break;

               case crypto_flavor_sign:
                  if (RSA_sign(nid, encoded, encoded_len, buf, &siglen, fkey->rsa) != 1) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": RSA_sign failed \n");
                     goto err;
                  }
                  break;

               default:
                  if (!IS_EVP_TESTCASE(flavor, evp.pkey)) {
                     fprintf(stderr, LUNA_FUNC_NAME ": WARNING: default case for RSA sign: flavor = %u \n", flavor);
                  }
                  break;
            }
         }
#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
         if (strcmp("DSA", keytype) == 0) {
            evp.pkey = fkey->pkey_dsa;
            if (flavor == crypto_flavor_sign) {
               if (DSA_sign(nid, encoded, encoded_len, buf, &siglen, fkey->dsa) != 1) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": DSA_sign failed \n");
                  goto err;
               }
            }
         }
#endif /* OPENSSL_NO_DSA */

#ifdef LUNA_OSSL_ECDSA
         if (strcmp("ECDSA", keytype) == 0) {
            evp.pkey = fkey->pkey_ec;
            if (flavor == crypto_flavor_sign) {
               if (ECDSA_sign(nid, encoded, encoded_len, buf, &siglen, fkey->ec) != 1) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": ECDSA_sign failed \n");
                  goto err;
               }
            }
         }
#endif /* LUNA_OSSL_ECDSA */

         if (evp.pkey != NULL) {
            const EVP_MD *sig_md = EVP_get_digestbynid(evp.nid);
            const EVP_MD *oaep_md = EVP_get_digestbynid(evp.nid);
            const EVP_MD *mgf1_md = EVP_get_digestbynid(local_param.want_mgf1_vary ? evp.mgf1_nid : evp.nid);
            if ((flavor == crypto_flavor_digest_sign) || (flavor == crypto_flavor_pkcs_pss))  {
               evp.mctx = LUNA_EVP_MD_CTX_new();
               evp.pkctx = NULL;
               /* NOTE: EVP_PKEY_CTX gets allocated and owned by EVP_MD_CTX */
               if (EVP_DigestSignInit(evp.mctx, &evp.pkctx, sig_md, (local_param.want_engine_impl ? fkey->e : NULL), evp.pkey) <= 0)
                  goto err;
               if (strcmp("RSA", keytype) == 0) {
                  if (EVP_PKEY_CTX_set_rsa_padding(evp.pkctx, RSA_PKCS1_PSS_PADDING) <= 0)
                     goto err;
                  /* NOTE: calling EVP_PKEY_CTX_set_signature_md with sig_md would be redundant */
                  if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp.pkctx, mgf1_md) <= 0)
                     goto err;
                  /* NOTE: typical saltlen is 0 or EVP_MD_size(md) */
                  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(evp.pkctx, engineperf_vary_saltlen(sig_md, have_pt, 0, want_vary)) <= 0)
                     goto err;
               }
               if (EVP_DigestSignUpdate(evp.mctx, from, from_len) <= 0)
                  goto err;
               if (EVP_DigestSignFinal(evp.mctx, NULL, &evp.cipherlen) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_DigestSignFinal failed \n");
                  goto err;
               }
               if (evp.cipher != NULL)
                  OPENSSL_free(evp.cipher);
               evp.cipher = OPENSSL_malloc(evp.cipherlen);
               if (EVP_DigestSignFinal(evp.mctx, evp.cipher, &evp.cipherlen) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_DigestSignFinal failed \n");
                  goto err;
               }
               LUNA_EVP_MD_CTX_free(evp.mctx);
               evp.mctx = NULL;
               evp.pkctx = NULL;
            } else if (flavor == crypto_flavor_pkcs_oaep) {
               evp.pkctx = EVP_PKEY_CTX_new(evp.pkey, (local_param.want_engine_impl ? fkey->e : NULL));
               if (evp.pkctx == NULL)
                  goto err;
               if (EVP_PKEY_encrypt_init(evp.pkctx) <= 0)
                  goto err;
               if (strcmp("RSA", keytype) == 0) {
                  if (EVP_PKEY_CTX_set_rsa_padding(evp.pkctx, RSA_PKCS1_OAEP_PADDING) <= 0)
                     goto err;
                  if (EVP_PKEY_CTX_set_rsa_oaep_md(evp.pkctx, oaep_md) <= 0)
                     goto err;
                  if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp.pkctx, mgf1_md) <= 0)
                     goto err;
                  evp.labellen = engineperf_vary_label(evp.label, sizeof(evp.label), have_pt, want_vary);
#if 0
                  /* FIXME: cannot set label when using openssl3 plus engine */
                  if (local_param.want_rsa_oaep_label) {
                     /* NOTE: duplicate label because context takes ownership of pointer */
                     /* coverity: evp.pkctx takes ownership of label */
                     if (EVP_PKEY_CTX_set0_rsa_oaep_label(evp.pkctx, OPENSSL_strdup(evp.label), evp.labellen) <= 0)
                        goto err;
                  }
#endif
               }
               if (EVP_PKEY_encrypt(evp.pkctx, NULL, &evp.cipherlen, from, from_len) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_PKEY_encrypt failed \n");
                  goto err;
               }
               if (evp.cipher != NULL)
                  OPENSSL_free(evp.cipher);
               evp.cipher = OPENSSL_malloc(evp.cipherlen);
               if (EVP_PKEY_encrypt(evp.pkctx, evp.cipher, &evp.cipherlen, from, from_len) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_PKEY_encrypt failed \n");
                  goto err;
               }
               EVP_PKEY_CTX_free(evp.pkctx);
               evp.pkctx = NULL;
            }
            if (!want_verify) {
               OPENSSL_free(evp.cipher);
               evp.cipher = NULL;
            }
         }

      } /* want_sign */

      if (want_verify) {
         if ( want_sign && (!want_vary) ) {
            /* if testing verify then sign data once */
            want_sign = 0;
            luna_stopwatch_start2(&lsw, local_param.seconds);
         }

#ifndef OPENSSL_NO_RSA
         if (strcmp("RSA", keytype) == 0) {
            int outlen = 0;
            switch (flavor) {
               case crypto_flavor_priv_enc:
                  if ( (outlen = RSA_public_decrypt(sig_size, buf, buf2, fkey->rsa, RSA_PKCS1_PADDING)) < 1 ) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": RSA_public_decrypt failed \n");
                     goto err;
                  }

                  if ( (outlen != encoded_len) || (memcmp(buf2, encoded, encoded_len) != 0) ) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": memcmp failed \n");
                     goto err;
                  }
                  break;

               case crypto_flavor_priv_dec:
               case crypto_flavor_oaep_sha1:
                  if (sig_size < 1) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": sig_size < 1 \n");
                     goto err;
                  }

                  if ( (outlen = RSA_private_decrypt(sig_size, buf, buf2, fkey->rsa,
                     flavor == crypto_flavor_oaep_sha1 ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING)) < 1 ) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": RSA_private_decrypt failed \n");
                     goto err;
                  }

                  if ( (outlen != encoded_len) || (memcmp(buf2, encoded, encoded_len) != 0) ) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": memcmp failed \n");
                     goto err;
                  }
                  break;

               case crypto_flavor_sign:
                  if (RSA_verify(nid, encoded, encoded_len, buf, siglen, fkey->rsa) != 1) {
                     if (!want_hush)
                        fprintf(stderr, LUNA_FUNC_NAME ": RSA_verify failed \n");
                     goto err;
                  }
                  break;

               default:
                  if (!IS_EVP_TESTCASE(flavor, evp.pkey)) {
                     fprintf(stderr, LUNA_FUNC_NAME ": WARNING: default case for RSA verify: flavor = %u \n", flavor);
                  }
                  break;
            }
         }
#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
         if (strcmp("DSA", keytype) == 0) {
            if (flavor == crypto_flavor_sign) {
               if (DSA_verify(nid, encoded, encoded_len, buf, siglen, fkey->dsa) != 1) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": DSA_verify failed \n");
                  goto err;
               }
            }
         }
#endif /* OPENSSL_NO_DSA */

#ifdef LUNA_OSSL_ECDSA
         if (strcmp("ECDSA", keytype) == 0) {
            if (flavor == crypto_flavor_sign) {
               if (ECDSA_verify(nid, encoded, encoded_len, buf, siglen, fkey->ec) != 1) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": ECDSA_verify failed \n");
                  goto err;
               }
            }
         }
#endif /* LUNA_OSSL_ECDSA */

         if (evp.pkey != NULL) {
            const EVP_MD *sig_md = EVP_get_digestbynid(evp.nid);
            const EVP_MD *oaep_md = EVP_get_digestbynid(evp.nid);
            const EVP_MD *mgf1_md = EVP_get_digestbynid(local_param.want_mgf1_vary ? evp.mgf1_nid : evp.nid);
            if ((flavor == crypto_flavor_digest_sign) || (flavor == crypto_flavor_pkcs_pss)) {
               evp.mctx = LUNA_EVP_MD_CTX_new();
               evp.pkctx = NULL;
               /* NOTE: EVP_PKEY_CTX gets allocated and owned by EVP_MD_CTX */
               if (EVP_DigestVerifyInit(evp.mctx, &evp.pkctx, sig_md, (local_param.want_engine_impl ? fkey->e : NULL), evp.pkey) <= 0)
                  goto err;
               if (strcmp("RSA", keytype) == 0) {
                  if (EVP_PKEY_CTX_set_rsa_padding(evp.pkctx, RSA_PKCS1_PSS_PADDING) <= 0)
                     goto err;
                  /* NOTE: calling EVP_PKEY_CTX_set_signature_md with sig_md would be redundant */
                  if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp.pkctx, mgf1_md) <= 0)
                     goto err;
                  /* NOTE: typical saltlen is 0 or EVP_MD_size(md) */
                  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(evp.pkctx, engineperf_vary_saltlen(sig_md, have_pt, 1, want_vary)) <= 0)
                     goto err;
               }
               if (EVP_DigestVerifyUpdate(evp.mctx, from, from_len) <= 0)
                  goto err;
               if (EVP_DigestVerifyFinal(evp.mctx, evp.cipher, evp.cipherlen) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_DigestVerifyFinal failed \n");
                  goto err;
               }
               LUNA_EVP_MD_CTX_free(evp.mctx);
               evp.mctx = NULL;
               /* NOTE: pkctx is owned by mctx so invalidate pkctx */
               evp.pkctx = NULL;
            } else if (flavor == crypto_flavor_pkcs_oaep) {
               evp.out = NULL;
               evp.outlen = 0;
               evp.pkctx = EVP_PKEY_CTX_new(evp.pkey, (local_param.want_engine_impl ? fkey->e : NULL));
               if (evp.pkctx == NULL)
                  goto err;
               if (EVP_PKEY_decrypt_init(evp.pkctx) <= 0)
                  goto err;
               if (strcmp("RSA", keytype) == 0) {
                  if (EVP_PKEY_CTX_set_rsa_padding(evp.pkctx, RSA_PKCS1_OAEP_PADDING) <= 0)
                     goto err;
                  if (EVP_PKEY_CTX_set_rsa_oaep_md(evp.pkctx, oaep_md) <= 0)
                     goto err;
                  if (EVP_PKEY_CTX_set_rsa_mgf1_md(evp.pkctx, mgf1_md) <= 0)
                     goto err;
                  evp.labellen = engineperf_vary_label(evp.label, sizeof(evp.label), have_pt, want_vary);
#if 0
                  /* FIXME: cannot set label when using openssl3 plus engine */
                  if (local_param.want_rsa_oaep_label) {
                     /* NOTE: duplicate label because context takes ownership of pointer */
                     /* coverity: evp.pkctx takes ownership of label */
                     if (EVP_PKEY_CTX_set0_rsa_oaep_label(evp.pkctx, OPENSSL_strdup(evp.label), evp.labellen) <= 0)
                        goto err;
                  }
#endif
               }
               if (EVP_PKEY_decrypt(evp.pkctx, NULL, &evp.outlen, evp.cipher, evp.cipherlen) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_PKEY_decrypt failed \n");
                  goto err;
               }
               evp.out = OPENSSL_malloc(evp.outlen);
               if (EVP_PKEY_decrypt(evp.pkctx, evp.out, &evp.outlen, evp.cipher, evp.cipherlen) <= 0) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": EVP_PKEY_decrypt failed \n");
                  goto err;
               }
               if ( (evp.outlen != from_len) || (memcmp(evp.out, from, from_len) != 0) ) {
                  if (!want_hush)
                     fprintf(stderr, LUNA_FUNC_NAME ": memcmp failed \n");
                  goto err;
               }
               OPENSSL_free(evp.out);
               evp.out = NULL;
               evp.outlen = 0;
               EVP_PKEY_CTX_free(evp.pkctx);
               evp.pkctx = NULL;
            }
         }

      } /* want_verify */

#ifndef OPENSSL_NO_RSA
      if (strcmp("LOAD_RSA", keytype) == 0) {
         EVP_PKEY *pkey = NULL;
         const char *fn = "tmprsakey.pem";

         pkey = (local_param.error_login) ? NULL : ENGINE_load_private_key(fkey->e, fn, NULL, NULL);
         if ((pkey == NULL) || (LUNA_EVP_PKEY_get0_RSA(pkey) == NULL)) {
            if (!want_hush)
               fprintf(stderr, LUNA_FUNC_NAME ": ENGINE_load_private_key failed. \n");
            local_param.error_login = 1; /* paranoia... avoiding repeated bad login */
            goto err;
         }

         EVP_PKEY_free(pkey);
      }
#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
      if (strcmp("LOAD_DSA", keytype) == 0) {
         EVP_PKEY *pkey = NULL;
         const char *fn = "tmpdsakey.pem";

         pkey = (local_param.error_login) ? NULL : ENGINE_load_private_key(fkey->e, fn, NULL, NULL);
         if ((pkey == NULL) || (LUNA_EVP_PKEY_get0_DSA(pkey) == NULL)) {
            if (!want_hush)
               fprintf(stderr, LUNA_FUNC_NAME ": ENGINE_load_private_key failed. \n");
            local_param.error_login = 1; /* paranoia... avoiding repeated bad login */
            goto err;
         }

         EVP_PKEY_free(pkey);
      }
#endif /* OPENSSL_NO_RSA */

#ifdef LUNA_OSSL_ECDSA
      if (strcmp("LOAD_ECDSA", keytype) == 0) {
         EVP_PKEY *pkey = NULL;
         const char *fn = "tmpecdsakey.pem";

         pkey = (local_param.error_login) ? NULL : ENGINE_load_private_key(fkey->e, fn, NULL, NULL);
         if ((pkey == NULL) || (LUNA_EVP_PKEY_get0_EC_KEY(pkey) == NULL)) {
            if (!want_hush)
               fprintf(stderr, LUNA_FUNC_NAME ": ENGINE_load_private_key failed. \n");
            local_param.error_login = 1; /* paranoia... avoiding repeated bad login */
            goto err;
         }

         EVP_PKEY_free(pkey);
      }
#endif /* LUNA_OSSL_ECDSA */

      if (have_pt) {
         if (have_pt->want_loops && !have_pt->want_fini) {
            have_pt->loops++;
         }
      }
   } /* for loop */

   luna_stopwatch_stop(&lsw);

   if (have_pt == NULL) {
      luna_stopwatch_report_wrapper(&lsw, foo_key_report_size(fkey, keytype), loops, 1, want_verify_in, keytype, fkey,
                                    flavor);
   }

   goto cleanup;

err:
   fprintf(stderr, "***WARNING: thread stopped due to error (loops = %ld).\n", (long)(have_pt?have_pt->loops:0));

cleanup:
   if (buf != NULL) {
      free(buf);
   }

   if (buf2 != NULL) {
      free(buf2);
   }

   if (evp.cipher != NULL) {
      OPENSSL_free(evp.cipher);
   }

   if (evp.out != NULL) {
      OPENSSL_free(evp.out);
   }

   if (evp.mctx != NULL) {
      LUNA_EVP_MD_CTX_free(evp.mctx);
      /* NOTE: pkctx is owned by mctx so invalidate pkctx */
      evp.pkctx = NULL;
   }

   if (evp.pkctx != NULL) {
      EVP_PKEY_CTX_free(evp.pkctx);
      evp.pkctx = NULL;
   }

   return;
}

/* Test multi-threaded (thread entry function) */
static void engineperf_multi_f(void *context) {
   foo_thread_t *pt = (foo_thread_t *)context;
#ifdef ENGINEPERF_STRESS
   do {
      engineperf_signver3(pt->fkey, pt->want_verify, pt->keytype, pt->flavor, pt);
      pt->have_init = 1; /* failsafe */
      if (!pt->want_fini) {
         foo_thread_msleep(10);
         pt->want_hush = 1; /* NOTE: avoid cascading error messages */
      }
   } while (!pt->want_fini); /* NOTE: continue looping because we want to stress the engine in the presence of errors */
#else  /* ENGINEPERF_STRESS */
   engineperf_signver3(pt->fkey, pt->want_verify, pt->keytype, pt->flavor, pt);
#endif /* ENGINEPERF_STRESS */
   pt->have_init = 1; /* failsafe: signal have_init = 1 */
   pt->have_fini = 1; /* failsafe: signal have_fini = 1 */
   return;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_multi_thread"

/* Test multi-threaded */
static void engineperf_multi_thread(foo_key_t *fkey, int want_verify, const char *keytype, crypto_flavor_t flavor) {
   unsigned ii = 0;
   foo_thread_t *pt = NULL;
   foo_thread_t *ttab = NULL;
   LUNA_TIME_UNIT_T loops = 0;
   unsigned sig_size = 0;

   luna_stopwatch_t lsw = LUNA_STOPWATCH_T_INIT;

   /* NOTE: setup once; otherwise, the threads may clobber each other */
   sig_size = fkey->sig_size = engineperf_signver3_setup(fkey, want_verify, keytype, flavor);
   if (sig_size < 1) {
      fprintf(stderr, LUNA_FUNC_NAME ": engineperf_signver3_setup failed \n");
      return;
   }

   /* zeroize thread table */
   ttab = (foo_thread_t *)malloc(sizeof(foo_thread_t) * LOCAL_MAX_THREAD);
   if (ttab == NULL) {
      fprintf(stderr, LUNA_FUNC_NAME ": malloc failed \n");
      return;
   }
   memset(ttab, 0, (sizeof(foo_thread_t) * LOCAL_MAX_THREAD));

   /* init threads */
   IF_DEBUG(fprintf(stderr, "init threads... \n"););
   for (ii = 0, pt = ttab; ii < local_param.threads; ii++, pt++) {
      if (foo_thread_init(pt, engineperf_multi_f, fkey, want_verify, keytype, flavor)) {
         fprintf(stderr, LUNA_FUNC_NAME ": foo_thread_init failed \n");
         return;
      }
   }

   /* wait for init ack */
   IF_DEBUG(fprintf(stderr, "wait for init ack... \n"););
   for (ii = 0, pt = ttab; ii < local_param.threads; ii++, pt++) {
      while (pt->have_init == 0) {
         foo_thread_msleep(10); /* NOT timing sensitive */
      }
   }

   /* assert want_loops  */
   IF_DEBUG(fprintf(stderr, "assert want_loops... \n"););
   luna_stopwatch_start2(&lsw, local_param.seconds);
   for (ii = 0, pt = ttab; ii < local_param.threads; ii++, pt++) {
      pt->want_loops = 1; /* meaning each thread should start incrementing "pt->loops" */
   }

   /* allow threads to run */
   IF_DEBUG(fprintf(stderr, "allow threads to run... \n"););
   for (; luna_stopwatch_update(&lsw) == 0;) {
      foo_thread_msleep(1000); /* NOT timing sensitive */
   }

   /* count loops, stop timer */
   loops = 0;
   for (ii = 0, pt = ttab; ii < local_param.threads; ii++, pt++) {
      loops += pt->loops;
   }
   luna_stopwatch_stop(&lsw);

   /* assert want_fini */
   IF_DEBUG(fprintf(stderr, "assert fini... \n"););
   for (ii = 0, pt = ttab; ii < local_param.threads; ii++, pt++) {
      pt->want_fini = 1; /* meaning each thread should stop incrementing "pt->loops" */
   }

   /* wait for fini ack */
   IF_DEBUG(fprintf(stderr, "wait for fini ack... \n"););
   for (ii = 0, pt = ttab; ii < local_param.threads; ii++, pt++) {
      while (pt->have_fini == 0) {
         foo_thread_msleep(10); /* NOT timing sensitive */
      }
   }

   /* report after all threads stopped */
   luna_stopwatch_report_wrapper(&lsw, foo_key_report_size(fkey, keytype), loops, 1, want_verify, keytype, fkey,
                                 flavor);

   free(ttab);
}

#ifdef LUNA_OSSL_WINDOWS

/* Start timer */
static void luna_stopwatch_start2(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T seconds) {
   lsw->t1 = lsw->t0 = GetTickCount();
   lsw->seconds = seconds;
}

/* Stop timer */
static void luna_stopwatch_stop(luna_stopwatch_t *lsw) { lsw->t1 = GetTickCount(); }

/* Return elapsed time (microsecs) */
static LUNA_TIME_UNIT_T luna_stopwatch_usec(luna_stopwatch_t *lsw) {
   if (lsw->t1 <= lsw->t0) {
      return 0;
   }

   return ((lsw->t1 - lsw->t0) * 1000);
}

/* update stop watch */
static int luna_stopwatch_update(luna_stopwatch_t *lsw) {
   LUNA_TIME_UNIT_T t1;
   LUNA_TIME_UNIT_T t2;

   t1 = GetTickCount();
   if (t1 < lsw->t0) {
      return -1; /* overflow1 */
   }

   t2 = lsw->t0 + (lsw->seconds * 1000);
   if (t2 < lsw->t0) {
      return -1; /* overflow2 */
   }

   if (t1 >= t2) {
      return 1; /* time expired */
   }

   return 0;
}

/* thread entry function (for CreateThread) */
static DWORD WINAPI foo_thread_proc(void *context) {
   foo_thread_t *pt = (foo_thread_t *)context;
   pt->f(pt);
   return 0;
}

/* init thread */
static int foo_thread_init(foo_thread_t *pt, foo_thread_f f, foo_key_t *fkey, int want_verify, const char *keytype,
                           int flavor) {
   memset(pt, 0, sizeof(*pt));
   pt->f = f;
   pt->fkey = fkey;
   pt->want_verify = want_verify;
   pt->keytype = keytype;
   pt->flavor = flavor;
   if (CreateThread(NULL, 0, foo_thread_proc, (void *)pt, 0, NULL) == NULL) {
      fprintf(stderr, "CreateThread failed. \n");
      return -1;
   }

   return 0;
}

/* sleep milliseconds */
static void foo_thread_msleep(unsigned millisecs) { Sleep(millisecs ? millisecs : 1); }

#else /* LUNA_OSSL_WINDOWS */

/* Start timer */
static void luna_stopwatch_start2(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T seconds) {
   struct timeval tv;
   gettimeofday(&tv, NULL);
   lsw->t1 = lsw->t0 = ((tv.tv_sec * 1000000) + tv.tv_usec);
   lsw->seconds = seconds;
}

/* Stop timer */
static void luna_stopwatch_stop(luna_stopwatch_t *lsw) {
   struct timeval tv;
   gettimeofday(&tv, NULL);
   lsw->t1 = ((tv.tv_sec * 1000000) + tv.tv_usec);
}

/* Return elapsed time (microsecs) */
static LUNA_TIME_UNIT_T luna_stopwatch_usec(luna_stopwatch_t *lsw) {
   if (lsw->t1 <= lsw->t0) {
      lsw->t0 = lsw->t1;
      return 0;
   }

   return (lsw->t1 - lsw->t0);
}

/* update stop watch */
static int luna_stopwatch_update(luna_stopwatch_t *lsw) {
   LUNA_TIME_UNIT_T t1;
   LUNA_TIME_UNIT_T t2;
   struct timeval tv;

   gettimeofday(&tv, NULL);
   t1 = ((tv.tv_sec * 1000000) + tv.tv_usec);
   if (t1 < lsw->t0) {
      return -1; /* overflow1 */
   }

   t2 = lsw->t0 + (lsw->seconds * 1000000);
   if (t2 < lsw->t0) {
      return -1; /* overflow2 */
   }

   if (t1 >= t2) {
      return 1; /* time expired */
   }

   return 0;
}

/* thread entry function (for pthread_create) */
static void *foo_start_routine(void *context) {
   foo_thread_t *pt = (foo_thread_t *)context;
   pt->f(pt);
   return 0;
}

/* init thread */
static int foo_thread_init(foo_thread_t *pt, foo_thread_f f, foo_key_t *fkey, int want_verify, const char *keytype,
                           crypto_flavor_t flavor) {
   pthread_t foo_thread;
   pthread_attr_t foo_attr;

   memset(&foo_thread, 0, sizeof(foo_thread));
   memset(&foo_attr, 0, sizeof(foo_attr));

   memset(pt, 0, sizeof(*pt));
   pt->f = f;
   pt->fkey = fkey;
   pt->want_verify = want_verify;
   pt->keytype = keytype;
   pt->flavor = flavor;

   pthread_attr_init(&foo_attr);
   pthread_attr_setscope(&foo_attr, PTHREAD_SCOPE_SYSTEM);
   if (pthread_create(&foo_thread, &foo_attr, foo_start_routine, (void *)pt) != 0) {
      fprintf(stderr, "pthread_create failed. \n");
      return -1;
   }

   return 0;
}

/* sleep milliseconds */
static void foo_thread_msleep(unsigned millisecs) {
   struct timespec time1;

   time1.tv_sec = (millisecs / 1000);
   time1.tv_nsec = ((millisecs % 1000) * 1000000);
   nanosleep(&time1, NULL);
}

#endif /* LUNA_OSSL_WINDOWS */

/****************************************/
/* START OF SAMPLE CODE FOR HA RECOVERY */
/****************************************/

static volatile int pending_Recover = 0;  /* flag; set to 1 if HA Recovery is pending */
static volatile int pending_Finalize = 0; /* flag; set to 1 if C_Finalize is pending */

static foo_thread_t *pt_monitor = NULL; /* pointer; set to the monitor thread */

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_monitor_f"

/* entry function for the monitor thread */
static void engineperf_monitor_f(void *pt_context) {
   foo_thread_t *pt = (foo_thread_t *)pt_context;
   int rc = 0;
   CK_ULONG ul = 0;
   int flag_memberStatus = 0;
   int have_err = 0;
   int loops = 0;
#ifdef ENGINEPERF_STRESS
   unsigned intervalPoll = 10; /* 10ms = interval for stress test */
#else
   unsigned intervalPoll = (5 * 1000); /* 5s = typical poll interval */
#endif

   luna_ha_status_v2_t cmd;
   luna_ha_status_v2_t cmd_prev;

   memset(&cmd, 0, sizeof(cmd));
   memset(&cmd_prev, 0, sizeof(cmd_prev));

   /* loop until want_fini or error */
   pt->have_init = 1;
   for (loops = 0; !(pt->want_fini); loops++) {
      /* call get ha state at regular intervals */
      foo_thread_msleep(intervalPoll);

      /* invoke CA_GetHAState via openssl engine */
      memset(&cmd, 0, sizeof(cmd));
      cmd.version = sizeof(cmd);
      cmd.instance = 0;
      rc = ENGINE_ctrl_cmd(pt->fkey->e, "GET_HA_STATE", 0, &cmd, NULL, 0);

      /* do basic exception handling */
      if (rc != 1)
         have_err = 1;

      /* NOTE: you can detect error earlier by testing other conditions as follows:
       *   1. cmd.st.memberList[].memberStatus = 0x30 (CKR_DEVICE_ERROR) for every item in memberList;
       *   2. cmd._ckrv = 0xE0 (CKR_TOKEN_NOT_PRESENT);
       *   3. cmd.st.listSize = 0;
       *   4. cmd._ckrv = 0x54 (CKR_FUNCTION_NOT_SUPPORTED);
       */
      if (flag_memberStatus)
         have_err = 1;
      if (cmd._ckrv == CKR_TOKEN_NOT_PRESENT)
         have_err = 1;
      if (cmd.st.listSize == 0)
         have_err = 1;

      /* debug print luna_ha_status_t */
      if (have_err || (loops == 0) || memcmp(&cmd_prev, &cmd, sizeof(cmd_prev))) {
         fprintf(stderr, "DEBUG: GET_HA_STATE: rc = %d. \n", (int)rc);
         fprintf(stderr, "   .version = %lu. \n", (unsigned long)cmd.version);
         fprintf(stderr, "   .instance = %lu. \n", (unsigned long)cmd.instance);
         fprintf(stderr, "   ._slotID = %lu. \n", (unsigned long)cmd._slotID);
         fprintf(stderr, "   ._ckrv = 0x%lx. \n", (unsigned long)cmd._ckrv);
         fprintf(stderr, "   .st.groupSerial = %s. \n", cmd.st.groupSerial);
         fprintf(stderr, "   .st.listSize = %lu. \n", (unsigned long)cmd.st.listSize);
         flag_memberStatus = (cmd.st.listSize > 0) ? 1 : 0;
         for (ul = 0; ul < cmd.st.listSize; ul++) {
            fprintf(stderr, "   .st.memberList[%lu]. \n", (unsigned long)ul);
            fprintf(stderr, "      .memberSerial = %s. \n", cmd.st.memberList[ul].memberSerial);
            fprintf(stderr, "      .memberStatus = 0x%lx. \n", (unsigned long)cmd.st.memberList[ul].memberStatus);
            flag_memberStatus = flag_memberStatus && (cmd.st.memberList[ul].memberStatus == CKR_DEVICE_ERROR);
         }
      }

      memcpy(&cmd_prev, &cmd, sizeof(cmd_prev));

      /* if error then exit this thread; it is the job of the main thread to respawn this thread */
      if (have_err)
         goto err;
   }

   pt->have_fini = 1;
   return;

err:
   fprintf(stderr, "WARNING: " LUNA_FUNC_NAME " is failing. \n");

   /* set pending_Recover */
   pending_Recover = 1;

   pt->have_fini = 1;
   return;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_monitor_init"

/* init/fini the monitor thread */
static void engineperf_monitor_init(foo_key_t *fkey, int want_fini) {
   if (!local_param.want_haGet && !local_param.want_haRecover)
      return;

   if (want_fini) {
      if (pt_monitor != NULL) {
         pt_monitor->want_fini = 1;
         IF_DEBUG(fprintf(stderr, "wait for pt_monitor->have_fini... \n"););
         while (pt_monitor->have_fini == 0) {
            foo_thread_msleep(10);
         }

         IF_DEBUG(fprintf(stderr, "wait for pt_monitor->have_fini ok. \n"););
         free(pt_monitor);
         pt_monitor = NULL;
      }
   } else {
      if (pt_monitor == NULL) {
         pt_monitor = (foo_thread_t *)malloc(sizeof(foo_thread_t));
         if (foo_thread_init(pt_monitor, engineperf_monitor_f, fkey, 0, "(keytype)", (crypto_flavor_t)0))
            goto err;
      }
   }

   return;

err:
   fprintf(stderr, "ERROR: " LUNA_FUNC_NAME " is failing. \n");
   return;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_monitor_finalize_cb"

/* callback function for the monitor thread indicates C_Finalize is complete */
static void engineperf_monitor_finalize_cb(void *cb_context) {
   /* clear pending_Finalize */
   pending_Finalize = 0;
   fprintf(stderr, "INFO: " LUNA_FUNC_NAME " is running: cb_context = 0x%p. \n", (void *)cb_context);

   return;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "engineperf_monitor_flush"

/* flush signals pending in the monitor thread */
static void engineperf_monitor_flush(foo_key_t *fkey) {
   unsigned seconds = 20;
   int rc = 0;

   luna_set_finalize_pending_t cmd;
   memset(&cmd, 0, sizeof(cmd));

   if (pending_Recover && local_param.want_haRecover) {
      /* clear pending_Recover */
      pending_Recover = 0;

      /* flush openssl error messages */
      engineperf_err_flush();

      /* sleep long enough for network stack to wakeup */
      fprintf(stderr, "WARNING: you have %u seconds to restore network connection... \n", (unsigned)seconds);
      fflush(stderr);
      foo_thread_msleep(seconds * 1000);

      /* set pending_Finalize */
      pending_Finalize = 1;

      /* invoke C_Finalize via openssl engine */
      memset(&cmd, 0, sizeof(cmd));
      cmd.version = sizeof(cmd);
      cmd.cb = engineperf_monitor_finalize_cb;
      cmd.cb_context = NULL;
      cmd.flags = 0;
      rc = ENGINE_ctrl_cmd(fkey->e, "SET_FINALIZE_PENDING", 0, &cmd, NULL, 0);
      if (rc != 1)
         goto err;

      /* you may NOT assume that C_Finalize gets called synchronously */
      IF_DEBUG(fprintf(stderr, "wait for pending_Finalize... \n"););
      while (pending_Finalize) {
         foo_thread_msleep(10);
      }
      IF_DEBUG(fprintf(stderr, "wait for pending_Finalize ok. \n"););

      /* invoke C_Initialize via openssl engine */
      /* actually, this gets deferred until the next crypto operation */

      /* if login parameters then login */
      if (local_param.have_login) {
         rc = ENGINE_ctrl_cmd_string(fkey->e, "login", local_param.login, 0);
         if (rc != 1) {
            /* panic because login failure burns login attempts */
            fprintf(stderr, "PANIC: " LUNA_FUNC_NAME ": login is failing. \n");
            engineperf_exit(-1);
         }
      }

      /* respawn monitor thread */
      engineperf_monitor_init(fkey, 1);
      engineperf_monitor_init(fkey, 0);
   } else if (pending_Recover) {
      /* flush openssl error messages */
      engineperf_err_flush();
      /* respawn monitor thread */
      engineperf_monitor_init(fkey, 1);
      engineperf_monitor_init(fkey, 0);
   }

   return;

err:
   fprintf(stderr, "ERROR: " LUNA_FUNC_NAME " is failing. \n");
   return;
}

/**************************************/
/* END OF SAMPLE CODE FOR HA RECOVERY */
/**************************************/

/* report results */
static void luna_stopwatch_report(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T report_size, LUNA_TIME_UNIT_T loops,
                                  int want_hz, const char *context) {
   LUNA_TIME_UNIT_T footime = 0;
   LUNA_TIME_UNIT_T fookbps = 0;
   LUNA_TIME_UNIT_T foohz = 0;
   LUNA_TIME_UNIT_T fookbpsmod = 0;
   LUNA_TIME_UNIT_T foohzmod = 0;

   footime = luna_stopwatch_usec(lsw);
   if ((footime / 1000000) == 0) {
      return; /* divide by zero */
   }

   if (want_hz) {
      foohz = (loops * 10000) / ((footime + 50) / 100);      /* beware of overflow */
      foohzmod = ((loops * 10000) % ((footime + 50) / 100)); /* beware of overflow */
      fprintf(stdout, "%s: %lu loops in %lu micro-seconds (%lu.%lu Hz). \n", (char *)context, (unsigned long)loops,
              (unsigned long)footime, (unsigned long)foohz, (unsigned long)foohzmod);
   } else {
      fookbps = ((report_size * loops) * 1000) / (footime / 1);      /* beware of overflow */
      fookbpsmod = (((report_size * loops) * 1000)) % (footime / 1); /* beware of overflow */
      fprintf(stdout, "%s: %lu loops in %lu micro-seconds (%lu.%lu kBps). \n", (char *)context, (unsigned long)loops,
              (unsigned long)footime, (unsigned long)fookbps, (unsigned long)fookbpsmod);
   }

   fflush(stdout);
}

/* report results (wrapper to luna_stopwatch_report) */
static void luna_stopwatch_report_wrapper(luna_stopwatch_t *lsw, LUNA_TIME_UNIT_T report_size, LUNA_TIME_UNIT_T loops,
                                          int want_hz, int want_verify, const char *keytype, foo_key_t *fkey,
                                          crypto_flavor_t flavor) {
   const char *szFlavor;

   char szblah[LOCAL_MAX_STRING];

   memset(szblah, 0, sizeof(szblah));

   switch (flavor) {
   case crypto_flavor_priv_enc:
      szFlavor = want_verify ? "public_decrypt" : "private_encrypt";
      break;

   case crypto_flavor_priv_dec:
      szFlavor = want_verify ? "private_decrypt" : "public_encrypt";
      break;

   case crypto_flavor_sign:
      szFlavor = want_verify ? "verify" : "sign";
      break;

   case crypto_flavor_digest_sign:
      szFlavor = want_verify ? "digest verify" : "digest sign";
      break;

   case crypto_flavor_pkcs_pss:
      szFlavor = want_verify ? "pkcs pss verify" : "pkcs pss sign";
      break;

   case crypto_flavor_oaep_sha1:
      szFlavor = want_verify ? "oaep sha1 decrypt" : "oaep sha1 encrypt";
      break;

   case crypto_flavor_pkcs_oaep:
      szFlavor = want_verify ? "pkcs oaep decrypt" : "pkcs oaep encrypt";
      break;

   case crypto_flavor_null:
   default:
      szFlavor = "bits";
      break;
   }

   if ( (strcmp("ECDSA", keytype) == 0)
      || (strcmp("LOAD_ECDSA", keytype) == 0) ) {
      snprintf(szblah, sizeof(szblah), "%s %s %s", (char *)keytype, (char *)foo_key_report_name(fkey, keytype), szFlavor);
   } else {
      snprintf(szblah, sizeof(szblah), "%s %u %s", (char *)keytype, (unsigned)(report_size * 8), szFlavor);
   }

   luna_stopwatch_report(lsw, report_size, loops, 1, szblah);
   return;
}

/* main */
int main(int argc, char **argv) {
   const char *sz = NULL;
   int ii = 0;
   foo_key_t fkey;
   ENGINE *eout = NULL;
   OSSL_PROVIDER *prov = NULL;;

   /* init global data */
   memset(&local_param, 0, sizeof(local_param));

   local_param.threads = LOCAL_DEFAULT_THREADS;
   local_param.seconds = LOCAL_DEFAULT_SECONDS;
   local_param.set_default =
       ENGINE_METHOD_ALL; /* (ENGINE_METHOD_RSA | ENGINE_METHOD_DSA | ENGINE_METHOD_RAND | ENGINE_METHOD_ECDSA) */
#ifndef TRY_PKCS11SO_ENGINE
   local_param.load_private = 0;
#else                         /* TRY_PKCS11SO_ENGINE */
   local_param.load_private = 1;
#endif                        /* TRY_PKCS11SO_ENGINE */
   local_param.pk11_slot = 0; /* "0" is the default for pkcs11 engine; you can try "--pkcs11=1". */
   local_param.want_fips = 1;
   local_param.want_engine_impl = 0;
   local_param.want_mgf1_vary = 0;
   local_param.want_rsa_oaep_label = 0;

   /* hello world */
   fprintf(stdout, "Copyright " LOCAL_APP_COPYRIGHT " Thales Group. All rights reserved.\n");
   fprintf(stdout, LOCAL_APP_NAME " is the property of Thales Group and is provided to our customers\n");
   fprintf(stdout, "for the purpose of diagnostic and development only.  Any re-distribution of\n");
   fprintf(stdout, "this program in whole or in part is a violation of the license agreement.\n\n");

   fprintf(stdout, LOCAL_APP_NAME " " LOCAL_APP_VERSION " " __DATE__ " " __TIME__ "\n");
   fflush(stdout);
   fprintf(stdout, "Source: %s: Using %s \n", (char*)__FILE__, (char*)OPENSSL_VERSION_TEXT);
   fflush(stdout);

   /* command-line */
   if (argc > 1) {
      for (ii = 1; ii < argc; ii++) {
         if (strncmp("--enginearg=", argv[ii], strlen("--enginearg=")) == 0) {
            engineperf_sscanf_s(argv[ii], "--enginearg=%s", local_param.enginearg, sizeof(local_param.enginearg));
            local_param.have_enginearg = 1;
         } else if (strncmp("--login=", argv[ii], strlen("--login=")) == 0) {
            engineperf_sscanf_s(argv[ii], "--login=%s", local_param.login, sizeof(local_param.login));
            local_param.have_login = 1;
         } else if (strncmp("--threads=", argv[ii], strlen("--threads=")) == 0) {
            sscanf(argv[ii], "--threads=%u", &local_param.threads);
            if (local_param.threads > LOCAL_MAX_THREAD) {
               local_param.threads = LOCAL_MAX_THREAD;
            }
         } else if (strncmp("--seconds=", argv[ii], strlen("--seconds=")) == 0) {
            sscanf(argv[ii], "--seconds=%u", &local_param.seconds);
         } else if (strcmp("--software", argv[ii]) == 0) {
            local_param.set_default = ENGINE_METHOD_NONE;
            local_param.want_software = 1;
         } else if (strcmp("--load_private", argv[ii]) == 0) {
            local_param.load_private = 1;
         }
#ifdef TRY_PKCS11SO_ENGINE
         else if (strncmp("--pkcs11=", argv[ii], strlen("--pkcs11=")) == 0) {
            sscanf(argv[ii], "--pkcs11=%u", &local_param.pk11_slot);
            local_param.want_pkcs11 = 1;
         }
#endif /* TRY_PKCS11SO_ENGINE */
         else if (strcmp("--haGet", argv[ii]) == 0) {
            local_param.want_haGet = 1;
         } else if (strcmp("--haRecover", argv[ii]) == 0) {
            local_param.want_haRecover = 1;
         } else if (strcmp("--no-cleanup", argv[ii]) == 0) {
            local_param.want_no_cleanup = 1;
         } else if (strncmp("--fips=", argv[ii], strlen("--fips=")) == 0) {
            sscanf(argv[ii], "--fips=%u", &local_param.want_fips);
         } else if (strcmp("--rsasign", argv[ii]) == 0) {
            local_param.only_rsasign = 1;
         } else if (strcmp("--engine_impl", argv[ii]) == 0) {
            local_param.want_engine_impl = 1;
         } else if (strcmp("--mgf1_vary", argv[ii]) == 0) {
            local_param.want_mgf1_vary = 1;
         } else if (strcmp("--rsa_oaep_label", argv[ii]) == 0) {
            local_param.want_rsa_oaep_label = 1;
         } else if (strcmp("--engine", argv[ii]) == 0) {
            local_param.want_engine = 1;
         } else if (strcmp("--provider", argv[ii]) == 0) {
            local_param.want_provider = 1;
            engineperf_strncpy(local_param.providers, "lunaprov,default", sizeof(local_param.providers));
         } else if (strncmp("--providers=", argv[ii], strlen("--providers=")) == 0) {
            engineperf_sscanf_s(argv[ii], "--providers=%s", local_param.providers, sizeof(local_param.providers));
            local_param.want_provider = 1;
         } else {
            fprintf(stderr, "Unrecognized option \"%s\". \n", (char *)argv[ii]);
            fprintf(stderr, "Usage: %s \n", (char *)argv[0]);
            fprintf(stderr, "\t[--enginearg=slot:major:minor]  legacy engine command. \n");
            fprintf(stderr, "\t[--login=slot:major:minor[:password]]   legacy engine command. \n");
            fprintf(stderr, "\t[--threads=UINT]   number of threads (default=%u). \n", (unsigned)LOCAL_DEFAULT_THREADS);
            fprintf(stderr, "\t[--seconds=UINT]   duration of each sub-test (default=%u). \n",
                    (unsigned)LOCAL_DEFAULT_SECONDS);
            fprintf(stderr, "\t[--engine]         use engine (default=gem). \n");
            fprintf(stderr, "\t[--provider]       use provider (default=lunaprov,default). \n");
            fprintf(stderr, "\t[--providers=...]  specify providers. \n");
            fprintf(stderr, "\t[--software]       use software (override engine, provider). \n");
            fprintf(stderr, "\t[--load_private]   call ENGINE_load_private_key. \n");
#ifdef TRY_PKCS11SO_ENGINE
            fprintf(stderr, "\t[--pkcs11=SLOT]    use engine \"pkcs11\" (default=\"" ENGINE_LUNACA3_ID "\"). \n");
#endif /* TRY_PKCS11SO_ENGINE */
            fprintf(stderr, "\t[--fips=UINT]      1 turns on FIPS mode in application (default), otherwise off.\n");
            fprintf(stderr, "\t[--haGet]          Call CA_GetHAState for HA debug purpose. \n");
            fprintf(stderr, "\t[--haRecover]      Call CA_GetHAState for HA recovery purpose. \n");
            fprintf(stderr, "\t[--no-cleanup]     Avoid ENGINE_cleanup (due to segfault?). \n");
            fprintf(stderr, "\t[--rsasign]        Test RSA sign and verify only. \n");
            fprintf(stderr, "\t[--engine_impl]    Use engine implementation (due to FIPS mode in HSM). \n");
            fprintf(stderr, "\t[--mgf1_vary]      Vary the MGF1 for RSA OAEP or PSS (if HSM supports it). \n");
            fprintf(stderr, "\n");
            fflush(stderr);
            engineperf_exit(-1);
         }
      }
   }

   /* check mandatory hardware interface (--engine xor --provider) */
   /* NOTE: it is possible to specify both --engine and --software */
   /* NOTE: likewise, --provider and --software */
   if ( ! LOCAL_XOR_2WAY( local_param.want_engine , local_param.want_provider ) ) {
      fprintf(stderr, "ERROR: must specify exactly one of { --engine , --provider }. \n");
      engineperf_exit(-1);
   }

   fprintf(stdout, "NOTE: number of threads = %u. \n", (unsigned)local_param.threads);

   /* init openssl */
#if defined(LUNA_OSSL3)
   /* best practice: set OPENSSL_INIT_NO_ATEXIT but not OPENSSL_INIT_LOAD_CONFIG */
   OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);
#else
   /* obsolete initialization routines */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
#endif

   /* init openssl thread-safety */
   engineperf_mt_init();

   /* clean fkey */
   memset(&fkey, 0, sizeof(fkey));

   /* load engine or provider */
   if (local_param.want_engine && !local_param.want_provider) {
      sz = engineperf_engine_load(&eout);
      if (sz != NULL) {
         fprintf(stderr, "ERROR: engineperf_engine_load: %s \n", (char *)sz);
         engineperf_exit(-1);
      }
      fkey.e = eout;
      engineperf_engine_connect(&fkey, 0);
   } else if (!local_param.want_engine && local_param.want_provider) {
      sz = engineperf_provider_load(&prov);
      if (sz != NULL) {
         fprintf(stderr, "ERROR: engineperf_provider_load: %s \n", (char *)sz);
         engineperf_exit(-1);
      }
      fkey.prov = prov;
   } else {
      fprintf(stderr, "ERROR: neither engine nor provider specified. \n");
      engineperf_exit(-1);
   }

   /* warn about using the software option with hardware keys */
   if (local_param.want_software) {
      fprintf(stdout, "WARNING: user is bypassing engine with option \"--software\". \n");
      fprintf(stdout, "  Therefore, private key crypto ops will fail when keyfiles refer to hardware keys. \n");
   }

   /* set FIPS mode just before the application requests crypto algorithms */
   if (local_param.want_fips) {
      printf("Attempting to run in FIPS mode.\n");
      if ((!engineperf_FIPS_mode_set(1)) || (!engineperf_FIPS_mode())) {
         fprintf(stderr, "ERROR: failed to enter FIPS mode. \n");
         engineperf_exit(-1);
      }
      printf("Running in FIPS mode.\n");
   } else {
      printf("Not running in FIPS mode.\n");
   }

   /* run the same tests for any number of threads */
   engineperf_monitor_init(&fkey, 0);
   if (!local_param.only_rsasign) {
      engineperf_multi_thread(&fkey, 0, "RAND", crypto_flavor_null);
      engineperf_monitor_flush(&fkey);
   }
#ifndef OPENSSL_NO_RSA
   if (local_param.want_engine) {
      // deprecated along with engine
      engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_sign);
      engineperf_monitor_flush(&fkey);
      engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_sign);
      engineperf_monitor_flush(&fkey);
   }
   engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_digest_sign);
   engineperf_monitor_flush(&fkey);
   engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_digest_sign);
   engineperf_monitor_flush(&fkey);
   engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_pkcs_pss);
   engineperf_monitor_flush(&fkey);
   engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_pkcs_pss);
   engineperf_monitor_flush(&fkey);
   engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_pkcs_oaep);
   engineperf_monitor_flush(&fkey);
   engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_pkcs_oaep);
   engineperf_monitor_flush(&fkey);
   if (!local_param.only_rsasign) {
      if (local_param.want_engine) {
         // deprecated along with engine
         engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_priv_enc);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_priv_enc);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_priv_dec);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_priv_dec);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 0, "RSA", crypto_flavor_oaep_sha1);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 1, "RSA", crypto_flavor_oaep_sha1);
         engineperf_monitor_flush(&fkey);
      }
   }
#endif /*  OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
   if (!local_param.only_rsasign) {
      if (local_param.want_engine) {
         // deprecated along with engine
         engineperf_multi_thread(&fkey, 0, "DSA", crypto_flavor_sign);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 1, "DSA", crypto_flavor_sign);
         engineperf_monitor_flush(&fkey);
      }
      engineperf_multi_thread(&fkey, 0, "DSA", crypto_flavor_digest_sign);
      engineperf_monitor_flush(&fkey);
      engineperf_multi_thread(&fkey, 1, "DSA", crypto_flavor_digest_sign);
      engineperf_monitor_flush(&fkey);
   }
#endif /*  OPENSSL_NO_DSA */
#ifdef LUNA_OSSL_ECDSA
   if (!local_param.only_rsasign) {
      if (local_param.want_engine) {
         // deprecated along with engine
         engineperf_multi_thread(&fkey, 0, "ECDSA", crypto_flavor_sign);
         engineperf_monitor_flush(&fkey);
         engineperf_multi_thread(&fkey, 1, "ECDSA", crypto_flavor_sign);
         engineperf_monitor_flush(&fkey);
      }
      engineperf_multi_thread(&fkey, 0, "ECDSA", crypto_flavor_digest_sign);
      engineperf_monitor_flush(&fkey);
      engineperf_multi_thread(&fkey, 1, "ECDSA", crypto_flavor_digest_sign);
      engineperf_monitor_flush(&fkey);
   }
#endif /*  LUNA_OSSL_ECDSA */
#ifndef OPENSSL_NO_RSA
   if (local_param.want_engine && !local_param.only_rsasign && local_param.load_private != 0) {
      // deprecated along with engine
      engineperf_multi_thread(&fkey, 0, "LOAD_RSA", crypto_flavor_null);
      engineperf_monitor_flush(&fkey);
   }
#endif /*  OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
   if (local_param.want_engine && !local_param.only_rsasign && local_param.load_private != 0) {
      // deprecated along with engine
      engineperf_multi_thread(&fkey, 0, "LOAD_DSA", crypto_flavor_null);
      engineperf_monitor_flush(&fkey);
   }
#endif /*  OPENSSL_NO_DSA */
#ifdef LUNA_OSSL_ECDSA
   if (local_param.want_engine && !local_param.only_rsasign && local_param.load_private != 0) {
      // deprecated along with engine
      engineperf_multi_thread(&fkey, 0, "LOAD_ECDSA", crypto_flavor_null);
      engineperf_monitor_flush(&fkey);
   }
#endif /*  LUNA_OSSL_ECDSA */
   engineperf_monitor_init(&fkey, 1);

/* clean fkey */
#ifndef OPENSSL_NO_RSA
   if (fkey.pkey_rsa != NULL) {
      EVP_PKEY_free(fkey.pkey_rsa);
      fkey.pkey_rsa = NULL;
      fkey.rsa = NULL;
   }
   if (fkey.rsa != NULL) {
      RSA_free(fkey.rsa);
      fkey.rsa = NULL;
   }
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
   if (fkey.pkey_dsa != NULL) {
      EVP_PKEY_free(fkey.pkey_dsa);
      fkey.pkey_dsa = NULL;
      fkey.dsa = NULL;
   }
   if (fkey.dsa != NULL) {
      DSA_free(fkey.dsa);
      fkey.dsa = NULL;
   }
#endif /* OPENSSL_NO_DSA */
#ifdef LUNA_OSSL_ECDSA
   if (fkey.pkey_ec != NULL) {
      EVP_PKEY_free(fkey.pkey_ec);
      fkey.pkey_ec = NULL;
      fkey.ec = NULL;
   }
   if (fkey.ec != NULL) {
      EC_KEY_free(fkey.ec);
      fkey.ec = NULL;
   }
#endif /* LUNA_OSSL_ECDSA */

   engineperf_err_flush();

   /* unload engine or provider */
   if (local_param.want_engine && !local_param.want_provider) {
      engineperf_engine_connect(&fkey, 1);
      sz = engineperf_engine_unload(eout);
      eout = NULL;
      if (sz != NULL) {
         fprintf(stderr, "WARNING: engineperf_engine_unload: %s \n", (char *)sz);
      }
   } else if (!local_param.want_engine && local_param.want_provider) {
      sz = engineperf_provider_unload(prov);
      prov = NULL;
      if (sz != NULL) {
         fprintf(stderr, "WARNING: engineperf_provider_unload: %s \n", (char *)sz);
      }
   }

   /* fini openssl thread-safety */
   engineperf_mt_fini();

   /* fini openssl */
#if defined(LUNA_OSSL_CLEANUP)
   if (!local_param.want_no_cleanup) {
      OPENSSL_cleanup();
   }
#endif

   /* fini global data */
   memset(&local_param, 0, sizeof(local_param));

   return 0;
}

/* print and clear err messages */
static void engineperf_err_flush(void) {
   BIO *bio_err = NULL;

   if (bio_err == NULL) {
      if ((bio_err = BIO_new(BIO_s_file())) != NULL) {
         BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
      }
   }

   if (bio_err != NULL) {
      ERR_print_errors(bio_err);
      BIO_free(bio_err);
   }

   ERR_clear_error();
}

/* exit (dump error stack) */
static void engineperf_exit(int exitcode) {
   engineperf_err_flush();
   exit(exitcode);
}

/*
 * multi-thread support
 *
 * NOTE: multi-threaded applications must call CRYPTO_set_id_callback and CRYPTO_set_locking_callback.
 */

#ifdef ENGINEPERF_NO_LOCKING_CALLBACKS

/* It is no longer necessary to set locking callbacks in a multi-threaded environment. */
static void engineperf_mt_init(void) {}
static void engineperf_mt_fini(void) {}

#else /* ENGINEPERF_NO_LOCKING_CALLBACKS */

#ifdef LUNA_OSSL_WINDOWS

typedef HANDLE engineperf_mutex_t;

#define LUNA_MUTEX_T_INIT NULL
#define LUNA_ERRORLOG printf
#define LUNA_MUTEX_SELF() (GetCurrentThreadId())

/* Init global mutex */
static int engineperf_mutex_init(engineperf_mutex_t *pmu) {
   if (pmu[0] == NULL) /* init once */
   {
      pmu[0] = CreateMutex(NULL, FALSE, NULL);
   }
   return (pmu[0] == NULL) ? 1 : 0;
}

/* Fini global mutex */
static void engineperf_mutex_fini(engineperf_mutex_t *pmu) {
   CloseHandle(pmu[0]);
   pmu[0] = NULL;
}

/* Enter global mutex */
static void engineperf_mutex_enter(engineperf_mutex_t *pmu) {
   DWORD rc = WaitForSingleObject(pmu[0], INFINITE);
   if ((rc != WAIT_ABANDONED) && (rc != WAIT_OBJECT_0)) {
      fprintf(stderr, "exit due to engineperf_mutex_enter \n");
      LUNA_ERRORLOG("exit due to engineperf_mutex_enter");
      exit(-1);
   }
}

/* Exit global mutex */
static void engineperf_mutex_exit(engineperf_mutex_t *pmu) {
   if (ReleaseMutex(pmu[0]) == 0) {
      fprintf(stderr, "exit due to engineperf_mutex_exit \n");
      LUNA_ERRORLOG("exit due to engineperf_mutex_exit");
      exit(-1);
   }
}

#else /* LUNA_OSSL_WINDOWS */

typedef struct engineperf_mutex_s {
   int magic;
   pthread_mutex_t mu;
} engineperf_mutex_t;

#define LUNA_MUTEX_T_INIT \
   { 0 }
#define LUNA_ERRORLOG printf
#define LUNA_MUTEX_SELF() (pthread_self())

/* Init global mutex */
static int engineperf_mutex_init(engineperf_mutex_t *pmu) {
   int rc = -1;
   if (pmu->magic == 0) /* init once */
   {
      memset(pmu, 0, sizeof(*pmu));
      rc = pthread_mutex_init(&(pmu->mu), NULL);
      if (rc == 0) {
         pmu->magic = 0x12345678;
      }
   }
   return (pmu->magic != 0x12345678) ? 1 : 0;
}

/* Fini global mutex */
static void engineperf_mutex_fini(engineperf_mutex_t *pmu) {
   pthread_mutex_destroy(&(pmu->mu));
   memset(pmu, 0, sizeof(*pmu));
}

/* Enter global mutex */
static void engineperf_mutex_enter(engineperf_mutex_t *pmu) {
   if (pthread_mutex_lock(&(pmu->mu)) != 0) {
      fprintf(stderr, "exit due to engineperf_mutex_enter \n");
      LUNA_ERRORLOG("exit due to engineperf_mutex_enter");
      exit(-1);
   }
}

/* Exit global mutex */
static void engineperf_mutex_exit(engineperf_mutex_t *pmu) {
   if (pthread_mutex_unlock(&(pmu->mu)) != 0) {
      fprintf(stderr, "exit due to engineperf_mutex_exit \n");
      LUNA_ERRORLOG("exit due to engineperf_mutex_exit");
      exit(-1);
   }
}

#endif /* LUNA_OSSL_WINDOWS */

/* array of mutexes */
static engineperf_mutex_t lock_cs[CRYPTO_NUM_LOCKS];

/* callback function for openssl lock/unlock */
static void engineperf_mt_cb(int mode, int type, const char *file, int line) {
   if (mode & CRYPTO_LOCK)
      engineperf_mutex_enter(&lock_cs[type]);
   else
      engineperf_mutex_exit(&lock_cs[type]);
}

/* get current thread id */
static unsigned long engineperf_mt_tid(void) {
   return (unsigned long)LUNA_MUTEX_SELF();
}

/* init array of mutexes */
static void engineperf_mt_init(void) {
   int i = 0;
   memset(&lock_cs, 0, sizeof(lock_cs));
   for (i = 0; i < CRYPTO_NUM_LOCKS; i++) {
      engineperf_mutex_init(&lock_cs[i]);
   }

   CRYPTO_set_id_callback(engineperf_mt_tid);
   CRYPTO_set_locking_callback(engineperf_mt_cb);
}

/* fini array of mutexes */
static void engineperf_mt_fini(void) {
   int i = 0;
   CRYPTO_set_locking_callback(NULL);
   for (i = 0; i < CRYPTO_NUM_LOCKS; i++) {
      engineperf_mutex_fini(&lock_cs[i]);
   }
   memset(&lock_cs, 0, sizeof(lock_cs));
}

#endif /* ENGINEPERF_NO_LOCKING_CALLBACKS */

/* SHA256 using EVP */
static int engineperf_SHA256(const unsigned char *d, size_t n, unsigned char *md) {
   return EVP_Digest(d, n, md, NULL, EVP_sha256(), NULL);
}

/* vary saltlen according to loop count, for testing openssl corner cases */
/* NOTE: most apps would simply set saltlen to 0 or to EVP_MD_size(md) */
static int engineperf_vary_saltlen(const EVP_MD *md, foo_thread_t *have_pt, int verify, int want_vary) {
   static int engineperf_loops = 0;
   int loops = have_pt ? (want_vary ? have_pt->loops: 0)
      : (want_vary ? engineperf_loops++ : 0);
   int ret = 0;
   switch (loops % 5) {
   case 0:
      ret = 0; /* no salt */
      break;
#if defined(RSA_PSS_SALTLEN_DIGEST) && defined(RSA_PSS_SALTLEN_AUTO)
   case 1:
   case 2:
      ret = verify ? RSA_PSS_SALTLEN_AUTO : RSA_PSS_SALTLEN_DIGEST;
      break;
#endif
#ifdef RSA_PSS_SALTLEN_MAX
   case 3:
      ret = verify ? RSA_PSS_SALTLEN_AUTO : RSA_PSS_SALTLEN_MAX;
      break;
#endif
   case 4:
   default:
      ret = EVP_MD_size(md); /* saltlen equals digest len */
      break;
   }
   return ret;
}

/* vary label according to loop count, for testing openssl corner cases */
/* NOTE: most apps would simply set label to zero-length string */
static size_t engineperf_vary_label( unsigned char *buf, size_t n, foo_thread_t *have_pt, int want_vary) {
   static int engineperf_loops = 0;
   int loops = have_pt ? (want_vary ? have_pt->loops : 0)
      : (want_vary ? engineperf_loops++ : 0);
   int ret = 0;
   switch (loops % 2) {
   case 0:
      ret = 0; /* no label */
      break;
   case 1:
   default:
      strncpy((char*)buf, "label this", n);
      ret = 10;
      break;
   }
   return ret;
}

#if defined(LUNA_OSSL3)

static int engineperf_FIPS_mode(void) {
   return EVP_default_properties_is_fips_enabled(libctx);
}

static int engineperf_FIPS_mode_set(int r) {
   return EVP_default_properties_enable_fips(libctx, r);
}

#else /* LUNA_OSSL3 */

static int engineperf_FIPS_mode(void) {
   return FIPS_mode();
}

static int engineperf_FIPS_mode_set(int r) {
   return FIPS_mode_set(r);
}

#endif /* LUNA_OSSL3 */


static char *engineperf_strncpy(char *dest, const char *src, size_t n) {
    if (dest == NULL || n < 1)
        return NULL;
    dest[0] = 0;
    if (src != NULL)
        strncpy(dest, src, (n - 1));
    dest[n - 1] = 0;
    return dest;
}

static int engineperf_sscanf_s(const char *str, const char *format, char *dest, size_t maxlen) {
   return sscanf(str, format, dest);
}

/*****************************************************************************/

/* For CodeWarrior */
#if 0
extern "C" {
#endif

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

/* FIXME: bad style */
#include "e_gem_compat.c"

/* eof */
