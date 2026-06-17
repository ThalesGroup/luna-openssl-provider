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

#ifndef NO_HW
#ifndef NO_HW_LUNACA3

#if defined(OS_AIX) || defined(AIX) || defined(_AIX)
#define _POSIX_SOURCE (1)
#define _XOPEN_SOURCE_EXTENDED (1)
#endif /* AIX */

/* openssl headers */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
/* internal: #include <openssl/dso.h> */
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif /* OPENSSL_NO_DSA */

/* assert version is 1.0.0 or higher */
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
#error "OpenSSL version is too old for this engine source!"
#endif

/* detect windows */
#if defined(OPENSSL_SYS_WINDOWS)
#define LUNA_OSSL_WINDOWS (1)
#endif

/* detect pkey_meths (minimum version is 1.0.0d) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x1000004fL)
#define LUNA_OSSL_PKEY_METHS (1)
#endif /* PKEY_METHS */

/* detect ecdsa (minimum version is 0.9.8l or fips 1.2.3) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x00908060L) && !defined(OPENSSL_NO_ECDSA) && !defined(OPENSSL_NO_EC)
#define LUNA_OSSL_ECDSA (1)
#endif /* OPENSSL_NO_ECDSA... */

/* detect auto de-initialize (minimum version 1.1.0) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define LUNA_AUTO_DEINIT (1)
#endif

/* detect sha3 support (minimum version is 1.1.1c) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x1010103fL)
#define LUNA_OSSL_SHA3 (1)
#endif

/* detect sslv3 (cutoff version is 3.0.0) */
#if (1) && (OPENSSL_VERSION_NUMBER < 0x30000000L)
#define LUNA_OSSL_SSLV3 (1)
#endif

/* detect openssl3 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#define LUNA_OSSL3 (1)
#endif

/* NOTE: set private_encode to NULL to avoid openssl clobbering the public key
 * in openssl 1.1.x, openssl3 til further notice
 */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x10101000L)
#define LUNA_OSSL_ASN1_SET_PRIVATE_DSA_NULL (1)
#endif

/* NOTE: EVP_PKEY_asn1_copy does not copy everything in openssl 1.1.x (openssl3 is ok) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x10100000L) && (OPENSSL_VERSION_NUMBER < 0x30000000L)
#define LUNA_OSSL_ASN1_SET_SECURITY_BITS (1)
#endif

/* NOTE: check key pairwise consistency */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define LUNA_OSSL_METH_SET_CHECK_KEYPAIR (1)
#define LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR (1)
#endif

#if defined(LUNA_OSSL_ECDSA)
/* internal: #include <openssl/ec_lcl.h> */
/* internal: #include <openssl/ecs_locl.h> */
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#endif /* LUNA_OSSL_ECDSA */

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef LUNA_OSSL_WINDOWS
#include <windows.h>
#include <process.h>
#include <conio.h>
#include <sys/types.h>
#include <sys/stat.h>
typedef unsigned long LUNA_PID_T;
typedef DWORD LUNA_TIME_UNIT_T;
#define LUNA_GETPID() ((LUNA_PID_T)_getpid())
#else /* LUNA_OSSL_WINDOWS */
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
typedef unsigned long LUNA_PID_T;
typedef unsigned long LUNA_TIME_UNIT_T;
#define LUNA_GETPID() ((LUNA_PID_T)getpid())
#endif /* LUNA_OSSL_WINDOWS */

/* luna headers */
#include "e_gem.h"
#include "e_gem_err.h"
#include "e_gem_compat.h"
#define LUNA_INVALID_HANDLE ((CK_OBJECT_HANDLE)CK_INVALID_HANDLE)
#define LUNA_INVALID_SLOTID ((CK_SLOT_ID)~0UL)
#define LUNACA3_LIB_NAME "Luna gem engine"

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/* For CodeWarrior */
#if 0
}
#endif

/*****************************************************************************/

#ifndef CKR_USER_ALREADY_LOGGED_IN
#define CKR_USER_ALREADY_LOGGED_IN (0x00000100)
#endif
#ifndef CKR_CRYPTOKI_ALREADY_INITIALIZED
#define CKR_CRYPTOKI_ALREADY_INITIALIZED (0x00000191)
#endif

/* Define Cryptoki library config file */
#ifndef LUNA_OSSL_WINDOWS
#define LUNA_CONF_PATH "/etc"
#define LUNA_FILE_SLASH "/"
#define LUNA_CONF_FILE "Chrystoki.conf"
#else
#define LUNA_CONF_PATH "c:\\windows"
#define LUNA_FILE_SLASH "\\"
#define LUNA_CONF_FILE "crystoki.ini"
#endif
#define LUNA_CONF_ENVVAR "ChrystokiConfigurationPath"
#define LUNA_CONF_SECTION "GemEngine"

/* Miscellaneous defines */
#define ENGINE_LUNACA3_ID "gem" /* lowercase is the convention */
#define ENGINE_LUNACA3_NAME "Gem engine support"
#define ENGINE_LUNACA3_RSA_EX_PRIV "Gem RSA private"
#define ENGINE_LUNACA3_RSA_EX_PUB "Gem RSA public"
#define ENGINE_LUNACA3_DSA_EX_PRIV "Gem DSA private"
#define ENGINE_LUNACA3_DSA_EX_PUB "Gem CA3 DSA public"
#define ENGINE_LUNACA3_ECDSA_EX_PRIV "Gem CA3 ECDSA private"
#define ENGINE_LUNACA3_ECDSA_EX_PUB "Gem CA3 ECDSA public"

#define ENGINE_KEY_SECURE "KeySecure"

#define LUNA_PUBLIC (0)
#define LUNA_PRIVATE (1)

/* Number of bytes read per call to C_GenerateRandom */
#define LUNA_RAND_CHUNK (4096)

/* Buffer size large enough to receive formatted string */
#define LUNA_ATOI_BYTES (64)

/* LogLevels */
#define LUNA_LOGLEVEL_CRIT (0)
#define LUNA_LOGLEVEL_ERR (1)
#define LUNA_LOGLEVEL_WARN (2)
#define LUNA_LOGLEVEL_NOTICE (3)
#define LUNA_LOGLEVEL_INFO (4)
#define LUNA_LOGLEVEL_DEBUG (5)
#define LUNA_LOGLEVEL_DEBUG2 (6)

/* Debugging */
#define DEBUG_HW_LUNACA3 1
#if defined(DEBUG_HW_LUNACA3) || defined(CONF_DEBUG) || defined(DEBUG)
#define IF_LUNA_DEBUG(statement__)                        \
   do {                                                   \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_DEBUG) { \
         statement__;                                     \
      }                                                   \
   } while (0)
#define IF_LUNA_DEBUG2(statement__)                        \
   do {                                                    \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_DEBUG2) { \
         statement__;                                      \
      }                                                    \
   } while (0)
#define LOCAL_CONFIG_LUNA_DEBUG (1)
#else
#define IF_LUNA_DEBUG(statement__)
#define IF_LUNA_DEBUG2(statement__)
#undef LOCAL_CONFIG_LUNA_DEBUG
#endif

/* Macros */
#define LUNA_DIM(a__) (sizeof(a__) / sizeof((a__)[0]))
#define LUNA_MIN(a__, b__) (((a__) < (b__)) ? (a__) : (b__))
#define LUNA_DIFF(a__, b__) (((a__) < (b__)) ? ((b__) - (a__)) : ((a__) - (b__)))

/* Errorlog, Eventlog, ProfileLog */
static void luna_xlog(int level, const char *msg, unsigned long lvalue);
#define LUNA_LOGLEVEL_EVENT LUNA_LOGLEVEL_NOTICE
#define LUNA_LOGLEVEL_PROFILE LUNA_LOGLEVEL_INFO
#define LUNA_TO_ULONG(_x) ((unsigned long)(size_t)(_x))
#define LUNA_ERRORLOG(_m)                                      \
   do {                                                        \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_ERR) {        \
         luna_xlog(LUNA_LOGLEVEL_ERR, (_m), LUNA_TO_ULONG(0)); \
      }                                                        \
   } while (0)
#define LUNA_ERRORLOGL(_m, _l)                                  \
   do {                                                         \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_ERR) {         \
         luna_xlog(LUNA_LOGLEVEL_ERR, (_m), LUNA_TO_ULONG(_l)); \
      }                                                         \
   } while (0)
#define LUNA_EVENTLOG(_m)                                        \
   do {                                                          \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_EVENT) {        \
         luna_xlog(LUNA_LOGLEVEL_EVENT, (_m), LUNA_TO_ULONG(0)); \
      }                                                          \
   } while (0)
#define LUNA_EVENTLOGL(_m, _l)                                    \
   do {                                                           \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_EVENT) {         \
         luna_xlog(LUNA_LOGLEVEL_EVENT, (_m), LUNA_TO_ULONG(_l)); \
      }                                                           \
   } while (0)
#define LUNA_PROFILELOGL(_m, _l)                                    \
   do {                                                             \
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_PROFILE) {         \
         luna_xlog(LUNA_LOGLEVEL_PROFILE, (_m), LUNA_TO_ULONG(_l)); \
      }                                                             \
   } while (0)

/* definitions for cached data */
#define LUNA_MAX_SLOT (2)
#define LUNA_MAX_LABEL (32)
#define LUNA_MIN_LABEL (7) /* 7 = short enough to remember; long enough to avoid conflicts */

struct luna_cache_s;

struct luna_cache_s {
   /* pointer to next item */
   struct luna_cache_s *next;

   /* various data to cache */
   CK_SESSION_HANDLE ckses;
};

typedef struct luna_cache_s luna_cache_t;

#define LUNA_CACHE_T_INIT \
   { NULL, LUNA_INVALID_HANDLE }

typedef void (*luna_cache_delete_callback_f)(luna_cache_t *item, int index);

static luna_cache_t luna_ckses[LUNA_MAX_SLOT] = {LUNA_CACHE_T_INIT, LUNA_CACHE_T_INIT};

static void luna_cache_init(luna_cache_t *qu);
static void luna_cache_fini(luna_cache_t *qu);
static void luna_cache_push(luna_cache_t *qu, luna_cache_t *item);
static luna_cache_t *luna_cache_pop(luna_cache_t *qu);
static luna_cache_t *luna_cache_new_ckses(CK_SESSION_HANDLE ckses);
static void luna_cache_delete_item(luna_cache_t *item);
static void luna_cache_delete_ALL(luna_cache_t *head, luna_cache_delete_callback_f cb);

/* Definitions for managing session contexts */
typedef struct luna_context_st {
   int flagInit;               /* flag; true if valid */
   CK_SLOT_ID slotid;          /* slot id */
   CK_SESSION_HANDLE hSession; /* the session handle */
   int purpose;                /* enum; indicating terms of use; e.g., encrypt (if applicable) */
   LUNA_PID_T pid;             /* process id */
   unsigned count_c_init;      /* library init count */
   luna_cache_t *pcache;       /* pointer to cache item */
   unsigned per_slot_id;       /* per slot id */
   int flagFinalizePending;    /* flag; true if mutex held for purpose of C_Finalize */
   CK_RV rv_last;
   int flagError;              /* flag; true if previous open failed */
} luna_context_t;

#define LUNA_CONTEXT_T_INIT \
   { 0, 0, 0, 0, 0, 0, NULL, 0, 0, CKR_OK, 0 }

/* Definitions for managing passphrase */
typedef struct {
   int boolInit;               /* flag; true if valid */
   char *szPass;               /* pass phrase */
   CK_SESSION_HANDLE hSession; /* the session handle */
} luna_passphrase_t;

#define LUNA_PASSWD_T_INIT \
   { 0, NULL, LUNA_INVALID_HANDLE }
#define LUNA_PASSWD_MAXLEN (255)
#define LUNA_PASSWD_MAXBLK (20 + (LUNA_PASSWD_MAXLEN + 1) + 4) /* must be a multiple of 20 */
#define LUNA_FILENAME_MAXLEN (255)

/* Functions that require engine */
static int luna_init_engine(ENGINE *e);
static int luna_finish_engine(ENGINE *e);
static int luna_ctrl_engine(ENGINE *e, int cmd, long i, void *p, void (*f)(void));
static int luna_cmdarg_engine_ext2(char *arg, int cmd);
static int luna_bind_engine(ENGINE *e);
static int luna_destroy_engine(ENGINE *e);

/* Miscellaneous Functions */
static int luna_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int luna_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int luna_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int luna_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

typedef struct luna_oaep_params_st {
    const EVP_MD *oaep_md;
    const EVP_MD *mgf1_md;
    unsigned char *oaep_label;
    int labellen;
} luna_oaep_params;

static int luna_rsa_priv_dec_x509(luna_oaep_params *oaep_params, int flen, const unsigned char *from, size_t tolen, unsigned char *to, RSA *rsa, int padding);
static char *luna_strncpy(char *dest, const char *src, size_t n);

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
static int luna_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
static int luna_rsa_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
static int luna_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

static DSA_SIG *luna_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int luna_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
static int luna_dsa_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa);

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
static int luna_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */

static int luna_set_app_id(CK_ULONG appid_hi, CK_ULONG appid_lo);
static int luna_open_session(CK_SLOT_ID slotid, CK_SESSION_HANDLE *shandle);
static int luna_close_session(CK_SESSION_HANDLE hSession);
static int luna_open_session_and_login(CK_SLOT_ID slotid, CK_SESSION_HANDLE *shandle, char *password);
static int luna_parse_session_desc(const char *p, session_desc *desc, char **password);
static char *luna_parse_slotid2(const char *p, int *pflaglabel);
static int luna_logout(CK_SESSION_HANDLE hSession);
#ifdef LUNA_RAND_RETURN_VALUE
static int luna_rand_seed(const void *buf, int num);
static int luna_rand_add(const void *buf, int num, double add_entropy);
#else
static void luna_rand_seed(const void *buf, int num);
static void luna_rand_add(const void *buf, int num, double add_entropy);
#endif
static int luna_rand_bytes(unsigned char *buf, int num);
static void luna_rand_cleanup(void);
static int luna_rand_pseudo_bytes(unsigned char *buf, int num);
static int luna_rand_status(void);
static int luna_open_context(luna_context_t *context);
static int luna_open_context_ndx(luna_context_t *context, unsigned ndx_specific);
static void luna_close_context(luna_context_t *context);
static void luna_close_context_w_err(luna_context_t *context, int flag_err, CK_RV rv_last);
static int luna_init_properties2(void);
static void luna_fini_properties2(void);
static char *luna_getprop(const char *confpath, const char *ssection, const char *svalue);
static int luna_get_session_info(CK_SESSION_HANDLE shandle, CK_SESSION_INFO_PTR psinfo);
static CK_ULONG get_ulong_serial_from_string_serial(CK_CHAR *serialString, CK_ULONG defaultSerial);
static int luna_get_ha_state(CK_SLOT_ID slotid, luna_ha_status_v2_t *d);
static int luna_set_conf_path(char *p);
static int luna_set_disable_check_finalize(char *p);
static int luna_set_intermediate_processes(char *p);
static char *luna_get_conf_path(void);
static int luna_set_engine_init(char *p);
static int luna_set_engine2_init(char *p);
static char *luna_get_engine_init(void);
static char *luna_get_engine2_init(void);
static char *luna_get_engine_init_ndx(unsigned ndx);
static char *luna_itoa(char *buffer, unsigned value);
#ifdef LOCAL_CONFIG_LUNA_DEBUG
static void luna_dumpdata(char *prefix, const void *data, const size_t len);
static void luna_dump_s(char *prefix, const char *value);
static void luna_dump_l(char *prefix, long value);
#endif
static char *luna_filenamedup(char *spath, char *sfile);

/* stub functions, that must return success */
static CK_RV STUB_CA_SetApplicationID(CK_ULONG major, CK_ULONG minor) {
    return CKR_OK;
}

/* stub functions, that must return failure */
static CK_RV STUB_CT_HsmIdFromSlotId(CK_SLOT_ID slotID, unsigned int *pHsmID) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV STUB_CA_GetHAState(CK_SLOT_ID slotId, CK_HA_STATE_PTR pState) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV STUB_CA_DeriveKeyAndWrap(
        CK_SESSION_HANDLE hSession,          /* session */
        CK_MECHANISM_PTR  pMechanism,        /* derive mechanism */
        CK_OBJECT_HANDLE  hBaseKey,          /* base key */
        CK_ATTRIBUTE_PTR  pTemplate,         /* extra derive parameters (public key?) */
        CK_ULONG          ulAttributeCount,  /* template length */
        CK_MECHANISM_PTR  pMechanismWrap,    /* wrap mechanism (can be no-encryption for now) */
        CK_OBJECT_HANDLE  hWrappingKey,      /* wrap key (can be NULL for now) */
        CK_BYTE_PTR       pWrappedKey,       /* gets wrapped key */
        CK_ULONG_PTR      pulWrappedKeyLens) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV STUB_CA_EncapsulateKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hPublicKey,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulAttributeCount,
    CK_BYTE_PTR          pCiphertext,
    CK_ULONG_PTR         pulCiphertextLen,
    CK_OBJECT_HANDLE_PTR phKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV STUB_CA_DecapsulateKey(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hPrivateKey,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulAttributeCount,
    CK_BYTE_PTR          pCiphertextKey,
    CK_ULONG             ulCiphertextLen,
    CK_OBJECT_HANDLE_PTR phKey) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static int luna_ps_check_lib(void);
static int luna_pa_check_lib(void);

static CK_OBJECT_HANDLE luna_find_dsa_handle(luna_context_t *ctx, DSA *dsa, int hintPrivate);
static CK_OBJECT_HANDLE luna_find_dsa_handle_FAST(luna_context_t *ctx, DSA *dsa, int hintPrivate);
static CK_OBJECT_HANDLE luna_find_rsa_handle(luna_context_t *ctx, RSA *rsa, int hintPrivate);
static CK_OBJECT_HANDLE luna_find_rsa_handle_FAST(luna_context_t *ctx, RSA *rsa, int hintPrivate);

static int luna_attribute_malloc(luna_context_t *ctx, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pAttr);
static int luna_attribute_malloc_FAST(luna_context_t *ctx, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pAttr,
                                      unsigned nAttr);
static int luna_attribute_malloc2(CK_ATTRIBUTE_PTR pAttr, CK_ULONG type, CK_VOID_PTR value, CK_ULONG len);
static void luna_attribute_free(CK_ATTRIBUTE_PTR p_attr);
static void luna_attribute_free_all(CK_ATTRIBUTE_PTR p_attr, unsigned max_attr);

static int luna_find_object_ex1(luna_context_t *ctx, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
                                CK_OBJECT_HANDLE_PTR pHandle, int flagCountMustEqualOne);

static int luna_get_rsa_ex(void);
static int luna_get_dsa_ex(void);
static int luna_get_ecdsa_ex(void);
static int luna_get_disable_rsa(void);
static int luna_get_disable_dsa(void);
static int luna_get_disable_ecdsa(void);
static int luna_get_enable_load_privkey(void);
static int luna_get_enable_load_pubkey(void);
#if defined(LUNA_OSSL_PKEY_METHS)
static int luna_get_enable_pkey_meths(void);
static int luna_get_enable_pkey_asn1_meths(void);
#endif
static int luna_get_disable_register_all(void);
static int luna_get_enable_digests(void);
static int luna_get_enable_login_init(void);
static int luna_get_enable_rsa_gen_key_pair(void);
static int luna_get_enable_dsa_gen_key_pair(void);
static int luna_get_enable_pqc_gen_key_pair(void);
static int luna_get_enable_ec_gen_key_pair(void);
static int luna_get_enable_ed_gen_key_pair(void);
static int luna_get_enable_em_gen_key_pair(void);
static int luna_get_recovery_level(void);
static int luna_get_token_object(void);
static int luna_get_pqc_shim(void);
static int luna_get_DelegateHwPqcKemEncapToSw(void);
static int luna_get_DelegateSwPqcKemEncapRngToHw(void);

static int luna_gets_passphrase(const char *szslotid, char *secretString, unsigned maxlen);
static int luna_gets_passdll(const char *szslotid, char *secretString, unsigned maxlen, const char *szdll);
static char *luna_sprintf_hex(char *fp0, unsigned char *id, unsigned size);
static int luna_SHA1(const unsigned char *d, size_t n, unsigned char *md);
static int luna_SHA1too(const unsigned char *d1, size_t n1, const unsigned char *d2, size_t n2, unsigned char *md);
static int luna_RAND_bytes(unsigned char *buf, int num);

/* mutex */
static int luna_mutex_init(void);
static void luna_mutex_fini(void);
static void luna_mutex_enter(void);
static void luna_mutex_exit(void);
static void luna_mutex_enter_ndx(unsigned ndx);
static void luna_mutex_exit_ndx(unsigned ndx);

#define LUNA_MUTEX_NDX_HW (0)
#define LUNA_MUTEX_NDX_SW (1)

/* check key in hardware or not */
#define LUNA_CHECK_IS_HARDWARE 0
#define LUNA_CHECK_IS_SOFTWARE 1
#define LUNA_CHECK_ERROR (-1)

static int luna_rsa_check_private(RSA *rsa);
static int luna_rsa_check_public(RSA *rsa);
static int luna_dsa_check_private(DSA *dsa);
static int luna_dsa_check_public(DSA *dsa);

/* pkcs#11 library */
static int luna_load_p11(void);
static void luna_unload_p11(void);
static int luna_init_p11_conditional_ex(int have_lock);
static void luna_fini_p11(void);

static void *LUNA_malloc(int size0);
static void LUNA_free(void *ptr0);
static int LUNA_cleanse(void *ptr0, int size0);
static int LUNA_cleanse_free(void *ptr0, int size0);

typedef struct luna_stopwatch_s {
   LUNA_TIME_UNIT_T t0;
   LUNA_TIME_UNIT_T t1;
} luna_stopwatch_t;

static void luna_stopwatch_start(luna_stopwatch_t *lsw);
static void luna_stopwatch_stop(luna_stopwatch_t *lsw);
static LUNA_TIME_UNIT_T luna_stopwatch_usec(luna_stopwatch_t *lsw);

/* Dynamic shared object interface */
typedef void* LUNA_DSO_T;
typedef void (*LUNA_DSO_F)(void);
static LUNA_DSO_T luna_dso_load(const char *szDll);
static LUNA_DSO_F luna_dso_bind_func(LUNA_DSO_T dso, const char *szFunction);
static void luna_dso_free(LUNA_DSO_T dso);

/* sleep */
static void luna_sleep_milli(unsigned millisecs);

/* Forward reference (load priv/pub key) */
static EVP_PKEY *luna_load_privkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data);
static EVP_PKEY *luna_load_pubkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data);

static int luna_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
static int luna_dsa_keygen(DSA *dsa);
static int luna_label_to_slotid(const char *tokenlabel, CK_SLOT_ID *pslotid);
static int luna_ckatab_pre_keygen(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *tab, CK_ULONG tabsize);

static void LUNA_pw_malloc(luna_passphrase_t *ppw, char *szpw);
static void LUNA_pw_free(luna_passphrase_t *ppw);
static CK_RV LUNA_pw_login(luna_passphrase_t *ppw, CK_SESSION_HANDLE hSession);

#ifdef LUNA_OSSL_PKEY_METHS
static int luna_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
static int luna_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid);
static void luna_pkey_init_meth_table(void);
static void luna_pkey_fini_meth_table(void);
#endif
static int luna_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
static int luna_gets_passfile(const char *filename, char *password, unsigned maxlen);
static int luna_parse_password(const char *p, char **password);

static CK_USER_TYPE luna_get_userType(void);
static int luna_get_rsaPkcsPaddingType(void);

static void luna_register_atexit_handler(void);
static int luna_get_flag_exit(void);

#ifdef LUNA_OSSL_ASN1_SET_SECURITY_BITS
static int luna_rsa_security_bits(const EVP_PKEY *pkey);
static int luna_dsa_security_bits(const EVP_PKEY *pkey);
static int luna_ec_security_bits(const EVP_PKEY *pkey);
#endif

#if defined(LUNA_OSSL_METH_SET_CHECK_KEYPAIR) || defined(LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR)
static int luna_rsa_check_keypair0(EVP_PKEY *pkey);
static int luna_dsa_check_keypair0(EVP_PKEY *pkey);
static int luna_ec_check_keypair0(EVP_PKEY *pkey);
#endif
#ifdef LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR
static int luna_rsa_check_keypair1(const EVP_PKEY *pkey);
static int luna_dsa_check_keypair1(const EVP_PKEY *pkey);
static int luna_ec_check_keypair1(const EVP_PKEY *pkey);
#endif

#ifdef LUNA_CONFIG_OSSL_PROVIDER
/* openssl security level 2 */
#define LUNA_RSA_KEYSIZE_MIN (2048)
#define LUNA_DSA_KEYSIZE_MIN (2048)
#define LUNA_DSA_QBITS_MIN (224)
#define LUNA_EC_KEYSIZE_MIN (224)
#else
/* openssl security level 1 */
#define LUNA_RSA_KEYSIZE_MIN (1024)
#define LUNA_DSA_KEYSIZE_MIN (1024)
#define LUNA_DSA_QBITS_MIN (224)
#define LUNA_EC_KEYSIZE_MIN (160)
#endif

/* Global data (per slot data) */
struct luna_per_slot_s {
   CK_SLOT_ID g_slot_id;
   CK_SESSION_HANDLE g_session_handle;
   volatile int g_luna_rsa_ex_priv;
   volatile int g_luna_rsa_ex_pub;
   volatile int g_count_activity;
   volatile int g_luna_dsa_ex_priv;
   volatile int g_luna_dsa_ex_pub;
   volatile int g_luna_ecdsa_ex_priv;
   volatile int g_luna_ecdsa_ex_pub;
};

typedef struct luna_per_slot_s luna_per_slot_t;

static luna_per_slot_t g_luna_per_slot[LUNA_MAX_SLOT] = {{LUNA_INVALID_SLOTID, LUNA_INVALID_HANDLE, -1, -1, 0, -1, -1, -1, -1},
                                                         {LUNA_INVALID_SLOTID, LUNA_INVALID_HANDLE, -1, -1, 0, -1, -1, -1, -1}};

static luna_passphrase_t g_pw_per_slot[LUNA_MAX_SLOT] = {LUNA_PASSWD_T_INIT, LUNA_PASSWD_T_INIT};

/* Global data (library load state) */
static LUNA_DSO_T luna_dso = NULL;
static volatile int luna_have_c_funclist = 0;

/* Global data (library init state) */
static volatile int luna_have_c_init = 0;
static volatile int luna_have_c_error = 0;
static volatile unsigned luna_count_c_init = 1; /* the count is never equal to zero */
static volatile int g_count_activity = 0;

/* Global data (for user configuration) */
static struct {
   char *CONF_PATH;
   char *CONF_ENGINE_INIT;
   char *CONF_ENGINE2_INIT;
} g_preconfig = {NULL, NULL, NULL};

static struct {
   char *SO_PATH;
   char *EngineInit;
   char *RSA_EX;
   char *LogLevel;

   char *Appliance;
   char *DisableRsa;
   char *DisableDsa;
   char *DisableRand;

   char *EnableLoadPrivKey;
   char *EnableLoadPubKey;
   char *DisableCheckFinalize;
   char *IntermediateProcesses;

   char *Engine2Init; /* experimental */
   char *LogRootDir;
   char *DisableSessionCache;
   char *DisableEcdsa; /* misnomer: should be DisableEc since it applies to ecdsa and ecdh, etc */

   char *EnableRsaEx;
   char *EnableDsaEx;
   char *EnableEcdsaEx;
   char *DisableMultiThread;

   char *EnableLoginInit;
   char *EnableRsaGenKeyPair;
   char *EnableDsaGenKeyPair;
   char *EnableRsaSignVerify;

   char *DisablePublicCrypto;
   char *EnablePkeyMeths;
   char *EnablePkeyAsn1Meths;
   char *EnableDigests;

   char *DisableRegisterAll;
   char *EnableLimitedUser;
   char *EnableRsaPkcsPadding; /* do rsaPkcsPadding in the engine, raw rsa in the hsm */
   char *IncludePqc; /* algorithm names to enable in hardware or ALL by default */

   char *ExcludePqc; /* algorithms to disable in hardware or NONE by default */
   char *EnablePqcGenKeyPair; /* PQC keypair generation */
   char *EnableEcGenKeyPair; /* EC keypair generation for PQC-hybrid and Classic */
   char *RecoveryLevel; /* 0 = no recovery, 1 = c_login, 2 = c_finalize */

   char *EnableEdGenKeyPair; /* EC-EDWARDS keypair generation for PQC-hybrid and Classic */
   char *EnableEmGenKeyPair; /* EC-MONTGOMERY keypair generation for PQC-hybrid and Classic */
   char *EnableTokenObject; /* create persistent objects in HSM (default=1) */
   char *EnablePqcShim; /* using the PQC shim (default=0) */

   char *DelegateHwPqcKemEncapToSw; /* delegate hardware-bound pqc kem encap to software (default=0) */
   char *DelegateSwPqcKemEncapRngToHw; /* delegate software-bound pqc rng to hardware (default=0) */

} g_config = {NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL, NULL, NULL,
              NULL, NULL};

static struct {
   volatile int LogLevel;
   volatile int DisableCheckFinalize;
   volatile int IntermediateProcesses;
   volatile int DisableRand;
   volatile int DisableSessionCache;

   volatile int DisableMultiThread;
   volatile int DisablePublicCrypto;
} g_postconfig = {0, 0, 0, 0, 0, 0, 0};

static struct {
   volatile LUNA_PID_T pid_bind;         /* process id when luna_bind_engine was called the first time */
   volatile int pid_intermediate_count;  /* intermediate processes count.  Counter to keep track of how many processes
                                            deep the current process is. */
   volatile LUNA_PID_T pid_intermediate; /* process id of latest intermediate process after changing from pid_bind */
   volatile LUNA_PID_T pid_c_init;       /* process id when C_Initialize was called */
   volatile int in_child_v;              /* flag true when running in child process (virtual) */
} g_rtconfig = {0, 0, 0, 0, 0};

static int skip_c_initialize = 0;

/* Library entry points */
static struct {
   CK_C_GetFunctionList C_GetFunctionList;
   CK_FUNCTION_LIST_PTR std;
   struct {
      CK_CA_SetApplicationID CA_SetApplicationID;
      CK_CT_HsmIdFromSlotId CT_HsmIdFromSlotId;
      CK_CA_GetHAState CA_GetHAState;
      CK_CA_DeriveKeyAndWrap CA_DeriveKeyAndWrap;
      CK_CA_EncapsulateKey CA_EncapsulateKey;
      CK_CA_DecapsulateKey CA_DecapsulateKey;
   } ext;
} p11 = {0, 0, {0, 0, 0, 0, 0, 0}};

/* Saved function pointers */
static int (*saved_rsa_pub_dec)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) = NULL;
static int (*saved_rsa_pub_enc)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) = NULL;
static int (*saved_rsa_priv_enc)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) = NULL;
static int (*saved_rsa_priv_dec)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) = NULL;

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
static struct _saved_rsa {
   int (*sign_init)(EVP_PKEY_CTX *ctx);
   int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
   int (*decrypt_init)(EVP_PKEY_CTX *ctx);
   int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
   int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
   int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
} saved_rsaenc = { NULL, NULL, NULL, NULL, NULL, NULL },
  saved_rsapss = { NULL, NULL, NULL, NULL, NULL, NULL };
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

static DSA_SIG *(*saved_dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa) = NULL;
static int (*saved_dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp) = NULL;
static int (*saved_dsa_do_verify)(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa) = NULL;

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
static struct _saved_dsa {
   int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
   int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
} saved_dsa = { NULL, NULL };
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */

#if defined(LUNA_OSSL_ECDSA)
static int (*saved_ecdsa_sign)(int type, const unsigned char *dgst, int dlen,
      unsigned char *sigbuf, unsigned int *siglen, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *dsa) = NULL;
static ECDSA_SIG *(*saved_ecdsa_do_sign)(const unsigned char *dgst, int dlen, const BIGNUM *, const BIGNUM *,
                                         EC_KEY *eckey) = NULL;
static int (*saved_ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp) = NULL;
static int (*saved_ecdsa_do_verify)(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
                                    EC_KEY *eckey) = NULL;
static int (*saved_ecdsa_keygen)(EC_KEY *key) = NULL;
static int (*saved_ecdsa_compute_key)(unsigned char **psec, size_t *pseclen,
                                      const EC_POINT *pub_key, const EC_KEY *ecdh) = NULL;
#endif

/* Command codes (legacy functions) */
#define ENGINE_CMD_LUNA_LEGACY_DEV_SELECT (ENGINE_CMD_BASE + 0)
#define ENGINE_CMD_LUNA_LEGACY_OPEN_SESSION_BY_STRUCT (ENGINE_CMD_BASE + 1)
#define ENGINE_CMD_LUNA_LEGACY_LOGIN (ENGINE_CMD_BASE + 2)
#define ENGINE_CMD_LUNA_ENGINE_CMD_BASE (ENGINE_CMD_BASE + 3)

/* Command codes (exported through ENGINE_CMD_DEFN structure) */
#define ENGINE_CMD_LUNA_ENGINEARG (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 0)
#define ENGINE_CMD_LUNA_OPEN_SESSION_BY_STRING (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 1)
#define ENGINE_CMD_LUNA_CLOSE_SESSION_BY_STRING (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 2)
#define ENGINE_CMD_LUNA_LOGIN_BY_STRING (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 3)
#define ENGINE_CMD_LUNA_LOGOUT_BY_STRING (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 4)
#define ENGINE_CMD_LUNA_ENGINEINIT (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 5)
#define ENGINE_CMD_LUNA_CONFPATH (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 6)
#define ENGINE_CMD_LUNA_CONF_ENGINE_INIT (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 7)
#define ENGINE_CMD_LUNA_CONF_ENGINE2_INIT (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 8)
#define ENGINE_CMD_LUNA_ENGINE2INIT (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 9)
#define ENGINE_CMD_LUNA_DISABLECHECKFINALIZE (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 10)
#define ENGINE_CMD_LUNA_SO_PATH (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 11)
#define ENGINE_CMD_LUNA_GET_HA_STATE (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 12)
#define ENGINE_CMD_LUNA_SET_FINALIZE_PENDING (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 13)
#define ENGINE_CMD_LUNA_SKIP_C_INITIALIZE (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 14)
#define ENGINE_CMD_LUNA_INTERMEDIATEPROCESSES (ENGINE_CMD_LUNA_ENGINE_CMD_BASE + 15)

#define ENGINE_ENGINE_INIT_PASSWORD_SZ \
   "[:password=<password>][:passfile=<filename>][:passenv=<variable>][:passdev=console]"
/* Engine command definitions */
static const ENGINE_CMD_DEFN luna_cmd_defns[] = {
    /* New commands that were created especially for CMD_DEFN */
    {ENGINE_CMD_LUNA_ENGINEARG, "enginearg", "enginearg:<slot>:<appid>:<appid>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_OPEN_SESSION_BY_STRING, "openSession", "openSession:<slot>:<appid>:<appid>",
     ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_CLOSE_SESSION_BY_STRING, "closeSession", "closeSession:<slot>:<appid>:<appid>",
     ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_LOGIN_BY_STRING, "login", "login:<slot>:<appid>:<appid>[:<password>]", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_LOGOUT_BY_STRING, "logout", "logout:<slot>:<appid>:<appid>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_ENGINEINIT, "engineinit", "engineinit:<slot>:<appid>:<appid>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_CONFPATH, "CONF_PATH", "CONF_PATH:/path/to/chrystoki/conf", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_CONF_ENGINE_INIT, "ENGINE_INIT",
     "ENGINE_INIT:<slot>:<appid>:<appid>" ENGINE_ENGINE_INIT_PASSWORD_SZ, ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_CONF_ENGINE2_INIT, "ENGINE2_INIT",
     "ENGINE2_INIT:<slot>:<appid>:<appid>" ENGINE_ENGINE_INIT_PASSWORD_SZ, ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_ENGINE2INIT, "engine2init", "engine2init:<slot>:<appid>:<appid>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_DISABLECHECKFINALIZE, "DisableCheckFinalize", "DisableCheckFinalize:<value>",
     ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_SO_PATH, "SO_PATH", "SO_PATH:<path>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_GET_HA_STATE, "GET_HA_STATE", "GET_HA_STATE:<pointer>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_SET_FINALIZE_PENDING, "SET_FINALIZE_PENDING", "SET_FINALIZE_PENDING:<pointer>",
     ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_SKIP_C_INITIALIZE, "SKIP_C_INITIALIZE", "SKIP_C_INITIALIZE:<value>", ENGINE_CMD_FLAG_STRING},
    {ENGINE_CMD_LUNA_INTERMEDIATEPROCESSES, "IntermediateProcesses", "IntermediateProcesses:<value>",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}};

/* RSA entry points */
/* possible flags: RSA_FLAG_FIPS_METHOD, RSA_FLAG_NON_FIPS_ALLOW, RSA_FLAG_EXT_PKEY */
static RSA_METHOD *p_luna_rsa_method = NULL; /* aka "Luna RSA method" */

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
static EVP_PKEY_METHOD *p_luna_evp_pkey_rsaenc = NULL;
static EVP_PKEY_METHOD *p_luna_evp_pkey_rsapss = NULL;
#ifdef LUNA_RSA_USE_EVP_ASN1_METHS
static EVP_PKEY_ASN1_METHOD *p_luna_asn1_rsaenc = NULL;
static EVP_PKEY_ASN1_METHOD *p_luna_asn1_rsapss = NULL;
#endif /* LUNA_RSA_USE_EVP_ASN1_METHS */
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

/* DSA entry points */
/* possible flags: DSA_FLAG_FIPS_METHOD, DSA_FLAG_NON_FIPS_ALLOW, (DSA_FLAG_EXT_PKEY) */
static DSA_METHOD *p_luna_dsa_method = NULL; /* aka "Luna DSA method" */

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
static EVP_PKEY_METHOD *p_luna_evp_pkey_dsa = NULL;
#ifdef LUNA_DSA_USE_EVP_ASN1_METHS
static EVP_PKEY_ASN1_METHOD *p_luna_asn1_dsa = NULL;
#endif /* LUNA_DSA_USE_EVP_ASN1_METHS */
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */

#if defined(LUNA_OSSL_ECDSA)
/* Forward reference */
static CK_OBJECT_HANDLE luna_find_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, int hintPrivate);
static CK_OBJECT_HANDLE luna_find_ecdsa_handle_FAST(luna_context_t *ctx, EC_KEY *dsa, int hintPrivate);
static void luna_cache_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, CK_OBJECT_HANDLE hPublic, CK_OBJECT_HANDLE hPrivate);
static ECDSA_SIG *luna_ecdsa_do_sign(const unsigned char *dgst, int dlen, const BIGNUM *inv, const BIGNUM *rp,
                                     EC_KEY *dsa);
static int luna_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *bnctx, BIGNUM **kinv, BIGNUM **r);
static int luna_ecdsa_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *dsa);
static int luna_ecdsa_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sigbuf, unsigned int *siglen, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *dsa);
static int luna_ecdsa_verify(int type, const unsigned char *dgst, int dlen, const unsigned char *sigbuf, int siglen, EC_KEY *dsa);
static int luna_ecdsa_keygen(EC_KEY *key);
static int luna_ecdsa_compute_key(unsigned char **psec, size_t *pseclen,
                                  const EC_POINT *pub_key, const EC_KEY *ecdh);

/* ECDSA entry points */
/* possible flags: ECDSA_FLAG_FIPS_METHOD, EC_FLAG_NON_FIPS_ALLOW, (EC_FLAG_EXT_PKEY), (EC_FLAG_FIPS_CHECKED) */
static LUNA_EC_KEY_METHOD *p_luna_ecdsa_method = NULL;

#ifdef LUNA_EC_USE_EVP_PKEY_METHS
static EVP_PKEY_METHOD *p_luna_evp_pkey_ec = NULL;
#ifdef LUNA_EC_USE_EVP_ASN1_METHS
static EVP_PKEY_ASN1_METHOD *p_luna_asn1_ec = NULL;
#endif /* LUNA_EC_USE_EVP_ASN1_METHS */
#endif /* LUNA_EC_USE_EVP_PKEY_METHS */

#define NID_ec NID_X9_62_id_ecPublicKey
#define luna_get_disable_ec luna_get_disable_ecdsa

static int luna_ecdsa_check_private(EC_KEY *eckey);
static int luna_ecdsa_check_public(EC_KEY *eckey);

#endif /* LUNA_OSSL_ECDSA */

/* Random number generation entry point */
/* Note: rand_seed entry point was removed because it impacts performance
 * severely for dynamic sessions
 */
static RAND_METHOD luna_rand = {
    luna_rand_seed,         /* rand_seed */
    luna_rand_bytes,        /* rand_bytes */
    luna_rand_cleanup,      /* rand_cleanup */
    luna_rand_add,          /* rand_add */
    luna_rand_pseudo_bytes, /* rand_pseudo_bytes */
    luna_rand_status        /* rand_status */
};

#ifdef OPENSSL_NO_DYNAMIC_ENGINE

static ENGINE *ENGINE_gem(void);

/* Driver load point */
void ENGINE_load_gem(void) {
   ENGINE *e = ENGINE_gem();
   if (e == NULL)
      return;
   ENGINE_add(e);
   ENGINE_free(e);
   ERR_clear_error();
}

/* Engine constructor */
static ENGINE *ENGINE_gem(void) {
   ENGINE *ret = ENGINE_new();
   if (ret == NULL)
      return NULL;
   if (!luna_bind_engine(ret)) {
      ENGINE_free(ret);
      return NULL;
   }
   return ret;
}

#endif

/* Global data (engine init state) */
static volatile int luna_have_mutex_init = 0;
static volatile int luna_have_prop_init = 0;
static volatile int luna_have_rsa_init = 0;
static volatile int luna_have_dsa_init = 0;
static volatile int luna_have_ecdsa_init = 0;
static volatile int luna_have_pkey_meths = 0;
static volatile int luna_have_strings_init = 0;

/* Set entry point binding (reference: ssl_init_Module, ssl_init_Engine, ssl_init_SSLLibrary, ssl_util_thread_setup,
 * etc.) */
static int luna_bind_engine(ENGINE *e) {
   /* register atexit handler if any */
   luna_register_atexit_handler();

   /* init pid_bind */
   if (g_rtconfig.pid_bind == (LUNA_PID_T)0) {
      g_rtconfig.pid_bind = LUNA_GETPID();
   }

   /* init mutex (once) */
   if (luna_have_mutex_init == 0) {
      if (luna_mutex_init()) {
         LUNA_ERRORLOG("luna_bind_engine: luna_mutex_init");
         return 0;
      }
      luna_have_mutex_init = 1;
   }

   /* initialize properties (once) */
   if (luna_have_prop_init == 0) {
      if (luna_init_properties2()) {
         LUNA_ERRORLOG("luna_bind_engine: luna_init_properties2");
         return 0;
      }
      luna_have_prop_init = 1;
   }



#ifndef OPENSSL_NO_RSA
   /* initialize RSA entry points (once) */
   if (luna_have_rsa_init == 0) {

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
      /* create method for EVP_PKEY_RSA */
      /* LUNA-31156: tls1.2 fails unless we omit flag EVP_PKEY_FLAG_AUTOARGLEN here.
       * As a result, more checking (lengths) must be done by the engine (see luna_rsa_decrypt, luna_rsa_sign).
       */
      p_luna_evp_pkey_rsaenc = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0); /* removed EVP_PKEY_FLAG_AUTOARGLEN */
      if (p_luna_evp_pkey_rsaenc != NULL) {
         const EVP_PKEY_METHOD *pkey_method = EVP_PKEY_meth_find(EVP_PKEY_RSA);
         if (pkey_method != NULL) {
            EVP_PKEY_meth_copy(p_luna_evp_pkey_rsaenc, pkey_method);
#ifdef LUNA_OSSL_METH_SET_CHECK_KEYPAIR
            EVP_PKEY_meth_set_check(p_luna_evp_pkey_rsaenc, luna_rsa_check_keypair0);
#endif
            /* EVP_PKEY_meth_set_sign for PSS support */
            EVP_PKEY_meth_get_sign(p_luna_evp_pkey_rsaenc, &saved_rsaenc.sign_init, &saved_rsaenc.sign);
            EVP_PKEY_meth_set_sign(p_luna_evp_pkey_rsaenc, saved_rsaenc.sign_init, luna_rsa_sign);
            /* EVP_PKEY_meth_set_decrypt for OAEP support */
            EVP_PKEY_meth_get_decrypt(p_luna_evp_pkey_rsaenc, &saved_rsaenc.decrypt_init, &saved_rsaenc.decrypt);
            EVP_PKEY_meth_set_decrypt(p_luna_evp_pkey_rsaenc, saved_rsaenc.decrypt_init, luna_rsa_decrypt);
            /* EVP_PKEY_meth_set_ctrl for keygen support */
            EVP_PKEY_meth_get_ctrl(p_luna_evp_pkey_rsaenc, &saved_rsaenc.ctrl, &saved_rsaenc.ctrl_str);
            EVP_PKEY_meth_set_ctrl(p_luna_evp_pkey_rsaenc, luna_rsa_ctrl, saved_rsaenc.ctrl_str);
         } else {
            EVP_PKEY_meth_free(p_luna_evp_pkey_rsaenc);
            p_luna_evp_pkey_rsaenc = NULL;
         }
      }

      /* create method for EVP_PKEY_RSA_PSS */
      p_luna_evp_pkey_rsapss = EVP_PKEY_meth_new(EVP_PKEY_RSA_PSS, 0); /* removed EVP_PKEY_FLAG_AUTOARGLEN */
      if (p_luna_evp_pkey_rsapss != NULL) {
         const EVP_PKEY_METHOD *pkey_method = EVP_PKEY_meth_find(EVP_PKEY_RSA_PSS);
         if (pkey_method != NULL) {
            EVP_PKEY_meth_copy(p_luna_evp_pkey_rsapss, pkey_method);
#ifdef LUNA_OSSL_METH_SET_CHECK_KEYPAIR
            EVP_PKEY_meth_set_check(p_luna_evp_pkey_rsapss, luna_rsa_check_keypair0);
#endif
            /* EVP_PKEY_meth_set_sign for PSS support */
            EVP_PKEY_meth_get_sign(p_luna_evp_pkey_rsapss, &saved_rsapss.sign_init, &saved_rsapss.sign);
            EVP_PKEY_meth_set_sign(p_luna_evp_pkey_rsapss, saved_rsapss.sign_init, luna_rsa_sign);
         } else {
            EVP_PKEY_meth_free(p_luna_evp_pkey_rsapss);
            p_luna_evp_pkey_rsapss = NULL;
         }
      }

#ifdef LUNA_RSA_USE_EVP_ASN1_METHS
      /* NOTE: an ASN1 method declares that the engine can handle legacy keys */
      /* create ASN1 method, EVP_PKEY_RSA */
      p_luna_asn1_rsaenc = EVP_PKEY_asn1_new(EVP_PKEY_RSA, ASN1_PKEY_SIGPARAM_NULL, "RSA", "Luna RSA method (ASN1)");
      if (p_luna_asn1_rsaenc != NULL) {
         const EVP_PKEY_ASN1_METHOD *asn1_method = EVP_PKEY_asn1_find(NULL, EVP_PKEY_RSA);
         if (asn1_method != NULL) {
            EVP_PKEY_asn1_copy(p_luna_asn1_rsaenc, asn1_method);
#ifdef LUNA_OSSL_ASN1_SET_SECURITY_BITS
            EVP_PKEY_asn1_set_security_bits(p_luna_asn1_rsaenc, luna_rsa_security_bits);
#endif
#ifdef LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR
            EVP_PKEY_asn1_set_check(p_luna_asn1_rsaenc, luna_rsa_check_keypair1);
#endif
         } else {
            EVP_PKEY_asn1_free(p_luna_asn1_rsaenc);
            p_luna_asn1_rsaenc = NULL;
         }
      }

      /* create ASN1 method, EVP_PKEY_RSA_PSS */
      p_luna_asn1_rsapss = EVP_PKEY_asn1_new(EVP_PKEY_RSA_PSS, ASN1_PKEY_SIGPARAM_NULL, "RSA-PSS", "Luna RSA-PSS method (ASN1)");
      if (p_luna_asn1_rsapss != NULL) {
         const EVP_PKEY_ASN1_METHOD *asn1_method = EVP_PKEY_asn1_find(NULL, EVP_PKEY_RSA_PSS);
         if (asn1_method != NULL) {
            EVP_PKEY_asn1_copy(p_luna_asn1_rsapss, asn1_method);
#ifdef LUNA_OSSL_ASN1_SET_SECURITY_BITS
            EVP_PKEY_asn1_set_security_bits(p_luna_asn1_rsapss, luna_rsa_security_bits);
#endif
#ifdef LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR
            EVP_PKEY_asn1_set_check(p_luna_asn1_rsapss, luna_rsa_check_keypair1);
#endif
         } else {
            EVP_PKEY_asn1_free(p_luna_asn1_rsapss);
            p_luna_asn1_rsapss = NULL;
         }
      }

#endif /* LUNA_RSA_USE_EVP_ASN1_METHS */
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

      p_luna_rsa_method = LUNA_RSA_meth_new("Luna RSA method", 0);
      if (p_luna_rsa_method == NULL) {
         return 0; /* unlikely */
      }

      LUNA_RSA_METH_SET_DEFAULT(p_luna_rsa_method);

      if (luna_get_enable_rsa_gen_key_pair()) {
         LUNA_RSA_METH_SET_KEYGEN_EX(p_luna_rsa_method, luna_rsa_keygen);
      }

      /* possible flags: RSA_FLAG_FIPS_METHOD, RSA_FLAG_NON_FIPS_ALLOW, RSA_FLAG_EXT_PKEY */
#ifdef RSA_FLAG_FIPS_METHOD
      LUNA_RSA_METH_OR_FLAGS(p_luna_rsa_method, RSA_FLAG_FIPS_METHOD);
#endif
#ifdef RSA_FLAG_NON_FIPS_ALLOW
      LUNA_RSA_METH_OR_FLAGS(p_luna_rsa_method, RSA_FLAG_NON_FIPS_ALLOW);
#endif
#ifdef RSA_FLAG_EXT_PKEY
      LUNA_RSA_METH_OR_FLAGS(p_luna_rsa_method, RSA_FLAG_EXT_PKEY);
#endif

      luna_have_rsa_init = 1;
   }
#endif /* OPENSSL_NO_RSA */



#ifndef OPENSSL_NO_DSA
   /* initialize DSA entry points (once) */
   if (luna_have_dsa_init == 0) {

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
      /* create method for EVP_PKEY_DSA */
      p_luna_evp_pkey_dsa = EVP_PKEY_meth_new(EVP_PKEY_DSA, EVP_PKEY_FLAG_AUTOARGLEN);
      if (p_luna_evp_pkey_dsa != NULL) {
         const EVP_PKEY_METHOD *pkey_method = EVP_PKEY_meth_find(EVP_PKEY_DSA);
         if (pkey_method != NULL) {
            EVP_PKEY_meth_copy(p_luna_evp_pkey_dsa, pkey_method);
#ifdef LUNA_OSSL_METH_SET_CHECK_KEYPAIR
            EVP_PKEY_meth_set_check(p_luna_evp_pkey_dsa, luna_dsa_check_keypair0);
#endif
            /* EVP_PKEY_meth_set_ctrl for dsa keygen support */
            EVP_PKEY_meth_get_ctrl(p_luna_evp_pkey_dsa, &saved_dsa.ctrl, &saved_dsa.ctrl_str);
            EVP_PKEY_meth_set_ctrl(p_luna_evp_pkey_dsa, luna_dsa_ctrl, saved_dsa.ctrl_str);
         } else {
            EVP_PKEY_meth_free(p_luna_evp_pkey_dsa);
            p_luna_evp_pkey_dsa = NULL;
         }
      }

#ifdef LUNA_DSA_USE_EVP_ASN1_METHS
      /* create ASN1 method, EVP_PKEY_DSA */
      p_luna_asn1_dsa = EVP_PKEY_asn1_new(EVP_PKEY_DSA, ASN1_PKEY_SIGPARAM_NULL, "DSA", "Luna DSA-method (ASN1)");
      if (p_luna_asn1_dsa != NULL) {
         const EVP_PKEY_ASN1_METHOD *asn1_method = EVP_PKEY_asn1_find(NULL, EVP_PKEY_DSA);
         if (asn1_method != NULL) {
            EVP_PKEY_asn1_copy(p_luna_asn1_dsa, asn1_method);
#ifdef LUNA_OSSL_ASN1_SET_PRIVATE_DSA_NULL
            /* NOTE: set private_encode to NULL to avoid openssl clobbering the public key */
            EVP_PKEY_asn1_set_private(p_luna_asn1_dsa, NULL, NULL, NULL);
#endif
#ifdef LUNA_OSSL_ASN1_SET_SECURITY_BITS
            EVP_PKEY_asn1_set_security_bits(p_luna_asn1_dsa, luna_dsa_security_bits);
#endif
#ifdef LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR
            EVP_PKEY_asn1_set_check(p_luna_asn1_dsa, luna_dsa_check_keypair1);
#endif
         } else {
            EVP_PKEY_asn1_free(p_luna_asn1_dsa);
            p_luna_asn1_dsa = NULL;
         }
      }
#endif /* LUNA_DSA_USE_EVP_ASN1_METHS */
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */

      p_luna_dsa_method = LUNA_DSA_meth_new("Luna DSA method", 0);
      if (p_luna_dsa_method == NULL) {
         return 0; /* unlikely */
      }

      LUNA_DSA_METH_SET_DEFAULT(p_luna_dsa_method);

      if (luna_get_enable_dsa_gen_key_pair()) {
         LUNA_DSA_METH_SET_KEYGEN_EX(p_luna_dsa_method, luna_dsa_keygen);
      }

      /* possible flags: DSA_FLAG_FIPS_METHOD, DSA_FLAG_NON_FIPS_ALLOW, (DSA_FLAG_EXT_PKEY) */
#ifdef DSA_FLAG_FIPS_METHOD
      LUNA_DSA_METH_OR_FLAGS(p_luna_dsa_method, DSA_FLAG_FIPS_METHOD);
#endif
#ifdef DSA_FLAG_NON_FIPS_ALLOW
      LUNA_DSA_METH_OR_FLAGS(p_luna_dsa_method, DSA_FLAG_NON_FIPS_ALLOW);
#endif
#ifdef DSA_FLAG_EXT_PKEY
      LUNA_DSA_METH_OR_FLAGS(p_luna_dsa_method, DSA_FLAG_EXT_PKEY);
#endif

      luna_have_dsa_init = 1;
   }
#endif /* OPENSSL_NO_DSA */



#if defined(LUNA_OSSL_ECDSA)
   /* initialize ECDSA entry points (once) */
   if (luna_have_ecdsa_init == 0) {

#ifdef LUNA_EC_USE_EVP_PKEY_METHS
      /* create method for EVP_PKEY_EC */
      p_luna_evp_pkey_ec = EVP_PKEY_meth_new(EVP_PKEY_EC, EVP_PKEY_FLAG_AUTOARGLEN);
      if (p_luna_evp_pkey_ec != NULL) {
         const EVP_PKEY_METHOD *pkey_method = EVP_PKEY_meth_find(EVP_PKEY_EC);
         if (pkey_method != NULL) {
            EVP_PKEY_meth_copy(p_luna_evp_pkey_ec, pkey_method);
#ifdef LUNA_OSSL_METH_SET_CHECK_KEYPAIR
            EVP_PKEY_meth_set_check(p_luna_evp_pkey_ec, luna_ec_check_keypair0);
#endif
            /* nothing to override yet */
         } else {
            EVP_PKEY_meth_free(p_luna_evp_pkey_ec);
            p_luna_evp_pkey_ec = NULL;
         }
      }

#ifdef LUNA_EC_USE_EVP_ASN1_METHS
      /* create ASN1 method, EVP_PKEY_EC */
      p_luna_asn1_ec = EVP_PKEY_asn1_new(EVP_PKEY_EC, ASN1_PKEY_SIGPARAM_NULL, "EC", "Luna EC-method (ASN1)");
      if (p_luna_asn1_ec != NULL) {
         const EVP_PKEY_ASN1_METHOD *asn1_method = EVP_PKEY_asn1_find(NULL, EVP_PKEY_EC);
         if (asn1_method != NULL) {
            EVP_PKEY_asn1_copy(p_luna_asn1_ec, asn1_method);
#ifdef LUNA_OSSL_ASN1_SET_SECURITY_BITS
            EVP_PKEY_asn1_set_security_bits(p_luna_asn1_ec, luna_ec_security_bits);
#endif
#ifdef LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR
            EVP_PKEY_asn1_set_check(p_luna_asn1_ec, luna_ec_check_keypair1);
#endif
         } else {
            EVP_PKEY_asn1_free(p_luna_asn1_ec);
            p_luna_asn1_ec = NULL;
         }
      }
#endif /* LUNA_EC_USE_EVP_ASN1_METHS */
#endif /* LUNA_EC_USE_EVP_PKEY_METHS */

      p_luna_ecdsa_method = LUNA_EC_KEY_meth_new("Luna ECDSA method", 0);
      if (p_luna_ecdsa_method == NULL) {
         return 0; /* unlikely */
      }

      LUNA_EC_KEY_METH_SET_DEFAULT(p_luna_ecdsa_method);

      /* possible flags: ECDSA_FLAG_FIPS_METHOD, EC_FLAG_NON_FIPS_ALLOW, (EC_FLAG_EXT_PKEY), (EC_FLAG_FIPS_CHECKED) */
#ifdef ECDSA_FLAG_FIPS_METHOD
      LUNA_EC_KEY_METH_OR_FLAGS(p_luna_ecdsa_method, ECDSA_FLAG_FIPS_METHOD);
#endif
#ifdef EC_FLAG_NON_FIPS_ALLOW
      LUNA_EC_KEY_METH_OR_FLAGS(p_luna_ecdsa_method, EC_FLAG_NON_FIPS_ALLOW);
#endif
#ifdef EC_FLAG_EXT_PKEY
      LUNA_EC_KEY_METH_OR_FLAGS(p_luna_ecdsa_method, EC_FLAG_EXT_PKEY);
#endif
#ifdef EC_FLAG_FIPS_CHECKED
      LUNA_EC_KEY_METH_OR_FLAGS(p_luna_ecdsa_method, EC_FLAG_FIPS_CHECKED);
#endif

      luna_have_ecdsa_init = 1;
   }
#endif /* LUNA_OSSL_ECDSA */



   /* setup pkey methods once */
   if (luna_have_pkey_meths == 0) {
#ifdef LUNA_OSSL_PKEY_METHS
      luna_pkey_init_meth_table();
#endif /* LUNA_OSSL_PKEY_METHS */
      luna_have_pkey_meths = 1;
   }

   /* initialize engine entry points (for each engine reference 'e') */
   if (!ENGINE_set_id(e, ENGINE_LUNACA3_ID) || !ENGINE_set_name(e, ENGINE_LUNACA3_NAME) ||
#ifndef OPENSSL_NO_RSA
       ((luna_get_disable_rsa()) ? 0 : (!ENGINE_set_RSA(e, p_luna_rsa_method))) ||
#endif
#ifndef OPENSSL_NO_DSA
       ((luna_get_disable_dsa()) ? 0 : (!ENGINE_set_DSA(e, p_luna_dsa_method))) ||
#endif
#if defined(LUNA_OSSL_ECDSA)
       ((luna_get_disable_ecdsa()) ? 0 : (!LUNA_ENGINE_set_ECDSA(e, p_luna_ecdsa_method))) ||
#endif
       !ENGINE_set_destroy_function(e, luna_destroy_engine) || !ENGINE_set_init_function(e, luna_init_engine) ||
       !ENGINE_set_finish_function(e, luna_finish_engine) || !ENGINE_set_ctrl_function(e, luna_ctrl_engine) ||
       ((g_postconfig.DisableRand != 0) ? 0 : (!ENGINE_set_RAND(e, &luna_rand))) ||
       ((!luna_get_enable_load_privkey()) ? 0 : (!ENGINE_set_load_privkey_function(e, luna_load_privkey))) ||
       ((!luna_get_enable_load_pubkey()) ? 0 : (!ENGINE_set_load_pubkey_function(e, luna_load_pubkey))) ||
#ifdef LUNA_OSSL_PKEY_METHS
       ((!luna_get_enable_pkey_meths()) ? 0 : (!ENGINE_set_pkey_meths(e, luna_pkey_meths))) ||
       ((!luna_get_enable_pkey_asn1_meths()) ? 0 : (!ENGINE_set_pkey_asn1_meths(e, luna_pkey_asn1_meths))) ||
#endif
       ((!luna_get_enable_digests()) ? 0 : (!ENGINE_set_digests(e, luna_digests))) ||
#ifdef ENGINE_FLAGS_NO_REGISTER_ALL
       ((!luna_get_disable_register_all()) ? 0 : (!ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL))) ||
#endif
       !ENGINE_set_cmd_defns(e, luna_cmd_defns)) {
      LUNA_ERRORLOG("luna_bind_engine: ENGINE_set");
      return 0;
   }

   /* initialize engine strings (once) */
   if (luna_have_strings_init == 0) {
      ERR_load_LUNACA3_strings();
      luna_have_strings_init = 1;
   }

   LUNA_EVENTLOGL("luna_bind_engine: success", 1);
   return 1;
}

/* Undo luna_bind_engine and luna_init_engine;
 *   this is the last chance to release resources before the application ends;
 *   this gets called when the external reference count drops to zero;
 *   this could happen more than once per application.
 */
static int luna_destroy_engine(ENGINE *e) {
   /* NOTE: due to openssl 1.1.0 auto-deinitialization the library may not be loaded. */
   if (luna_get_flag_exit() == 0) {
      luna_fini_p11();
      luna_unload_p11();
   }

   /* clean passwords iff in child; the parent needs to propagate password to child */
   if (g_rtconfig.in_child_v != 0) {
      unsigned ii = 0;
      for (ii = 0; ii < LUNA_MAX_SLOT; ii++) {
         if ((ii > 0) && (luna_get_engine2_init() == NULL))
            break;
         if (luna_get_enable_login_init()) {
            LUNA_pw_free(&(g_pw_per_slot[ii]));
         }
      }
   }

   if (luna_have_strings_init) {
      /* NOTE: otherwise OpenSSL detects memory leak here */
      ERR_unload_LUNACA3_strings();
      luna_have_strings_init = 0;
   }

   /* cleanup pkey methods */
   if (luna_have_pkey_meths) {
#ifdef LUNA_OSSL_PKEY_METHS
      luna_pkey_fini_meth_table();
#endif /* LUNA_OSSL_PKEY_METHS */
      luna_have_pkey_meths = 0;
   }

#if defined(LUNA_OSSL_ECDSA)
   /* cleanup ec method */
   if (luna_have_ecdsa_init) {
      /* confirmed: engine owns the pointer, so we can delete it for ec, dsa, rsa */
      LUNA_EC_KEY_meth_free(p_luna_ecdsa_method);
      p_luna_ecdsa_method = NULL;
      luna_have_ecdsa_init = 0;
   }
#endif

   /* cleanup dsa method  */
   if (luna_have_dsa_init) {
      LUNA_DSA_meth_free(p_luna_dsa_method);
      p_luna_dsa_method = NULL;
      luna_have_dsa_init = 0;
   }

   /* cleanup rsa method */
   if (luna_have_rsa_init) {
      LUNA_RSA_meth_free(p_luna_rsa_method);
      p_luna_rsa_method = NULL;
      luna_have_rsa_init = 0;
   }

   if (luna_have_prop_init) {
      /* NOTE: otherwise OpenSSL detects memory leak here */
      (void)luna_fini_properties2();
      (void)luna_set_engine_init(NULL); /* FIXME:SW: this setting should persist */
      (void)luna_set_engine2_init(NULL); /* FIXME:SW: this setting should persist */
      (void)luna_set_conf_path(NULL); /* FIXME:SW: this setting should persist */
      (void)luna_set_disable_check_finalize(NULL); /* FIXME:SW: this setting should persist */
      luna_have_prop_init = 0;
   }

   if (luna_have_mutex_init) {
      (void)luna_mutex_fini();
      luna_have_mutex_init = 0;
   }

   LUNA_EVENTLOGL("luna_destroy_engine: success", 1);
   return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_init_engine"

/* Init the engine */
/* NOTE: this function shall always return 1 despite errors */
static int luna_init_engine(ENGINE *engine) {
   int want_session = 0;
   int want_login = 0;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));

   { /* init pid_intermediate */
      LUNA_PID_T pid_now = LUNA_GETPID();
      if (pid_now != g_rtconfig.pid_bind) {
         if (g_rtconfig.pid_intermediate != (LUNA_PID_T)pid_now) {
            g_rtconfig.pid_intermediate_count++;
            g_rtconfig.pid_intermediate = pid_now;
         }
      }
   } /* init pid_intermediate */

   /* Prompt for password(s) */
   want_session = (luna_get_engine_init() != NULL);
   want_login = luna_get_enable_login_init();
   if ( want_session && want_login ) {
      unsigned ii = 0;
      for (ii = 0; ii < LUNA_MAX_SLOT; ii++) {
         if ((ii > 0) && (luna_get_engine2_init() == NULL))
            break;
         if ( want_login ) {
            int rc = 0;
            char *password = NULL;

            if (g_pw_per_slot[ii].boolInit != 0)
               continue; /* prompt for password once in parent process! */
            LUNA_pw_free(&(g_pw_per_slot[ii]));
            rc = luna_parse_password(luna_get_engine_init_ndx(ii), &password);
            if ((rc != 1) || (password == NULL)) {
               LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
               ERR_add_error_data(2, "luna_parse_password=0x", luna_itoa(itoabuf, rc));
               LUNA_ERRORLOGL(LUNA_FUNC_NAME ": luna_parse_password", rc);
            }
            if (password != NULL) {
               LUNA_pw_malloc(&(g_pw_per_slot[ii]), password);
               LUNA_free(password);
               password = NULL;
            }
         }
      }
   }

   /* Test that we can open a context on each slot when we need to */
   if ( want_session ) {
      unsigned ii = 0;
      for (ii = 0; ii < LUNA_MAX_SLOT; ii++) {
         luna_context_t ctx = LUNA_CONTEXT_T_INIT;
         CK_SESSION_INFO sessinfo;

         memset(&ctx, 0, sizeof(ctx));
         memset(&sessinfo, 0, sizeof(sessinfo));
         if ((ii > 0) && (luna_get_engine2_init() == NULL))
            break;
         if (luna_open_context_ndx(&ctx, ii) == 0) {
            LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
            ERR_add_error_data(1, LUNA_FUNC_NAME ": luna_open_context");
            LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_open_context");
         } else {
            /* NOTE: never cache this session in the parent process (in the case of forking app) */
            luna_close_context_w_err(&ctx, -1, CKR_GENERAL_ERROR);
         }
      }
   }

   LUNA_EVENTLOGL("luna_init_engine: success", 1);
   return 1;
}

/* Undo luna_init_engine... actually we'll defer that to luna_destroy_engine. */
static int luna_finish_engine(ENGINE *engine) {
   LUNA_EVENTLOGL("luna_finish_engine: success", 1);
   return 1;
}

/* Load the P11 library conditionally */
static int luna_load_p11_deferred(void) {
   /* load p11 library (once) */
   if (luna_have_c_funclist == 0) {
      if (luna_load_p11() != 1) {
         LUNA_ERRORLOG("luna_load_p11_deferred: luna_load_p11");
         return 0;
      }
      luna_have_c_funclist = 1;
   }
   LUNA_EVENTLOGL("luna_load_p11_deferred: success", 1);

   return 1;
}

/* Load the P11 library */
static int luna_load_p11(void) {
   CK_RV retCode = CKR_OK;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   if (g_config.SO_PATH == NULL) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "DSO not set");
      LUNA_ERRORLOG("luna_load_p11: SO_PATH");
      return 0;
   }

   if (luna_dso == NULL) {
      luna_dso = luna_dso_load(g_config.SO_PATH);
   }

   if (luna_dso == NULL) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(2, "DSO not loadable ", g_config.SO_PATH);
      LUNA_ERRORLOG("luna_load_p11: luna_dso");
      return 0;
   }

   /* Have library */
   p11.C_GetFunctionList = (CK_C_GetFunctionList)luna_dso_bind_func(luna_dso, "C_GetFunctionList");
   if ((p11.C_GetFunctionList != NULL) && (!luna_pa_check_lib())) {
      p11.ext.CA_SetApplicationID = (CK_CA_SetApplicationID)luna_dso_bind_func(luna_dso, "CA_SetApplicationID");
      p11.ext.CT_HsmIdFromSlotId = NULL;
      p11.ext.CA_GetHAState = (CK_CA_GetHAState)luna_dso_bind_func(luna_dso, "CA_GetHAState");
      if (p11.ext.CA_SetApplicationID == NULL) {
         p11.ext.CT_HsmIdFromSlotId = (CK_CT_HsmIdFromSlotId)luna_dso_bind_func(luna_dso, "CT_HsmIdFromSlotId");
      }
      p11.ext.CA_DeriveKeyAndWrap = (CK_CA_DeriveKeyAndWrap)luna_dso_bind_func(luna_dso, "CA_DeriveKeyAndWrap");
      p11.ext.CA_EncapsulateKey = (CK_CA_EncapsulateKey)luna_dso_bind_func(luna_dso, "CA_EncapsulateKey");
      p11.ext.CA_DecapsulateKey = (CK_CA_DecapsulateKey)luna_dso_bind_func(luna_dso, "CA_DecapsulateKey");
   } else if (!luna_pa_check_lib()) {
      p11.C_GetFunctionList = (CK_C_GetFunctionList)luna_dso_bind_func(luna_dso, "P11Wrap_GetFunctionList");
      p11.ext.CA_SetApplicationID = (CK_CA_SetApplicationID)luna_dso_bind_func(luna_dso, "P11Wrap_SetApplicationID");
      p11.ext.CT_HsmIdFromSlotId = NULL;
      p11.ext.CA_GetHAState = (CK_CA_GetHAState)luna_dso_bind_func(luna_dso, "P11Wrap_GetHAState");
      if (p11.ext.CA_SetApplicationID == NULL) {
         p11.ext.CT_HsmIdFromSlotId = (CK_CT_HsmIdFromSlotId)luna_dso_bind_func(luna_dso, "P11Wrap_CT_HsmIdFromSlotId");
      }
      p11.ext.CA_DeriveKeyAndWrap = (CK_CA_DeriveKeyAndWrap)luna_dso_bind_func(luna_dso, "P11Wrap_DeriveKeyAndWrap");
      p11.ext.CA_EncapsulateKey = (CK_CA_EncapsulateKey)luna_dso_bind_func(luna_dso, "P11Wrap_EncapsulateKey");
      p11.ext.CA_DecapsulateKey = (CK_CA_DecapsulateKey)luna_dso_bind_func(luna_dso, "P11Wrap_DecapsulateKey");
   }

   if (p11.C_GetFunctionList == NULL) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "C_GetFunctionList not found");
      LUNA_ERRORLOG("luna_load_p11: C_GetFunctionList");
      return 0;
   }

   /*QQQ - Need to handle this as the Ingrian library doesn't have either
    *      function.  This is no longer an error when KeySecure is involved.
    */
   if (!luna_pa_check_lib()) {
      if ((p11.ext.CA_SetApplicationID == NULL) && (p11.ext.CT_HsmIdFromSlotId == NULL)) {
         LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
         ERR_add_error_data(1, "function not found");
         LUNA_ERRORLOG("luna_load_p11: function not found");
         return 0;
      }
   }

   if (p11.ext.CA_SetApplicationID == NULL) {
      p11.ext.CA_SetApplicationID = STUB_CA_SetApplicationID;
   }

   if (p11.ext.CT_HsmIdFromSlotId == NULL) {
      p11.ext.CT_HsmIdFromSlotId = STUB_CT_HsmIdFromSlotId;
   }

   if (p11.ext.CA_GetHAState == NULL) {
      p11.ext.CA_GetHAState = STUB_CA_GetHAState;
   }

   if (p11.ext.CA_DeriveKeyAndWrap == NULL) {
      p11.ext.CA_DeriveKeyAndWrap = STUB_CA_DeriveKeyAndWrap;
   }

   if (p11.ext.CA_EncapsulateKey == NULL) {
      p11.ext.CA_EncapsulateKey = STUB_CA_EncapsulateKey;
   }

   if (p11.ext.CA_DecapsulateKey == NULL) {
      p11.ext.CA_DecapsulateKey = STUB_CA_DecapsulateKey;
   }

   retCode = p11.C_GetFunctionList(&p11.std);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_GetFunctionList=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_load_p11: C_GetFunctionList failed", retCode);
      return 0;
   }

   luna_have_c_funclist = 1;
   LUNA_EVENTLOGL("luna_load_p11: success", 1);
   return 1;
}

/* Unload the P11 library */
static void luna_unload_p11(void) {
   luna_have_c_funclist = 0;
   memset(&p11, 0, sizeof(p11));
   if (luna_dso != NULL) {
      luna_dso_free(luna_dso);
      luna_dso = NULL;
   }

   LUNA_EVENTLOG("luna_unload_p11: success");
}

static int luna_do_deferred_login(void);

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_init_p11_deferred"

/* Initialize the P11 library (deferred) */
static int luna_init_p11_deferred(void) {
   CK_RV retCode = CKR_OK;
   char itoabuf[LUNA_ATOI_BYTES];
   luna_stopwatch_t lsw;

   memset(itoabuf, 0, sizeof(itoabuf));
   if (luna_load_p11_deferred() != 1) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_load_p11_deferred");
      LUNA_ERRORLOG(LUNA_FUNC_NAME": luna_load_p11_deferred");
      return 0;
   }

   if (luna_have_c_init) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "P11 already initialized");
      LUNA_ERRORLOG(LUNA_FUNC_NAME": luna_have_c_init");
      return 0;
   }

#if 0
#error "This is too restrictive wrt BIND."
   if(luna_have_c_error) {
      LUNA_ERRORLOG(LUNA_FUNC_NAME": luna_have_c_error");
      return 0;
   }
#endif

   luna_cache_init(&luna_ckses[0]);
   luna_cache_init(&luna_ckses[1]);
   g_rtconfig.pid_c_init = LUNA_GETPID();
   luna_stopwatch_start(&lsw);
   if (!skip_c_initialize) {
      if (luna_pa_check_lib()) {
         CK_C_INITIALIZE_ARGS initArgs;
         memset(&initArgs, 0, sizeof(initArgs));
         initArgs.flags = CKF_OS_LOCKING_OK;
         initArgs.pReserved = NULL_PTR;

         retCode = p11.std->C_Initialize((CK_VOID_PTR)&initArgs);
      } else {
         retCode = p11.std->C_Initialize(NULL_PTR);
      }
      retCode = (retCode == CKR_CRYPTOKI_ALREADY_INITIALIZED) ? CKR_OK : retCode;
   }

   luna_stopwatch_stop(&lsw);
   if (retCode != CKR_OK) {
      luna_have_c_error = 1;
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Initialize=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME": C_Initialize", retCode);
      if (!skip_c_initialize) {
         (void)p11.std->C_Finalize(NULL_PTR); /* for buggy cryptoki library */
      }
      return 0;
   }

   /* Register RSA extension */
   if (luna_get_rsa_ex()) {
      g_luna_per_slot[0].g_luna_rsa_ex_priv = RSA_get_ex_new_index(0, ENGINE_LUNACA3_RSA_EX_PRIV, NULL, NULL, NULL);
      g_luna_per_slot[0].g_luna_rsa_ex_pub = RSA_get_ex_new_index(0, ENGINE_LUNACA3_RSA_EX_PUB, NULL, NULL, NULL);
      g_luna_per_slot[1].g_luna_rsa_ex_priv = RSA_get_ex_new_index(0, ENGINE_LUNACA3_RSA_EX_PRIV, NULL, NULL, NULL);
      g_luna_per_slot[1].g_luna_rsa_ex_pub = RSA_get_ex_new_index(0, ENGINE_LUNACA3_RSA_EX_PUB, NULL, NULL, NULL);
   }

   /* Register DSA extension */
   if (luna_get_dsa_ex()) {
      g_luna_per_slot[0].g_luna_dsa_ex_priv = DSA_get_ex_new_index(0, ENGINE_LUNACA3_DSA_EX_PRIV, NULL, NULL, NULL);
      g_luna_per_slot[0].g_luna_dsa_ex_pub = DSA_get_ex_new_index(0, ENGINE_LUNACA3_DSA_EX_PUB, NULL, NULL, NULL);
      g_luna_per_slot[1].g_luna_dsa_ex_priv = DSA_get_ex_new_index(0, ENGINE_LUNACA3_DSA_EX_PRIV, NULL, NULL, NULL);
      g_luna_per_slot[1].g_luna_dsa_ex_pub = DSA_get_ex_new_index(0, ENGINE_LUNACA3_DSA_EX_PUB, NULL, NULL, NULL);
   }

   /* Register ECDSA extension */
   if (luna_get_ecdsa_ex()) {
#if defined(LUNA_OSSL_ECDSA)
      g_luna_per_slot[0].g_luna_ecdsa_ex_priv = LUNA_EC_KEY_get_ex_new_index(ENGINE_LUNACA3_ECDSA_EX_PRIV);
      g_luna_per_slot[0].g_luna_ecdsa_ex_pub = LUNA_EC_KEY_get_ex_new_index(ENGINE_LUNACA3_ECDSA_EX_PUB);
      g_luna_per_slot[1].g_luna_ecdsa_ex_priv = LUNA_EC_KEY_get_ex_new_index(ENGINE_LUNACA3_ECDSA_EX_PRIV);
      g_luna_per_slot[1].g_luna_ecdsa_ex_pub = LUNA_EC_KEY_get_ex_new_index(ENGINE_LUNACA3_ECDSA_EX_PUB);
#endif /* LUNA_OSSL_ECDSA */
   }

   luna_count_c_init++;
   /* the count is never equal to zero */
   if (luna_count_c_init == 0)
       luna_count_c_init = 1;
   /* SW: do not clear this variable: luna_have_c_error = 0; */
   luna_have_c_init = 1;

   /* Execute post command that sets the application id */
   /* NOTE: this will fail if user specifies slot id = "some label" and the token is not present. */
   {
      char *EngineInit = luna_get_engine_init();
      if (EngineInit != NULL) {
         if (luna_cmdarg_engine_ext2(EngineInit, ENGINE_CMD_LUNA_ENGINEINIT) != 1) {
            luna_have_c_error = 1;
            if (!skip_c_initialize) {
               p11.std->C_Finalize(NULL_PTR);
            }
            luna_have_c_init = 0;
            LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
            ERR_add_error_data(1, "ENGINE_CMD_LUNA_ENGINEINIT");
            LUNA_ERRORLOG(LUNA_FUNC_NAME": ENGINE_CMD_LUNA_ENGINEINIT");
            return 0;
         }
      }
   }

   {
      char *Engine2Init = luna_get_engine2_init();
      if (Engine2Init != NULL) {
         if (luna_cmdarg_engine_ext2(Engine2Init, ENGINE_CMD_LUNA_ENGINE2INIT) != 1) {
            luna_have_c_error = 1;
            if (!skip_c_initialize) {
               p11.std->C_Finalize(NULL_PTR);
            }
            luna_have_c_init = 0;
            LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
            ERR_add_error_data(1, "ENGINE_CMD_LUNA_ENGINE2INIT");
            LUNA_ERRORLOG(LUNA_FUNC_NAME": ENGINE_CMD_LUNA_ENGINE2INIT");
            return 0;
         }
      }
   }

   /* Perform deferred login for each slot */
   if (luna_do_deferred_login() == 0) {
       luna_have_c_error = 1;
       if (!skip_c_initialize) {
          (void)p11.std->C_Finalize(NULL_PTR);
       }
       luna_have_c_init = 0;
       LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
       ERR_add_error_data(1, "luna_do_deferred_login");
       LUNA_ERRORLOG(LUNA_FUNC_NAME": luna_do_deferred_login");
       return 0;
   }

   LUNA_EVENTLOGL(LUNA_FUNC_NAME": success", 1);
   LUNA_PROFILELOGL(LUNA_FUNC_NAME": p11 delay (usec)", luna_stopwatch_usec(&lsw));
   return 1;
}

/* login during engine initialize or during engine recovery */
static int luna_do_deferred_login(void) {
   CK_RV rv = 0;
   unsigned ii = 0;

   /* NOTE: check initialized prior to login, in the case of multiple recovery attempts */
   if (luna_have_c_init != 1)
       return 0;

   for (ii = 0; ii < LUNA_MAX_SLOT; ii++) {
      if ((ii > 0) && (luna_get_engine2_init() == NULL))
         break;

      if (luna_get_enable_login_init()) {
         if ((g_pw_per_slot[ii].boolInit != 1) || (g_pw_per_slot[ii].szPass == NULL)) {
            return 0;
         }

         if (luna_open_session(g_luna_per_slot[ii].g_slot_id, &(g_pw_per_slot[ii].hSession)) != 1) {
            return 0;
         }

         rv = LUNA_pw_login(&(g_pw_per_slot[ii]), g_pw_per_slot[ii].hSession);
         if (rv != CKR_OK) {
            (void)luna_close_session(g_pw_per_slot[ii].hSession);
            g_pw_per_slot[ii].hSession = LUNA_INVALID_HANDLE;
            return 0;
         }
      }
   }

   return 1;
}

/* Initialize the P11 library (conditional) */
static int luna_init_p11_conditional_ex(int have_lock) {
   int rc = 0;

   if (!have_lock) {
      luna_mutex_enter();
   }

   rc = (luna_have_c_init == 1) ? 1 : luna_init_p11_deferred();

   if (!have_lock) {
      luna_mutex_exit();
   }

   return rc;
}

/* flag to avoid cascading errors (session cache) */
static int luna_is_cb_tainted = 0;

/* callback for close session (session cache) */
static void luna_callback_close_session(luna_cache_t *item, int index) {
   if (index == 0)
       luna_is_cb_tainted = 0;
   if (item == NULL)
      return;
   if (item->ckses == LUNA_INVALID_HANDLE)
      return;
   if (luna_is_cb_tainted == 0) {
      if (luna_close_session(item->ckses) != CKR_OK) {
          luna_is_cb_tainted = 1;
      }
   }
   item->ckses = LUNA_INVALID_HANDLE;
}

static void luna_fini_p11(void) {
   CK_RV retCode = CKR_OK;
   int errActive = (g_count_activity > 0);
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   if (luna_have_c_init) {
      luna_stopwatch_t lsw;

      /* Measure total delay due to teardown */
      luna_stopwatch_start(&lsw);

      /* Perform deferred logout (overkill because we are about to call C_Finalize...) */
      if (1) {
         unsigned ii = 0;
         for (ii = 0; ii < LUNA_MAX_SLOT; ii++) {
            if ((ii > 0) && (luna_get_engine2_init() == NULL))
               break;
            if (luna_get_enable_login_init()) {
               if (g_pw_per_slot[ii].boolInit != 1)
                  continue;
               if (g_pw_per_slot[ii].szPass == NULL)
                  continue;
               if (g_pw_per_slot[ii].hSession != LUNA_INVALID_HANDLE) {
                  (void)p11.std->C_Logout(g_pw_per_slot[ii].hSession);
                  (void)luna_close_session(g_pw_per_slot[ii].hSession);
                  g_pw_per_slot[ii].hSession = LUNA_INVALID_HANDLE;
               }
            }
         }
      }

      /* C_Finalize; close cached sessions otherwise, token session leak */
      luna_cache_delete_ALL(&(luna_ckses[0]), luna_callback_close_session);
      luna_cache_delete_ALL(&(luna_ckses[1]), luna_callback_close_session);
      if (!skip_c_initialize) {
         retCode = p11.std->C_Finalize(NULL_PTR);
      }
      luna_stopwatch_stop(&lsw);
      if (retCode != CKR_OK) {
         LUNACA3err(LUNACA3_F_FINISH, LUNACA3_R_EPKCS11);
         ERR_add_error_data(2, "C_Finalize=0x", luna_itoa(itoabuf, retCode));
         LUNA_ERRORLOGL("luna_fini_p11: C_Finalize", retCode);
      }
      luna_have_c_init = 0;
      LUNA_PROFILELOGL("luna_fini_p11: p11 delay (usec)", luna_stopwatch_usec(&lsw));
   }

   /* SW: do not clear this variable: luna_have_c_error = 0; */
   luna_cache_fini(&luna_ckses[0]);
   luna_cache_fini(&luna_ckses[1]);
   /* NOTE: legacy code avoids resetting g_slot_id: g_luna_per_slot[0].g_slot_id = LUNA_INVALID_SLOTID; */
   g_luna_per_slot[0].g_session_handle = LUNA_INVALID_HANDLE;
   g_luna_per_slot[0].g_luna_rsa_ex_priv = -1;
   g_luna_per_slot[0].g_luna_rsa_ex_pub = -1;
   g_luna_per_slot[0].g_count_activity = 0;
   g_luna_per_slot[0].g_luna_dsa_ex_priv = -1;
   g_luna_per_slot[0].g_luna_dsa_ex_pub = -1;
   g_luna_per_slot[0].g_luna_ecdsa_ex_priv = -1;
   g_luna_per_slot[0].g_luna_ecdsa_ex_pub = -1;
   /* NOTE: legacy code avoids resetting g_slot_id: g_luna_per_slot[1].g_slot_id = LUNA_INVALID_SLOTID; */
   g_luna_per_slot[1].g_session_handle = LUNA_INVALID_HANDLE;
   g_luna_per_slot[1].g_luna_rsa_ex_priv = -1;
   g_luna_per_slot[1].g_luna_rsa_ex_pub = -1;
   g_luna_per_slot[1].g_count_activity = 0;
   g_luna_per_slot[1].g_luna_dsa_ex_priv = -1;
   g_luna_per_slot[1].g_luna_dsa_ex_pub = -1;
   g_luna_per_slot[1].g_luna_ecdsa_ex_priv = -1;
   g_luna_per_slot[1].g_luna_ecdsa_ex_pub = -1;
   g_count_activity = 0;
   LUNA_EVENTLOGL("luna_fini_p11: success", 1);
   if (errActive) {
      LUNA_ERRORLOG("luna_fini_p11: activity count > 0");
   }
}

/* Query session info */
static int luna_get_session_info(CK_SESSION_HANDLE shandle, CK_SESSION_INFO_PTR psinfo) {
   CK_RV retCode = CKR_OK;

   retCode = p11.std->C_GetSessionInfo(shandle, psinfo);
   if (retCode != CKR_OK) {
      LUNA_ERRORLOGL("luna_get_session_info: C_GetSessionInfo", retCode);
      return 0;
   }
   return 1;
}

static CK_ULONG get_ulong_serial_from_string_serial(CK_CHAR *serialStringIn, CK_ULONG defaultSerial) {
   size_t n;
   char *serialString = (char*)serialStringIn;
   char *s, *e, *p;
   CK_ULONG serial;

   n = strnlen(serialString, CK_TOKEN_SERIAL_NUMBER_SIZE + 4);
   e = &(serialString[n]);
   s = n > 9 ? &(serialString[n - 9]) : serialString;
   p = s;

   while (p < e) {
      if (*p < '0' || *p > '9') {
         return defaultSerial;
      }
      p++;
   }
   serial = atol(s);
   return serial;
}

/* Query High Availability state */
static int luna_get_ha_state(CK_SLOT_ID slotid, luna_ha_status_v2_t *d) {
   CK_RV retCode;
   unsigned i;
   CK_HA_STATUS_V2 status;
   CK_HA_STATUS_V1 *pStatus;
   CK_HA_STATUS_V1 s1;
   CK_HA_STATUS_V2 s2;
   luna_ha_status_v1_t *d2;
   char itoabuf[LUNA_ATOI_BYTES];

   retCode = CKR_OK;

   memset(itoabuf, 0, sizeof(itoabuf));

   memset(&status, 0, sizeof(CK_HA_STATUS_V2));
   status.listSize = 0xFFFFFFFF;

   d->_slotID = slotid;
   d->_ckrv = retCode = p11.ext.CA_GetHAState(slotid, &status);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_GET_HA_STATE, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "CA_GetHAState=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_get_ha_state: CA_GetHAState", retCode);
      return 0;
   }

   if (status.listSize == 0xFFFFFFFF)  /* Version of SA is expecting legacy CK_HA_STATUS */
   {
      if (d->version == sizeof(luna_ha_status_v1_t)) {
         d2 = (luna_ha_status_v1_t *)d;
         memcpy(&(d2->st), &status, sizeof(CK_HA_STATUS_V1));
      } else if (d->version == sizeof(luna_ha_status_v2_t)) {
         memset(&s2, 0, sizeof(s2));
         pStatus = (CK_HA_STATUS_V1 *)(&status);
         snprintf((char*)s2.groupSerial, sizeof(s2.groupSerial),
            "%lu", pStatus->groupSerial);
         s2.listSize = pStatus->listSize;
         for (i = 0; i < pStatus->listSize; i++) {
            snprintf((char*)s2.memberList[i].memberSerial, sizeof(s2.memberList[i].memberSerial),
               "%lu", pStatus->memberList[i].memberSerial);
            s2.memberList[i].memberStatus = pStatus->memberList[i].memberStatus;
         }
         memcpy(&(d->st), &s2, sizeof(CK_HA_STATUS_V2));
      } else {
         LUNACA3err(LUNACA3_F_GET_HA_STATE, LUNACA3_R_EINVHASTATUSVER);
         ERR_add_error_data(2, "HA status version=0x", luna_itoa(itoabuf, d->version));
         LUNA_ERRORLOGL("luna_get_ha_state: Invalid ha status struct version", d->version);
         return 0;
      }
   } else  /* Version of SA is expecting Luna SA6 and later CK_HA_STATUS */
   {
      if (d->version == sizeof(luna_ha_status_v2_t)) {
         memcpy(&(d->st), &status, sizeof(CK_HA_STATUS_V2));
      } else if (d->version == sizeof(luna_ha_status_v1_t)) {
         memset(&s1, 0, sizeof(s1));
         s1.groupSerial = get_ulong_serial_from_string_serial(status.groupSerial, 1);
         s1.listSize = status.listSize;
         for (i = 0; i < status.listSize; i++) {
            s1.memberList[i].memberSerial =
                get_ulong_serial_from_string_serial(status.memberList[i].memberSerial, i + 1);
            s1.memberList[i].memberStatus = status.memberList[i].memberStatus;
         }
         d2 = (luna_ha_status_v1_t *)d;
         memcpy(&(d2->st), &s1, sizeof(CK_HA_STATUS_V1));
      } else {
         LUNACA3err(LUNACA3_F_GET_HA_STATE, LUNACA3_R_EINVHASTATUSVER);
         ERR_add_error_data(2, "HA status version=0x", luna_itoa(itoabuf, d->version));
         LUNA_ERRORLOGL("luna_get_ha_state: Invalid ha status struct version", d->version);
         return 0;
      }
   }
   return 1;
}

/* Open session */
static int luna_open_session(CK_SLOT_ID slotid, CK_SESSION_HANDLE *shandle) {
   CK_RV retCode = CKR_OK;
   CK_FLAGS flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION);
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   retCode = p11.std->C_OpenSession(slotid, flags, "Application", 0, shandle);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_OPENSESSION, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_OpenSession=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_open_session: C_OpenSession", retCode);
      return 0;
   }

   return 1;
}

/* Close session */
static int luna_close_session(CK_SESSION_HANDLE shandle) {
   CK_RV retCode = CKR_OK;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   retCode = p11.std->C_CloseSession(shandle);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_CLOSESESSION, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_CloseSession=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_close_session: C_CloseSession", retCode);
      return 0;
   }
   return 1;
}

/* Open session and login */
static int luna_open_session_and_login(CK_SLOT_ID slotid, CK_SESSION_HANDLE *shandle, char *password) {
   CK_RV retCode = CKR_OK;
   CK_USER_TYPE userType = luna_get_userType();
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   if (!luna_open_session(slotid, shandle))
      return 0;

   if (password != NULL) {
      retCode = p11.std->C_Login(*shandle, userType, (CK_BYTE_PTR)password, (CK_ULONG)strlen(password));
   } else {
      retCode = p11.std->C_Login(*shandle, userType, NULL, 0);
   }
   retCode = (retCode == CKR_USER_ALREADY_LOGGED_IN) ? CKR_OK : retCode;
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_LOGIN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Login=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_open_session_and_login: C_Login", retCode);
      goto err;
   }
   return 1;

err:
   return 0;
}

/* Logout */
static int luna_logout(CK_SESSION_HANDLE hSession) {
   CK_RV retCode = CKR_OK;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   retCode = p11.std->C_Logout(hSession);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_LOGOUT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Logout=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_logout: C_Logout", retCode);
      return 0;
   }
   return 1;
}

/* Execute engine control command */
static int luna_ctrl_engine(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {
   int ret = 1;

   switch (cmd) {
      /* These commands run AFTER luna_init_engine; i.e., "post" commands.
       * Hence, P11 library is initialized with luna_init_p11_conditional_ex().
       */
      case ENGINE_CMD_LUNA_LEGACY_DEV_SELECT: {
         /* Set the global session handle */
         /* i = session handle */
         CK_SESSION_INFO sinfo;
         memset(&sinfo, 0, sizeof(sinfo));
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         if ((ret = luna_get_session_info((CK_SESSION_HANDLE)i, &sinfo)) == 0)
            break;
         g_luna_per_slot[0].g_slot_id = sinfo.slotID;
         g_luna_per_slot[0].g_session_handle = i;
         break;
      }

      case ENGINE_CMD_LUNA_LEGACY_OPEN_SESSION_BY_STRUCT: {
         /* Set the application id, open a new session, and, set the global session handle */
         /* p = pointer to struct { app_id , session handle } */
         session_desc *d = (session_desc *)p;
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         if ((ret = luna_set_app_id(d->app_id.hi, d->app_id.low)) == 0)
            break;
         if ((ret = luna_open_session(d->slot, &d->handle)) == 0)
            break;
         g_luna_per_slot[0].g_slot_id = d->slot;
         g_luna_per_slot[0].g_session_handle = d->handle;
         break;
      }

      case ENGINE_CMD_LUNA_GET_HA_STATE: {
         luna_ha_status_v2_t *d = (luna_ha_status_v2_t *)p;
         int instance = 0;
         ret = 0;
         if (d == NULL)
            break;
         if (d->version != sizeof(luna_ha_status_v2_t) && d->version != sizeof(luna_ha_status_v1_t))
            break;
         if ((d->instance < 0) || (d->instance > 1))
            break;
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         instance = (luna_get_engine2_init() == NULL) ? 0 : d->instance;
         luna_mutex_enter();
         ret = luna_get_ha_state(g_luna_per_slot[instance].g_slot_id, d);
         luna_mutex_exit();
         break;
      }

      case ENGINE_CMD_LUNA_SET_FINALIZE_PENDING: {
         luna_set_finalize_pending_t *d = (luna_set_finalize_pending_t *)p;
         ret = 0;
         if (d == NULL)
            break;
         if (d->version != sizeof(luna_set_finalize_pending_t))
            break;
         luna_mutex_enter();
         while (g_count_activity > 0) {
            luna_mutex_exit();
            luna_sleep_milli(100);
            luna_mutex_enter();
         }
         luna_fini_p11(); /* synchronous */
         luna_mutex_exit();
         if (d->cb != NULL) {
            d->cb(d->cb_context);
         }

         ret = 1;
         break;
      }

      case ENGINE_CMD_LUNA_LEGACY_LOGIN: {
         /* Open a new session, login, and, set the global session handle */
         /* i = slot id */
         /* p = pointer to session handle */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         if ((ret = luna_open_session_and_login((CK_SLOT_ID)i, p, NULL)) == 0)
            break;
         g_luna_per_slot[0].g_slot_id = (CK_SLOT_ID)i;
         g_luna_per_slot[0].g_session_handle = *((CK_SESSION_HANDLE *)p);
         break;
      }

      case ENGINE_CMD_LUNA_ENGINEINIT: {
         /* Set the application id, global slot id */
         /* p = pointer to string "slotid:appid:appid" */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         ret = luna_cmdarg_engine_ext2((char *)p, ENGINE_CMD_LUNA_ENGINEINIT);
         break;
      }

      case ENGINE_CMD_LUNA_ENGINE2INIT: {
         /* Set the application id, global slot id */
         /* p = pointer to string "slotid:appid:appid" */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         ret = luna_cmdarg_engine_ext2((char *)p, ENGINE_CMD_LUNA_ENGINE2INIT);
         break;
      }

      case ENGINE_CMD_LUNA_ENGINEARG:
      case ENGINE_CMD_LUNA_OPEN_SESSION_BY_STRING: {
         /* Set the application id, open a new session, and, set the global session handle */
         /* p = pointer to string "slotid:appid:appid" */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         ret = luna_cmdarg_engine_ext2((char *)p, ENGINE_CMD_LUNA_OPEN_SESSION_BY_STRING);
         break;
      }

      case ENGINE_CMD_LUNA_LOGIN_BY_STRING: {
         /* Set the application id, open a new session, login, and, set the global session handle */
         /* p = pointer to string "slotid:appid:appid" */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         ret = luna_cmdarg_engine_ext2((char *)p, ENGINE_CMD_LUNA_LOGIN_BY_STRING);
         break;
      }

      case ENGINE_CMD_LUNA_LOGOUT_BY_STRING: {
         /* Set the application id, logout */
         /* p = pointer to string "slotid:appid:appid" */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         ret = luna_cmdarg_engine_ext2((char *)p, ENGINE_CMD_LUNA_LOGOUT_BY_STRING);
         break;
      }

      case ENGINE_CMD_LUNA_CLOSE_SESSION_BY_STRING: {
         /* Close session */
         /* p = pointer to string "slotid:appid:appid" */
         if ((ret = luna_init_p11_conditional_ex(0)) == 0)
            break;
         ret = luna_cmdarg_engine_ext2((char *)p, ENGINE_CMD_LUNA_CLOSE_SESSION_BY_STRING);
         break;
      }

      /* Remaining commands run BEFORE luna_init_engine; i.e., "pre" commands.
       * Hence, it is wrong to call luna_init_p11_conditional_ex().
       */
      case ENGINE_CMD_LUNA_CONFPATH: {
         ret = luna_set_conf_path((char *)p);
         break;
      }

      case ENGINE_CMD_LUNA_CONF_ENGINE_INIT: {
         ret = luna_set_engine_init((char *)p);
         break;
      }

      case ENGINE_CMD_LUNA_CONF_ENGINE2_INIT: {
         ret = luna_set_engine2_init((char *)p);
         break;
      }

      case ENGINE_CMD_LUNA_DISABLECHECKFINALIZE: {
         ret = luna_set_disable_check_finalize((char *)p);
         break;
      }

      case ENGINE_CMD_LUNA_INTERMEDIATEPROCESSES: {
         ret = luna_set_intermediate_processes((char *)p);
         break;
      }

      case ENGINE_CMD_LUNA_SO_PATH: {
         /* NOTE: the command "SO_PATH" is a no-op here.
          * It is provided for compatibility only.
          * A user should configure this stuff via config file (see LUNA_CONF_FILE).
          */
         ret = 1;
         break;
      }

      case ENGINE_CMD_LUNA_SKIP_C_INITIALIZE: {
         if (p) {
            skip_c_initialize = atoi((char *)p);
         } else {
            skip_c_initialize = 1; /* assume turning on */
         }
         ret = 1;
         break;
      }

      default: {
         LUNACA3err(LUNACA3_F_CTRL, LUNACA3_R_ENOSYS);
         ret = 0;
         break;
      }
   } /* switch */

   return ret;
}

/* Set application id */
static int luna_set_app_id(CK_ULONG appid_hi, CK_ULONG appid_lo) {
   CK_RV retCode = CKR_OK;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));

   /* NOTE: if user sets EnableLoginInit then do not call CA_SetApplicationID. */
   if ((appid_hi != 0) && (appid_lo != 0) && (luna_get_enable_login_init() == 0)) {
      retCode = p11.ext.CA_SetApplicationID(appid_hi, appid_lo);
      if (retCode != CKR_OK) {
         LUNACA3err(LUNACA3_F_SETAPPID, LUNACA3_R_EPKCS11);
         ERR_add_error_data(2, "C_SetApplicationID=0x", luna_itoa(itoabuf, retCode));
         LUNA_ERRORLOGL("luna_set_app_id: C_SetApplicationID", retCode);
         return 0;
      }
   }

   return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_dsa_handle"

/* Find DSA key handle */
static CK_OBJECT_HANDLE luna_find_dsa_handle(luna_context_t *ctx, DSA *dsa, int bPrivate) {
   CK_OBJECT_HANDLE rethandle = LUNA_INVALID_HANDLE;

   CK_BYTE_PTR bufP = NULL;
   CK_BYTE_PTR bufQ = NULL;
   CK_BYTE_PTR bufG = NULL;
   CK_BYTE_PTR bufPub = NULL;
   CK_ULONG rcCount = 0;
   CK_ULONG rcBase = 0;
   CK_OBJECT_HANDLE tmphandle = LUNA_INVALID_HANDLE;
   CK_OBJECT_CLASS ulClass = 0;
   CK_KEY_TYPE ulKeyType = 0;
   CK_ATTRIBUTE attrib[6];
   CK_ATTRIBUTE dsa_id_value_template[1];
   const BIGNUM *p = NULL;
   const BIGNUM *q = NULL;
   const BIGNUM *g = NULL;
   const BIGNUM *pub_key = NULL;

   memset(attrib, 0, sizeof(attrib));
   memset(dsa_id_value_template, 0, sizeof(dsa_id_value_template));
   dsa_id_value_template[0].type = CKA_ID;
   dsa_id_value_template[0].pValue = NULL_PTR;
   dsa_id_value_template[0].ulValueLen = 0;

   p = LUNA_DSA_GET_p(dsa);
   q = LUNA_DSA_GET_q(dsa);
   g = LUNA_DSA_GET_g(dsa);
   pub_key = LUNA_DSA_GET_pub_key(dsa);
   bufP = (CK_BYTE_PTR)LUNA_malloc(BN_num_bytes(p));
   bufQ = (CK_BYTE_PTR)LUNA_malloc(BN_num_bytes(q));
   bufG = (CK_BYTE_PTR)LUNA_malloc(BN_num_bytes(g));
   bufPub = (CK_BYTE_PTR)LUNA_malloc(BN_num_bytes(pub_key));
   if ((bufP == NULL) || (bufQ == NULL) || (bufG == NULL) || (bufPub == NULL)) {
      goto err;
   }

   rcCount = 0;
   ulKeyType = CKK_DSA;
   attrib[rcCount].type = CKA_KEY_TYPE;
   attrib[rcCount].pValue = &ulKeyType;
   attrib[rcCount].ulValueLen = sizeof(ulKeyType);
   rcCount++;

   attrib[rcCount].type = CKA_PRIME;
   attrib[rcCount].pValue = bufP;
   attrib[rcCount].ulValueLen = BN_bn2bin(p, attrib[rcCount].pValue);
   rcCount++;

   attrib[rcCount].type = CKA_SUBPRIME;
   attrib[rcCount].pValue = bufQ;
   attrib[rcCount].ulValueLen = BN_bn2bin(q, attrib[rcCount].pValue);
   rcCount++;

#if 0
   /* FIXME: CKA_BASE with leading zero is a problem so ignore CKA_BASE for now */
   attrib[rcCount].type = CKA_BASE;
   attrib[rcCount].pValue = bufG;
   attrib[rcCount].ulValueLen = BN_bn2bin(g, attrib[rcCount].pValue);
   rcCount++;
   rcBase = rcCount;
#endif

   ulClass = CKO_PUBLIC_KEY;
   attrib[rcCount].type = CKA_CLASS;
   attrib[rcCount].pValue = &ulClass;
   attrib[rcCount].ulValueLen = sizeof(ulClass);
   rcCount++;

   attrib[rcCount].type = CKA_VALUE;
   attrib[rcCount].pValue = bufPub;
   attrib[rcCount].ulValueLen = BN_bn2bin(pub_key, attrib[rcCount].pValue);
   rcCount++;

   /* Find public key */
   if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 0)) {
      LUNACA3err(LUNACA3_F_FIND_DSA, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_object_ex1");
      goto err;
   }

   /* Find private key using CKA_ID of public key */
   if (bPrivate) {
      /* Extract its CKA_ID attribute unique for a dsa key pair */
      if (!luna_attribute_malloc(ctx, tmphandle, dsa_id_value_template)) {
         LUNACA3err(LUNACA3_F_FIND_DSA, LUNACA3_R_EGETATTR);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_attribute_malloc");
         goto err;
      }

      rcCount = rcBase;
      ulClass = CKO_PRIVATE_KEY;
      attrib[rcCount].type = CKA_CLASS;
      attrib[rcCount].pValue = &ulClass;
      attrib[rcCount].ulValueLen = sizeof(ulClass);
      rcCount++;

      attrib[rcCount] = dsa_id_value_template[0];
      rcCount++;

      /* Find private object */
      if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 0)) {
         LUNACA3err(LUNACA3_F_FIND_DSA, LUNACA3_R_EFINDKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_object_ex1");
         goto err;
      }
   }

   /* on success, set 'rethandle' */
   rethandle = tmphandle;

err:
   /* undo luna_attribute_malloc */
   luna_attribute_free(dsa_id_value_template);

   /* undo LUNA_malloc */
   if (bufP != NULL) {
      LUNA_free(bufP);
   }
   if (bufQ != NULL) {
      LUNA_free(bufQ);
   }
   if (bufG != NULL) {
      LUNA_free(bufG);
   }
   if (bufPub != NULL) {
      LUNA_free(bufPub);
   }

   return rethandle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_dsa_handle_FAST"

/* Find DSA key handle by cache or regular find operation */
static CK_OBJECT_HANDLE luna_find_dsa_handle_FAST(luna_context_t *ctx, DSA *dsa, int bPrivate) {
   CK_OBJECT_HANDLE handle = LUNA_INVALID_HANDLE;
   void *dsa_ex = NULL;
   unsigned per_slot_id = ctx->per_slot_id;

   if (bPrivate) {
      dsa_ex = (g_luna_per_slot[per_slot_id].g_luna_dsa_ex_priv == -1)
                   ? NULL
                   : DSA_get_ex_data(dsa, g_luna_per_slot[per_slot_id].g_luna_dsa_ex_priv);
      if (dsa_ex != NULL) {
         handle = (CK_OBJECT_HANDLE)((size_t)dsa_ex); /* Cache hit */
      } else {
         handle = luna_find_dsa_handle(ctx, dsa, bPrivate); /* Cache miss */
         if ((g_luna_per_slot[per_slot_id].g_luna_dsa_ex_priv != -1) && (handle != LUNA_INVALID_HANDLE)) {
            DSA_set_ex_data(dsa, g_luna_per_slot[per_slot_id].g_luna_dsa_ex_priv, (void *)((size_t)handle));
         }
      }
   } else {
      dsa_ex = (g_luna_per_slot[per_slot_id].g_luna_dsa_ex_pub == -1)
                   ? NULL
                   : DSA_get_ex_data(dsa, g_luna_per_slot[per_slot_id].g_luna_dsa_ex_pub);
      if (dsa_ex != NULL) {
         handle = (CK_OBJECT_HANDLE)((size_t)dsa_ex); /* Cache hit */
      } else {
         handle = luna_find_dsa_handle(ctx, dsa, bPrivate); /* Cache miss */
         if ((g_luna_per_slot[per_slot_id].g_luna_dsa_ex_pub != -1) && (handle != LUNA_INVALID_HANDLE)) {
            DSA_set_ex_data(dsa, g_luna_per_slot[per_slot_id].g_luna_dsa_ex_pub, (void *)((size_t)handle));
         }
      }
   }

   return handle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_rsa_handle"

/* Find RSA key handle by modulus attribute */
static CK_OBJECT_HANDLE luna_find_rsa_handle(luna_context_t *ctx, RSA *rsa, int bPrivate) {
   const CK_OBJECT_CLASS keyclassPublic = CKO_PUBLIC_KEY;
   const CK_OBJECT_CLASS keyclassPrivate = CKO_PRIVATE_KEY;
   const CK_KEY_TYPE keytypeRSA = CKK_RSA;

   unsigned char *bufN = NULL;
   unsigned char *bufE = NULL;
   unsigned ndx = 0;
   CK_OBJECT_HANDLE handle = LUNA_INVALID_HANDLE;
   CK_ATTRIBUTE attrib[4];
   int numAttrs = 0;

   memset(attrib, 0, sizeof(attrib));

   bufN = (unsigned char *)LUNA_malloc(BN_num_bytes(LUNA_RSA_GET_n(rsa)));
   bufE = (unsigned char *)LUNA_malloc(BN_num_bytes(LUNA_RSA_GET_e(rsa)));
   if ((bufN == NULL) || (bufE == NULL)) {
      goto err;
   }

   /* find key handle */
   if (luna_pa_check_lib()) {
      char rsatempkeyname[81] = "";

      /* get CKA_LABEL from rsa attribute p */
      BN_bn2bin(LUNA_RSA_GET_p(rsa), (unsigned char *)rsatempkeyname);

      attrib[0].type = CKA_LABEL;
      attrib[0].pValue = rsatempkeyname;
      attrib[0].ulValueLen = (CK_ULONG)strlen(rsatempkeyname);
      numAttrs = 1;
   } else {
      if (bPrivate) {
         attrib[ndx = 0].type = CKA_CLASS;
         attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPrivate;
         attrib[ndx].ulValueLen = sizeof(keyclassPrivate);
      } else {
         attrib[ndx = 0].type = CKA_CLASS;
         attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPublic;
         attrib[ndx].ulValueLen = sizeof(keyclassPublic);
      }

      attrib[ndx = 1].type = CKA_KEY_TYPE;
      attrib[ndx].pValue = (CK_BYTE_PTR)&keytypeRSA;
      attrib[ndx].ulValueLen = sizeof(keytypeRSA);

      attrib[ndx = 2].type = CKA_PUBLIC_EXPONENT;
      attrib[ndx].pValue = (CK_BYTE_PTR)bufE;
      attrib[ndx].ulValueLen = BN_bn2bin(LUNA_RSA_GET_e(rsa), (unsigned char *)bufE);

      attrib[ndx = 3].type = CKA_MODULUS;
      attrib[ndx].pValue = (CK_BYTE_PTR)bufN;
      attrib[ndx].ulValueLen = BN_bn2bin(LUNA_RSA_GET_n(rsa), (unsigned char *)bufN);

      numAttrs = 4;
   }

   if (!luna_find_object_ex1(ctx, attrib, numAttrs, &handle, 0)) {
      if (bPrivate) {
         LUNACA3err(LUNACA3_F_FIND_RSA, LUNACA3_R_EFINDKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_object_ex1");
      }
      goto err;
   }

err:
   if (bufN != NULL) {
      LUNA_free(bufN);
   }
   if (bufE != NULL) {
      LUNA_free(bufE);
   }
   return handle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_rsa_handle_FAST"

/* Find RSA key handle by cache or regular find operation */
static CK_OBJECT_HANDLE luna_find_rsa_handle_FAST(luna_context_t *ctx, RSA *rsa, int bPrivate) {
   CK_OBJECT_HANDLE handle = LUNA_INVALID_HANDLE;
   void *rsa_ex = NULL;
   unsigned per_slot_id = ctx->per_slot_id;

   if (bPrivate) {
      rsa_ex = (g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv == -1)
                   ? NULL
                   : RSA_get_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv);
      if (rsa_ex != NULL) {
         handle = (CK_OBJECT_HANDLE)((size_t)rsa_ex); /* Cache hit */
      } else {
         handle = luna_find_rsa_handle(ctx, rsa, bPrivate); /* Cache miss */
         if ((g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv != -1) && (handle != LUNA_INVALID_HANDLE)) {
            /* KeySecure does not persist handle so can't cache it here */
            if (!luna_pa_check_lib()) {
               RSA_set_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv, (void *)((size_t)handle));
            }
         }
      }
   } else {
      rsa_ex = (g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub == -1)
                   ? NULL
                   : RSA_get_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub);
      if (rsa_ex != NULL) {
         handle = (CK_OBJECT_HANDLE)((size_t)rsa_ex); /* Cache hit */
      } else {
         handle = luna_find_rsa_handle(ctx, rsa, bPrivate); /* Cache miss */
         if ((g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub != -1) && (handle != LUNA_INVALID_HANDLE)) {
            RSA_set_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub, (void *)((size_t)handle));
         }
      }
   }

   return handle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_cache_rsa_handle"

/* Cache RSA key handle once per key */
static void luna_cache_rsa_handle(luna_context_t *ctx, RSA *rsa, CK_OBJECT_HANDLE handle_pri,
                                  CK_OBJECT_HANDLE handle_pub) {
   void *rsa_ex = NULL;
   unsigned per_slot_id = ctx->per_slot_id;

   /* private */
   rsa_ex = (g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv == -1)
                ? NULL
                : RSA_get_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv);
   if (rsa_ex == NULL) {
      if ((g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv != -1) && (handle_pri != LUNA_INVALID_HANDLE)) {
         RSA_set_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_priv, (void *)((size_t)handle_pri));
      }
   }

   /* public */
   rsa_ex = (g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub == -1)
                ? NULL
                : RSA_get_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub);
   if (rsa_ex == NULL) {
      if ((g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub != -1) && (handle_pub != LUNA_INVALID_HANDLE)) {
         RSA_set_ex_data(rsa, g_luna_per_slot[per_slot_id].g_luna_rsa_ex_pub, (void *)((size_t)handle_pub));
      }
   }
}

/* Execute engine command */
static int luna_cmdarg_engine_ext2(char *arg, int cmd) {
   int ret = 1;
   session_desc session;
   char *password = NULL;

   /* Verify library loaded */
   if (luna_have_c_init == 0)
      return 0;

   memset(&session, 0, sizeof(session));

   if (arg == NULL) {
      LUNACA3err(LUNACA3_F_CMDARG, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG("luna_cmdarg_engine_ext2: arg");
      return 0;
   }
   /* Parse string format:  "slotid:appidhi:appidlo" */
   if (!luna_parse_session_desc((char *)arg, &session, &password)) {
      LUNACA3err(LUNACA3_F_CMDARG, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG("luna_cmdarg_engine_ext2: luna_parse_session_desc");
      return 0;
   }
   /* Set App Id */
   if (!luna_set_app_id(session.app_id.hi, session.app_id.low)) {
      if (password) {
         LUNA_free(password);
         password = NULL;
      }
      LUNA_ERRORLOG("luna_cmdarg_engine_ext2: luna_set_app_id");
      return 0;
   }
   /* Execute requested action */
   switch (cmd) {
      case ENGINE_CMD_LUNA_ENGINEINIT:
         g_luna_per_slot[0].g_slot_id = session.slot;
         g_luna_per_slot[0].g_session_handle = 0;
         ret = 1;
         break;

      case ENGINE_CMD_LUNA_ENGINE2INIT:
         g_luna_per_slot[1].g_slot_id = session.slot;
         g_luna_per_slot[1].g_session_handle = 0;
         ret = 1;
         break;

      case ENGINE_CMD_LUNA_ENGINEARG:
      case ENGINE_CMD_LUNA_OPEN_SESSION_BY_STRING:
         g_luna_per_slot[0].g_slot_id = session.slot;
         ret = luna_open_session(session.slot, &(g_luna_per_slot[0].g_session_handle));
         break;

      case ENGINE_CMD_LUNA_LOGIN_BY_STRING:
         g_luna_per_slot[0].g_slot_id = session.slot;
         ret = luna_open_session_and_login(session.slot, &(g_luna_per_slot[0].g_session_handle), password);
         break;

      case ENGINE_CMD_LUNA_LOGOUT_BY_STRING:
         ret = luna_logout(g_luna_per_slot[0].g_session_handle);
         break;

      case ENGINE_CMD_LUNA_CLOSE_SESSION_BY_STRING:
         ret = luna_close_session(g_luna_per_slot[0].g_session_handle);
         g_luna_per_slot[0].g_session_handle = 0;
         break;
   } /* switch */
   if (password != NULL) {
      LUNA_free(password);
      password = NULL;
   }
   return ret;
}

/* Perform RSA private encrypt crypto operation */
static int luna_rsa_priv_enc_software(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;
   luna_mutex_enter_ndx(LUNA_MUTEX_NDX_SW); /* NOTE: beware of recursion */
   rc = (saved_rsa_priv_enc != NULL) ? saved_rsa_priv_enc(flen, from, to, rsa, padding) : -1;
   luna_mutex_exit_ndx(LUNA_MUTEX_NDX_SW);
   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_priv_enc_software: rc", rc);
   }
   return rc;
}

typedef struct luna_pss_params_st {
    const EVP_MD *sig_md;
    const EVP_MD *mgf1_md;
    int saltlen;
} luna_pss_params;

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_from_pss_params"

static int luna_from_pss_params(luna_pss_params *pss_params, CK_RSA_PKCS_PSS_PARAMS *params, RSA *rsa, int verify)
{
    if (pss_params == NULL)
        return -1;

    const EVP_MD *sig_md = pss_params->sig_md;
    const EVP_MD *mgf1_md = pss_params->mgf1_md;
    int saltlen = pss_params->saltlen; /* checked further down */

    if (sig_md == NULL || mgf1_md == NULL)
        return -1;
    switch(EVP_MD_type(sig_md)) {
    case NID_sha1:
        params->hashAlg = CKM_SHA_1;
        break;
    case NID_sha224:
        params->hashAlg = CKM_SHA224;
        break;
    case NID_sha256:
        params->hashAlg = CKM_SHA256;
        break;
    case NID_sha384:
        params->hashAlg = CKM_SHA384;
        break;
    case NID_sha512:
        params->hashAlg = CKM_SHA512;
        break;
#if defined(LUNA_OSSL_SHA3)
    case NID_sha3_224:
        params->hashAlg = CKM_SHA3_224;
        break;
    case NID_sha3_256:
        params->hashAlg = CKM_SHA3_256;
        break;
    case NID_sha3_384:
        params->hashAlg = CKM_SHA3_384;
        break;
    case NID_sha3_512:
        params->hashAlg = CKM_SHA3_512;
        break;
#endif /* LUNA_OSSL_SHA3 */
    default:
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOGL(LUNA_FUNC_NAME ": unknown sig_md", EVP_MD_type(sig_md));
        return -1;
    }

    switch(EVP_MD_type(mgf1_md)) {
    case NID_sha1:
        params->mgf = CKG_MGF1_SHA1;
        break;
    case NID_sha224:
        params->mgf = CKG_MGF1_SHA224;
        break;
    case NID_sha256:
        params->mgf = CKG_MGF1_SHA256;
        break;
    case NID_sha384:
        params->mgf = CKG_MGF1_SHA384;
        break;
    case NID_sha512:
        params->mgf = CKG_MGF1_SHA512;
        break;
#if defined(LUNA_OSSL_SHA3)
    case NID_sha3_224:
        params->mgf = CKG_MGF1_SHA3_224;
        break;
    case NID_sha3_256:
        params->mgf = CKG_MGF1_SHA3_256;
        break;
    case NID_sha3_384:
        params->mgf = CKG_MGF1_SHA3_384;
        break;
    case NID_sha3_512:
        params->mgf = CKG_MGF1_SHA3_512;
        break;
#endif /* LUNA_OSSL_SHA3 */
    default:
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOGL(LUNA_FUNC_NAME ": unknown mgf1_md", EVP_MD_type(mgf1_md));
        return -1;
    }

#if defined(RSA_PSS_SALTLEN_MAX_SIGN) && defined(RSA_PSS_SALTLEN_MAX)
    /* check old compatible max salt length for sign only */
    if ( !verify && (saltlen == RSA_PSS_SALTLEN_MAX_SIGN) ) {
         saltlen = RSA_PSS_SALTLEN_MAX;
    }
#endif

    /* check new salt length */
    if (saltlen <= 0) {

        if (saltlen == 0) {
            params->sLen = 0;
        }

#if defined(RSA_PSS_SALTLEN_DIGEST)
        else if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
            params->sLen = EVP_MD_size(sig_md);
        }
#endif

#if defined(RSA_PSS_SALTLEN_MAX)
        else if (saltlen == RSA_PSS_SALTLEN_MAX) {
            int sLen;
            int hLen = EVP_MD_size(sig_md);
            int MSBits = (BN_num_bits(LUNA_RSA_GET_n(rsa)) - 1) & 0x7;
            int emLen = RSA_size(rsa);
            if (MSBits == 0) {
                emLen--;
            }
            if (emLen < hLen + 2) {
                LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
                LUNA_ERRORLOGL(LUNA_FUNC_NAME ": out of range emLen", emLen);
                return -1;
            }
            sLen = emLen - hLen - 2;
            params->sLen = sLen;
        }
#endif

        else {
            LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
            LUNA_ERRORLOGL(LUNA_FUNC_NAME ": unknown saltlen", saltlen);
            return -1;
        }

    } else {
        params->sLen = saltlen;
    }

    return 1;
}

static int luna_to_pss_params(luna_pss_params *pss_params, void *evp_pkey_ctx) {
    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX*) evp_pkey_ctx;
    const EVP_MD *sig_md = NULL;
    const EVP_MD *mgf1_md = NULL;
    int saltlen = 0;
    memset(pss_params, 0, sizeof(*pss_params));
    if (ctx == NULL) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": ctx is mandatory for pss");
        return 0;
    }
    if ((EVP_PKEY_CTX_get_signature_md(ctx, &sig_md) <= 0) || (sig_md == NULL)) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": sig_md is null");
        return 0;
    }
    if ((EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1_md) <= 0) || (mgf1_md == NULL)) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": mgf1_md is null");
        return 0;
    }
    if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen) <= 0) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": saltlen is null");
        return 0;
    }
    pss_params->sig_md = sig_md;
    pss_params->mgf1_md = mgf1_md;
    pss_params->saltlen = saltlen;
    return 1;
}

#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_from_oaep_params"

static int luna_from_oaep_params(luna_oaep_params *oaep_params, CK_RSA_PKCS_OAEP_PARAMS *params)
{
    if (oaep_params == NULL) {
        params->hashAlg = CKM_SHA_1;
        params->mgf = CKG_MGF1_SHA1;
        params->source = CKZ_DATA_SPECIFIED;
        params->pSourceData = 0;
        params->ulSourceDataLen = 0;
        return 1; /* success - ctx is optional for oaep - for backward compat */
    }

    const EVP_MD *oaep_md = oaep_params->oaep_md;
    const EVP_MD *mgf1_md = oaep_params->mgf1_md;
    unsigned char *oaep_label = oaep_params->oaep_label;
    int labellen = oaep_params->labellen;

    switch(EVP_MD_type(mgf1_md)) {
    case NID_sha1:
        params->mgf = CKG_MGF1_SHA1;
        break;
    case NID_sha224:
        params->mgf = CKG_MGF1_SHA224;
        break;
    case NID_sha256:
        params->mgf = CKG_MGF1_SHA256;
        break;
    case NID_sha384:
        params->mgf = CKG_MGF1_SHA384;
        break;
    case NID_sha512:
        params->mgf = CKG_MGF1_SHA512;
        break;
#if defined(LUNA_OSSL_SHA3)
    case NID_sha3_224:
        params->mgf = CKG_MGF1_SHA3_224;
        break;
    case NID_sha3_256:
        params->mgf = CKG_MGF1_SHA3_256;
        break;
    case NID_sha3_384:
        params->mgf = CKG_MGF1_SHA3_384;
        break;
    case NID_sha3_512:
        params->mgf = CKG_MGF1_SHA3_512;
        break;
#endif /* LUNA_OSSL_SHA3 */
    default:
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOGL(LUNA_FUNC_NAME ": unknown mgf1_md", EVP_MD_type(mgf1_md));
        return -1;
    }

    switch(EVP_MD_type(oaep_md)) {
    case NID_sha1:
        params->hashAlg = CKM_SHA_1;
        break;
    case NID_sha224:
        params->hashAlg = CKM_SHA224;
        break;
    case NID_sha256:
        params->hashAlg = CKM_SHA256;
        break;
    case NID_sha384:
        params->hashAlg = CKM_SHA384;
        break;
    case NID_sha512:
        params->hashAlg = CKM_SHA512;
        break;
#if defined(LUNA_OSSL_SHA3)
    case NID_sha3_224:
        params->hashAlg = CKM_SHA3_224;
        break;
    case NID_sha3_256:
        params->hashAlg = CKM_SHA3_256;
        break;
    case NID_sha3_384:
        params->hashAlg = CKM_SHA3_384;
        break;
    case NID_sha3_512:
        params->hashAlg = CKM_SHA3_512;
        break;
#endif /* LUNA_OSSL_SHA3 */
    default:
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOGL(LUNA_FUNC_NAME ": unknown oaep_md", EVP_MD_type(oaep_md));
        return -1;
    }

    if (labellen > 0) {
        params->source = CKZ_DATA_SPECIFIED;
        params->pSourceData = oaep_label;
        params->ulSourceDataLen = labellen;
    } else {
        params->source = CKZ_DATA_SPECIFIED;
        params->pSourceData = 0;
        params->ulSourceDataLen = 0;
    }

    return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_to_oaep_params"

static int luna_to_oaep_params(luna_oaep_params *oaep_params, void *evp_pkey_ctx)
{
    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX*) evp_pkey_ctx;

    const EVP_MD *oaep_md = NULL;
    const EVP_MD *mgf1_md = NULL;
    unsigned char *oaep_label = NULL;
    int labellen;

    if (ctx == NULL)
        return -1;

    if ((EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1_md) <= 0) || (mgf1_md == NULL)) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": mgf1_md is null");
        return -1;
    }

    if ((EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &oaep_md) <= 0) || (oaep_md == NULL)) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": oaep_md is null");
        return -1;
    }

#if 0 /* FIXME: openssl3 crashes if we try calling EVP_PKEY_CTX_get0_rsa_oaep_label !? */
    /* NOTE: this next function may return a non-null pointer with a zero length */
    labellen = EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &oaep_label);
    /* NOTE: openssl3 tends to return -1 when attributes are not set */
    if (labellen == -1 && oaep_label == NULL) {
        labellen = 0;
    }
    if ((labellen < 0) || (labellen > 0 && oaep_label == NULL)) {
        LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
        LUNA_ERRORLOG(LUNA_FUNC_NAME ": oaep_label is null");
        return -1;
    }

#else
    /* assume there is no rsa_oaep_label */
    labellen = 0;
#endif

    oaep_params->oaep_md = oaep_md;
    oaep_params->mgf1_md = mgf1_md;
    oaep_params->oaep_label = oaep_label;
    oaep_params->labellen = labellen;

    return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_priv_enc_pkcs"

/* luna_rsa_priv_enc_pkcs */
static int luna_rsa_priv_enc_pkcs(luna_pss_params *pss_params, int flen, const unsigned char *from, size_t tolen, unsigned char *to, RSA *rsa, int padding) {
   int num = 0, i = 0;
   CK_ULONG cklen = 0;
   CK_RV retCode = CKR_OK;
   CK_OBJECT_HANDLE privKeyHandle = LUNA_INVALID_HANDLE;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;
   char itoabuf[LUNA_ATOI_BYTES];

   CK_MECHANISM rsa_mechanism;
   CK_RSA_PKCS_PSS_PARAMS params;
   memset(itoabuf, 0, sizeof(itoabuf));
   memset(&rsa_mechanism, 0, sizeof(rsa_mechanism));

   int enginePaddingType = 0;
   unsigned char *buf = NULL;
   unsigned long buflen = 0;

   /* Check rsa */
   switch (luna_rsa_check_private(rsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         return luna_rsa_priv_enc_software(flen, from, to, rsa, padding);
      default: /* error */
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_rsa_check");
         goto err;
   }

   num = RSA_size(rsa);
   if ( (flen > num) || ((padding == RSA_X931_PADDING) && ((flen+2) > num)) ) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": flen", flen);
      goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   if ((privKeyHandle = luna_find_rsa_handle_FAST(&ctx, rsa, LUNA_PRIVATE)) == LUNA_INVALID_HANDLE) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_rsa_handle_FAST");
      goto err;
   }

   if ((buf = (unsigned char *)LUNA_malloc(num)) == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_ENOMEM);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_malloc");
      goto err;
   }
   buflen = num;

   switch (padding) {
      case RSA_NO_PADDING:
         rsa_mechanism.mechanism = CKM_RSA_X_509;
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         i = RSA_padding_add_none(buf, num, from, flen);
         buflen = num;
         break;
      case RSA_PKCS1_PADDING:
         enginePaddingType = luna_get_rsaPkcsPaddingType();
         if ( enginePaddingType == 2 || enginePaddingType == 1 ) {
            rsa_mechanism.mechanism = CKM_RSA_X_509;
            rsa_mechanism.pParameter = NULL_PTR;
            rsa_mechanism.ulParameterLen = 0;
            /* NOTE: only add type 1 during rsa private encrypt; see rsa_ossl_private_encrypt */
            i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
            buflen = num;
         } else {
            rsa_mechanism.mechanism = CKM_RSA_PKCS;
            rsa_mechanism.pParameter = NULL_PTR;
            rsa_mechanism.ulParameterLen = 0;
            memcpy(buf, from, flen);
            i = 1;
            buflen = flen;
         }
         break;
#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
      case RSA_PKCS1_PSS_PADDING:
          if (luna_from_pss_params(pss_params, &params, rsa, 0) <= 0) {
              LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
              LUNA_ERRORLOG(LUNA_FUNC_NAME ": failed to process pss params");
              goto err;
          }
          rsa_mechanism.mechanism = CKM_RSA_PKCS_PSS;
          rsa_mechanism.pParameter = &params;
          rsa_mechanism.ulParameterLen = sizeof(params);
          memcpy(buf, from, flen);
          i = 1;
          buflen = flen;
          break;
#endif
      case RSA_X931_PADDING:
          rsa_mechanism.mechanism = CKM_RSA_X9_31;
          rsa_mechanism.pParameter = NULL_PTR;
          rsa_mechanism.ulParameterLen = 0;
          memcpy(buf, from, flen);
          /* NOTE: byte already appended: luna_rsa_x931_hash_id(flen); */
          buf[flen] = 0xcc;
          i = 1;
          buflen = flen + 1;
          break;
      default:
         i = -1;
         break;
   }

   if (i <= 0) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EPADDING);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": i", i);
      goto err;
   }

   if (rsa_mechanism.mechanism == CKM_RSA_X_509) {
      retCode = p11.std->C_DecryptInit(ctx.hSession, &rsa_mechanism, privKeyHandle);
      if (retCode != CKR_OK) {
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EPKCS11);
         ERR_add_error_data(2, "C_DecryptInit=0x", luna_itoa(itoabuf, retCode));
         LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_DecryptInit", retCode);
         goto err;
      }

      IF_LUNA_DEBUG(luna_dumpdata("RSA priv dec (encrypted):     ", buf, buflen));
      cklen = (CK_ULONG)tolen; /* NOTE: same as RSA_size(rsa) */
      retCode = p11.std->C_Decrypt(ctx.hSession, (CK_BYTE_PTR)buf, buflen, (CK_BYTE_PTR)to, &cklen);
      if (retCode != CKR_OK) {
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EPKCS11);
         ERR_add_error_data(2, "C_Decrypt=0x", luna_itoa(itoabuf, retCode));
         LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Decrypt", retCode);
         goto err;
      }

   } else {
      retCode = p11.std->C_SignInit(ctx.hSession, &rsa_mechanism, privKeyHandle);
      if (retCode != CKR_OK) {
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EPKCS11);
         ERR_add_error_data(2, "C_SignInit=0x", luna_itoa(itoabuf, retCode));
         LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_SignInit", retCode);
         goto err;
      }

      IF_LUNA_DEBUG(luna_dumpdata("RSA privenc (clear):     ", buf, buflen));
      cklen = (CK_ULONG)tolen; /* NOTE: same as RSA_size(rsa) */
      retCode = p11.std->C_Sign(ctx.hSession, (CK_BYTE_PTR)buf, (CK_ULONG)buflen, (CK_BYTE_PTR)to, &cklen);
      if (retCode != CKR_OK) {
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EPKCS11);
         ERR_add_error_data(2, "C_Sign=0x", luna_itoa(itoabuf, retCode));
         LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Sign", retCode);
         goto err;
      }
   }

   IF_LUNA_DEBUG(luna_dumpdata("RSA privenc (signed):     ", to, cklen));
   LUNA_cleanse_free(buf, num);
   luna_close_context(&ctx);
   return (int)cklen;

err:
   LUNA_cleanse_free(buf, num);
   luna_close_context_w_err(&ctx, -1, retCode);
   return -1;
}

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_sign"

static int luna_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
   EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
   if (pkey == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": pkey is null");
      return -1;
   }
   /* TODO: should we call EVP_PKEY_get1_RSA or EVP_PKEY_get0_RSA here?
    * Historically, this code just wants to peek at the key structure without
    * changing the reference count. So, calling EVP_PKEY_get0_RSA makes sense for now.
    */
   RSA *rsa = LUNA_EVP_PKEY_get0_RSA(pkey);
   if (rsa == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": rsa is null");
      return -1;
   }

   int padding = 0;
   if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": get_rsa_padding failed");
      return -1;
   }

   /* check signature buffer length */
   size_t rsasize = (size_t)RSA_size(rsa);
   if (sig == NULL) {
      *siglen = rsasize; // success
      return 1;
   }

   if (*siglen < rsasize) {
       return -1;
   }

   /* NOTE: RSA_PKCS1_PSS_PADDING is the only padding type implemented correctly here */
   if (padding != RSA_PKCS1_PSS_PADDING) {
      if (saved_rsapss.sign != NULL) {
         return saved_rsapss.sign(ctx, sig, siglen, tbs, tbslen);
      } else {
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": saved_rsapss.sign is null");
         return -1;
      }
   }

   switch (luna_rsa_check_private(rsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         if (saved_rsapss.sign != NULL) {
            return saved_rsapss.sign(ctx, sig, siglen, tbs, tbslen);
         } else {
            LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINVAL);
            LUNA_ERRORLOG(LUNA_FUNC_NAME ": saved_rsapss.sign is null");
            return -1;
         }
      default: /* error */
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_ENCRYPT, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_rsa_check");
         return -1;
   }

    // return 1 on success; return 0 or negative number on failure
    // side-effect siglen on success only
    int ret;
    luna_pss_params pss_params;
    memset(&pss_params, 0, sizeof(pss_params));
    luna_to_pss_params(&pss_params, ctx);
    int rcLen = luna_rsa_priv_enc_pkcs(&pss_params, (int) tbslen, tbs, *siglen, sig, rsa, padding);
    ret = (rcLen > 0) ? 1 : -1;
    if (ret == 1) {
        *siglen = (size_t) rcLen; // success
    }

   return ret;
}

#endif


static int luna_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;
   int rsasize = RSA_size(rsa);

   if (to == NULL) {
      /* possibly some crazy app is querying output length */
      rc = rsasize;
   } else {
      rc = luna_rsa_priv_enc_pkcs(NULL, flen, from, (size_t)rsasize, to, rsa, padding);
   }

   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_priv_enc: rc", rc);
   }

   return rc;
}

/* Perform RSA public encrypt crypto operation */
static int luna_rsa_pub_enc_software(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;
   luna_mutex_enter_ndx(LUNA_MUTEX_NDX_SW); /* NOTE: beware of recursion */
   rc = (saved_rsa_pub_enc != NULL) ? saved_rsa_pub_enc(flen, from, to, rsa, padding) : -1;
   luna_mutex_exit_ndx(LUNA_MUTEX_NDX_SW);
   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_pub_enc_software: rc", rc);
   }
   return rc;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_pub_enc_x509"

static int luna_rsa_pub_enc_x509(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int i = 0, num = 0, sublen = 0;
   CK_ULONG cklen = 0;
   CK_RV retCode = CKR_OK;
   CK_OBJECT_HANDLE pubKeyHandle = LUNA_INVALID_HANDLE;
   unsigned char *buf = NULL;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   char itoabuf[LUNA_ATOI_BYTES];
   CK_MECHANISM rsa_mechanism;
   CK_RSA_PKCS_OAEP_PARAMS oaepParams;
   memset(itoabuf, 0, sizeof(itoabuf));
   memset(&rsa_mechanism, 0, sizeof(rsa_mechanism));
   memset(&oaepParams, 0, sizeof(oaepParams));

   int enginePaddingType = 0;

   /* Check rsa */
   switch (luna_rsa_check_public(rsa)) {
      case 0: /* hardware */
         if (g_postconfig.DisablePublicCrypto == 0)
            break; /* plan A */
                   /* plan B -- fall through */
      case 1:      /* software */
         return luna_rsa_pub_enc_software(flen, from, to, rsa, padding);
      default: /* error */
         LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_rsa_check");
         goto err;
   }

   sublen = num = RSA_size(rsa);
   if (flen > num) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": flen", flen);
      goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   pubKeyHandle = luna_find_rsa_handle_FAST(&ctx, rsa, LUNA_PUBLIC);
   if (pubKeyHandle == LUNA_INVALID_HANDLE) {
      /* if public key handle not found then perform this public operation in software  */
      luna_close_context(&ctx); /* likely */
      return luna_rsa_pub_enc_software(flen, from, to, rsa, padding);
   }

   if ((buf = (unsigned char *)LUNA_malloc(num)) == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_ENOMEM);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_malloc");
      goto err;
   }

   switch (padding) {
      case RSA_PKCS1_PADDING:
         enginePaddingType = luna_get_rsaPkcsPaddingType();
         if ( enginePaddingType == 2 || enginePaddingType == 1 ) {
            rsa_mechanism.mechanism = CKM_RSA_X_509;
            rsa_mechanism.pParameter = NULL_PTR;
            rsa_mechanism.ulParameterLen = 0;
            sublen = num;
            /* NOTE: only add type 2 during rsa public encrypt; see rsa_ossl_public_encrypt */
            i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
         } else {
            rsa_mechanism.mechanism = CKM_RSA_PKCS;
            rsa_mechanism.pParameter = NULL_PTR;
            rsa_mechanism.ulParameterLen = 0;
            memcpy(buf, from, flen);
            sublen = flen;
            i = flen;
         }
         break;
#ifndef OPENSSL_NO_SHA
      case RSA_PKCS1_OAEP_PADDING:
         if (luna_from_oaep_params(NULL, &oaepParams) <= 0) {
            LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_EINVAL);
            LUNA_ERRORLOG(LUNA_FUNC_NAME ": failed to process oaep params");
            goto err;
         }
         rsa_mechanism.mechanism = CKM_RSA_PKCS_OAEP;
         rsa_mechanism.pParameter = &oaepParams;
         rsa_mechanism.ulParameterLen = sizeof(oaepParams);
         memcpy(buf, from, flen);
         sublen = flen;
         i = flen; /* was: i=RSA_padding_add_PKCS1_OAEP(buf,num,from,flen,NULL,0); */
         break;
#endif
#ifdef LUNA_OSSL_SSLV3
      case RSA_SSLV23_PADDING:
         rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm. */
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         sublen = num;
         i = RSA_padding_add_SSLv23(buf, num, from, flen);
         break;
#endif
      case RSA_NO_PADDING:
         rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm. */
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         sublen = num;
         i = RSA_padding_add_none(buf, num, from, flen);
         break;
      default:
         i = -1;
         break;
   } /* switch */
   if (i <= 0) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_EPADDING);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": i", i);
      goto err;
   }

   retCode = p11.std->C_EncryptInit(ctx.hSession, &rsa_mechanism, pubKeyHandle);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_EncryptInit=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_EncryptInit", retCode);
      goto err;
   }

   cklen = num; /* NOTE: same as RSA_size(rsa) */
   retCode = p11.std->C_Encrypt(ctx.hSession, buf, sublen, to, &cklen);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_ENCRYPT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Encrypt=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Encrypt", retCode);
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("RSA pubenc (clear):     ", buf, num));
   IF_LUNA_DEBUG(luna_dumpdata("RSA pubenc (encrypted): ", to, cklen));

   LUNA_cleanse_free(buf, num);
   luna_close_context(&ctx);
   return (int)cklen;

err:
   LUNA_cleanse_free(buf, num);
   luna_close_context_w_err(&ctx, -1, retCode);
   return -1;
}

static int luna_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;

   if (to == NULL) {
      /* possibly some crazy app is querying output length */
      rc = RSA_size(rsa);
   } else {
      rc = luna_rsa_pub_enc_x509(flen, from, to, rsa, padding);
   }

   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_pub_enc: rc", rc);
   }

   return rc;
}

/* Perform RSA private decrypt crypto operation */
static int luna_rsa_priv_dec_software(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;
   luna_mutex_enter_ndx(LUNA_MUTEX_NDX_SW); /* NOTE: beware of recursion */
   rc = (saved_rsa_priv_dec != NULL) ? saved_rsa_priv_dec(flen, from, to, rsa, padding) : -1;
   luna_mutex_exit_ndx(LUNA_MUTEX_NDX_SW);
   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_priv_dec_software: rc", rc);
   }
   return rc;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_priv_dec_x509"

static int luna_rsa_priv_dec_x509(luna_oaep_params *oaep_params, int flen, const unsigned char *from,
        size_t tolen, unsigned char *to, RSA *rsa, int padding)
{
   int sslLen = -1, r = -1, num = 0;
   unsigned char *buf = NULL;
   unsigned char *pad = NULL;
   CK_RV retCode = CKR_OK;
   CK_OBJECT_HANDLE privKeyHandle = LUNA_INVALID_HANDLE;
   CK_ULONG cklen = 0;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   char itoabuf[LUNA_ATOI_BYTES];
   CK_MECHANISM rsa_mechanism;
   CK_RSA_PKCS_OAEP_PARAMS oaepParams;
   memset(itoabuf, 0, sizeof(itoabuf));
   memset(&rsa_mechanism, 0, sizeof(rsa_mechanism));
   memset(&oaepParams, 0, sizeof(oaepParams));

   int enginePaddingType = 0;

   /* Check rsa */
   switch (luna_rsa_check_private(rsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         return luna_rsa_priv_dec_software(flen, from, to, rsa, padding);
      default: /* error */
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_rsa_check");
         goto err;
   }

   num = (int)tolen; /* NOTE: same as RSA_size(rsa); */
   if (flen > num) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": flen", flen);
      goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   if ((privKeyHandle = luna_find_rsa_handle_FAST(&ctx, rsa, LUNA_PRIVATE)) == LUNA_INVALID_HANDLE) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_rsa_handle_FAST");
      goto err;
   }

   if ((buf = (unsigned char *)LUNA_malloc(num)) == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_ENOMEM);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_malloc");
      goto err;
   }

   switch (padding) {
      case RSA_PKCS1_PADDING:
         enginePaddingType = luna_get_rsaPkcsPaddingType();
         if ( enginePaddingType == 2 || enginePaddingType == 1 ) {
            rsa_mechanism.mechanism = CKM_RSA_X_509;
            rsa_mechanism.pParameter = NULL_PTR;
            rsa_mechanism.ulParameterLen = 0;
         } else {
            rsa_mechanism.mechanism = CKM_RSA_PKCS;
            rsa_mechanism.pParameter = NULL_PTR;
            rsa_mechanism.ulParameterLen = 0;
         }
         break;
#ifndef OPENSSL_NO_SHA
      case RSA_PKCS1_OAEP_PADDING:
         if (luna_from_oaep_params(oaep_params, &oaepParams) <= 0) {
            LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
            LUNA_ERRORLOG(LUNA_FUNC_NAME ": failed to process oaep params");
            goto err;
         }
         rsa_mechanism.mechanism = CKM_RSA_PKCS_OAEP;
         rsa_mechanism.pParameter = &oaepParams;
         rsa_mechanism.ulParameterLen = sizeof(oaepParams);
         break;
#endif
#ifdef LUNA_OSSL_SSLV3
      case RSA_SSLV23_PADDING:
         rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm. */
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         break;
#endif
      case RSA_NO_PADDING:
         rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm. */
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         break;
      default:
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
         LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
         goto err;
   } /* switch */

   retCode = p11.std->C_DecryptInit(ctx.hSession, &rsa_mechanism, privKeyHandle);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_DecryptInit=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_DecryptInit", retCode);
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("RSA priv dec (encrypted):     ", from, flen));
   cklen = num; /* NOTE: same as RSA_size(rsa) */
   retCode = p11.std->C_Decrypt(ctx.hSession, (CK_BYTE_PTR)from, flen, (CK_BYTE_PTR)buf, &cklen);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Decrypt=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Decrypt", retCode);
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("RSA priv dec (decrypted): ", buf, cklen));

   switch (padding) {
      case RSA_PKCS1_PADDING:
         if ( enginePaddingType == 2 || enginePaddingType == 1 ) {
            for (pad = buf; (cklen > 0) && (*pad == 0);) {
               pad++;
               cklen--;
            } /* remove leading zeros */
            /* NOTE: only check type 2 during rsa private decrypt; see rsa_ossl_private_decrypt */
            r = sslLen = RSA_padding_check_PKCS1_type_2(to, num, pad, cklen, num);
         } else {
            /* CKM_RSA_PKCS was done in hardware */
            memcpy(to, buf, cklen);
            r = sslLen = cklen;
         }
         break;
#ifndef OPENSSL_NO_SHA
      case RSA_PKCS1_OAEP_PADDING:
         /* was: r = sslLen = RSA_padding_check_PKCS1_OAEP(to, num, pad, cklen, num, NULL, 0); */
         memcpy(to, buf, cklen);
         r = sslLen = cklen;
         break;
#endif
#ifdef LUNA_OSSL_SSLV3
      case RSA_SSLV23_PADDING:
         for (pad = buf; (cklen > 0) && (*pad == 0);) {
            pad++;
            cklen--;
         } /* remove leading zeros */
         r = sslLen = RSA_padding_check_SSLv23(to, num, pad, cklen, num);
         break;
#endif
      case RSA_NO_PADDING:
         for (pad = buf; (cklen > 0) && (*pad == 0);) {
            pad++;
            cklen--;
         } /* remove leading zeros */
         r = sslLen = RSA_padding_check_none(to, num, pad, cklen, num);
         break;
   } /* switch */

   if (r < 0) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EPADDING);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": r", r);
      goto err;
   }

   LUNA_cleanse_free(buf, num);
   luna_close_context(&ctx);
   return sslLen;

err:
   LUNA_cleanse_free(buf, num);
   luna_close_context_w_err(&ctx, -1, retCode);
   return -1;
}

static int luna_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;
   int rsasize = RSA_size(rsa);

   /*printf("luna_rsa_priv_dec: flen = %d, from = %p, to = %p, rsa = %p, padding = %d \n",
           flen, from, to, rsa, padding);*/
   if (to == NULL) {
      /* possibly some crazy app is querying output length */
      rc = rsasize;
   } else {
      rc = luna_rsa_priv_dec_x509(NULL, flen, from, (size_t)rsasize, to, rsa, padding);
   }

   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_priv_dec: rc", rc);
   }

   return rc;
}

/* Perform RSA public decrypt crypto operation */
static int luna_rsa_pub_dec_software(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;
   luna_mutex_enter_ndx(LUNA_MUTEX_NDX_SW); /* NOTE: beware of recursion */
   rc = (saved_rsa_pub_dec != NULL) ? saved_rsa_pub_dec(flen, from, to, rsa, padding) : -1;
   luna_mutex_exit_ndx(LUNA_MUTEX_NDX_SW);
   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_pub_dec_software: rc", rc);
   }
   return rc;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_pub_dec_x509"

static int luna_rsa_pub_dec_x509(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int num = 0, r = -1;
   CK_ULONG cklen = 0;
   CK_RV retCode = CKR_OK;
   CK_OBJECT_HANDLE pubKeyHandle = LUNA_INVALID_HANDLE;
   unsigned char *buf = NULL;
   unsigned char *pad = NULL;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;
   char itoabuf[LUNA_ATOI_BYTES];

   CK_MECHANISM rsa_mechanism;
   memset(itoabuf, 0, sizeof(itoabuf));
   memset(&rsa_mechanism, 0, sizeof(rsa_mechanism));

   /* Check rsa */
   switch (luna_rsa_check_public(rsa)) {
      case 0: /* hardware */
         if (g_postconfig.DisablePublicCrypto == 0)
            break; /* plan A */
                   /* plan B -- fall through */
      case 1:      /* software */
         return luna_rsa_pub_dec_software(flen, from, to, rsa, padding);
      default: /* error */
         LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_rsa_check");
         goto err;
   }

   num = RSA_size(rsa);
   if (flen > num) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": flen", flen);
      goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   pubKeyHandle = luna_find_rsa_handle_FAST(&ctx, rsa, LUNA_PUBLIC);
   if (pubKeyHandle == LUNA_INVALID_HANDLE) {
      /* if public key handle not found then perform this public operation in software  */
      luna_close_context(&ctx); /* likely */
      return luna_rsa_pub_dec_software(flen, from, to, rsa, padding);
   }

   if ((buf = (unsigned char *)LUNA_malloc(num)) == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_ENOMEM);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_malloc");
      goto err;
   }

   switch (padding) {
      case RSA_PKCS1_PADDING:
         /* NOTE: the request is for "rsa public decrypt with pkcs1 padding" however the hsm cannot do that.
          * Instead we can try "rsa public encrypt with no padding" in hsm followed by padding check in software.
          * Otherwise, we are sunk (cannot use the hsm for rsa public key ops).
          * Finally, just set "DisablePublicCrypto=1" and enjoy faster public key ops in software.
          */
         rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm */
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         break;
      case RSA_NO_PADDING:
         rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm */
         rsa_mechanism.pParameter = NULL_PTR;
         rsa_mechanism.ulParameterLen = 0;
         break;
      case RSA_X931_PADDING:
          /* NOTE: same note as for RSA_PKCS1_PADDING above. */
          rsa_mechanism.mechanism = CKM_RSA_X_509; /* FIXME: assumes non-fips hsm */
          rsa_mechanism.pParameter = NULL_PTR;
          rsa_mechanism.ulParameterLen = 0;
          break;
      default:
         LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EINVAL);
         LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
         goto err;
   } /* switch */

   if (rsa_mechanism.mechanism == CKM_RSA_X_509) {
       retCode = p11.std->C_EncryptInit(ctx.hSession, &rsa_mechanism, pubKeyHandle);
       if (retCode != CKR_OK) {
          LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EPKCS11);
          ERR_add_error_data(2, "C_EncryptInit=0x", luna_itoa(itoabuf, retCode));
          LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_EncryptInit", retCode);
          goto err;
       }

       IF_LUNA_DEBUG(luna_dumpdata("RSA pubdec (encrypted):     ", from, flen));
       /* NOTE: cannot decrypt using a public key (key type inconsistent) */
       cklen = num; /* NOTE: same as RSA_size(rsa) */
       retCode = p11.std->C_Encrypt(ctx.hSession, (CK_BYTE_PTR)from, flen, (CK_BYTE_PTR)buf, &cklen);
       if (retCode != CKR_OK) {
          LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EPKCS11);
          ERR_add_error_data(2, "C_Encrypt=0x", luna_itoa(itoabuf, retCode));
          LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Encrypt", retCode);
          goto err;
       }

       IF_LUNA_DEBUG(luna_dumpdata("RSA pubdec (decrypted): ", buf, cklen));

   } else {
       LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EINVAL);
       LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
       goto err;
   }

   switch (padding) {
      case RSA_PKCS1_PADDING:
         if (rsa_mechanism.mechanism == CKM_RSA_X_509) {
            /* NOTE: only check type 1 during rsa public decrypt; see rsa_ossl_public_decrypt */
            r = RSA_padding_check_PKCS1_type_1(to, num, buf, cklen, num);
         } else {
            r = cklen;
            memcpy(to, buf, cklen);
         }
         break;
      case RSA_NO_PADDING:
         for (pad = buf; (cklen > 0) && (*pad == 0);) {
            pad++;
            cklen--;
         } /* remove leading zeros */
         r = RSA_padding_check_none(to, num, pad, cklen, num);
         break;
      case RSA_X931_PADDING:
          if (rsa_mechanism.mechanism == CKM_RSA_X_509) {
             r = RSA_padding_check_X931(to, num, buf, cklen, num);
          } else {
             r = cklen;
             memcpy(to, buf, cklen);
          }
          break;
   } /* switch */

   if (r < 0) {
      LUNACA3err(LUNACA3_F_RSA_PUBLIC_DECRYPT, LUNACA3_R_EPADDING);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": padding", padding);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": r", r);
      goto err;
   }

   if (rsa_mechanism.mechanism == CKM_RSA_X_509) {
       IF_LUNA_DEBUG(luna_dumpdata("RSA pubdec (decrypted no pad): ", to, r));
   }

   LUNA_cleanse_free(buf, num);
   luna_close_context(&ctx);
   return r;

err:
   LUNA_cleanse_free(buf, num);
   luna_close_context_w_err(&ctx, -1, retCode);
   return -1;
}

static int luna_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
   int rc;

   if (to == NULL) {
      /* possibly some crazy app is querying output length */
      rc = RSA_size(rsa);
   } else {
      rc = luna_rsa_pub_dec_x509(flen, from, to, rsa, padding);
   }

   if (rc <= 0) {
      LUNA_ERRORLOGL("luna_rsa_pub_dec: rc", rc);
   }

   return rc;
}

#define LUNA_DSA_MAX_SIGRET (512)

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_dsa_do_sign"

/* Perform DSA sign crypto operation */
static DSA_SIG *luna_dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa) {
   DSA_SIG *sig = NULL;
   CK_OBJECT_HANDLE priv_handle = LUNA_INVALID_HANDLE;
   CK_ULONG siglen = 0;
   CK_BYTE sigret[LUNA_DSA_MAX_SIGRET];
   CK_RV retCode = CKR_OK;
   CK_ULONG rlen = 0;
   CK_ULONG slen = 0;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;
   char itoabuf[LUNA_ATOI_BYTES];

   CK_MECHANISM dsa_pkcs_mechanism;
   memset(itoabuf, 0, sizeof(itoabuf));
   memset(sigret, 0, sizeof(sigret));
   memset(&dsa_pkcs_mechanism, 0, sizeof(dsa_pkcs_mechanism));
   dsa_pkcs_mechanism.mechanism = CKM_DSA;
   dsa_pkcs_mechanism.pParameter = NULL_PTR;
   dsa_pkcs_mechanism.ulParameterLen = 0;

   /* Check dsa */
   switch (luna_dsa_check_private(dsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         if (saved_dsa_do_sign != NULL) {
            return saved_dsa_do_sign(dgst, dlen, dsa);
         }
      /* fall through */
      default: /* error */
         LUNACA3err(LUNACA3_F_DSA_SIGN, LUNACA3_R_EINKEY);
         goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   /* Find object */
   if ((priv_handle = luna_find_dsa_handle_FAST(&ctx, dsa, LUNA_PRIVATE)) == LUNA_INVALID_HANDLE) {
      LUNACA3err(LUNACA3_F_DSA_SIGN, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_dsa_handle");
      goto err;
   }

   /* SignInit */
   retCode = p11.std->C_SignInit(ctx.hSession, &dsa_pkcs_mechanism, priv_handle);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_DSA_SIGN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_SignInit(DSA)=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_SignInit", retCode);
      goto err;
   }

   /* Sign */
   IF_LUNA_DEBUG(luna_dumpdata("hash to sign (raw): ", dgst, dlen));
   siglen = sizeof(sigret);
   retCode = p11.std->C_Sign(ctx.hSession, (CK_BYTE_PTR)dgst, (CK_ULONG)dlen, sigret, &siglen);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_DSA_SIGN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Sign(DSA)=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Sign", retCode);
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("hash signed: ", sigret, siglen));

   if ((sig = DSA_SIG_new()) == NULL) {
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": DSA_SIG_new");
      goto err;
   }

   rlen = siglen / 2;
   slen = siglen - rlen;
   LUNA_DSA_SIG_SET_r_s(sig, BN_bin2bn(sigret, rlen, NULL), BN_bin2bn((sigret + rlen), slen, NULL));

   luna_close_context(&ctx);
   return sig;

err:
   luna_close_context_w_err(&ctx, -1, retCode);
   return NULL;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_dsa_sign_setup"

/* Perform DSA sign setup */
static int luna_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp) {
   /* Check dsa */
   switch (luna_dsa_check_private(dsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         if (saved_dsa_sign_setup != NULL) {
            return saved_dsa_sign_setup(dsa, ctx_in, kinvp, rp);
         }
      /* fall through */
      default: /* error */
         LUNACA3err(LUNACA3_F_DSA_SIGN, LUNACA3_R_EINKEY);
         return 0;
   }

   return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_dsa_do_verify"

/* Perform DSA verify crypto operation */
static int luna_dsa_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa) {
   CK_OBJECT_HANDLE pub_handle = LUNA_INVALID_HANDLE;
   CK_BYTE sigbuf[128];
   CK_RV retCode = CKR_OK;
   CK_ULONG rlen = 0;
   CK_ULONG slen = 0;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;
   char itoabuf[LUNA_ATOI_BYTES];

   CK_MECHANISM dsa_pkcs_mechanism;
   memset(itoabuf, 0, sizeof(itoabuf));
   memset(sigbuf, 0, sizeof(sigbuf));
   memset(&dsa_pkcs_mechanism, 0, sizeof(dsa_pkcs_mechanism));
   dsa_pkcs_mechanism.mechanism = CKM_DSA;
   dsa_pkcs_mechanism.pParameter = NULL_PTR;
   dsa_pkcs_mechanism.ulParameterLen = 0;

   /* Check dsa */
   switch (luna_dsa_check_public(dsa)) {
      case 0: /* hardware */
         if (g_postconfig.DisablePublicCrypto == 0)
            break; /* plan A */
                   /* plan B -- fall through */
      case 1:      /* software */
         if (saved_dsa_do_verify != NULL) {
            return saved_dsa_do_verify(dgst, dgst_len, sig, dsa);
         }
      /* fall through */
      default: /* error */
         LUNACA3err(LUNACA3_F_DSA_VERIFY, LUNACA3_R_EINKEY);
         goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   /* Find object */
   if ((pub_handle = luna_find_dsa_handle_FAST(&ctx, dsa, LUNA_PUBLIC)) == LUNA_INVALID_HANDLE) {
      /* if public key handle not found then perform this public operation in software  */
      luna_close_context(&ctx); /* likely */
      if (saved_dsa_do_verify != NULL) {
         return saved_dsa_do_verify(dgst, dgst_len, sig, dsa);
      }

      LUNACA3err(LUNACA3_F_DSA_VERIFY, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_dsa_handle");
      goto err;
   }

   /* Verify init */
   retCode = p11.std->C_VerifyInit(ctx.hSession, &dsa_pkcs_mechanism, pub_handle);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_DSA_VERIFY, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_VerifyInit(DSA)=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_VerifyInit", retCode);
      goto err;
   }

   /* convert the signature from bignum to a string */
   rlen = BN_bn2bin(LUNA_DSA_SIG_GET_r(sig), sigbuf);
   slen = BN_bn2bin(LUNA_DSA_SIG_GET_s(sig), (sigbuf + rlen));

   /* Verify */
   IF_LUNA_DEBUG(luna_dumpdata("hash to verify (raw): ", dgst, dgst_len));
   retCode = p11.std->C_Verify(ctx.hSession, (CK_BYTE_PTR)dgst, (CK_ULONG)dgst_len, sigbuf, (rlen + slen));
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_DSA_VERIFY, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Verify(DSA)=0x", luna_itoa(itoabuf, retCode));
      IF_LUNA_DEBUG(luna_dumpdata("verified hash: ", sigbuf, (rlen + slen)));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Verify", retCode);
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("verified hash: ", sigbuf, (rlen + slen)));

   /* Close context */
   luna_close_context(&ctx);
   return 1;

err:
   luna_close_context_w_err(&ctx, -1, retCode);
   return 0;
}

/* Dynamic Engine support (optional) */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_fn(ENGINE *e, const char *id) {
   if (id && (strcmp(id, ENGINE_LUNACA3_ID) != 0))
      return 0;
   if (!luna_bind_engine(e))
      return 0;
   return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */

/* SW: avoid non-portable <ctype.h> */
static int luna_isalpha(int c) {
   if ((c >= 'a') && (c <= 'z'))
      return 1;
   if ((c >= 'A') && (c <= 'Z'))
      return 1;
   return 0;
}

static int luna_isdigit(int c) {
   if ((c >= '0') && (c <= '9'))
      return 1;
   return 0;
}

static int luna_isalnum(int c) { return luna_isalpha(c) || luna_isdigit(c); }

static int luna_isspace(int c) {
   if (c == ' ')
      return 1;
   if (c == '\f')
      return 1;
   if (c == '\n')
      return 1;
   if (c == '\r')
      return 1;
   if (c == '\t')
      return 1;
   if (c == '\v')
      return 1;
   return 0;
}

/* Parse string and return just the slotid portion (LUNA_malloc'ed) */
static char *luna_parse_slotid2(const char *arg, int *pflaglabel) {
   char *s0 = NULL, *sslot = NULL;
   char *ptr = NULL;
   char *rcptr = NULL;

   if (arg == NULL)
      return NULL; /* likely */
   if (pflaglabel == NULL)
      return NULL; /* unlikely */

   /* Parse string format:  "slotid:appidhi:appidlo[:password]" */
   sslot = s0 = BUF_strdup(arg);
   if (s0 == NULL)
      goto err;

   /* eat whitespace */
   for (; *sslot; sslot++) {
      if (!luna_isspace(*sslot))
         break;
   }

   /* look for starting quote and ending quote (or alternative quote) */
   if ((((*sslot) == '\"') && ((ptr = strstr((sslot + 1), "\":")) != NULL)) ||
       (((*sslot) == '@') && ((ptr = strstr((sslot + 1), "@:")) != NULL)) ||
       (((*sslot) == '#') && ((ptr = strstr((sslot + 1), "#:")) != NULL)) ||
       (((*sslot) == '%') && ((ptr = strstr((sslot + 1), "%:")) != NULL)) ||
       (((*sslot) == '^') && ((ptr = strstr((sslot + 1), "^:")) != NULL)) ||
       (((*sslot) == '~') && ((ptr = strstr((sslot + 1), "~:")) != NULL))) {
      /* Init string slotid */
      sslot++;
      (*ptr) = 0;
      ptr++;
      (*ptr) = 0;
      ptr++;
      (*pflaglabel) = 1;
   } else {
      /* Init numeric slotid */
      if ((ptr = strchr(sslot, ':')) == NULL)
         goto err;
      (*ptr) = 0;
      ptr++;
   }

   rcptr = BUF_strdup(sslot);
   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return rcptr;

err:
   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return NULL;
}

/* Parse string and initialize session descriptor */
/* NOTE: slotid is either a numeric slot number or a token label (within quotes) */
/* NOTE: assumes C_GetSlotList will succeed. */
static int luna_parse_session_desc(const char *arg, session_desc *desc, char **password) {
   char *s0 = NULL, *sslot = NULL, *hi = NULL, *lo = NULL, *spwd = NULL;
   char *ptr = NULL;

   if (arg == NULL)
      return -1; /* likely */
   if (desc == NULL)
      return -1; /* unlikely */

   memset(desc, 0, sizeof(*desc));

   /* Parse string format:  "slotid:appidhi:appidlo[:password]" */
   sslot = s0 = BUF_strdup(arg);
   if (s0 == NULL)
      goto err;

   /* eat whitespace */
   for (; *sslot; sslot++) {
      if (!luna_isspace(*sslot))
         break;
   }

   /* look for starting quote and ending quote (or alternative quote) */
   if ((((*sslot) == '\"') && ((ptr = strstr((sslot + 1), "\":")) != NULL)) ||
       (((*sslot) == '@') && ((ptr = strstr((sslot + 1), "@:")) != NULL)) ||
       (((*sslot) == '#') && ((ptr = strstr((sslot + 1), "#:")) != NULL)) ||
       (((*sslot) == '%') && ((ptr = strstr((sslot + 1), "%:")) != NULL)) ||
       (((*sslot) == '^') && ((ptr = strstr((sslot + 1), "^:")) != NULL)) ||
       (((*sslot) == '~') && ((ptr = strstr((sslot + 1), "~:")) != NULL))) {
      /* Init string slotid */
      sslot++;
      (*ptr) = 0;
      ptr++;
      (*ptr) = 0;
      ptr++;
      if (luna_label_to_slotid(sslot, &desc->slot) != 1)
         goto err;
      hi = ptr;
   } else {
      /* Init numeric slotid */
      if ((ptr = strchr(sslot, ':')) == NULL)
         goto err;
      (*ptr) = 0;
      ptr++;
      desc->slot = atoi(sslot);
      hi = ptr;
   }

   if ((lo = strchr(hi, ':')) == NULL)
      goto err;
   /* Extract minor appid */
   *lo = 0;
   lo++;
   /* Extract password */
   if ((spwd = strchr(lo, ':')) != NULL) {
      *spwd = 0;
      spwd++;
      if ((strlen(spwd) > 0) && (strcmp(spwd, "NULL") != 0)) {
         (*password) = BUF_strdup(spwd);
         if (!(*password))
            goto err;
      }
   }
   /* Init the structure (remaining) */
   desc->app_id.hi = atoi(hi);
   desc->app_id.low = atoi(lo);
   desc->handle = LUNA_INVALID_HANDLE;
   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return 1;

err:
   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return 0;
}

/* Check HW RNG is usable.  Beware of engine calling itself recursively. */
static int luna_rand_check(void) {
   if (g_postconfig.DisableCheckFinalize == 0) {
      /* FIXME: variable "in_child_v" may not be set yet! */
      if (g_rtconfig.in_child_v != 1)
         return 0;
   }
   if (g_postconfig.DisableMultiThread != 0)
      return 0;
   return 1; /* 1 = HW RNG is usable */
}

/* Generate random bytes */
static int luna_rand_bytes(unsigned char *buf, int num) {
   int rc = 0;
   CK_RV retCode = CKR_OK;
   unsigned char *buf_ptr = (unsigned char *)buf;
   unsigned remain = (unsigned)num;
   unsigned chunk = 0;
   luna_context_t ctx = LUNA_CONTEXT_T_INIT;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   if (luna_rand_check() == 1) {
      /* HW RNG */
      if (luna_open_context(&ctx) == 0)
         return 0;
      for (; (remain > 0);) {
         chunk = (remain < LUNA_RAND_CHUNK) ? remain : LUNA_RAND_CHUNK;
         retCode = p11.std->C_GenerateRandom(ctx.hSession, (CK_BYTE_PTR)buf_ptr, chunk);
         if (retCode != CKR_OK) {
            LUNACA3err(LUNACA3_F_GENERATE_RANDOM, LUNACA3_R_EPKCS11);
            ERR_add_error_data(2, "C_GenerateRandom=0x", luna_itoa(itoabuf, retCode));
            LUNA_ERRORLOGL("luna_rand_bytes: C_GenerateRandom", retCode);
            luna_close_context_w_err(&ctx, -1, retCode);
            return 0;
         }
         remain -= chunk;
         buf_ptr += chunk;
      }
      luna_close_context(&ctx);
      rc = 1;
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         rc = meth->bytes(buf, num);
      }
   }

   if (rc != 1) {
      LUNA_ERRORLOGL("luna_rand_bytes: rc", rc);
   }

   return rc;
}

static int luna_rand_pseudo_bytes(unsigned char *buf, int num) {
   int rc = 0;
   if (luna_rand_check() == 1) {
      /* HW RNG */
      rc = luna_rand_bytes(buf, num);
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         rc = meth->pseudorand(buf, num);
      }
   }

   if (rc != 1) {
      LUNA_ERRORLOGL("luna_rand_pseudo_bytes: rc", rc);
   }

   return rc;
}

static int luna_rand_status(void) {
   int rc = 0;
   if (luna_rand_check() == 1) {
      /* HW RNG */
      rc = 1;
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         rc = meth->status();
      }
   }

   if (rc != 1) {
      LUNA_ERRORLOGL("luna_rand_status: rc", rc);
   }

   return rc;
}

#ifdef LUNA_RAND_RETURN_VALUE
static int luna_rand_seed(const void *buf, int num) {
   int rc = 0;
   if (luna_rand_check() == 1) {
      /* HW RNG */
      rc = 1;
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         rc = meth->seed(buf, num);
      }
   }
   return rc;
}
#else
static void luna_rand_seed(const void *buf, int num) {
   if (luna_rand_check() == 1) {
      /* HW RNG */
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         meth->seed(buf, num);
      }
   }
}
#endif

static void luna_rand_cleanup(void) {

}

#ifdef LUNA_RAND_RETURN_VALUE
static int luna_rand_add(const void *buf, int num, double add_entropy) {
   int rc = 0;
   if (luna_rand_check() == 1) {
      /* HW RNG */
      rc = 1;
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         rc = meth->add(buf, num, add_entropy);
      }
   }
   return rc;
}
#else
static void luna_rand_add(const void *buf, int num, double add_entropy) {
   if (luna_rand_check() == 1) {
      /* HW RNG */
   } else {
      /* SW RNG */
      const RAND_METHOD *meth = LUNA_RAND_OpenSSL();
      if (meth != NULL) {
         meth->add(buf, num, add_entropy);
      }
   }
}
#endif

/* flag to block threads during pkcs11 recovery */
static volatile int luna_flag_recovery = 0;

/* Open a session context */
static int luna_open_context_ndx(luna_context_t *context, unsigned ndx_specific) {
   luna_cache_t *pcache = NULL;
   unsigned per_slot_id = 0;
   LUNA_PID_T pid_now = (LUNA_PID_T)0;
   char message[100] = {0};

   /* allow multiple open attempts by the same thread (check for error 1st) */
   if (context->flagError != 0) {
       return 0;
   }

   /* allow multiple open attempts by the same thread (check for success 2nd) */
   if (context->flagInit == 1) {
       return 1;
   }

   /* reset context (set flagError in case of error) */
   memset(context, 0, sizeof(*context));
   context->flagError = 1;

   /* check if threads are blocked for recovery attempt */
   luna_mutex_enter();
   while (luna_flag_recovery) {
       //fprintf(stderr, "[openWait]"); fflush(stderr);
       luna_mutex_exit();
       luna_sleep_milli(10);
       luna_mutex_enter();
   }

   /* Conditional C_Finalize */
   if (g_postconfig.DisableCheckFinalize == 0) {
      pid_now = LUNA_GETPID();
      if (pid_now != g_rtconfig.pid_c_init) /* if child detects fork */
      {
         luna_fini_p11();
      }
   }

   /* Deferred C_Initialize */
   if (luna_init_p11_conditional_ex(1) != 1) {
      LUNA_ERRORLOG("luna_open_context: luna_init_p11_conditional_ex");
      luna_mutex_exit();
      return 0;
   }

   /* Conditional C_Finalize (pending) */
   if (g_postconfig.DisableCheckFinalize == 0) {
      if (g_postconfig.LogLevel >= LUNA_LOGLEVEL_EVENT) {
         sprintf(message, "luna_open_context_ndx: pid_bind=%d", (int)g_rtconfig.pid_bind);
         LUNA_EVENTLOG(message);
         sprintf(message, "luna_open_context_ndx: pid_c_init=%d", (int)g_rtconfig.pid_c_init);
         LUNA_EVENTLOG(message);
         sprintf(message, "luna_open_context_ndx: pid_intermediate=%d", (int)g_rtconfig.pid_intermediate);
         LUNA_EVENTLOG(message);
         sprintf(message, "luna_open_context_ndx: pid_intermediate_count=%d", (int)g_rtconfig.pid_intermediate_count);
         LUNA_EVENTLOG(message);
         sprintf(message, "luna_open_context_ndx: in_child_v=%d", (int)g_rtconfig.in_child_v);
         LUNA_EVENTLOG(message);
      }

      pid_now = LUNA_GETPID();
      if (pid_now == g_rtconfig.pid_bind) /* if parent calls the engine */
      {
         g_rtconfig.in_child_v = 0;
         context->flagFinalizePending = 1;
      } else {
         if (g_rtconfig.pid_intermediate != (LUNA_PID_T)pid_now) /* new intermediate process has called engine */
         {
            g_rtconfig.pid_intermediate_count++;
            g_rtconfig.pid_intermediate = pid_now;
         }
         if (g_rtconfig.pid_intermediate_count > g_postconfig.IntermediateProcesses) {
            g_rtconfig.in_child_v = 1;
         } else {
            g_rtconfig.in_child_v = 0;
            context->flagFinalizePending = 1;
         }
      }
   } else {
      g_rtconfig.in_child_v = 1;
   }

   /* C_OpenSession */
   if (luna_get_engine2_init() == NULL) {
      per_slot_id = 0;
   } else {
      if (ndx_specific >= LUNA_MAX_SLOT) {
         /* Use shortest waiting line. Default to the first line that should be served by the fastest hsm. */
         if (g_luna_per_slot[0].g_count_activity <= g_luna_per_slot[1].g_count_activity) {
            per_slot_id = 0;
         } else {
            per_slot_id = 1;
         }
      } else {
         /* Use specified index. */
         per_slot_id = ndx_specific;
      }
   }

   context->per_slot_id = per_slot_id;
   context->slotid = g_luna_per_slot[per_slot_id].g_slot_id;
   context->count_c_init = luna_count_c_init;
   context->pid = LUNA_GETPID();
   pcache = luna_cache_pop(&luna_ckses[per_slot_id]);
   if (pcache == NULL) {
      if (luna_open_session(context->slotid, &context->hSession) == 0) {
         LUNA_ERRORLOG("luna_open_context: luna_open_session");
         if (context->flagFinalizePending == 1) {
            luna_fini_p11();
         }
         luna_mutex_exit();
         return 0;
      }
      if (luna_ps_check_lib() == 1) {
         CK_RV rv2 = CKR_OK;
         rv2 = LUNA_pw_login(&(g_pw_per_slot[per_slot_id]), context->hSession);
         if (rv2 != CKR_OK) {
            LUNA_ERRORLOGL("luna_open_context: LUNA_pw_login", rv2);
            (void)luna_close_session(context->hSession);
            context->hSession = LUNA_INVALID_HANDLE;
            if (context->flagFinalizePending == 1) {
               luna_fini_p11();
            }
            luna_mutex_exit();
            return 0;
         }
      }
      pcache = luna_cache_new_ckses(context->hSession);
   } else {
      context->hSession = pcache->ckses;
   }

   context->pcache = pcache;
   context->flagInit = 1;
   /* clear flagError in case of success */
   context->flagError = 0;
   g_luna_per_slot[per_slot_id].g_count_activity++;
   g_count_activity++;

   /* Conditional mutex exit */
   if ((context->flagFinalizePending == 0) && (g_postconfig.DisableMultiThread == 0)) {
      luna_mutex_exit();
   }

   return 1;
}

static int luna_open_context(luna_context_t *context) { return luna_open_context_ndx(context, LUNA_MAX_SLOT); }

/* query pkcs11 return value indicates recovery is necessary */
static int luna_rv_severity(CK_RV rv) {
    if (rv == CKR_DEVICE_ERROR)
        return 2;
    if (rv == CKR_TOKEN_NOT_PRESENT)
        return 2;
    if (rv == CKR_SESSION_HANDLE_INVALID)
        return 1;
    return 0;
}

static int luna_rv_needs_recovery(CK_RV rv) {
    if (luna_rv_severity(rv) >= 1)
        return 1;
    return 0;
}

static int luna_rv_needs_finalize(CK_RV rv) {
    if (luna_rv_severity(rv) >= 2)
        return 1;
    return 0;
}

/* associate last error code with context */
static void luna_context_set_last_error(luna_context_t *context, CK_RV rv_last) {
    /* avoid overwriting a high severity code with a low severity code */
    if ( luna_rv_severity(rv_last) > luna_rv_severity(context->rv_last) ) {
        context->rv_last = rv_last;
    }
}

#define LUNA_21906_RECOVERY 1
#define LUNA_21906_RECOVERY_FINALIZE 1
/* experimental: #define LUNA_21906_SIMULATION 1 */

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_close_context_w_err"

/* Close a session context */
static void luna_close_context_w_err(luna_context_t *context, int flag_err, CK_RV rv_last) {
   const int w_err = ( (flag_err != 0) || (rv_last != CKR_OK) );
   const LUNA_PID_T pid_now = LUNA_GETPID();
   unsigned per_slot_id = 0;
   int flagRecoveryPending = 0;

   /* associate last error code with context */
   luna_context_set_last_error(context, rv_last);

   /* check context initialized */
   if (context->flagInit != 1)
      return;
   if (context->per_slot_id >= LUNA_MAX_SLOT)
      return;

   /* Conditional mutex enter */
   if ((context->flagFinalizePending == 0) && (g_postconfig.DisableMultiThread == 0)) {
      luna_mutex_enter();
   }

   /* decrement activity */
   per_slot_id = context->per_slot_id;
   if (g_luna_per_slot[per_slot_id].g_count_activity > 0) {
      g_luna_per_slot[per_slot_id].g_count_activity--;
   }
   if (g_count_activity > 0) {
      g_count_activity--;
   }

   /* return the session to the cache or to the hsm where possible */
   if ((luna_have_c_init == 1) && (context->count_c_init == luna_count_c_init) && (context->pid == pid_now)) {
      /* session is cacheable */
      if ( (context->pcache == NULL) || (w_err != 0) || (g_postconfig.DisableSessionCache != 0) ) {
         /* dont cache session, because an error occurred or session cache disabled */
         (void)luna_close_session(context->hSession);
         context->hSession = CK_INVALID_HANDLE;
         luna_cache_delete_item(context->pcache);
         context->pcache = NULL;
#if defined(LUNA_21906_SIMULATION)
         flagRecoveryPending = ( (rand() % 3) == 0 ) ? 1 : 0;
#else
         flagRecoveryPending = luna_rv_needs_recovery(context->rv_last);
#endif
      } else {
         /* cache session, because everything looks ok */
         luna_cache_push(&luna_ckses[per_slot_id], context->pcache);
         context->pcache = NULL;
#if defined(LUNA_21906_SIMULATION)
         flagRecoveryPending = ( (rand() % 5) == 0 ) ? 1 : 0;
#else
         flagRecoveryPending = 0;
#endif
      }
   } else {
      /* the session is NOT cacheable, because the library was re-initialized or forked */
      luna_cache_delete_item(context->pcache);
      context->pcache = NULL;
      flagRecoveryPending = 1;
   }

   /* if one session is bad then likely all sessions are bad so purge the cache */
   if (flagRecoveryPending) {
      luna_cache_delete_ALL(&(luna_ckses[0]), NULL);
      luna_cache_delete_ALL(&(luna_ckses[1]), NULL);
   }

   /* Conditional C_Finalize */
   if (context->flagFinalizePending == 1) {
      luna_fini_p11();
      LUNA_EVENTLOG("luna_close_context: pending luna_fini_p11");

#if defined(LUNA_21906_RECOVERY)
   } else {
      if (flagRecoveryPending) {
         /* block thread activity */
         luna_flag_recovery = 1;
         /* wait for thread activity to reach zero */
         while (g_count_activity > 0 ) {
             //fprintf(stderr, "[closeWait]"); fflush(stderr);
             luna_mutex_exit();
             luna_sleep_milli(10);
             luna_mutex_enter();
         }

         /* LUNA-21906 improve recovery */
         /* recovery is possible in two forms
          *   1. trigger c_login
          *   2. trigger c_finalize
          */
         if ( (flagRecoveryPending == 1) && (luna_get_recovery_level() >= 1) ) {
             if (luna_do_deferred_login() == 0) {
                 /* login failed, so try finalize (best effort) */
                 if ( luna_rv_needs_finalize(context->rv_last)
#if defined(LUNA_21906_SIMULATION)
                     || ((rand() % 4) == 0)
#endif
                     ) {
                     flagRecoveryPending = 2;
                 }
                 LUNA_EVENTLOG(LUNA_FUNC_NAME": recovery login failed");
             } else {
                 LUNA_EVENTLOG(LUNA_FUNC_NAME": recovery login ok");
             }
         }

#if defined(LUNA_21906_RECOVERY_FINALIZE)
         /* a failed c_login attempt can trigger a c_finalize attempt */
         if ( (flagRecoveryPending == 2) && (luna_get_recovery_level() >= 2) ) {
             /* FIXME:FIXME: finalizing here will have detrimental effect
              * for session objects used by the provider
              */
             luna_fini_p11();
             LUNA_EVENTLOG(LUNA_FUNC_NAME": recovery finalize ok");
         }
#endif

         /* unblock thread activity */
         luna_flag_recovery = 0;
      }
#endif /* LUNA_21906_IMPROVE_RECOVERY */
   }

   /* unconditional mutex exit */
   luna_mutex_exit();

   /* reset context (set flagError because contexts are not reusable after close) */
   memset(context, 0, sizeof(*context));
   context->flagError = 1;
}

static void luna_close_context(luna_context_t *context) {
   luna_close_context_w_err(context, 0, context->rv_last);
   return;
}

#define LUNA_CONFIG_GETPROP(_name) do { \
  if ((p = luna_getprop(cf, LUNA_CONF_SECTION, #_name))) { \
    g_config._name = p; \
  } \
} while (0)

#define LUNA_CONFIG_DEBUG(_name) do { \
  if (g_config._name != NULL) { \
    IF_LUNA_DEBUG(luna_dump_s(#_name" ", g_config._name)); \
  } \
} while (0)

/* Configure module */
static int luna_init_properties2(void) {
   char *p = NULL;
   char *cf = NULL;

   /* Get path to conf file */
   cf = luna_get_conf_path();
   if (cf == NULL) {
      LUNA_ERRORLOG("luna_init_properties2: luna_get_conf_path");
      return -1;
   }
   LUNA_EVENTLOG(cf);
   /* Read file */
   /* "LibPath/LibPath64" is required */
   if (sizeof(void *) >= 8) {
      if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "LibPath64"))) {
         g_config.SO_PATH = p;
         LUNA_EVENTLOG(g_config.SO_PATH);
      }
   } else {
      if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "LibPath"))) {
         g_config.SO_PATH = p;
         LUNA_EVENTLOG(g_config.SO_PATH);
      }
   }
   /* "EngineInit" may be necessary to set application id, open session for some applications; e.g., Apache */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EngineInit"))) {
      g_config.EngineInit = p;
   }
   /* "Engine2Init" may be necessary to set application id, open session for some applications; e.g., Apache */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "Engine2Init"))) {
      g_config.Engine2Init = p;
   }
   /* "RSA_EX" is optional to accelerate RSA */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "RSA_EX"))) {
      g_config.RSA_EX = p;
   }
   /* "EnableRsaEx" is optional to accelerate RSA */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableRsaEx"))) {
      g_config.EnableRsaEx = p;
   }
   /* "EnableDsaEx" is optional to accelerate DSA */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableDsaEx"))) {
      g_config.EnableDsaEx = p;
   }
   /* "EnableEcdsaEx" is optional to accelerate ECDSA */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableEcdsaEx"))) {
      g_config.EnableEcdsaEx = p;
   }
   /* "LogLevel" is optional for debug */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "LogLevel"))) {
      g_config.LogLevel = p;
   }
   /* "Appliance" may be used to specify what type of appliance we are connecting to Luna (Default), ProtectApp */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "Appliance"))) {
      g_config.Appliance = p;
   }
   /* "LogRootDir" is optional for debug */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "LogRootDir"))) {
      g_config.LogRootDir = p;
   }
   /* "DisableRsa" is optional to disable algorithm */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableRsa"))) {
      g_config.DisableRsa = p;
   }
   /* "DisableDsa" is optional to disable algorithm */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableDsa"))) {
      g_config.DisableDsa = p;
   }
   /* "DisableEcdsa" is optional to disable algorithm */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableEcdsa"))) {
      g_config.DisableEcdsa = p;
   } else {
       if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableEc"))) {
          g_config.DisableEcdsa = p;
       }
   }
   /* "DisableRand" is optional to disable algorithm */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableRand"))) {
      g_config.DisableRand = p;
   }
   /* "DisableSessionCache" is optional to disable cache */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableSessionCache"))) {
      g_config.DisableSessionCache = p;
   }
   /* "DisableMultiThread" is optional to disable multi-threading */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableMultiThread"))) {
      g_config.DisableMultiThread = p;
   }
   /* "DisablePublicCrypto" is optional to do public crypto in software */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisablePublicCrypto"))) {
      g_config.DisablePublicCrypto = p;
   }
   /* "EnableLoadPrivKey" is optional to enable function */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableLoadPrivKey"))) {
      g_config.EnableLoadPrivKey = p;
   }
   /* "EnableLoadPubKey" is optional to enable function */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableLoadPubKey"))) {
      g_config.EnableLoadPubKey = p;
   }
   /* "EnableLoginInit" is optional to prompt for password */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableLoginInit"))) {
      g_config.EnableLoginInit = p;
   }
   /* "EnableRsaGenKeyPair" is optional to generate rsa in engine */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableRsaGenKeyPair"))) {
      g_config.EnableRsaGenKeyPair = p;
   }
   /* "EnableDsaGenKeyPair" is optional to generate dsa in engine */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableDsaGenKeyPair"))) {
      g_config.EnableDsaGenKeyPair = p;
   }
   /* "EnablePqcGenKeyPair" is optional to generate pqc in engine */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnablePqcGenKeyPair"))) {
      g_config.EnablePqcGenKeyPair = p;
   }
   /* "EnableEcGenKeyPair" is optional to generate ec in engine */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableEcGenKeyPair"))) {
      g_config.EnableEcGenKeyPair = p;
   }
   /* "EnableEdGenKeyPair" is optional to generate EC-EDWARDS in provider */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableEdGenKeyPair"))) {
      g_config.EnableEdGenKeyPair = p;
   }
   /* "EnableEmGenKeyPair" is optional to generate EC-MONTGOMERY in provider */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableEmGenKeyPair"))) {
      g_config.EnableEmGenKeyPair = p;
   }
   /* "EnableRsaSignVerify" is optional to prompt for password */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableRsaSignVerify"))) {
      g_config.EnableRsaSignVerify = p;
   }
   /* "DisableCheckFinalize" is optional to disable check for Finalize */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableCheckFinalize"))) {
      g_config.DisableCheckFinalize = p;
   }
   /* "IntermediateProcesses" indicates how many processes are in between the most parent process and the child
    * processes */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "IntermediateProcesses"))) {
      g_config.IntermediateProcesses = p;
   }
   /* "EnablePkeyMeths" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnablePkeyMeths"))) {
      g_config.EnablePkeyMeths = p;
   }
   /* "EnablePkeyAsn1Meths" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnablePkeyAsn1Meths"))) {
      g_config.EnablePkeyAsn1Meths = p;
   }
   /* "DisableRegisterAll" is optional to disable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "DisableRegisterAll"))) {
      g_config.DisableRegisterAll = p;
   }
   /* "EnableDigests" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableDigests"))) {
      g_config.EnableDigests = p;
   }
   /* "EnableLimitedUser" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableLimitedUser"))) {
      g_config.EnableLimitedUser = p;
   }
   /* "EnableRsaPkcsPadding" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "EnableRsaPkcsPadding"))) {
      g_config.EnableRsaPkcsPadding = p;
   }
   /* "IncludePqc" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "IncludePqc"))) {
      g_config.IncludePqc = p;
   }
   /* "ExcludePqc" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "ExcludePqc"))) {
      g_config.ExcludePqc = p;
   }
   /* "RecoveryLevel" is optional to enable */
   if ((p = luna_getprop(cf, LUNA_CONF_SECTION, "RecoveryLevel"))) {
      g_config.RecoveryLevel = p;
   }
   /* misc config malloc */
   LUNA_CONFIG_GETPROP(EnableTokenObject);
   LUNA_CONFIG_GETPROP(EnablePqcShim);
   LUNA_CONFIG_GETPROP(DelegateHwPqcKemEncapToSw);
   LUNA_CONFIG_GETPROP(DelegateSwPqcKemEncapRngToHw);
   /* from string to integer (speed optimization) */
   g_postconfig.LogLevel = (g_config.LogLevel != NULL) ? atoi(g_config.LogLevel) : 0;
   g_postconfig.DisableCheckFinalize =
       (g_config.DisableCheckFinalize != NULL) ? atoi(g_config.DisableCheckFinalize) : 0;
   g_postconfig.IntermediateProcesses =
       (g_config.IntermediateProcesses != NULL) ? atoi(g_config.IntermediateProcesses) : 1;
   g_postconfig.DisableRand = (g_config.DisableRand != NULL) ? atoi(g_config.DisableRand) : 1; /* NOTE: on by default */
   g_postconfig.DisableSessionCache =
       (g_config.DisableSessionCache != NULL) ? atoi(g_config.DisableSessionCache) : 1; /* NOTE: on by default */
   g_postconfig.DisableMultiThread = (g_config.DisableMultiThread != NULL) ? atoi(g_config.DisableMultiThread) : 0;
   g_postconfig.DisablePublicCrypto =
       (g_config.DisablePublicCrypto != NULL) ? atoi(g_config.DisablePublicCrypto) : 1; /* NOTE: on by default */

   /* debug */
   if (cf)
      IF_LUNA_DEBUG(luna_dump_s("luna_get_conf_path", cf));
   if (sizeof(void *) >= 8) {
      if (g_config.SO_PATH)
         IF_LUNA_DEBUG(luna_dump_s("LibPath64", g_config.SO_PATH));
   } else {
      if (g_config.SO_PATH)
         IF_LUNA_DEBUG(luna_dump_s("LibPath", g_config.SO_PATH));
   }
   if (g_config.EngineInit)
      IF_LUNA_DEBUG(luna_dump_s("EngineInit", g_config.EngineInit));
   if (g_config.Engine2Init)
      IF_LUNA_DEBUG(luna_dump_s("Engine2Init", g_config.Engine2Init));
   if (g_config.RSA_EX)
      IF_LUNA_DEBUG(luna_dump_s("RSA_EX", g_config.RSA_EX));
   if (g_config.EnableRsaEx)
      IF_LUNA_DEBUG(luna_dump_s("EnableRsaEx", g_config.EnableRsaEx));
   if (g_config.EnableDsaEx)
      IF_LUNA_DEBUG(luna_dump_s("EnableDsaEx", g_config.EnableDsaEx));
   if (g_config.EnableEcdsaEx)
      IF_LUNA_DEBUG(luna_dump_s("EnableEcdsaEx", g_config.EnableEcdsaEx));
   if (g_config.LogLevel)
      IF_LUNA_DEBUG(luna_dump_s("LogLevel", g_config.LogLevel));
   if (g_config.Appliance)
      IF_LUNA_DEBUG(luna_dump_s("Appliance", g_config.Appliance));
   if (g_config.LogRootDir)
      IF_LUNA_DEBUG(luna_dump_s("LogRootDir", g_config.LogRootDir));
   if (g_config.DisableRsa)
      IF_LUNA_DEBUG(luna_dump_s("DisableRsa", g_config.DisableRsa));
   if (g_config.DisableDsa)
      IF_LUNA_DEBUG(luna_dump_s("DisableDsa", g_config.DisableDsa));
   if (g_config.DisableEcdsa)
      IF_LUNA_DEBUG(luna_dump_s("DisableEcdsa", g_config.DisableEcdsa));
   if (g_config.DisableRand)
      IF_LUNA_DEBUG(luna_dump_s("DisableRand", g_config.DisableRand));
   if (g_config.DisableSessionCache)
      IF_LUNA_DEBUG(luna_dump_s("DisableSessionCache", g_config.DisableSessionCache));
   if (g_config.DisableMultiThread)
      IF_LUNA_DEBUG(luna_dump_s("DisableMultiThread", g_config.DisableMultiThread));
   if (g_config.DisablePublicCrypto)
      IF_LUNA_DEBUG(luna_dump_s("DisablePublicCrypto", g_config.DisablePublicCrypto));
   if (g_config.EnableLoadPrivKey)
      IF_LUNA_DEBUG(luna_dump_s("EnableLoadPrivKey", g_config.EnableLoadPrivKey));
   if (g_config.EnableLoadPubKey)
      IF_LUNA_DEBUG(luna_dump_s("EnableLoadPubKey", g_config.EnableLoadPubKey));
   if (g_config.EnableLoginInit)
      IF_LUNA_DEBUG(luna_dump_s("EnableLoginInit", g_config.EnableLoginInit));
   if (g_config.EnableRsaGenKeyPair)
      IF_LUNA_DEBUG(luna_dump_s("EnableRsaGenKeyPair", g_config.EnableRsaGenKeyPair));
   if (g_config.EnableDsaGenKeyPair)
      IF_LUNA_DEBUG(luna_dump_s("EnableDsaGenKeyPair", g_config.EnableDsaGenKeyPair));
   if (g_config.EnablePqcGenKeyPair)
      IF_LUNA_DEBUG(luna_dump_s("EnablePqcGenKeyPair", g_config.EnablePqcGenKeyPair));
   if (g_config.EnableEcGenKeyPair)
      IF_LUNA_DEBUG(luna_dump_s("EnableEcGenKeyPair", g_config.EnableEcGenKeyPair));
   if (g_config.EnableEdGenKeyPair)
      IF_LUNA_DEBUG(luna_dump_s("EnableEdGenKeyPair", g_config.EnableEdGenKeyPair));
   if (g_config.EnableEmGenKeyPair)
      IF_LUNA_DEBUG(luna_dump_s("EnableEmGenKeyPair", g_config.EnableEmGenKeyPair));
   if (g_config.EnableRsaSignVerify)
      IF_LUNA_DEBUG(luna_dump_s("EnableRsaSignVerify", g_config.EnableRsaSignVerify));
   if (g_config.EnablePkeyMeths)
      IF_LUNA_DEBUG(luna_dump_s("EnablePkeyMeths", g_config.EnablePkeyMeths));
   if (g_config.EnablePkeyAsn1Meths)
      IF_LUNA_DEBUG(luna_dump_s("EnablePkeyAsn1Meths", g_config.EnablePkeyAsn1Meths));
   if (g_config.DisableRegisterAll)
      IF_LUNA_DEBUG(luna_dump_s("DisableRegisterAll", g_config.DisableRegisterAll));
   if (g_config.EnableDigests)
      IF_LUNA_DEBUG(luna_dump_s("EnableDigests", g_config.EnableDigests));
   if (g_config.EnableLimitedUser)
      IF_LUNA_DEBUG(luna_dump_s("EnableLimitedUser", g_config.EnableLimitedUser));
   if (g_config.EnableRsaPkcsPadding )
      IF_LUNA_DEBUG(luna_dump_s("EnableRsaPkcsPadding ", g_config.EnableRsaPkcsPadding ));
   if (g_config.IncludePqc )
      IF_LUNA_DEBUG(luna_dump_s("IncludePqc ", g_config.IncludePqc ));
   if (g_config.ExcludePqc )
      IF_LUNA_DEBUG(luna_dump_s("ExcludePqc ", g_config.ExcludePqc ));
   if (g_config.RecoveryLevel )
      IF_LUNA_DEBUG(luna_dump_s("RecoveryLevel ", g_config.RecoveryLevel ));
   /* misc config debug */
   LUNA_CONFIG_DEBUG(EnableTokenObject);
   LUNA_CONFIG_DEBUG(EnablePqcShim);
   LUNA_CONFIG_DEBUG(DelegateHwPqcKemEncapToSw);
   LUNA_CONFIG_DEBUG(DelegateSwPqcKemEncapRngToHw);
   return 0;
}

#define LUNA_CONFIG_FREE(_name) do { \
  if (g_config._name != NULL) { \
    LUNA_free(g_config._name); \
    g_config._name = NULL; \
  } \
} while (0)

/* Deconfigure module (undo luna_init_configure) */
static void luna_fini_properties2(void) {
   if (g_config.SO_PATH != NULL) {
      LUNA_free(g_config.SO_PATH);
      g_config.SO_PATH = NULL;
   }
   if (g_config.EngineInit != NULL) {
      LUNA_free(g_config.EngineInit);
      g_config.EngineInit = NULL;
   }
   if (g_config.Engine2Init != NULL) {
      LUNA_free(g_config.Engine2Init);
      g_config.Engine2Init = NULL;
   }
   if (g_config.RSA_EX != NULL) {
      LUNA_free(g_config.RSA_EX);
      g_config.RSA_EX = NULL;
   }
   if (g_config.EnableRsaEx != NULL) {
      LUNA_free(g_config.EnableRsaEx);
      g_config.EnableRsaEx = NULL;
   }
   if (g_config.EnableDsaEx != NULL) {
      LUNA_free(g_config.EnableDsaEx);
      g_config.EnableDsaEx = NULL;
   }
   if (g_config.EnableEcdsaEx != NULL) {
      LUNA_free(g_config.EnableEcdsaEx);
      g_config.EnableEcdsaEx = NULL;
   }
   if (g_config.LogLevel != NULL) {
      LUNA_free(g_config.LogLevel);
      g_config.LogLevel = NULL;
   }
   if (g_config.LogRootDir != NULL) {
      LUNA_free(g_config.LogRootDir);
      g_config.LogRootDir = NULL;
   }
   if (g_config.DisableRsa != NULL) {
      LUNA_free(g_config.DisableRsa);
      g_config.DisableRsa = NULL;
   }
   if (g_config.DisableDsa != NULL) {
      LUNA_free(g_config.DisableDsa);
      g_config.DisableDsa = NULL;
   }
   if (g_config.DisableEcdsa != NULL) {
      LUNA_free(g_config.DisableEcdsa);
      g_config.DisableEcdsa = NULL;
   }
   if (g_config.DisableRand != NULL) {
      LUNA_free(g_config.DisableRand);
      g_config.DisableRand = NULL;
   }
   if (g_config.DisableSessionCache != NULL) {
      LUNA_free(g_config.DisableSessionCache);
      g_config.DisableSessionCache = NULL;
   }
   if (g_config.DisableMultiThread != NULL) {
      LUNA_free(g_config.DisableMultiThread);
      g_config.DisableMultiThread = NULL;
   }
   if (g_config.DisablePublicCrypto != NULL) {
      LUNA_free(g_config.DisablePublicCrypto);
      g_config.DisablePublicCrypto = NULL;
   }
   if (g_config.EnableLoadPrivKey != NULL) {
      LUNA_free(g_config.EnableLoadPrivKey);
      g_config.EnableLoadPrivKey = NULL;
   }
   if (g_config.EnableLoadPubKey != NULL) {
      LUNA_free(g_config.EnableLoadPubKey);
      g_config.EnableLoadPubKey = NULL;
   }
   if (g_config.EnableLoginInit != NULL) {
      LUNA_free(g_config.EnableLoginInit);
      g_config.EnableLoginInit = NULL;
   }
   if (g_config.EnableRsaGenKeyPair != NULL) {
      LUNA_free(g_config.EnableRsaGenKeyPair);
      g_config.EnableRsaGenKeyPair = NULL;
   }
   if (g_config.EnableDsaGenKeyPair != NULL) {
      LUNA_free(g_config.EnableDsaGenKeyPair);
      g_config.EnableDsaGenKeyPair = NULL;
   }
   if (g_config.EnablePqcGenKeyPair != NULL) {
      LUNA_free(g_config.EnablePqcGenKeyPair);
      g_config.EnablePqcGenKeyPair = NULL;
   }
   if (g_config.EnableEcGenKeyPair != NULL) {
      LUNA_free(g_config.EnableEcGenKeyPair);
      g_config.EnableEcGenKeyPair = NULL;
   }
   if (g_config.EnableEdGenKeyPair != NULL) {
      LUNA_free(g_config.EnableEdGenKeyPair);
      g_config.EnableEdGenKeyPair = NULL;
   }
   if (g_config.EnableEmGenKeyPair != NULL) {
      LUNA_free(g_config.EnableEmGenKeyPair);
      g_config.EnableEmGenKeyPair = NULL;
   }
   if (g_config.EnableRsaSignVerify != NULL) {
      LUNA_free(g_config.EnableRsaSignVerify);
      g_config.EnableRsaSignVerify = NULL;
   }
   if (g_config.EnablePkeyMeths != NULL) {
      LUNA_free(g_config.EnablePkeyMeths);
      g_config.EnablePkeyMeths = NULL;
   }
   if (g_config.EnablePkeyAsn1Meths != NULL) {
      LUNA_free(g_config.EnablePkeyAsn1Meths);
      g_config.EnablePkeyAsn1Meths = NULL;
   }
   if (g_config.DisableRegisterAll != NULL) {
      LUNA_free(g_config.DisableRegisterAll);
      g_config.DisableRegisterAll = NULL;
   }
   if (g_config.EnableDigests != NULL) {
      LUNA_free(g_config.EnableDigests);
      g_config.EnableDigests = NULL;
   }
   if (g_config.EnableLimitedUser != NULL) {
      LUNA_free(g_config.EnableLimitedUser);
      g_config.EnableLimitedUser = NULL;
   }
   if (g_config.EnableRsaPkcsPadding != NULL) {
      LUNA_free(g_config.EnableRsaPkcsPadding);
      g_config.EnableRsaPkcsPadding = NULL;
   }
   if (g_config.IncludePqc != NULL) {
      LUNA_free(g_config.IncludePqc);
      g_config.IncludePqc = NULL;
   }
   if (g_config.ExcludePqc != NULL) {
      LUNA_free(g_config.ExcludePqc);
      g_config.ExcludePqc = NULL;
   }
   if (g_config.RecoveryLevel != NULL) {
      LUNA_free(g_config.RecoveryLevel);
      g_config.RecoveryLevel = NULL;
   }
   /* misc config free */
   LUNA_CONFIG_FREE(EnableTokenObject);
   LUNA_CONFIG_FREE(EnablePqcShim);
   LUNA_CONFIG_FREE(DelegateHwPqcKemEncapToSw);
   LUNA_CONFIG_FREE(DelegateSwPqcKemEncapRngToHw);
}

#define LUNA_MAX_LINE_LEN (1024)
#define LUNA_MAX_STRING (2048 + 32)
#define LUNA_MIN_STRING (4)

/* Read property value from config file */
static char *luna_getprop(const char *confpath, const char *ssection, const char *svalue) {
#ifndef LUNA_OSSL_WINDOWS
   int rlen = 0;
   unsigned tmplen = 0;
   char *p = NULL, *e = NULL, *l = NULL;
   char *quote = NULL;
   BIO *cfgbio = NULL;
   char rbuf[LUNA_MAX_LINE_LEN + 1];

   memset(rbuf, 0, sizeof(rbuf));

   if (confpath == NULL) {
      return NULL;
   }
   cfgbio = BIO_new_file(confpath, "r");
   if (cfgbio == NULL) {
      LUNACA3err(LUNACA3_F_ENGINE, LUNACA3_R_ENOFILE);
      ERR_add_error_data(2, "File not found ", confpath);
      return NULL;
   }

   for (;;) {
      if (!(rlen = BIO_gets(cfgbio, rbuf, LUNA_MAX_LINE_LEN)))
         break;

      /* find the section string, and, opening brace */
      p = strstr(rbuf, ssection);
      quote = strstr(rbuf, "{");
      if ((p == NULL) || (strlen(p) == 0))
         continue;
      if ((quote == NULL) || (strlen(quote) == 0))
         continue;

      /* found the section - let's iterate within section */
      for (quote = NULL; (quote == NULL);) {
         if (!(rlen = BIO_gets(cfgbio, rbuf, LUNA_MAX_LINE_LEN)))
            break;

         /* check for closing brace */
         quote = strstr(rbuf, "}");

         /* find the value string; beware of substrings; e.g., LibPath and LibPath64 */
         tmplen = strlen(svalue);
         p = strstr(rbuf, svalue);
         if ((p == NULL) || (strlen(p) <= tmplen))
            continue;
         if ((luna_isalnum(p[tmplen])) || (p[tmplen] == '_'))
            continue;

         /* find and skip past = */
         p = strchr(p, '=');
         if ((p == NULL) || (strlen(p) == 0))
            continue;

         /* skip past = and eat all white space */
         while (luna_isspace(*(++p)))
            ;

         /* find terminating ; and replace with null */
         if ((e = strchr(p, ';')) == NULL)
            continue;
         (*e) = 0;

         /* found the data - let's break */
         l = BUF_strdup(p);
         break;
      }
      break; /* Break since we already encountered the section name */
   }
   /* Close file handle */
   BIO_free(cfgbio);
   return l;
#else  /* LUNA_OSSL_WINDOWS */
   const char *pbError = "##ERROR##";
   DWORD dwrc = 0;
   char rbuf[LUNA_MAX_LINE_LEN + 1];

   memset(rbuf, 0, sizeof(rbuf));
   dwrc = GetPrivateProfileStringA(ssection, svalue, pbError, rbuf, LUNA_MAX_LINE_LEN, (char *)confpath);

   if ((dwrc < 1) || (strcmp(rbuf, pbError) == 0)) {
      return NULL;
   }

   return BUF_strdup(rbuf);
#endif /* LUNA_OSSL_WINDOWS */
}

/* Set path to conf file */
static int luna_set_conf_path(char *p) {
   if (g_preconfig.CONF_PATH != NULL) {
      LUNA_free(g_preconfig.CONF_PATH);
   }
   g_preconfig.CONF_PATH = (p) ? BUF_strdup(p) : NULL;
   return 1;
}

/* luna_set_disable_check_finalize */
static int luna_set_disable_check_finalize(char *p) {
   if (g_config.DisableCheckFinalize != NULL) {
      LUNA_free(g_config.DisableCheckFinalize);
   }
   g_config.DisableCheckFinalize = (p) ? BUF_strdup(p) : NULL;
   g_postconfig.DisableCheckFinalize =
       (g_config.DisableCheckFinalize != NULL) ? atoi(g_config.DisableCheckFinalize) : 0;

   return 1;
}

/* luna_set_intermediate_processes */
static int luna_set_intermediate_processes(char *p) {
   if (g_config.IntermediateProcesses != NULL) {
      LUNA_free(g_config.IntermediateProcesses);
   }
   g_config.IntermediateProcesses = (p) ? BUF_strdup(p) : NULL;
   g_postconfig.IntermediateProcesses =
       (g_config.IntermediateProcesses != NULL) ? atoi(g_config.IntermediateProcesses) : 1;

   return 1;
}

/* Get path to conf file */
static char *luna_get_conf_path(void) {
   char *cf = NULL;
   char *envpath = 0;
   if (g_preconfig.CONF_PATH != NULL) {
      cf = g_preconfig.CONF_PATH;
   } else {
      envpath = getenv(LUNA_CONF_ENVVAR);
      if (envpath != NULL) {
         g_preconfig.CONF_PATH = luna_filenamedup(envpath, LUNA_CONF_FILE);
      } else {
         g_preconfig.CONF_PATH = luna_filenamedup(LUNA_CONF_PATH, LUNA_CONF_FILE);
      }
      cf = g_preconfig.CONF_PATH;
   }
   return cf;
}

/* Set engine init params */
static int luna_set_engine_init(char *p) {
   if (g_preconfig.CONF_ENGINE_INIT != NULL) {
      LUNA_free(g_preconfig.CONF_ENGINE_INIT);
   }
   g_preconfig.CONF_ENGINE_INIT = (p) ? BUF_strdup(p) : NULL;
   return 1;
}

/* Set engine init params */
static int luna_set_engine2_init(char *p) {
   if (g_preconfig.CONF_ENGINE2_INIT != NULL) {
      LUNA_free(g_preconfig.CONF_ENGINE2_INIT);
   }
   g_preconfig.CONF_ENGINE2_INIT = (p) ? BUF_strdup(p) : NULL;
   return 1;
}

/* Get engine init params */
static char *luna_get_engine_init(void) {
   char *cf = NULL;
   if (g_preconfig.CONF_ENGINE_INIT != NULL) {
      cf = g_preconfig.CONF_ENGINE_INIT;
   } else {
      cf = g_config.EngineInit;
   }
   return cf;
}

/* Get engine2 init params */
static char *luna_get_engine2_init(void) {
   char *cf = NULL;
   if (g_preconfig.CONF_ENGINE2_INIT != NULL) {
      cf = g_preconfig.CONF_ENGINE2_INIT;
   } else {
      cf = g_config.Engine2Init;
   }
   return cf;
}

/* Get engine init params by index */
static char *luna_get_engine_init_ndx(unsigned ndx) {
   if (ndx == 0)
      return luna_get_engine_init();
   if (ndx == 1)
      return luna_get_engine2_init();
   return NULL;
}

/* Create filename */
static char *luna_filenamedup(char *spath, char *sfile) {
   char *fn = NULL;
   size_t len = 0;
   if (strlen(spath) > LUNA_MAX_STRING)
      return NULL;
   if (strlen(sfile) > LUNA_MAX_STRING)
      return NULL;
   len = (strlen(spath) + 1 + strlen(sfile) + 1 + 8);
   if (len > LUNA_MAX_STRING)
      return NULL;
   fn = (char *)LUNA_malloc((int)len);
   if (fn == NULL)
      return NULL;
   fn[0] = '\0';
   snprintf(fn, len, "%s%s%s", (char *)spath, (char *)LUNA_FILE_SLASH, (char *)sfile);
   return fn;
}

/* Translate integer to string */
static char *luna_itoa(char *buffer, unsigned value) {
   sprintf(buffer, "%08X", (unsigned)value);
   return buffer;
}

#ifdef LOCAL_CONFIG_LUNA_DEBUG

/* Dump hex data */
static void luna_dumpdata(char *prefix, const void *data__, const size_t len) {
   /* dump the prefix, length, first and last byte only */
   const unsigned char *data = (const unsigned char *)data__;
   if (data == NULL)
      return;
   if (len < 4)
      return;
   fprintf(stderr, "%s: %u: %02X %02X ... %02X %02X \n", (char *)(prefix ? prefix : ""), (unsigned)len,
           (unsigned)data[0],
           (unsigned)data[1],
           (unsigned)data[len - 2],
           (unsigned)data[len - 1]);
}

/* Dump string value */
static void luna_dump_s(char *prefix, const char *value) {
   fprintf(stderr, "%s: \"%s\"\n", (char *)prefix ? prefix : "", (char *)value);
}

/* Dump long value */
static void luna_dump_l(char *prefix, long value) {
   fprintf(stderr, "%s: %08X\n", (char *)prefix ? prefix : "", (unsigned)value);
}

#endif /* #ifdef LOCAL_CONFIG_LUNA_DEBUG */

/* Get attribute value */
static int luna_attribute_malloc(luna_context_t *ctx, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pAttr) {
   CK_RV retCode = CKR_OK;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   pAttr->ulValueLen = 0;
   pAttr->pValue = 0;
   retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttr, 1);
   if (retCode != CKR_OK) {
      goto err; /* likely */
   }
   /* NOTE: assert length is non-zero; esp. for CKA_ID */
   if (pAttr->ulValueLen < 1) {
      LUNACA3err(LUNACA3_F_GETATTRVALUE, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "ulValueLen < 1: ", luna_itoa(itoabuf, pAttr->type));
      goto err;
   }
   /* NOTE: always allocated on heap */
   pAttr->pValue = (CK_BYTE_PTR)LUNA_malloc(pAttr->ulValueLen);
   if (pAttr->pValue == NULL)
      goto err;
   retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttr, 1);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_GETATTRVALUE, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_GetAttributeValue=0x", luna_itoa(itoabuf, retCode));
      goto err;
   }
   IF_LUNA_DEBUG(luna_dumpdata("GetAttribute: ", pAttr->pValue, pAttr->ulValueLen));
   return 1;
err:
   if (pAttr->pValue != NULL)
      LUNA_free(pAttr->pValue);
   pAttr->ulValueLen = 0;
   pAttr->pValue = 0;
   luna_context_set_last_error(ctx, retCode);
   return 0;
}

static int luna_attribute_malloc2(CK_ATTRIBUTE_PTR pAttr, CK_ULONG type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) {
   pAttr->type = type;
   pAttr->pValue = 0;
   pAttr->ulValueLen = 0;

   if (ulValueLen < 1)
      return 0;
   if ((pAttr->pValue = LUNA_malloc(ulValueLen)) == NULL)
      return 0;

   pAttr->ulValueLen = ulValueLen;
   memcpy(pAttr->pValue, pValue, ulValueLen);
   return 1;
}

/* Find object */
static int luna_find_object_ex1(luna_context_t *ctx, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
                                CK_OBJECT_HANDLE_PTR pHandle, int flagCountMustEqualOne) {
   CK_RV retCode = CKR_OK;
#ifdef LUNA_OSSL_FIND_2_OBJECTS
   CK_OBJECT_HANDLE arrayHandle[2] = {LUNA_INVALID_HANDLE, LUNA_INVALID_HANDLE};
#else
   CK_OBJECT_HANDLE arrayHandle[1] = {LUNA_INVALID_HANDLE}; /* OPTIMIZE */
#endif
   CK_ULONG nObjFound = 0;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   retCode = p11.std->C_FindObjectsInit(ctx->hSession, pAttr, nAttr);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_FindObjectsInit=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_find_object_ex1: C_FindObjectsInit", retCode);
      goto err;
   }

   if (flagCountMustEqualOne) {
      retCode = p11.std->C_FindObjects(ctx->hSession, arrayHandle, LUNA_DIM(arrayHandle), &nObjFound);
   } else {
      retCode = p11.std->C_FindObjects(ctx->hSession, arrayHandle, 1, &nObjFound); /* possible optimization */
   }
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_FindObjects=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL("luna_find_object_ex1: C_FindObjects", retCode);
      goto err;
   }

#ifdef LUNA_OSSL_CALL_FINAL
   (void)p11.std->C_FindObjectsFinal(ctx->hSession);
#endif
   if (nObjFound < 1)
      goto err;
   if (arrayHandle[0] == LUNA_INVALID_HANDLE)
      goto err;
   IF_LUNA_DEBUG(luna_dump_l("FindObject.arrayHandle[0]", (long)arrayHandle[0]));
   if (flagCountMustEqualOne && (nObjFound != 1)) {
      IF_LUNA_DEBUG(luna_dump_l("FindObject.duplicates", (long)nObjFound));
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_DUPLICATE);
      LUNA_ERRORLOGL("luna_find_object_ex1: nObjFound", nObjFound);
      goto err;
   }
   (*pHandle) = arrayHandle[0];
   return 1;

err:
   (*pHandle) = 0;
   luna_context_set_last_error(ctx, retCode);
   return 0;
}

/* Get rsa extension */
static int luna_get_rsa_ex(void) {
   int flags = 0;
   if (g_config.EnableRsaEx != NULL) {
      flags = atoi(g_config.EnableRsaEx);
   } else {
      /* NOTE: check legacy config entry "RSA_EX" */
      if (g_config.RSA_EX != NULL) {
         flags = atoi(g_config.RSA_EX);
      } else {
         flags = 1; /* NOTE: on by default */
      }
   }
   return flags;
}

/* Get dsa extension */
static int luna_get_dsa_ex(void) {
   int flags = 0;
   if (g_config.EnableDsaEx != NULL) {
      flags = atoi(g_config.EnableDsaEx);
   } else {
      flags = 1; /* NOTE: on by default */
   }
   return flags;
}

/* Get ecdsa extension */
static int luna_get_ecdsa_ex(void) {
   int flags = 0;
   if (g_config.EnableEcdsaEx != NULL) {
      flags = atoi(g_config.EnableEcdsaEx);
   } else {
      flags = 1; /* NOTE: on by default */
   }
   return flags;
}

/* Get disable rsa */
static int luna_get_disable_rsa(void) {
   int flags = 0;
   if (g_config.DisableRsa != NULL) {
      flags = atoi(g_config.DisableRsa);
   } else {
      flags = 0;
   }
   return flags;
}

/* Get disable dsa */
static int luna_get_disable_dsa(void) {
   int flags = 0;
   if (g_config.DisableDsa != NULL) {
      flags = atoi(g_config.DisableDsa);
   } else {
      flags = 1; /* NOTE: on by default */
   }
   return flags;
}

/* Get disable ecdsa */
static int luna_get_disable_ecdsa(void) {
   int flags = 0;
   if (g_config.DisableEcdsa != NULL) {
      flags = atoi(g_config.DisableEcdsa);
   } else {
      flags = 1; /* NOTE: on by default */
   }
   return flags;
}

/* Get enable load_privkey */
static int luna_get_enable_load_privkey(void) {
   int value = 0;
   if (g_config.EnableLoadPrivKey != NULL) {
      value = atoi(g_config.EnableLoadPrivKey);
   } else {
      value = 1; /* NOTE: on by default */
   }
   return value;
}

/* Get enable load_pubkey */
static int luna_get_enable_load_pubkey(void) {
   int value = 0;
   if (g_config.EnableLoadPubKey != NULL) {
      value = atoi(g_config.EnableLoadPubKey);
   } else {
      value = 1; /* NOTE: on by default */
   }
   return value;
}

#if defined(LUNA_OSSL_PKEY_METHS)
/* Get enable pkey_meths */
static int luna_get_enable_pkey_meths(void) {
   int value = 0;
   if (g_config.EnablePkeyMeths != NULL) {
      value = atoi(g_config.EnablePkeyMeths);
   } else {
      value = 1; /* NOTE: on by default */
   }
   return value;
}

/* Get enable pkey_asn1_meths */
static int luna_get_enable_pkey_asn1_meths(void) {
   int value = 0;
   if (g_config.EnablePkeyAsn1Meths != NULL) {
      value = atoi(g_config.EnablePkeyAsn1Meths);
   } else {
      value = 1; /* NOTE: on by default */
   }
   return value;
}
#endif /* LUNA_OSSL_PKEY_METHS */

/* Get enable register_all */
static int luna_get_disable_register_all(void) {
   int value = 0;
   if (g_config.DisableRegisterAll != NULL) {
      value = atoi(g_config.DisableRegisterAll);
   } else {
      value = 1; /* NOTE: on by default */
   }
   return value;
}

/* Get enable digests */
static int luna_get_enable_digests(void) {
   int value = 0;
   if (g_config.EnableDigests != NULL) {
      value = atoi(g_config.EnableDigests);
   } else {
      value = 1; /* NOTE: on by default */
   }
   return value;
}

/* Get enable login init */
static int luna_get_enable_login_init(void) {
   int value = 0;
   if (g_config.EnableLoginInit != NULL) {
      value = atoi(g_config.EnableLoginInit);
   } else {
      value = 0;
   }
   return value;
}

/* Get enable rsa generate key pair */
static int luna_get_enable_rsa_gen_key_pair(void) {
   int value = 0;
   if (g_config.EnableRsaGenKeyPair != NULL) {
      value = atoi(g_config.EnableRsaGenKeyPair);
   } else {
      value = 0;
   }
   return value;
}

/* Get enable dsa generate key pair */
static int luna_get_enable_dsa_gen_key_pair(void) {
   int value = 0;
   if (g_config.EnableDsaGenKeyPair != NULL) {
      value = atoi(g_config.EnableDsaGenKeyPair);
   } else {
      value = 0;
   }
   return value;
}

/* Get enable pqc generate key pair */
static int luna_get_enable_pqc_gen_key_pair(void) {
   int value = 0;
   if (g_config.EnablePqcGenKeyPair != NULL) {
      value = atoi(g_config.EnablePqcGenKeyPair);
   } else {
      value = 0;
   }
   return value;
}

/* Get enable ec generate key pair */
static int luna_get_enable_ec_gen_key_pair(void) {
   int value = 0;
   if (g_config.EnableEcGenKeyPair != NULL) {
      value = atoi(g_config.EnableEcGenKeyPair);
   } else {
      value = 0;
   }
   return value;
}

/* Get enable ec-edwards generate key pair */
static int luna_get_enable_ed_gen_key_pair(void) {
   int value = 0;
   if (g_config.EnableEdGenKeyPair != NULL) {
      value = atoi(g_config.EnableEdGenKeyPair);
   } else {
      value = 0;
   }
   return value;
}

/* Get enable ec-montgomery generate key pair */
static int luna_get_enable_em_gen_key_pair(void) {
   int value = 0;
   if (g_config.EnableEmGenKeyPair != NULL) {
      value = atoi(g_config.EnableEmGenKeyPair);
   } else {
      value = 0;
   }
   return value;
}

/* Get recovery level */
static int luna_get_recovery_level(void) {
   int value = 0;
   if (g_config.RecoveryLevel != NULL) {
      value = atoi(g_config.RecoveryLevel);
   } else {
      value = 1; /* NOTE: 1 by default for DPOD */
   }
   return value;
}

/* Query is token object by default */
static int luna_get_token_object(void) {
   int value = 0;
   if (g_config.EnableTokenObject != NULL) {
      value = atoi(g_config.EnableTokenObject);
   } else {
      value = 1; /* NOTE: 1 by default for legacy */
   }
   return value;
}

/* Query using pqc shim */
static int luna_get_pqc_shim(void) {
   int value = 0;
   if (g_config.EnablePqcShim != NULL) {
      value = atoi(g_config.EnablePqcShim);
   } else {
      value = 0; /* NOTE: 0 by default going forward */
   }
   return value;
}

/* Query using DelegateHwPqcKemEncapToSw */
static int luna_get_DelegateHwPqcKemEncapToSw(void) {
   int value = 0;
   if (g_config.DelegateHwPqcKemEncapToSw != NULL) {
      value = atoi(g_config.DelegateHwPqcKemEncapToSw);
   } else {
      value = 0; /* NOTE: 0 by default */
   }
   return value;
}

/* Query using DelegateSwPqcKemEncapRngToHw */
static int luna_get_DelegateSwPqcKemEncapRngToHw(void) {
   int value = 0;
   if (g_config.DelegateSwPqcKemEncapRngToHw != NULL) {
      value = atoi(g_config.DelegateSwPqcKemEncapRngToHw);
   } else {
      value = 0; /* NOTE: 0 by default */
   }
   return value;
}

#ifdef LUNA_OSSL_WINDOWS

typedef HANDLE lunasys_mutex_t;

#define LUNA_MUTEX_T_INIT NULL

/* Init global mutex */
static int lunasys_mutex_init(lunasys_mutex_t *pmu) {
   if (pmu[0] == NULL) /* init once */
   {
      pmu[0] = CreateMutex(NULL, FALSE, NULL);
   }
   return (pmu[0] == NULL) ? 1 : 0;
}

/* Fini global mutex */
static void lunasys_mutex_fini(lunasys_mutex_t *pmu) {
   CloseHandle(pmu[0]);
   pmu[0] = NULL;
}

/* Enter global mutex */
static void lunasys_mutex_enter(lunasys_mutex_t *pmu) {
   DWORD rc = WaitForSingleObject(pmu[0], INFINITE);
   if ((rc != WAIT_ABANDONED) && (rc != WAIT_OBJECT_0)) {
      fprintf(stderr, "exit due to lunasys_mutex_enter \n");
      LUNA_ERRORLOG("exit due to lunasys_mutex_enter");
      exit(-1);
   }
}

/* Exit global mutex */
static void lunasys_mutex_exit(lunasys_mutex_t *pmu) {
   if (ReleaseMutex(pmu[0]) == 0) {
      fprintf(stderr, "exit due to lunasys_mutex_exit \n");
      LUNA_ERRORLOG("exit due to lunasys_mutex_exit");
      exit(-1);
   }
}

/* Start timer */
static void luna_stopwatch_start(luna_stopwatch_t *lsw) { lsw->t1 = lsw->t0 = GetTickCount(); }

/* Stop timer */
static void luna_stopwatch_stop(luna_stopwatch_t *lsw) { lsw->t1 = GetTickCount(); }

/* Return elapsed time (microsecs) */
static LUNA_TIME_UNIT_T luna_stopwatch_usec(luna_stopwatch_t *lsw) {
   if (lsw->t1 <= lsw->t0) {
      return 0;
   }

   return ((lsw->t1 - lsw->t0) * 1000);
}

/* luna_dso */
static LUNA_DSO_T luna_dso_load(const char *szDll) {
   wchar_t wcsDll[LUNA_MAX_STRING+1];
   size_t rc = mbstowcs(wcsDll, szDll, LUNA_MAX_STRING);
   if ( (rc < 12) || (rc >= LUNA_MAX_STRING) )
      return (LUNA_DSO_T)NULL;
   HMODULE h = LoadLibraryW(wcsDll);
   LUNA_DSO_T dso = (LUNA_DSO_T)h;
   return dso;
}

static LUNA_DSO_F luna_dso_bind_func(LUNA_DSO_T dso, const char *szFunction) {
   HMODULE h = (HMODULE)dso;
   LUNA_DSO_F f = (LUNA_DSO_F)GetProcAddress(h, szFunction);
   return f;
}

static void luna_dso_free(LUNA_DSO_T dso) {
   HMODULE h = (HMODULE)dso;
   (void)FreeLibrary(h);
}

static void luna_sleep_milli(unsigned millisecs) {
   Sleep(millisecs);
}

#else /* LUNA_OSSL_WINDOWS */

typedef struct lunasys_mutex_s {
   int magic;
   pthread_mutex_t mu;
} lunasys_mutex_t;

#define LUNA_MUTEX_T_INIT \
   { 0 }

/* Init global mutex */
static int lunasys_mutex_init(lunasys_mutex_t *pmu) {
   int rc;
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
static void lunasys_mutex_fini(lunasys_mutex_t *pmu) {
   pthread_mutex_destroy(&(pmu->mu));
   memset(pmu, 0, sizeof(*pmu));
}

/* Enter global mutex */
static void lunasys_mutex_enter(lunasys_mutex_t *pmu) {
   if (pthread_mutex_lock(&(pmu->mu)) != 0) {
      fprintf(stderr, "exit due to lunasys_mutex_enter \n");
      LUNA_ERRORLOG("exit due to lunasys_mutex_enter");
      exit(-1);
   }
}

/* Exit global mutex */
static void lunasys_mutex_exit(lunasys_mutex_t *pmu) {
   if (pthread_mutex_unlock(&(pmu->mu)) != 0) {
      fprintf(stderr, "exit due to lunasys_mutex_exit \n");
      LUNA_ERRORLOG("exit due to lunasys_mutex_exit");
      exit(-1);
   }
}

/* Start timer */
static void luna_stopwatch_start(luna_stopwatch_t *lsw) {
   struct timeval tv;
   gettimeofday(&tv, NULL);
   lsw->t1 = lsw->t0 = ((tv.tv_sec * 1000000) + tv.tv_usec);
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
      return 0;
   }

   return (lsw->t1 - lsw->t0);
}

/* luna_dso */
static LUNA_DSO_T luna_dso_load(const char *szDll) {
   void *h = dlopen(szDll, RTLD_LAZY); /* FIXME: RTLD_NOW ? */
   if (h == NULL) {
      char *szerr = dlerror();
      if (szerr != NULL) {
         LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
         ERR_add_error_data(2, "luna_dso_load:", szerr);
      }
   }
   LUNA_DSO_T dso = (LUNA_DSO_T)h;
   return dso;
}

static LUNA_DSO_F luna_dso_bind_func(LUNA_DSO_T dso, const char *szFunction) {
   void *h = (void *)dso;
   LUNA_DSO_F f = (LUNA_DSO_F)dlsym(h, szFunction);
   return f;
}

static void luna_dso_free(LUNA_DSO_T dso) {
   void *h = (void *)dso;
   (void)dlclose(h);
}

static void luna_sleep_milli(unsigned millisecs) {
   struct timespec time1;
   time1.tv_sec = (millisecs / 1000);
   time1.tv_nsec = ((millisecs % 1000) * 1000000);
   nanosleep(&time1, NULL);
}

#endif /* LUNA_OSSL_WINDOWS */

#define LUNA_MAX_MUTEX (2)

static lunasys_mutex_t mu_luna_engine[LUNA_MAX_MUTEX] = {LUNA_MUTEX_T_INIT, LUNA_MUTEX_T_INIT};

/* Init global mutex(es) */
static int luna_mutex_init(void) {
   unsigned ii = 0;
   for (ii = 0; ii < LUNA_MAX_MUTEX; ii++) {
      if (lunasys_mutex_init(&(mu_luna_engine[ii])))
         return 1;
   }
   return 0;
}

/* Fini global mutex(es) */
static void luna_mutex_fini(void) {
   unsigned ii = 0;
   for (ii = 0; ii < LUNA_MAX_MUTEX; ii++) {
      lunasys_mutex_fini(&(mu_luna_engine[ii]));
   }
}

/* Enter global mutex */
static void luna_mutex_enter_ndx(unsigned ndx) {
   if (ndx >= LUNA_MAX_MUTEX) {
      fprintf(stderr, "exit due to luna_mutex_enter_ndx(%u) \n", (unsigned)ndx);
      LUNA_ERRORLOGL("exit due to luna_mutex_enter_ndx", ndx);
      exit(-1);
   }
   lunasys_mutex_enter(&(mu_luna_engine[ndx]));
}

static void luna_mutex_enter(void) { luna_mutex_enter_ndx(LUNA_MUTEX_NDX_HW); }

/* Exit global mutex */
static void luna_mutex_exit_ndx(unsigned ndx) {
   if (ndx >= LUNA_MAX_MUTEX) {
      fprintf(stderr, "exit due to luna_mutex_exit_ndx(%u) \n", (unsigned)ndx);
      LUNA_ERRORLOGL("exit due to luna_mutex_exit_ndx", ndx);
      exit(-1);
   }
   lunasys_mutex_exit(&(mu_luna_engine[ndx]));
}

static void luna_mutex_exit(void) { luna_mutex_exit_ndx(LUNA_MUTEX_NDX_HW); }

/* Check rsa key */
static int luna_rsa_check_private(RSA *rsa) {
   /* If ANY public key member null then error */
   if (rsa == NULL)
      return -1;
   if (LUNA_RSA_GET_n(rsa) == NULL)
      return -1;
   if (LUNA_RSA_GET_e(rsa) == NULL)
      return -1;

   /* If ANY private key member null then hardware */
   /* NOTE: some of these members may be null TEMPORARILY due to cache effects! */
   if (LUNA_RSA_GET_d(rsa) == NULL)
      return 0;
   if (LUNA_RSA_GET_p(rsa) == NULL)
      return 0;
   if (LUNA_RSA_GET_q(rsa) == NULL)
      return 0;
   if (LUNA_RSA_GET_iqmp(rsa) == NULL)
      return 0;
   if (LUNA_RSA_GET_dmq1(rsa) == NULL)
      return 0;
   if (LUNA_RSA_GET_dmp1(rsa) == NULL)
      return 0;

   /* If ANY private key member matches sautil then hardware. */
   if ((BN_get_word(LUNA_RSA_GET_d(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_p(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_q(rsa)) == 1) ||
       (BN_get_word(LUNA_RSA_GET_iqmp(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_dmq1(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_dmp1(rsa)) == 1)) {
      return 0;
   }

   /* Otherwise, software. */
   return 1;
}

static int luna_rsa_check_public(RSA *rsa) {
   /* If ANY public key member null then error. */
   if (rsa == NULL)
      return -1;
   if (LUNA_RSA_GET_n(rsa) == NULL)
      return -1;
   if (LUNA_RSA_GET_e(rsa) == NULL)
      return -1;

   /* If ANY private key member null then software (optimization) */
   /* NOTE: some of these members may be null TEMPORARILY due to cache effects! */
   if (LUNA_RSA_GET_d(rsa) == NULL)
      return 1;
   if (LUNA_RSA_GET_p(rsa) == NULL)
      return 1;
   if (LUNA_RSA_GET_q(rsa) == NULL)
      return 1;
   if (LUNA_RSA_GET_iqmp(rsa) == NULL)
      return 1;
   if (LUNA_RSA_GET_dmq1(rsa) == NULL)
      return 1;
   if (LUNA_RSA_GET_dmp1(rsa) == NULL)
      return 1;

   /* If ANY private key member matches sautil then hardware. */
   if ((BN_get_word(LUNA_RSA_GET_d(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_p(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_q(rsa)) == 1) ||
       (BN_get_word(LUNA_RSA_GET_iqmp(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_dmq1(rsa)) == 1) || (BN_get_word(LUNA_RSA_GET_dmp1(rsa)) == 1)) {
      return 0;
   }

   /* Otherwise, software. */
   return 1;
}

/* Check dsa key */
static int luna_dsa_check_private(DSA *dsa) {
   /* If ANY public key member null then error */
   if (dsa == NULL)
      return -1;
   if (LUNA_DSA_GET_p(dsa) == NULL)
      return -1;
   if (LUNA_DSA_GET_q(dsa) == NULL)
      return -1;
   if (LUNA_DSA_GET_g(dsa) == NULL)
      return -1;
   if (LUNA_DSA_GET_pub_key(dsa) == NULL)
      return -1;

   /* If ANY private key member NULL then hardware */
   if (LUNA_DSA_GET_priv_key(dsa) == NULL)
      return 0;

   /* If ANY private key member matches sautil then hardware. */
   if (((BN_get_word(LUNA_DSA_GET_priv_key(dsa)) == 1) || (BN_num_bytes(LUNA_DSA_GET_priv_key(dsa)) <= 8))) {
      return 0;
   }

   /* Otherwise, software. */
   return 1;
}

static int luna_dsa_check_public(DSA *dsa) {
   /* If ANY public key member null then error */
   if (dsa == NULL)
      return -1;
   if (LUNA_DSA_GET_p(dsa) == NULL)
      return -1;
   if (LUNA_DSA_GET_q(dsa) == NULL)
      return -1;
   if (LUNA_DSA_GET_g(dsa) == NULL)
      return -1;
   if (LUNA_DSA_GET_pub_key(dsa) == NULL)
      return -1;

   /* If priv_key null then software (optimization) */
   /* NOTE: priv_key may be null TEMPORARILY due to cache effects! */
   if (LUNA_DSA_GET_priv_key(dsa) == NULL)
      return 1; /* previously, returning 0 here fails if public key not in hsm */

   /* If ANY private key member matches sautil then hardware. */
   if (((BN_get_word(LUNA_DSA_GET_priv_key(dsa)) == 1) || (BN_num_bytes(LUNA_DSA_GET_priv_key(dsa)) <= 8))) {
      return 0;
   }

   /* Otherwise, software. */
   return 1;
}

/* version string and comments */
const char *szRevisionLunaEngine =
    __FILE__ ": " LUNA_OPENSSL_VERSION_TEXT ", built " __DATE__ ", " __TIME__;
const char *szLunaEngineComment1 = "EnableSessionMutex was obsoleted";
const char *szLunaEngineComment2 = "RSA_EX is on by default";
const char *szLunaEngineComment3 = "DisableCipher was removed (ciphers removed)";
const char *szLunaEngineComment4 = "DisableDigest was removed (digests removed)";
const char *szLunaEngineComment5 = "DisableEcdsa was added (ecdsa added)";
const char *szLunaEngineComment6 = "EnableRsaEx was added";
const char *szLunaEngineComment7 = "EnableDsaEx was added";
const char *szLunaEngineComment8 = "EnableEcdsaEx was added";
const char *szLunaEngineComment9 = "DisableSessionCache was added";
const char *szLunaEngineComment10 = "DisableMultiThread was added";
const char *szLunaEngineComment11 = "Fixed RNG when DisableMultiThread=1";
const char *szLunaEngineComment12 = "EnableLoginInit was added";
const char *szLunaEngineComment13 = "EnableRsaGenKeyPair was added";
const char *szLunaEngineComment14 = "EnableDsaGenKeyPair was added";
const char *szLunaEngineComment15 = "EnableRsaSignVerify was added";
const char *szLunaEngineComment16 = "DisablePublicCrypto was added";
const char *szLunaEngineComment18 = "DisableSessionCache is on by default";
const char *szLunaEngineComment19 = "Redirection for DSA, ECDSA was fixed";
const char *szLunaEngineComment20 = "DisablePublicCrypto is on by default";
const char *szLunaEngineComment21 = "EnablePkeyMeths was added";
const char *szLunaEngineComment22 = "EnablePkeyAsn1Meths was added";
const char *szLunaEngineComment23 = "EnableDigests was added";
const char *szLunaEngineComment24 = "DisableRand is on by default";
const char *szLunaEngineComment25 = "EnableRsaSignVerify is on by default";
const char *szLunaEngineComment26 = "ECDSA is conditionally compiled";
const char *szLunaEngineComment27 = "DisableRegisterAll was added";
const char *szLunaEngineComment28 = "DisableRegisterAll is on by default";
const char *szLunaEngineComment29 = "EnablePkeyMeths is on by default";
const char *szLunaEngineComment30 = "EnableDigests is on by default";
const char *szLunaEngineComment31 = "EnableLoadPrivKey is on by default";
const char *szLunaEngineComment32 = "EnableLoadPubKey is on by default";
const char *szLunaEngineComment33 = "EnableLimitedUser is off by default";
const char *szLunaEngineComment34 = "Do not call luna_fini_p11 on exit";
const char *szLunaEngineComment35 = "EnablePkeyAsn1Meths is on by default";
const char *szLunaEngineComment36 = "EnableRsaPkcsPadding was added";
const char *szLunaEngineComment37 = "EnableRsaPkcsPadding is off by default";
const char *szLunaEngineComment38 = "IncludePqc was added";
const char *szLunaEngineComment39 = "ExcludePqc was added";
const char *szLunaEngineComment40 = "EnablePqcGenKeyPair was added";
const char *szLunaEngineComment41 = "EnableEcGenKeyPair was added";
const char *szLunaEngineComment42 = "RecoveryLevel was added";
const char *szLunaEngineComment43 = "EnableEdGenKeyPair was added";
const char *szLunaEngineComment44 = "EnableEmGenKeyPair was added";
const char *szLunaEngineComment45 = "EnableTokenObject was added (default=1)";
const char *szLunaEngineComment46 = "EnablePqcShim was added (default=0)";
const char *szLunaEngineComment47 = "DelegateHwPqcKemEncapToSw was added (default=0)";
const char *szLunaEngineComment48 = "DelegateSwPqcKemEncapRngToHw was added (default=0)";
const char *szLunaEngineComment49 = "DisableEc is an alias for DisableEcdsa";
const char *szLunaEngineCommentDevel = "CommentDevel: openssl-3.5.0-sw400";

/* convert to CK_ULONG from ByteArray (little-endian) */
static CK_ULONG luna_CK_ULONG_from_ByteArrayLE(CK_BYTE_PTR src, CK_ULONG srclen_) {
   CK_ULONG ii = 0;
   CK_ULONG dest = 0;
   CK_ULONG srclen = (srclen_ > sizeof(CK_ULONG)) ? sizeof(CK_ULONG) : srclen_;

   for (ii = 0; ii < srclen; ii++) {
      dest += ((CK_BYTE)src[srclen - 1 - ii]);
      if ((ii + 1) < srclen)
         dest <<= 8;
   }

   return dest;
}

#ifdef B_ENDIAN
/* convert to CK_ULONG from ByteArray (big-endian) */
static CK_ULONG luna_CK_ULONG_from_ByteArrayBE(CK_BYTE_PTR src, CK_ULONG srclen_) {
   CK_ULONG ii = 0;
   CK_ULONG dest = 0;
   CK_ULONG srclen = (srclen_ > sizeof(CK_ULONG)) ? sizeof(CK_ULONG) : srclen_;

   for (ii = 0; ii < srclen; ii++) {
      dest += ((CK_BYTE)src[ii]);
      if ((ii + 1) < srclen)
         dest <<= 8;
   }

   return dest;
}
#endif

/* helper function (convert ByteArray to CK_ULONG) */
static CK_ULONG luna_convert_attribute_to_ck_ulong(CK_ATTRIBUTE *pAttr) {
   if (pAttr == NULL)
      return 0;
   if (pAttr->pValue == NULL)
      return 0;
   if (pAttr->ulValueLen == 0)
      return 0;

#ifdef B_ENDIAN
   return luna_CK_ULONG_from_ByteArrayBE((CK_BYTE_PTR)pAttr->pValue, pAttr->ulValueLen);
#else
   return luna_CK_ULONG_from_ByteArrayLE((CK_BYTE_PTR)pAttr->pValue, pAttr->ulValueLen);
#endif
}

/* helper function (load RSA key) */
static EVP_PKEY *luna_load_rsa(ENGINE *eng, luna_context_t *pctx, CK_OBJECT_HANDLE handle, CK_ULONG ulClass,
        int hintPublic) {
   EVP_PKEY *rckey = NULL;
#ifndef OPENSSL_NO_RSA
   RSA *rsa = NULL;
   CK_BYTE baOne[1] = { 0x01 };
   CK_ATTRIBUTE attrOne = { ~0UL, &baOne, sizeof(baOne) };
   CK_ATTRIBUTE attrM;
   CK_ATTRIBUTE attrE;
   CK_ATTRIBUTE attrB;

   memset(&attrM, 0, sizeof(attrM));
   memset(&attrE, 0, sizeof(attrE));
   memset(&attrB, 0, sizeof(attrB));

   if (handle == LUNA_INVALID_HANDLE) {
      return NULL;
   }

   {
      CK_ATTRIBUTE attrib[3];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_PUBLIC_EXPONENT;
      attrib[0].pValue = NULL;
      attrib[0].ulValueLen = 1024; /* worst-case length */
      attrib[1].type = CKA_MODULUS;
      attrib[1].pValue = NULL;
      attrib[1].ulValueLen = 1024; /* worst-case length for 8kbit key */
      attrib[2].type = CKA_MODULUS_BITS;
      attrib[2].pValue = NULL;
      attrib[2].ulValueLen = sizeof(CK_ULONG);
      /* NOTE: luna_attribute_malloc_FAST may need to side-effect pctx->rv_last */
      if (!luna_attribute_malloc_FAST(pctx, handle, attrib, 3)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         return NULL;
      }

      attrE = attrib[0];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_PUBLIC_EXPONENT", attrE.pValue, attrE.ulValueLen));
      attrM = attrib[1];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_MODULUS", attrM.pValue, attrM.ulValueLen));
      attrB = attrib[2];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_MODULUS_BITS", attrB.pValue, attrB.ulValueLen));
   }

   /* NOTE: calling RSA_new_method(eng) is necessary in fips mode!? */
   if ((rsa = (eng == NULL ? RSA_new() : RSA_new_method(eng))) == NULL)
      goto err;
   if (!LUNA_RSA_SET_n_e_d(rsa,
      BN_bin2bn(attrM.pValue, attrM.ulValueLen, NULL),
      BN_bin2bn(attrE.pValue, attrE.ulValueLen, NULL),
      (hintPublic ? NULL : BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL))))
      goto err;
   if (!hintPublic) {
       if (!LUNA_RSA_SET_p_q(rsa,
          BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL),
          BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL)))
          goto err;
       if (!LUNA_RSA_SET_dmp1_dmq1_iqmp(rsa,
          BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL),
          BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL),
          BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL)))
          goto err;
   }
   /* possible flags: RSA_FLAG_FIPS_METHOD, RSA_FLAG_NON_FIPS_ALLOW, RSA_FLAG_EXT_PKEY */
#ifdef RSA_FLAG_FIPS_METHOD
   LUNA_RSA_OR_FLAGS(rsa, RSA_FLAG_FIPS_METHOD);
#endif
#ifdef RSA_FLAG_NON_FIPS_ALLOW
   LUNA_RSA_OR_FLAGS(rsa, RSA_FLAG_NON_FIPS_ALLOW);
#endif
#ifdef RSA_FLAG_EXT_PKEY
   LUNA_RSA_OR_FLAGS(rsa, RSA_FLAG_EXT_PKEY);
#endif
   /* init the return data structure */
   if ((rckey = EVP_PKEY_new()) == NULL)
      goto err;
   /* rckey takes ownership of rsa */
   if (EVP_PKEY_assign_RSA(rckey, rsa) <= 0)
      goto err;
   /* cache the rsa handle(s) */
   if (ulClass == CKO_PRIVATE_KEY) {
      luna_cache_rsa_handle(pctx, rsa, handle, 0);
   } else if (ulClass == CKO_PUBLIC_KEY) {
      luna_cache_rsa_handle(pctx, rsa, 0, handle);
   }
   /* free misc */
   LUNA_free(attrE.pValue);
   LUNA_free(attrM.pValue);
   LUNA_free(attrB.pValue);
   return rckey;

err:
   LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
   if (rckey != NULL) {
      EVP_PKEY_free(rckey);
   }
   if (rsa != NULL) {
      RSA_free(rsa);
   }

   LUNA_free(attrE.pValue);
   LUNA_free(attrM.pValue);
#endif /* OPENSSL_NO_RSA */
   return rckey;
}

/* helper function (load DSA key) */
static EVP_PKEY *luna_load_dsa(ENGINE *eng, luna_context_t *pctx, CK_OBJECT_HANDLE handle, CK_ULONG ulClass,
        int hintPublic) {
   EVP_PKEY *rckey = NULL;
#ifndef OPENSSL_NO_DSA
   CK_ULONG ulKeyClass = 0;
   DSA *dsa = NULL;
   CK_BYTE baOne[1] = { 0x01 };
   CK_ATTRIBUTE attrOne = { ~0UL, &baOne, sizeof(baOne) };
   CK_ATTRIBUTE attrP;
   CK_ATTRIBUTE attrQ;
   CK_ATTRIBUTE attrG;
   CK_ATTRIBUTE attrV;
   CK_ATTRIBUTE attrId;

   memset(&attrP, 0, sizeof(attrP));
   memset(&attrQ, 0, sizeof(attrQ));
   memset(&attrG, 0, sizeof(attrG));
   memset(&attrV, 0, sizeof(attrV));
   memset(&attrId, 0, sizeof(attrId));

   if (handle == LUNA_INVALID_HANDLE) {
      return NULL;
   }

   /* Read CKA_CLASS, CKA_PRIME, CKA_SUBPRIME, CKA_BASE */
   {
      CK_ATTRIBUTE attrib[4];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_CLASS;
      attrib[0].pValue = NULL;
      attrib[0].ulValueLen = sizeof(CK_ULONG);
      attrib[1].type = CKA_PRIME;
      attrib[1].pValue = NULL;
      attrib[1].ulValueLen = 1024; /* worst-case length */
      attrib[2].type = CKA_SUBPRIME;
      attrib[2].pValue = NULL;
      attrib[2].ulValueLen = 1024; /* worst-case length */
      attrib[3].type = CKA_BASE;
      attrib[3].pValue = NULL;
      attrib[3].ulValueLen = 1024; /* worst-case length */
      /* NOTE: luna_attribute_malloc_FAST may need to side-effect pctx->rv_last */
      if (!luna_attribute_malloc_FAST(pctx, handle, attrib, 4)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         return NULL;
      }
      ulKeyClass = luna_convert_attribute_to_ck_ulong(&attrib[0]);
      LUNA_free(attrib[0].pValue);
      attrib[0].pValue = NULL;
      attrP = attrib[1];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_PRIME", attrP.pValue, attrP.ulValueLen));
      attrQ = attrib[2];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_SUBPRIME", attrQ.pValue, attrQ.ulValueLen));
      attrG = attrib[3];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_BASE", attrG.pValue, attrG.ulValueLen));
   }

   if (ulKeyClass == CKO_PRIVATE_KEY) {
      /* Find the handle of the associated public key so we can read CKA_VALUE. */
      {
         CK_ATTRIBUTE attrib[1];
         memset(attrib, 0, sizeof(attrib));
         attrib[0].type = CKA_ID;
         attrib[0].pValue = NULL;
         attrib[0].ulValueLen = 0;
         /* NOTE: luna_attribute_malloc may need to side-effect pctx->rv_last */
         if (!luna_attribute_malloc(pctx, handle, attrib)) {
            LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
            goto err;
         }
         attrId = attrib[0];
      }

      {
         unsigned rcCount = 0;
         CK_ULONG ulKeyType = CKK_DSA;
         CK_ATTRIBUTE attrib[10];

         memset(attrib, 0, sizeof(attrib));

         attrib[rcCount].type = CKA_KEY_TYPE;
         attrib[rcCount].pValue = &ulKeyType;
         attrib[rcCount].ulValueLen = sizeof(ulKeyType);
         rcCount++;

         ulKeyClass = CKO_PUBLIC_KEY;
         attrib[rcCount].type = CKA_CLASS;
         attrib[rcCount].pValue = &ulKeyClass;
         attrib[rcCount].ulValueLen = sizeof(ulKeyClass);
         rcCount++;

         attrib[rcCount] = attrId;
         rcCount++;

         attrib[rcCount] = attrP;
         rcCount++;

         attrib[rcCount] = attrQ;
         rcCount++;

#if 0
         /* FIXME: CKA_BASE with leading zero is a problem so ignore CKA_BASE for now */
         attrib[rcCount] = attrG;
         rcCount++;
#endif

         handle = LUNA_INVALID_HANDLE;
         /* NOTE: luna_find_object_ex1 may need to side-effect pctx->rv_last */
         if (!luna_find_object_ex1(pctx, attrib, rcCount, &handle, 1)) {
            LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
            goto err;
         }
      }
   }

   {
      CK_ATTRIBUTE attrib[1];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_VALUE;
      attrib[0].pValue = NULL;
      attrib[0].ulValueLen = 0;
      /* NOTE: luna_attribute_malloc may need to side-effect pctx->rv_last */
      if (!luna_attribute_malloc(pctx, handle, attrib)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         LUNA_free(attrP.pValue);
         LUNA_free(attrQ.pValue);
         LUNA_free(attrG.pValue);
         return NULL;
      }
      attrV = attrib[0];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_VALUE", attrib[0].pValue, attrib[0].ulValueLen));
   }

   /* NOTE: calling DSA_new_method(eng) is necessary in fips mode!? */
   if ((dsa = (eng == NULL ? DSA_new() : DSA_new_method(eng))) == NULL)
      goto err;
   if (!LUNA_DSA_SET_p_q_g(dsa,
      BN_bin2bn(attrP.pValue, attrP.ulValueLen, NULL),
      BN_bin2bn(attrQ.pValue, attrQ.ulValueLen, NULL),
      BN_bin2bn(attrG.pValue, attrG.ulValueLen, NULL)))
      goto err;
   if (!LUNA_DSA_SET_pub_priv(dsa,
      BN_bin2bn(attrV.pValue, attrV.ulValueLen, NULL),
      (hintPublic ? NULL : BN_bin2bn(attrOne.pValue, attrOne.ulValueLen, NULL))))
      goto err;
   /* possible flags: DSA_FLAG_FIPS_METHOD, DSA_FLAG_NON_FIPS_ALLOW, (DSA_FLAG_EXT_PKEY) */
#ifdef DSA_FLAG_FIPS_METHOD
   LUNA_DSA_OR_FLAGS(dsa, DSA_FLAG_FIPS_METHOD);
#endif
#ifdef DSA_FLAG_NON_FIPS_ALLOW
   LUNA_DSA_OR_FLAGS(dsa, DSA_FLAG_NON_FIPS_ALLOW);
#endif
#ifdef DSA_FLAG_EXT_PKEY
   LUNA_DSA_OR_FLAGS(dsa, DSA_FLAG_EXT_PKEY);
#endif
   /* init the return data structure */
   if ((rckey = EVP_PKEY_new()) == NULL)
      goto err;
   /* rckey takes ownership of dsa */
   if (EVP_PKEY_assign_DSA(rckey, dsa) <= 0)
      goto err;
   /* free misc */
   LUNA_free(attrP.pValue);
   LUNA_free(attrQ.pValue);
   LUNA_free(attrG.pValue);
   LUNA_free(attrV.pValue);
   LUNA_free(attrId.pValue);
   return rckey;

err:
   LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
   if (rckey != NULL) {
      EVP_PKEY_free(rckey);
   }
   if (dsa != NULL) {
      DSA_free(dsa);
   }

   LUNA_free(attrP.pValue);
   LUNA_free(attrQ.pValue);
   LUNA_free(attrG.pValue);
   LUNA_free(attrV.pValue);
   LUNA_free(attrId.pValue);
#endif /* OPENSSL_NO_DSA */
   return rckey;
}

/* helper function (load ECDSA key) */
static EVP_PKEY *luna_load_ecdsa_FAST(ENGINE *eng, luna_context_t *pctx,
        CK_OBJECT_HANDLE hPublicIn, CK_OBJECT_HANDLE hPrivateIn, int hintPublic) {
   EVP_PKEY *rckey = NULL;
#if defined(LUNA_OSSL_ECDSA)
   EC_KEY *dsa = NULL;
   CK_ULONG ulKeyClass = 0;

   CK_ATTRIBUTE attrP;
   CK_ATTRIBUTE attrQ;
   CK_ATTRIBUTE attrId;

   /* OPTIMIZATION: private key handle yields the best performance */
   CK_OBJECT_HANDLE handle = (hPrivateIn != LUNA_INVALID_HANDLE) ? hPrivateIn : hPublicIn;

   memset(&attrP, 0, sizeof(attrP));
   memset(&attrQ, 0, sizeof(attrQ));
   memset(&attrId, 0, sizeof(attrId));

   if (handle == LUNA_INVALID_HANDLE) {
      return NULL;
   }

   /* Try read CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT */
   {
      CK_ATTRIBUTE attrib[3];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_CLASS;
      attrib[0].pValue = NULL;
      attrib[0].ulValueLen = sizeof(CK_ULONG);
      attrib[1].type = CKA_EC_PARAMS;
      attrib[1].pValue = NULL;
      attrib[1].ulValueLen = 1024; /* worst-case length */
      attrib[2].type = CKA_EC_POINT;
      attrib[2].pValue = NULL;
      attrib[2].ulValueLen = 1024; /* worst-case length */
      if (!luna_attribute_malloc_FAST(pctx, handle, attrib, 3)) {
         attrib[0].type = CKA_CLASS;
         attrib[0].pValue = NULL;
         attrib[0].ulValueLen = sizeof(CK_ULONG);
         attrib[1].type = CKA_EC_PARAMS;
         attrib[1].pValue = NULL;
         attrib[1].ulValueLen = 1024; /* worst-case length */
         /* Read CKA_CLASS, CKA_EC_PARAMS */
         if (!luna_attribute_malloc_FAST(pctx, handle, attrib, 2)) {
            LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
            return NULL;
         } else {
            ulKeyClass = luna_convert_attribute_to_ck_ulong(&attrib[0]);
            LUNA_free(attrib[0].pValue);
            attrib[0].pValue = NULL;
            attrP = attrib[1];
            IF_LUNA_DEBUG(luna_dumpdata("CKA_EC_PARAMS", attrP.pValue, attrP.ulValueLen));
         }
      } else {
         ulKeyClass = luna_convert_attribute_to_ck_ulong(&attrib[0]);
         LUNA_free(attrib[0].pValue);
         attrib[0].pValue = NULL;
         attrP = attrib[1];
         IF_LUNA_DEBUG(luna_dumpdata("CKA_EC_PARAMS", attrP.pValue, attrP.ulValueLen));
         attrQ = attrib[2];
         IF_LUNA_DEBUG(luna_dumpdata("CKA_EC_POINT", attrQ.pValue, attrQ.ulValueLen));
      }
   }

   if ((attrQ.pValue == NULL) && (ulKeyClass == CKO_PRIVATE_KEY)) {
      /* Find the handle of the associated public key so we can read CKA_EC_POINT. */
      {
         CK_ATTRIBUTE attrib[1];
         memset(attrib, 0, sizeof(attrib));
         attrib[0].type = CKA_ID;
         attrib[0].pValue = NULL;
         attrib[0].ulValueLen = 0;
         if (!luna_attribute_malloc(pctx, handle, attrib)) {
            LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
            goto err;
         }
         attrId = attrib[0];
      }

      {
         unsigned rcCount = 0;
         CK_ULONG ulKeyType = CKK_ECDSA;
         CK_ATTRIBUTE attrib[10];

         memset(attrib, 0, sizeof(attrib));

         attrib[rcCount].type = CKA_KEY_TYPE;
         attrib[rcCount].pValue = &ulKeyType;
         attrib[rcCount].ulValueLen = sizeof(ulKeyType);
         rcCount++;

         ulKeyClass = CKO_PUBLIC_KEY;
         attrib[rcCount].type = CKA_CLASS;
         attrib[rcCount].pValue = &ulKeyClass;
         attrib[rcCount].ulValueLen = sizeof(ulKeyClass);
         rcCount++;

         attrib[rcCount] = attrId;
         rcCount++;

         attrib[rcCount] = attrP;
         rcCount++;

         handle = hPublicIn;
         if (handle == LUNA_INVALID_HANDLE) {
             if (!luna_find_object_ex1(pctx, attrib, rcCount, &handle, 1)) {
                LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
                goto err;
             }
         }
      }
   }

   if (attrQ.pValue == NULL) {
      CK_ATTRIBUTE attrib[1];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_EC_POINT;
      attrib[0].pValue = NULL;
      attrib[0].ulValueLen = 0;
      if (!luna_attribute_malloc(pctx, handle, attrib)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         goto err;
      }
      attrQ = attrib[0];
      IF_LUNA_DEBUG(luna_dumpdata("CKA_EC_POINT", attrib[0].pValue, attrib[0].ulValueLen));
   }

   /* NOTE: calling EC_KEY_new_method(eng) is necessary in fips mode!? */
   if ((dsa = (eng == NULL ? EC_KEY_new() : LUNA_EC_KEY_new_method(eng))) == NULL) {
      LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
      goto err;
   }
   /* set group */
   if (1) {
      CK_BYTE_PTR buf_ptr = NULL;
      CK_ULONG buf_len = 0;
      const unsigned char **in = NULL;
      const EC_GROUP *group = NULL;

      buf_ptr = (CK_BYTE_PTR)attrP.pValue;
      buf_len = attrP.ulValueLen;
      in = (const unsigned char **)&buf_ptr;
      if (d2i_ECParameters(&dsa, in, buf_len) == NULL) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         ERR_add_error_data(1, "d2i_ECParameters");
         goto err;
      }

      if ((group = EC_KEY_get0_group(dsa)) == NULL)
         goto err;
      if (!EC_GROUP_check(group, NULL)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         ERR_add_error_data(1, "EC_GROUP_check");
         goto err;
      }
   }
   /* set public key */
   if (1) {
      CK_BYTE_PTR buf_ptr = (CK_BYTE_PTR)attrQ.pValue;
      CK_ULONG buf_len = attrQ.ulValueLen;
      if (!LUNA_o2i_ECPublicKey(&dsa, buf_ptr, buf_len)) {
         LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
         ERR_add_error_data(1, "LUNA_o2i_ECPublicKey");
         goto err;
      }
   }

   /* set private key (enhanced) */
   if (!hintPublic) {
      int i;
      unsigned char private_bin[512];
      int order = 0;
      int bits = 0;
      BIGNUM *num = NULL;
      const EC_GROUP *group = NULL;
      const BIGNUM *p_order = NULL;
      BIGNUM *p_alloc = NULL;

      if ((group = LUNA_EC_KEY_get0_group(dsa)) == NULL)
         goto err;
      if ((p_order = LUNA_EC_GROUP_get0_order(group, &p_alloc)) == NULL)
         goto err;
      if ((num = BN_new()) == NULL)
         goto err;

      order = BN_num_bytes(p_order);
      order = LUNA_MIN(order, LUNA_DIM(private_bin));
      bits = BN_num_bits(p_order);
      private_bin[0] = (0x80 >> (order * 8 - bits + 1));
      for (i = 1; i < order; i++)
         private_bin[i] = 0x5A;
      if (!BN_bin2bn(private_bin, order, num)) {
         BN_free(num);
         if (p_alloc)
            BN_free(p_alloc);
         goto err;
      }
      if (p_alloc)
         BN_free(p_alloc);
      /* set private key */
      if (!LUNA_EC_KEY_set_private_key(dsa, num))
         goto err;
   }

   /* possible flags: ECDSA_FLAG_FIPS_METHOD, EC_FLAG_NON_FIPS_ALLOW, (EC_FLAG_EXT_PKEY), (EC_FLAG_FIPS_CHECKED) */
#ifdef ECDSA_FLAG_FIPS_METHOD
   LUNA_EC_KEY_OR_FLAGS(dsa, ECDSA_FLAG_FIPS_METHOD);
#endif
#ifdef EC_FLAG_NON_FIPS_ALLOW
   LUNA_EC_KEY_OR_FLAGS(dsa, EC_FLAG_NON_FIPS_ALLOW);
#endif
#ifdef EC_FLAG_EXT_PKEY
   LUNA_EC_KEY_OR_FLAGS(dsa, EC_FLAG_EXT_PKEY);
#endif
#ifdef EC_FLAG_FIPS_CHECKED
   LUNA_EC_KEY_OR_FLAGS(dsa, EC_FLAG_FIPS_CHECKED);
#endif
   /* cache the known hsm object handles */
   luna_cache_ecdsa_handle(pctx, dsa, hPublicIn, hPrivateIn);
   /* init the return data structure */
   if ((rckey = EVP_PKEY_new()) == NULL)
      goto err;
   /* rckey takes ownership of dsa */
   if (EVP_PKEY_assign_EC_KEY(rckey, dsa) <= 0)
      goto err;
   /* free misc */
   LUNA_free(attrP.pValue);
   LUNA_free(attrQ.pValue);
   LUNA_free(attrId.pValue);
   return rckey;

err:
   LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
   if (rckey != NULL) {
      EVP_PKEY_free(rckey);
   }
   if (dsa != NULL) {
      EC_KEY_free(dsa);
   }

   LUNA_free(attrP.pValue);
   LUNA_free(attrQ.pValue);
   LUNA_free(attrId.pValue);
#endif /* LUNA_OSSL_ECDSA */
   return rckey;
}

/* CKA HEX2BN types */
#define LUNA_CKA_HEX2BN_ITEMS CKA_MODULUS /* RSA */, CKA_VALUE /* DSA */, CKA_EC_POINT /* ECDSA */, CKA_ID /* ANY */

/* NOTE: we can add up to 3 attributes at a time; e.g., CKA_CLASS, CKA_KEY_TYPE, plus one of {CKA_LABEL,
 * LUNA_CKA_HEX2BN_ITEMS}. */
#define LUNA_ATTR_MAX_INCREMENT (3)

/* helper function (convert string to attributes)
 *   returns number of attributes stored
 * e.g.,
 *   key_id="CKA_LABEL=my rsa key"
 *   or key_id="CKA_MODULUS=01020304..."
 *   or key_id="CKA_VALUE=01020304..."
 *   or key_id="CKA_EC_POINT=01020304..."
 *   or key_id="CKA_ID=01020304..."
 *   backstop rule: key_id="my rsa key" (implies CKA_LABEL)
 */
static unsigned luna_attribute_from_string(ENGINE *eng, const char *key_id, CK_ATTRIBUTE_PTR attribSearch,
                                           unsigned max_attr, int *have_class, int *have_label, int *have_type) {
   unsigned rcCount = 0;
   unsigned ii = 0;
   char *szSearch = NULL;          /* [LUNA_MAX_STRING + 1]; */
   unsigned char *baSearch = NULL; /* [LUNA_MAX_STRING+1]; */
   int want_backstop = 1;
   size_t tmpsize = 0;

   BIGNUM *bn = NULL;
   int rc;

   struct foo_lafs_s {
      CK_ULONG type;
      const char *sztype;
   } lafstab[] = {{CKA_MODULUS, "CKA_MODULUS="},   /* RSA (public/private) */
                  {CKA_VALUE, "CKA_VALUE="},       /* DSA (public) */
                  {CKA_EC_POINT, "CKA_EC_POINT="}, /* ECDSA (public) */
                  {CKA_ID, "CKA_ID="}};

   struct foo_lafs_s lafs_label = {CKA_LABEL, "CKA_LABEL="};

   if (max_attr < LUNA_ATTR_MAX_INCREMENT)
      goto err;

   if (strlen(key_id) < LUNA_MIN_STRING)
      goto err;

   memset(attribSearch, 0, (sizeof(CK_ATTRIBUTE) * max_attr));
   if ((szSearch = (char *)LUNA_malloc(LUNA_MAX_STRING + 1)) == NULL)
      goto err;
   memset(szSearch, 0, (LUNA_MAX_STRING + 1));
   luna_strncpy(szSearch, key_id, (LUNA_MAX_STRING + 1));
   if ((baSearch = (unsigned char *)LUNA_malloc(LUNA_MAX_STRING + 1)) == NULL)
      goto err;
   memset(baSearch, 0, (LUNA_MAX_STRING + 1));

   /* Fix the search string */
   szSearch[LUNA_MAX_STRING] = 0;
   for (ii = 0; ii < LUNA_MAX_STRING; ii++) {
      if ((szSearch[ii] == '\r') || (szSearch[ii] == '\n')) {
         szSearch[ii] = 0;
      }
   }
   if ((strlen(szSearch) < LUNA_MIN_STRING) || (szSearch[0] == '#'))
      goto err;
   IF_LUNA_DEBUG(luna_dump_s("szSearch", szSearch));

   /* Search for one of {CKA_LABEL, LUNA_CKA_HEX2BN_ITEMS}. */
   want_backstop = 1;
   tmpsize = strlen(lafs_label.sztype);
   if (strncmp(szSearch, lafs_label.sztype, tmpsize) == 0) {
      memmove(&szSearch[0], &szSearch[tmpsize], (strlen(&szSearch[tmpsize]) + 1));
      attribSearch[rcCount].type = CKA_LABEL;
      attribSearch[rcCount].pValue = &szSearch[0];
      attribSearch[rcCount].ulValueLen = (CK_ULONG)strlen(&szSearch[0]);
      rcCount++;
      szSearch = NULL; /* give ownership of szSearch to attribSearch */
      want_backstop = 0;
      (*have_label) = 1;
      /* CKA_LABEL is too generic to add CKA_KEY_TYPE, CKA_CLASS. */
   } else {
      struct foo_lafs_s *lafs_p = NULL;

      /* Search for one of {LUNA_CKA_HEX2BN_ITEMS}. */
      for (ii = 0, lafs_p = lafstab; ii < LUNA_DIM(lafstab); ii++, lafs_p++) {
         if (strncmp(szSearch, lafs_p->sztype, strlen(lafs_p->sztype)) == 0) {
            rc = BN_hex2bn(&bn, &szSearch[strlen(lafs_p->sztype)]);
            if (rc < 1 || bn == NULL)
               goto err;
            if (BN_num_bytes(bn) > LUNA_MAX_STRING)
               goto err;
            if ((rc = BN_bn2bin(bn, baSearch)) < 1)
               goto err;

            attribSearch[rcCount].type = lafs_p->type;
            attribSearch[rcCount].pValue = &baSearch[0];
            attribSearch[rcCount].ulValueLen = (unsigned)rc;
            rcCount++;
            baSearch = NULL; /* give ownership of baSearch to attribSearch */
            want_backstop = 0;

            /* add CKA_KEY_TYPE, CKA_CLASS is possible */
            if (lafs_p->type == CKA_MODULUS) {
               CK_ULONG keytype = CKK_RSA;

               luna_attribute_malloc2(&attribSearch[rcCount], CKA_KEY_TYPE, &keytype, sizeof(keytype));
               rcCount++;
               (*have_type) = 1;
            }

            if (lafs_p->type == CKA_VALUE) {
               CK_ULONG keytype = CKK_DSA;
               CK_ULONG keyclass = CKO_PUBLIC_KEY;

               luna_attribute_malloc2(&attribSearch[rcCount], CKA_KEY_TYPE, &keytype, sizeof(keytype));
               rcCount++;
               (*have_type) = 1;

               luna_attribute_malloc2(&attribSearch[rcCount], CKA_CLASS, &keyclass, sizeof(keyclass));
               rcCount++;
               (*have_class) = 1;
            }

            if (lafs_p->type == CKA_EC_POINT) {
               CK_ULONG keytype = CKK_ECDSA;
               CK_ULONG keyclass = CKO_PUBLIC_KEY;

               luna_attribute_malloc2(&attribSearch[rcCount], CKA_KEY_TYPE, &keytype, sizeof(keytype));
               rcCount++;
               (*have_type) = 1;

               luna_attribute_malloc2(&attribSearch[rcCount], CKA_CLASS, &keyclass, sizeof(keyclass));
               rcCount++;
               (*have_class) = 1;
            }

            if (lafs_p->type == CKA_ID) {
               /* CKA_ID is too generic to add CKA_KEY_TYPE, CKA_CLASS. */
            }

            /* stop after the first matching attribute */
            break;
         }
      }
   }

   /* backstop rule: key_id="my rsa key" (implies CKA_LABEL) */
   if (want_backstop && ((*have_label) == 0) && (szSearch != NULL)) {
      attribSearch[rcCount].type = CKA_LABEL;
      attribSearch[rcCount].pValue = &szSearch[0];
      attribSearch[rcCount].ulValueLen = (CK_ULONG)strlen(&szSearch[0]);
      rcCount++;
      szSearch = NULL; /* give ownership of szSearch to attribSearch */
      (*have_label) = 1;
   }

err:
   /* cleanup baSearch and/or szSearch */
   LUNA_free(baSearch);
   LUNA_free(szSearch);
   if (bn != NULL) {
      OPENSSL_free(bn);
   }

   return rcCount;
}

/* helper function (read attributes from file) */
static unsigned luna_attribute_from_fp(ENGINE *eng, FILE *fp, CK_ATTRIBUTE_PTR attribSearch, unsigned max_attr,
                                       int *have_class, int *have_label, int *have_type) {
   unsigned rcCount = 0, rc = 0;
   char *szSearch = NULL;

   if (max_attr < LUNA_ATTR_MAX_INCREMENT) {
      return 0;
   }

   if ((szSearch = (char *)LUNA_malloc(LUNA_MAX_STRING + 1)) == NULL) {
      return 0;
   }

   for (rc = 1; (rc > 0) && (rcCount < max_attr);) {
      memset(szSearch, 0, (LUNA_MAX_STRING + 1));
      if (fgets(szSearch, LUNA_MAX_STRING, fp) == NULL) {
         break;
      }
      szSearch[LUNA_MAX_STRING] = 0;
      rc = luna_attribute_from_string(eng, szSearch, &attribSearch[rcCount], (max_attr - rcCount), have_class,
                                      have_label, have_type);
      rcCount += rc;
   }

   LUNA_free(szSearch);
   return rcCount;
}

/* helper function (convert key_id to attributes) */
static unsigned luna_attribute_from_key_id(ENGINE *eng, const char *key_id, CK_ATTRIBUTE_PTR p_attr, unsigned max_attr,
                                           int *have_class, int *have_label, int *have_type) {
   unsigned rcCount = 0;
   FILE *fp = NULL;

   if ((fp = fopen(key_id, "r")) == NULL) {
      rcCount = luna_attribute_from_string(eng, key_id, p_attr, max_attr, have_class, have_label, have_type);
   } else {
      rcCount = luna_attribute_from_fp(eng, fp, p_attr, max_attr, have_class, have_label, have_type);
      fclose(fp);
   }

   return rcCount;
}

/* helper function (free data for all attribute types) */
static void luna_attribute_free_all(CK_ATTRIBUTE_PTR p_attr, unsigned max_attr) {
   unsigned ii = 0;

   for (ii = 0; ii < max_attr; ii++) {
      if (p_attr[ii].pValue != NULL) {
         LUNA_free(p_attr[ii].pValue);
         p_attr[ii].pValue = NULL;
         p_attr[ii].ulValueLen = 0;
      }
   }
}

/* helper function (free data for attribute) */
static void luna_attribute_free(CK_ATTRIBUTE_PTR p_attr) {
   luna_attribute_free_all(p_attr, 1);
   return;
}

#define CK_UNDEFINED 0x8FFFFFF
#define CKO_UNDEFINED CK_UNDEFINED
#define CKK_UNDEFINED CK_UNDEFINED

static void luna_fixup_pkey_load(EVP_PKEY **ppkey, CK_ULONG ckKeyType, ENGINE *e, int hintPublic);

/* helper function (load private/public key) */
static EVP_PKEY *luna_load_anykey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data,
                                  int hintPublic) {
   EVP_PKEY *rckey = NULL;
   CK_ULONG ulClass = CKO_UNDEFINED;
   CK_ULONG ulType = CKK_UNDEFINED;
   unsigned rcCount = 0;
   int have_class = 0;
   int have_type = 0;
   int have_label = 0;
   int added_class = 0;
   const char *key_id_ptr = NULL;
   FILE *fpTmp = NULL;
   CK_ATTRIBUTE attribSearch[11];

   memset(attribSearch, 0, sizeof(attribSearch));

   /* dnssec name mangles as "ENGINE:LABEL" while we expect "LABEL" */
   key_id_ptr = strstr(key_id, ENGINE_LUNACA3_ID":"); /* current engine name */
   if (key_id_ptr != NULL) {
      key_id = (key_id_ptr + strlen(ENGINE_LUNACA3_ID":"));
   } else {
      key_id_ptr = strstr(key_id, "pkcs11:"); /* dnssec engine name */
      if (key_id_ptr != NULL) {
         key_id = (key_id_ptr + strlen("pkcs11:"));
      } else {
         key_id_ptr = strstr(key_id, "LunaCA3:"); /* legacy engine name */
         if (key_id_ptr != NULL) {
            key_id = (key_id_ptr + strlen("LunaCA3:"));
         }
      }
   }

   /* Try traditional method */
   if ((fpTmp = fopen(key_id, "r")) != NULL) {
      BIO *in;

      fclose(fpTmp);
      in = BIO_new_file(key_id, "r");
      if (in == NULL)
         goto gather_method;

      rckey = hintPublic ? PEM_read_bio_PUBKEY(in, NULL, 0, NULL) : PEM_read_bio_PrivateKey(in, NULL, 0, NULL);

      BIO_free(in);
      if (rckey == NULL)
         goto gather_method;

      luna_fixup_pkey_load(&rckey, CKK_UNDEFINED, eng, hintPublic);
      return rckey;
   }

/* Otherwise, gather attributes for search criteria... */
gather_method:
   rcCount = luna_attribute_from_key_id(eng, key_id, attribSearch, LUNA_DIM(attribSearch), &have_class, &have_label,
                                        &have_type);
   /* +1+1 means make room for CKA_KEY_TYPE and CKA_CLASS */
   if ((rcCount < 1) || ((rcCount + 1 + 1) >= LUNA_DIM(attribSearch))) {
      LUNA_ERRORLOGL("luna_load_anykey: rcCount", rcCount);
      return NULL;
   }

   /* OPTIMIZATION: append CKA_KEY_TYPE to attribute list iff RSA is the only algorithm enabled */
   if ((have_type == 0) && (luna_get_disable_rsa() == 0) && (luna_get_disable_dsa() != 0) &&
       (luna_get_disable_ecdsa() != 0)) {
      ulType = CKK_RSA;
      luna_attribute_malloc2(&attribSearch[rcCount], CKA_KEY_TYPE, &ulType, sizeof(ulType));
      rcCount++;
      have_type = 1;
   }

   /* Append CKA_CLASS to attribute list */
   if (have_class == 0) {
      ulClass = hintPublic ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY;
      luna_attribute_malloc2(&attribSearch[rcCount], CKA_CLASS, &ulClass, sizeof(ulClass));
      rcCount++;
      have_class = 1;
      added_class = 1;
   }

   /* We have one or more of {CKA_LABEL, LUNA_CKA_HEX2BN_ITEMS}. ...
    * next find the key handle... and check the key type.
    */

   {
      luna_context_t ctx = LUNA_CONTEXT_T_INIT;
      CK_OBJECT_HANDLE handle = LUNA_INVALID_HANDLE;

      if (luna_open_context(&ctx) == 0) {
         luna_attribute_free_all(attribSearch, LUNA_DIM(attribSearch));
         LUNA_ERRORLOG("luna_load_anykey: luna_open_context");
         return NULL;
      }

      /* find the key handle; must be unique */
      /* NOTE: luna_find_object_ex1 may need to side-effect ctx.rv_last */
      if (!luna_find_object_ex1(&ctx, attribSearch, rcCount, &handle, 1)) {
         if (added_class) {
            rcCount--;
            luna_attribute_free(&attribSearch[rcCount]);
            ulClass = (!hintPublic) ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY;
            luna_attribute_malloc2(&attribSearch[rcCount], CKA_CLASS, &ulClass, sizeof(ulClass));
            rcCount++;
         }

         /* NOTE: luna_find_object_ex1 may need to side-effect ctx.rv_last */
         if (!added_class || !luna_find_object_ex1(&ctx, attribSearch, rcCount, &handle, 1)) {
            LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EFINDKEY);
            luna_close_context_w_err(&ctx, -1, ctx.rv_last);
            luna_attribute_free_all(attribSearch, LUNA_DIM(attribSearch));
            LUNA_ERRORLOG("luna_load_anykey: luna_find_object_ex1");
            return NULL;
         }
      }

      /* check the key type */
      {
         if (have_type == 0) {
            CK_ATTRIBUTE attrib[1];
            memset(attrib, 0, sizeof(attrib));
            attrib[0].type = CKA_KEY_TYPE;
            attrib[0].pValue = NULL;
            attrib[0].ulValueLen = 0;
            /* NOTE: luna_attribute_malloc may need to side-effect ctx.rv_last */
            if (!luna_attribute_malloc(&ctx, handle, attrib)) {
               LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
               luna_close_context_w_err(&ctx, -1, ctx.rv_last);
               luna_attribute_free_all(attribSearch, LUNA_DIM(attribSearch));
               LUNA_ERRORLOG("luna_load_anykey: luna_attribute_malloc");
               return NULL;
            }
            IF_LUNA_DEBUG(luna_dumpdata("CKA_KEY_TYPE", attrib[0].pValue, attrib[0].ulValueLen));
            ulType = luna_convert_attribute_to_ck_ulong(&attrib[0]);
            have_type = 1;
            LUNA_free(attrib[0].pValue);
            attrib[0].pValue = NULL;
            attrib[0].ulValueLen = 0;
         }

         switch (ulType) {
            case CKK_RSA: {
               /* NOTE: luna_load_rsa may need to side-effect ctx.rv_last */
               rckey = luna_load_rsa(eng, &ctx, handle, ulClass, hintPublic);
            } break;
            case CKK_DSA: {
               /* NOTE: luna_load_dsa may need to side-effect ctx.rv_last */
               rckey = luna_load_dsa(eng, &ctx, handle, ulClass, hintPublic);
            } break;
            case CKK_ECDSA: {
               /* NOTE: luna_load_ecdsa_FAST may need to side-effect ctx.rv_last */
               rckey = luna_load_ecdsa_FAST(eng, &ctx,
                       (ulClass == CKO_PUBLIC_KEY ? handle : LUNA_INVALID_HANDLE),
                       (ulClass == CKO_PRIVATE_KEY ? handle : LUNA_INVALID_HANDLE),
                       hintPublic );
            } break;
            default: {
               LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_ENOSYS);
               rckey = NULL;
               LUNA_ERRORLOGL("luna_load_anykey: keytype", ulType);
            } break;
         }
      }

      luna_close_context_w_err(&ctx, (rckey == NULL), ctx.rv_last);
   }

   luna_attribute_free_all(attribSearch, LUNA_DIM(attribSearch));
   luna_fixup_pkey_load(&rckey, ulType, eng, hintPublic);
   return rckey;
}

/* engine entry function (load private key) */
static EVP_PKEY *luna_load_privkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
   return luna_load_anykey(eng, key_id, ui_method, callback_data, 0);
}

/* engine entry function (load public key) */
static EVP_PKEY *luna_load_pubkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
   return luna_load_anykey(eng, key_id, ui_method, callback_data, 1);
}

/* log error/event messages; show the time, pid, message and optional long value */
static void luna_xlog(int level, const char *msg, unsigned long lvalue) {
   LUNA_PID_T ulpid = LUNA_GETPID();
   FILE *fp = NULL;
   struct tm *ptm1 = NULL;
   char *szLogRootDir;
   char *szFoo = NULL;
   time_t time1;
   char szPrefix[128];
   char szTime[128];
   char szPath[128];
   memset(&time1, 0, sizeof(time1));
   memset(szPrefix, 0, sizeof(szPrefix));
   memset(szTime, 0, sizeof(szTime));
   memset(szPath, 0, sizeof(szPath));
   time(&time1);
   ptm1 = localtime(&time1);
   szLogRootDir = (g_config.LogRootDir != NULL) ? g_config.LogRootDir : ((char *)"tmp");
   switch (level) {
      case LUNA_LOGLEVEL_PROFILE:
         sprintf(szPrefix, "lunaprof");
#ifndef LUNA_OSSL_WINDOWS
         snprintf(szPath, sizeof(szPath), "/%s/e_lunahsm/lunaprof/lunapid%0lu.log", (char *)szLogRootDir, (unsigned long)ulpid);
#else
         snprintf(szPath, sizeof(szPath), "c:\\%s\\e_lunahsm\\lunaprof\\lunapid%0lu.log", (char *)szLogRootDir, (unsigned long)ulpid);
#endif
         break;
      case LUNA_LOGLEVEL_EVENT:
         sprintf(szPrefix, "lunaevt");
#ifndef LUNA_OSSL_WINDOWS
         snprintf(szPath, sizeof(szPath), "/%s/e_lunahsm/lunaevt/lunapid%0lu.log", (char *)szLogRootDir, (unsigned long)ulpid);
#else
         snprintf(szPath, sizeof(szPath), "c:\\%s\\e_lunahsm\\lunaevt\\lunapid%0lu.log", (char *)szLogRootDir, (unsigned long)ulpid);
#endif
         break;
      default:
         sprintf(szPrefix, "lunaerr");
#ifndef LUNA_OSSL_WINDOWS
         snprintf(szPath, sizeof(szPath), "/%s/e_lunahsm/lunaerr/lunapid%0lu.log", (char *)szLogRootDir, (unsigned long)ulpid);
#else
         snprintf(szPath, sizeof(szPath), "c:\\%s\\e_lunahsm\\lunaerr\\lunapid%0lu.log", (char *)szLogRootDir, (unsigned long)ulpid);
#endif
         break;
   }
   if (strlen(szPath) < 32) {
      szFoo = "< 32";
      goto err;
   }
   if (strlen(szPath) > 96) {
      szFoo = "> 96";
      goto err;
   }
   if (strstr(szPath, "..") != NULL) {
      szFoo = "..";
      goto err;
   }
   if (strstr(szPath, "e_lunahsm") == NULL) {
      szFoo = "e_lunahsm";
      goto err;
   }
   if (strstr(szPath, "lunapid") == NULL) {
      szFoo = "lunapid";
      goto err;
   }
   if (strstr(szPath, ".log") == NULL) {
      szFoo = ".log";
      goto err;
   }
   if ((fp = fopen(szPath, "a")) == NULL) {
      szFoo = szPath;
      goto err;
   }
   if ((ptm1 != NULL) && (strftime(szTime, (sizeof(szTime) - 1), "%y/%m/%d[%H:%M:%S]", ptm1) > 0)) {
      fprintf(fp, "%s: %s: %s: %lx \n", (char *)szTime, (char *)szPrefix, (char *)msg, (unsigned long)lvalue);
   } else {
      fprintf(fp, "%s: %s: %lx \n", (char *)szPrefix, (char *)msg, (unsigned long)lvalue);
   }
   fclose(fp);
   memset(&time1, 0, sizeof(time1));
   memset(szPrefix, 0, sizeof(szPrefix));
   memset(szTime, 0, sizeof(szTime));
   memset(szPath, 0, sizeof(szPath));
   return;

err:
#ifndef LUNA_OSSL_WINDOWS
   if ((fp = fopen("/tmp/e_lunahsm.err", "a")) == NULL)
      return;
#else
   if ((fp = fopen("c:\\tmp\\e_lunahsm.err", "a")) == NULL)
      return;
#endif
   fprintf(fp, "reason: %s; msg: %s \n", (char *)szFoo, (char *)msg);
   fclose(fp);
   return;
}

/* implement memory redzone */
#define LUNA_MIN_MALLOC (1)
#define LUNA_MAX_MALLOC (LUNA_MAX_STRING + 8)
#define LUNA_MAX_REDZONE (16)
#define LUNA_REDZONE_VALUE(ii_) ((unsigned char)((ii_) + 0xBB))

static void luna_redzone_fill(unsigned char *ptr) {
   int ii = 0;
   for (ii = 0; ii < LUNA_MAX_REDZONE; ii++) {
      ptr[ii] = LUNA_REDZONE_VALUE(ii);
   }
}

static int luna_redzone_memcmp(unsigned char *ptr) {
   int ii = 0;
   int rc = 0;
   for (ii = 0; ii < LUNA_MAX_REDZONE; ii++) {
      if (ptr[ii] != LUNA_REDZONE_VALUE(ii)) {
         rc = (ii + 1);
      }
   }
   return rc;
}

/* wrapper for OPENSSL_malloc */
static void *LUNA_malloc(int size0) {
   int size = size0;
   unsigned char *ptr = NULL;

   if (size < LUNA_MIN_MALLOC)
      return NULL;
   if (size > LUNA_MAX_MALLOC)
      return NULL;

   size += LUNA_MAX_REDZONE;
   /* prevent compiler warning */
   if ((unsigned int)size <= (unsigned int)size0)
      return NULL;

   ptr = (unsigned char *)OPENSSL_malloc(size);
   if (ptr == NULL)
      return NULL;

   memset(ptr, 0, size);
   luna_redzone_fill(&ptr[size0]);
   return ptr;
}

/* wrapper for OPENSSL_free */
static void LUNA_free(void *ptr0) {
   if (ptr0 == NULL)
      return;
   OPENSSL_free(ptr0);
}

/* wrapper for OPENSSL_cleanse */
static int LUNA_cleanse(void *ptr0, int size0) {
   int rc;
   unsigned char *ptr = NULL;

   if (ptr0 == NULL || size0 > LUNA_MAX_MALLOC)
      return 0;

   ptr = (unsigned char *)ptr0;
   rc = luna_redzone_memcmp(&ptr[size0]);
   if (rc != 0) {
      LUNA_ERRORLOGL("luna_cleanse: rc", rc);
   }

   /* NOTE: cleanse does not mean zeroize! */
   OPENSSL_cleanse(ptr0, (size0 + LUNA_MAX_REDZONE));
   return rc;
}

static int LUNA_cleanse_free(void *ptr0, int size0) {
   int ret = 0;
   if (ptr0 == NULL)
      return 0;
   ret = LUNA_cleanse(ptr0, size0);
   LUNA_free(ptr0);
   return ret;
}

/* implementation for cached data */
static void luna_cache_init(luna_cache_t *qu) { memset(qu, 0, sizeof(*qu)); }

static void luna_cache_fini(luna_cache_t *qu) { memset(qu, 0, sizeof(*qu)); }

static void luna_cache_push(luna_cache_t *qu, luna_cache_t *item) {
   if (item == NULL)
      return;
   item->next = qu->next;
   qu->next = item;
}

static luna_cache_t *luna_cache_pop(luna_cache_t *qu) {
   luna_cache_t *item = qu->next;
   if (item == NULL)
      return NULL;
   qu->next = item->next;
   item->next = NULL;
   return item;
}

static luna_cache_t *luna_cache_new_ckses(CK_SESSION_HANDLE ckses) {
   luna_cache_t *ptr = (luna_cache_t *)LUNA_malloc(sizeof(luna_cache_t));
   if (ptr == NULL)
      return NULL;
   ptr->ckses = ckses;
   return ptr;
}

static void luna_cache_delete_item(luna_cache_t *item) {
   if (item == NULL)
      return;
   LUNA_free(item);
}

static void luna_cache_delete_ALL(luna_cache_t *pcache, luna_cache_delete_callback_f cb) {
   luna_cache_t *item = NULL;
   luna_cache_t *next = NULL;
   int count = 0;

   if (pcache == NULL)
      return;

   item = pcache->next;
   pcache->next = NULL;
   for (; item != NULL; item = next) {
      next = item->next;
      if (cb != NULL) {
         cb(item, count);
      }
      luna_cache_delete_item(item);
      count++;
   }
}

/* Format string with ascii hex bytes */
static char *luna_sprintf_hex(char *fp0, unsigned char *id, unsigned size) {
   unsigned ii = 0;
   char *fp = (char *)fp0;
   fp[0] = 0;
   for (ii = 0; ii < size; ii++) {
      sprintf(&fp[ii << 1], "%02x", (unsigned)id[ii]); /* lowercase for dnssec */
   }
   return fp0;
}

/*
 * ECDSA
 */

#if defined(LUNA_OSSL_ECDSA)

/* Checking if the value of the private key is a series of 0x5A with leading byte to make value one bit less than the
 * order. */
/* This is to prevent openssh from not liking the key but still giving us the ability to recognize that is is a hardware
 * key */
static int luna_ecdsa_check_enhanced(EC_KEY *eckey) {
   int i;
   unsigned char private_bin[512];
   int order = 0;
   int bits = 0;
   BIGNUM *num = NULL;
   const EC_GROUP *group = NULL;
   const BIGNUM *p_order = NULL;
   BIGNUM *p_alloc = NULL;

   if ((group = LUNA_EC_KEY_get0_group(eckey)) == NULL)
      return -1; /* error */
   if ((p_order = LUNA_EC_GROUP_get0_order(group, &p_alloc)) == NULL)
      return -1; /* error */
   if ((num = BN_new()) == NULL)
      return -1; /* error */

   order = BN_num_bytes(p_order);
   order = LUNA_MIN(order, LUNA_DIM(private_bin));
   bits = BN_num_bits(p_order);
   private_bin[0] = (0x80 >> (order * 8 - bits + 1));
   for (i = 1; i < order; i++)
      private_bin[i] = 0x5A;
   if (!BN_bin2bn(private_bin, order, num)) {
      BN_free(num);
      if (p_alloc)
         BN_free(p_alloc);
      return -1; /* error */
   }
   if (BN_cmp(num, LUNA_EC_KEY_get0_private_key(eckey)) == 0) {
      BN_free(num);
      if (p_alloc)
         BN_free(p_alloc);
      return 0; /* hardware */
   }
   BN_free(num);
   if (p_alloc)
      BN_free(p_alloc);
   return 1; /* software */
}

/* Check ecdsa key (compare with luna_dsa_check_private) */
static int luna_ecdsa_check_private(EC_KEY *eckey) {
   /* If ANY public key member null then error */
   if (eckey == NULL)
      return -1; /* error */
   if (LUNA_EC_KEY_get0_group(eckey) == NULL)
      return -1; /* error */
   if (LUNA_EC_KEY_get0_public_key(eckey) == NULL)
      return -1; /* error */

   /* If ANY private key member null then hardware */
   if (LUNA_EC_KEY_get0_private_key(eckey) == NULL)
      return 0; /* hardware */

   /* sautil check (basic) */
   if ( (BN_get_word(LUNA_EC_KEY_get0_private_key(eckey)) == 1) ||
        (BN_num_bytes(LUNA_EC_KEY_get0_private_key(eckey)) <= 8) ) {
      return 0; /* hardware */
   }

   /* sautil check (enhanced) */
   return luna_ecdsa_check_enhanced(eckey);
}

/* Check ecdsa key (compare with luna_dsa_check_public) */
static int luna_ecdsa_check_public(EC_KEY *eckey) {
   /* If ANY public key member null then error */
   if (eckey == NULL)
      return -1; /* error */
   if (LUNA_EC_KEY_get0_group(eckey) == NULL)
      return -1; /* error */
   if (LUNA_EC_KEY_get0_public_key(eckey) == NULL)
      return -1; /* error */

   /* If priv_key null then software (optimization) */
   /* NOTE: priv_key may be null TEMPORARILY due to cache effects! */
   if (LUNA_EC_KEY_get0_private_key(eckey) == NULL)
      return 1; /* software; previously, returning 0 here fails if public key not in hsm */

   /* sautil check (basic) */
   if ( (BN_get_word(LUNA_EC_KEY_get0_private_key(eckey)) == 1) ||
        (BN_num_bytes(LUNA_EC_KEY_get0_private_key(eckey)) <= 8) ) {
      return 0; /* hardware */
   }

   /* sautil check (enhanced) */
   return luna_ecdsa_check_enhanced(eckey);
}

#if 1

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_object_exact"

static int luna_find_object_exact(luna_context_t *ctx, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
                                    CK_OBJECT_HANDLE_PTR pHandle, CK_ATTRIBUTE_PTR attrExtra) {
    CK_ATTRIBUTE attr[6+1];
    CK_ULONG i;
    if (nAttr > (LUNA_DIM(attr) - 1))
        return 0;
    for (i = 0; i < nAttr; i++) {
        attr[i] = pAttr[i];
    }
    attr[i] = *attrExtra;
    return luna_find_object_ex1(ctx, attr, (nAttr+1), pHandle, 1);
}

#else
#error "obsolete: using exact algorithm finally :)"

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_memcmp_rev_inexact"

#define LUNA_MEMCMP_MIN_LEN (14)
#define LUNA_MEMCMP_MAX_DIFF (4)

/* Compare memory (reverse order, inexact) */
static int luna_memcmp_rev_inexact(CK_BYTE_PTR base_p, CK_ULONG base_len, CK_BYTE_PTR token_p, CK_ULONG token_len) {
   CK_ULONG max_count = 0;
   CK_ULONG diff_count = 0;
   CK_ULONG ii = 0;

   max_count = LUNA_MIN(base_len, token_len);
   if (max_count < LUNA_MEMCMP_MIN_LEN)
      return -1; /* not enough bytes to compare */

   diff_count = LUNA_DIFF(base_len, token_len);
   if (diff_count > LUNA_MEMCMP_MAX_DIFF)
      return -2; /* the sizes are not close enough */

   for (ii = 0; ii < max_count; ii++) {
      /* compare in reverse order */
      if (token_p[token_len - ii - 1] != base_p[base_len - ii - 1])
         break;
   }

   /* ii = number of bytes that matched */
   diff_count = LUNA_DIFF(ii, base_len);
   if (diff_count > LUNA_MEMCMP_MAX_DIFF)
      return -3; /* not enough matching bytes */

   /* TODO: we should check the value of the ignored bytes (e.g., asn1 header stuff) */

   return 0; /* success */
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_object_inexact"

/* Find object; must be unique; use inexact algorithm */
static int luna_find_object_inexact(luna_context_t *ctx, CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr,
                                    CK_OBJECT_HANDLE_PTR pHandle, CK_ATTRIBUTE_PTR attrBase) {
   int have_init = 0;
   CK_RV retLoop = CKR_OK;
   CK_RV retCode = CKR_OK;
   CK_ULONG obj_count = 0;
   CK_ULONG match_count = 0;
   CK_OBJECT_HANDLE match_handle = LUNA_INVALID_HANDLE;

   CK_ATTRIBUTE attrFoo[1];
   CK_OBJECT_HANDLE handles[1] = {LUNA_INVALID_HANDLE};

   memset(attrFoo, 0, sizeof(attrFoo));

   if ((attrBase == NULL) || (attrBase[0].pValue == NULL) || (attrBase[0].ulValueLen < LUNA_MEMCMP_MIN_LEN)) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNACA3_R_EINVAL");
      goto err;
   }

   /* FindObjectsInit */
   if (retCode == CKR_OK) {
      retCode = p11.std->C_FindObjectsInit(ctx->hSession, pAttr, nAttr);
      have_init = (retCode == CKR_OK) ? 1 : 0;
   }

   /* FindObjects */
   if (retCode == CKR_OK) {
      do {
         retLoop = CKR_GENERAL_ERROR; /* initially assume error */
         handles[0] = 0;
         obj_count = 0;
         retCode = p11.std->C_FindObjects(ctx->hSession, &handles[0], 1, &obj_count);
         if ((retCode == CKR_OK) && (obj_count == 1) && (handles[0] != LUNA_INVALID_HANDLE)) {
            attrFoo[0].type = attrBase[0].type;
            attrFoo[0].pValue = NULL;
            attrFoo[0].ulValueLen = 0;
            if (luna_attribute_malloc(ctx, handles[0], attrFoo)) {
               retLoop = CKR_OK; /* continue looping */
               if (luna_memcmp_rev_inexact((CK_BYTE_PTR)attrBase[0].pValue, attrBase[0].ulValueLen,
                                           (CK_BYTE_PTR)attrFoo[0].pValue, attrFoo[0].ulValueLen) == 0) {
                  /* found a match... maybe not the only match */
                  match_count++;
                  match_handle = handles[0];
               }

               /* Undo luna_attribute_malloc */
               luna_attribute_free(attrFoo);
            } else {
               /* failing to get attribute constitutes total failure */
               retLoop = CKR_GENERAL_ERROR;
            }
         } else {
            /* failing to iterate constitutes total failure */
            if (retCode != CKR_OK) {
               retLoop = retCode;
            }
         }
      } while (retLoop == CKR_OK);
   }

   /* FindObjectsFinal */
   if (have_init) {
#ifdef LUNA_OSSL_CALL_FINAL
      (void)p11.std->C_FindObjectsFinal(ctx->hSession);
#endif
      have_init = 0;
   }

   /* Undo luna_attribute_malloc */
   luna_attribute_free(attrFoo);

   /* Check result (silent) */
   if (match_count < 1)
      goto err;

   /* Check result (non-silent) */
   if (match_count != 1) {
      IF_LUNA_DEBUG(luna_dump_l("FindObject.duplicates", (long)match_count));
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_DUPLICATE);
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": match_count", match_count);
      goto err;
   }

   /* Return success */
   (*pHandle) = match_handle;
   return 1;

err:
   /* Return failure */
   (*pHandle) = LUNA_INVALID_HANDLE;
   luna_context_set_last_error(ctx, retCode);
   return 0;
}
#endif

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_ecdsa_handle"

/* Find ECDSA key handle */
static CK_OBJECT_HANDLE luna_find_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, int bPrivate) {
   CK_OBJECT_HANDLE rethandle = LUNA_INVALID_HANDLE;

   int rcSize1 = -1;
   int rcSize2 = -1;
   int foundPublic = 0;
   CK_BYTE_PTR bufP = NULL;
   CK_BYTE_PTR bufQ1 = NULL;
   CK_BYTE_PTR bufQ2 = NULL;
   CK_ULONG rcCount = 0;
   CK_ULONG rcBase = 0;
   CK_OBJECT_HANDLE tmphandle = LUNA_INVALID_HANDLE;
   CK_OBJECT_CLASS ulClass = 0;
   CK_KEY_TYPE ulKeyType = 0;

   CK_ATTRIBUTE attrib[6];
   CK_ATTRIBUTE attribId[1];
   CK_ATTRIBUTE attribPoint1[1];
   CK_ATTRIBUTE attribPoint2[1];

   memset(attrib, 0, sizeof(attrib));
   memset(attribId, 0, sizeof(attribId));
   memset(attribPoint1, 0, sizeof(attribPoint1));
   memset(attribPoint2, 0, sizeof(attribPoint2));

   /* Define base attributes (common to public and private key) */
   rcCount = 0;

   ulKeyType = CKK_EC;
   attrib[rcCount].type = CKA_KEY_TYPE;
   attrib[rcCount].pValue = &ulKeyType;
   attrib[rcCount].ulValueLen = sizeof(ulKeyType);
   rcCount++;

   if ((rcSize1 = i2d_ECParameters(dsa, &bufP)) < 1)
      goto done;
   attrib[rcCount].type = CKA_EC_PARAMS;
   attrib[rcCount].pValue = bufP;
   attrib[rcCount].ulValueLen = (CK_ULONG)rcSize1;
   rcCount++;

   /* Define public key attributes */
   rcBase = rcCount;

   ulClass = bPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
   attrib[rcCount].type = CKA_CLASS;
   attrib[rcCount].pValue = &ulClass;
   attrib[rcCount].ulValueLen = sizeof(ulClass);
   rcCount++;

   /* NOTE: LUNA_i2o_ECPublicKey returns all possible encodings of public key */
   if ((rcSize1 = LUNA_i2o_ECPublicKey(dsa, &bufQ1, &bufQ2, &rcSize2)) < 1)
      goto done;
   attribPoint1[0].type = CKA_EC_POINT;
   attribPoint1[0].pValue = bufQ1;
   attribPoint1[0].ulValueLen = (CK_ULONG)rcSize1;
   attribPoint2[0].type = CKA_EC_POINT;
   attribPoint2[0].pValue = bufQ2;
   attribPoint2[0].ulValueLen = (CK_ULONG)rcSize2;

   if ( !luna_find_object_exact(ctx, attrib, rcCount, &tmphandle, attribPoint1)
           && !luna_find_object_exact(ctx, attrib, rcCount, &tmphandle, attribPoint2) ) {
      if (bPrivate) {
         rcCount = rcBase;
         ulClass = CKO_PUBLIC_KEY;
         attrib[rcCount].type = CKA_CLASS;
         attrib[rcCount].pValue = &ulClass;
         attrib[rcCount].ulValueLen = sizeof(ulClass);
         rcCount++;
         if ( !luna_find_object_exact(ctx, attrib, rcCount, &tmphandle, attribPoint1)
                 && !luna_find_object_exact(ctx, attrib, rcCount, &tmphandle, attribPoint2) ) {
            LUNACA3err(LUNACA3_F_FIND_ECDSA, LUNACA3_R_EFINDKEY);
            LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_object_exact");
            goto done;
         } else {
            foundPublic = 1;
         }
      } else {
         LUNACA3err(LUNACA3_F_FIND_ECDSA, LUNACA3_R_EFINDKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_object_exact");
         goto done;
      }
   } else {
      foundPublic = bPrivate ? 0 : 1;
   }

   /* Find private key using CKA_ID of public key */
   if (bPrivate && foundPublic) {
      attribId[0].type = CKA_ID;
      attribId[0].pValue = NULL_PTR;
      attribId[0].ulValueLen = 0;
      if (!luna_attribute_malloc(ctx, tmphandle, attribId)) {
         LUNACA3err(LUNACA3_F_FIND_ECDSA, LUNACA3_R_EGETATTR);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_attribute_malloc");
         goto done;
      }

      /* Define private key attributes */
      rcCount = rcBase;

      ulClass = CKO_PRIVATE_KEY;
      attrib[rcCount].type = CKA_CLASS;
      attrib[rcCount].pValue = &ulClass;
      attrib[rcCount].ulValueLen = sizeof(ulClass);
      rcCount++;

      attrib[rcCount] = attribId[0]; /* copy struct */
      rcCount++;

      /* Find private key; no duplicates allowed for ecdsa */
      if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 1)) {
         LUNACA3err(LUNACA3_F_FIND_ECDSA, LUNACA3_R_EFINDKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_object_ex1");
         goto done;
      }
   }

   /* on success, set 'rethandle' */
   rethandle = tmphandle;

done:
   /* undo luna_attribute_malloc */
   luna_attribute_free(attribId);

   /* undo i2d_ECParameters */
   if (bufP != NULL) {
      OPENSSL_free(bufP);
   }

   /* undo i2o_ECPublicKey */
   if (bufQ1 != NULL) {
      OPENSSL_free(bufQ1);
   }
   if (bufQ2 != NULL) {
      OPENSSL_free(bufQ2);
   }

   return rethandle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_find_ecdsa_handle_FAST"

/* Find ECDSA key handle by cache or regular find operation */
static CK_OBJECT_HANDLE luna_find_ecdsa_handle_FAST(luna_context_t *ctx, EC_KEY *ecdsa, int bPrivate) {
   CK_OBJECT_HANDLE handle = LUNA_INVALID_HANDLE;
   void *ecdsa_ex = NULL;
   unsigned per_slot_id = ctx->per_slot_id;

   if (bPrivate) {
      ecdsa_ex = (g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_priv == -1)
                     ? NULL
                     : LUNA_EC_KEY_get_ex_data(ecdsa, g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_priv);
      if (ecdsa_ex != NULL) {
         handle = (CK_OBJECT_HANDLE)((size_t)ecdsa_ex); /* Cache hit */
      } else {
         handle = luna_find_ecdsa_handle(ctx, ecdsa, bPrivate); /* Cache miss */
         if ((g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_priv != -1) && (handle != LUNA_INVALID_HANDLE)) {
            LUNA_EC_KEY_set_ex_data(ecdsa, g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_priv, (void *)((size_t)handle));
         }
      }
   } else {
      ecdsa_ex = (g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_pub == -1)
                     ? NULL
                     : LUNA_EC_KEY_get_ex_data(ecdsa, g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_pub);
      if (ecdsa_ex != NULL) {
         handle = (CK_OBJECT_HANDLE)((size_t)ecdsa_ex); /* Cache hit */
      } else {
         handle = luna_find_ecdsa_handle(ctx, ecdsa, bPrivate); /* Cache miss */
         if ((g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_pub != -1) && (handle != LUNA_INVALID_HANDLE)) {
            LUNA_EC_KEY_set_ex_data(ecdsa, g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_pub, (void *)((size_t)handle));
         }
      }
   }

   return handle;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_cache_ecdsa_handle"

static void luna_cache_ecdsa_handle(luna_context_t *ctx, EC_KEY *keyout,
        CK_OBJECT_HANDLE hPublic, CK_OBJECT_HANDLE hPrivate)
{
    unsigned per_slot_id = ctx->per_slot_id;

    int extension_id = g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_pub;
    if ( (extension_id != -1) && (hPublic != LUNA_INVALID_HANDLE) ) {
        LUNA_EC_KEY_set_ex_data(keyout, extension_id, (void *)(size_t)hPublic);
    }

    extension_id = g_luna_per_slot[per_slot_id].g_luna_ecdsa_ex_priv;
    if ((extension_id != -1) && (hPrivate != LUNA_INVALID_HANDLE) ) {
        LUNA_EC_KEY_set_ex_data(keyout, extension_id, (void *)(size_t)hPrivate);
    }
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_do_sign"

#define LUNA_EC_KEY_MAX_SIGRET (512 * 2)

/* ECDSA do_sign */
static ECDSA_SIG *luna_ecdsa_do_sign(const unsigned char *dgst, int dlen, const BIGNUM *inv, const BIGNUM *rp,
                                     EC_KEY *dsa) {
   ECDSA_SIG *sig = NULL;

   CK_RV rv = CKR_OK;
   CK_ULONG siglen = 0;
   CK_ULONG rlen = 0;
   CK_ULONG slen = 0;
   CK_OBJECT_HANDLE priv_handle = LUNA_INVALID_HANDLE;
   const EC_GROUP *group = NULL;
   size_t field_len = 0;

   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   CK_MECHANISM mech;
   CK_BYTE sigret[LUNA_EC_KEY_MAX_SIGRET];
   char itoabuf[LUNA_ATOI_BYTES];

   memset(&mech, 0, sizeof(mech));
   memset(sigret, 0, sizeof(sigret));
   memset(itoabuf, 0, sizeof(itoabuf));

   /* Check ecdsa */
   switch (luna_ecdsa_check_private(dsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         if (saved_ecdsa_do_sign != NULL) {
            return saved_ecdsa_do_sign(dgst, dlen, inv, rp, dsa);
         }
      /* fall through */
      default: /* error */
         LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ecdsa_check");
         goto err;
   }

   if ((group = EC_KEY_get0_group(dsa)) == NULL)
      goto err;
   if (!(field_len = LUNA_EC_GROUP_get_field_len(group)))
      goto err;
   rlen = slen = (CK_ULONG)field_len;
   if ((rlen + slen) > sizeof(sigret)) {
      LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EINKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": keysize too big (avoiding buffer overflow)");
      goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   /* Find private key */
   if ((priv_handle = luna_find_ecdsa_handle_FAST(&ctx, dsa, LUNA_PRIVATE)) == LUNA_INVALID_HANDLE) {
      LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_ecdsa_handle");
      goto err;
   }

   /* Sign init */
   mech.mechanism = CKM_ECDSA;
   mech.pParameter = NULL_PTR;
   mech.ulParameterLen = 0;
   rv = p11.std->C_SignInit(ctx.hSession, &mech, priv_handle);
   if (rv != CKR_OK) {
      LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_SignInit(ECDSA)=0x", luna_itoa(itoabuf, rv));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_SignInit(ECDSA)", rv);
      goto err;
   }

   /* Sign */
   IF_LUNA_DEBUG(luna_dumpdata("ecdsa_sign in: ", dgst, dlen));
   /* NOTE: signature larger than field size; e.g., "OID_secp224k1". */
   siglen = sizeof(sigret);
   /* NOTE: dlen larger than the field size; e.g., "OID_sect113r1". */
   rv = p11.std->C_Sign(ctx.hSession, (CK_BYTE_PTR)dgst, (CK_ULONG)((CK_ULONG)dlen > rlen ? rlen : dlen), sigret,
                        &siglen);
   if ((rv == CKR_OK) && (siglen >= 20)) {
      /* NOTE: siglen != (2 x field size); e.g., "OID_X9_62_c2tnb431r1". */
      rlen = (siglen >> 1);
      slen = (siglen - rlen);
   } else {
      LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Sign(ECDSA)=0x", luna_itoa(itoabuf, rv));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Sign(ECDSA)", rv);
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("ecdsa_sign out: ", sigret, siglen));

   if ((sig = ECDSA_SIG_new()) == NULL) {
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": ECDSA_SIG_new");
      goto err;
   }

   if ( !LUNA_EC_KEY_SIG_SET_r_s( sig, BN_bin2bn((sigret + 0), rlen, NULL), BN_bin2bn((sigret + rlen), slen, NULL)) )
      goto err;

   /* Close context */
   luna_close_context(&ctx);
   return sig;

err:
   luna_close_context_w_err(&ctx, -1, rv);
   return NULL;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_sign_setup"

/* ECDSA sign setup */
static int luna_ecdsa_sign_setup(EC_KEY *dsa, BN_CTX *bnctx, BIGNUM **kinv, BIGNUM **r) {
   /* Check ecdsa */
   switch (luna_ecdsa_check_private(dsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         if (saved_ecdsa_sign_setup != NULL) {
            return saved_ecdsa_sign_setup(dsa, bnctx, kinv, r);
         }
      /* fall through */
      default: /* error */
         LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ecdsa_check");
         return 0;
   }

   return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_do_verify"

/* ECDSA do_verify */
static int luna_ecdsa_do_verify(const unsigned char *dgst, int dlen, const ECDSA_SIG *sig, EC_KEY *dsa) {
   CK_RV rv = CKR_OK;
   CK_ULONG rlen = 0;
   CK_ULONG slen = 0;
   CK_ULONG len1 = 0;
   CK_ULONG len2 = 0;
   CK_OBJECT_HANDLE pub_handle = LUNA_INVALID_HANDLE;
   const EC_GROUP *group = NULL;
   size_t field_len = 0;

   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   CK_MECHANISM mech;
   CK_BYTE sigret[LUNA_EC_KEY_MAX_SIGRET];
   char itoabuf[LUNA_ATOI_BYTES];

   memset(&mech, 0, sizeof(mech));
   memset(sigret, 0, sizeof(sigret));
   memset(itoabuf, 0, sizeof(itoabuf));

   /* Check ecdsa */
   switch (luna_ecdsa_check_public(dsa)) {
      case 0: /* hardware */
         if (g_postconfig.DisablePublicCrypto == 0)
            break; /* plan A */
                   /* plan B -- fall through */
      case 1:      /* software */
         if (saved_ecdsa_do_verify != NULL) {
            return saved_ecdsa_do_verify(dgst, dlen, sig, dsa);
         }
      /* fall through */
      default: /* error */
         LUNACA3err(LUNACA3_F_ECDSA_VERIFY, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ecdsa_check");
         goto err;
   }

   if ((group = EC_KEY_get0_group(dsa)) == NULL)
      goto err;
   if (!(field_len = LUNA_EC_GROUP_get_field_len(group)))
      goto err;
   rlen = slen = (CK_ULONG)field_len;
   if ((rlen + slen) > sizeof(sigret)) {
      LUNACA3err(LUNACA3_F_ECDSA_SIGN, LUNACA3_R_EINKEY);
      ERR_add_error_data(2, "(rlen + slen)=0x", luna_itoa(itoabuf, (rlen + slen)));
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": signature too big");
      goto err;
   }

   /* Open context */
   if (luna_open_context(&ctx) == 0)
      goto err;

   /* Find public key */
   if ((pub_handle = luna_find_ecdsa_handle_FAST(&ctx, dsa, LUNA_PUBLIC)) == LUNA_INVALID_HANDLE) {
      /* if public key handle not found then perform this public operation in software  */
      luna_close_context(&ctx); /* likely */
      if (saved_ecdsa_do_verify != NULL) {
         return saved_ecdsa_do_verify(dgst, dlen, sig, dsa);
      }

      LUNACA3err(LUNACA3_F_ECDSA_VERIFY, LUNACA3_R_EFINDKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_find_ecdsa_handle");
      goto err;
   }

   /* Verify init */
   mech.mechanism = CKM_ECDSA;
   mech.pParameter = NULL_PTR;
   mech.ulParameterLen = 0;
   rv = p11.std->C_VerifyInit(ctx.hSession, &mech, pub_handle);
   if (rv != CKR_OK) {
      LUNACA3err(LUNACA3_F_ECDSA_VERIFY, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_VerifyInit(ECDSA)=0x", luna_itoa(itoabuf, rv));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_VerifyInit(ECDSA)", rv);
      goto err;
   }

   /* Verify */
   len1 = BN_num_bytes(LUNA_EC_KEY_SIG_GET_r(sig));
   len2 = BN_num_bytes(LUNA_EC_KEY_SIG_GET_s(sig));
   if ((len1 + len2) > (rlen + slen)) {
      LUNACA3err(LUNACA3_F_ECDSA_VERIFY, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": lengths do not match");
      goto err;
   }
   IF_LUNA_DEBUG(luna_dumpdata("ecdsa_verify in: ", dgst, dlen));
   BN_bn2bin(LUNA_EC_KEY_SIG_GET_r(sig), (&(sigret[rlen - len1])));          /* NOTE: pad if necessary */
   BN_bn2bin(LUNA_EC_KEY_SIG_GET_s(sig), (&(sigret[rlen + (slen - len2)]))); /* NOTE: pad if necessary */
                                                         /* NOTE: truncate dlen to the appropriate number of bits */
   rv = p11.std->C_Verify(ctx.hSession, (CK_BYTE_PTR)dgst, (CK_ULONG)((CK_ULONG)dlen > rlen ? rlen : dlen), sigret,
                          (rlen + slen));
   if (rv != CKR_OK) {
      LUNACA3err(LUNACA3_F_ECDSA_VERIFY, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Verify(ECDSA)=0x", luna_itoa(itoabuf, rv));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_Verify(ECDSA)", rv);
      IF_LUNA_DEBUG(luna_dumpdata("ecdsa_verify err: ", sigret, (rlen + slen)));
      goto err;
   }

   IF_LUNA_DEBUG(luna_dumpdata("ecdsa_verify out: ", sigret, (rlen + slen)));

   /* Close context */
   luna_close_context(&ctx);
   return 1;

err:
   luna_close_context_w_err(&ctx, -1, rv);
   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_sign"

/* ECDSA sign (introduced by OpenSSL 1.1) is a wrapper function for do_sign */
/* FIXME: type is unused!? */
static int luna_ecdsa_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sigbuf, unsigned int *siglen, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *dsa) {
   ECDSA_SIG *sig = NULL;
   /* NOTE: no need to call saved_ecdsa_sign (for sw keys) since luna_ecdsa_do_sign handles both sw/hw */
   sig = luna_ecdsa_do_sign(dgst, dlen, inv, rp, dsa);
   if (sig == NULL)
      return 0;
   *siglen = i2d_ECDSA_SIG(sig, (sigbuf == NULL ? NULL : &sigbuf) );
   ECDSA_SIG_free(sig);
   return 1;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_verify"

/* ECDSA verify (introduced by OpenSSL 1.1) is a wrapper function for do_verify */
/* FIXME: type is unused!? */
static int luna_ecdsa_verify(int type, const unsigned char *dgst, int dlen, const unsigned char *sigbuf, int siglen, EC_KEY *dsa) {
   ECDSA_SIG *s = NULL;
   const unsigned char *p = sigbuf;
   unsigned char *der = NULL;
   int derlen;
   int ret = -1;
   s = ECDSA_SIG_new();
   if (s == NULL)
      return ret;
   if (d2i_ECDSA_SIG(&s, &p, siglen) == NULL)
      goto err;
   derlen = i2d_ECDSA_SIG(s, &der);
   if (derlen != siglen || memcmp(sigbuf, der, derlen) != 0)
      goto err;
   /* NOTE: no need to call saved_ecdsa_verify (for sw keys) since luna_ecdsa_do_verify handles both sw/hw */
   ret = luna_ecdsa_do_verify(dgst, dlen, s, dsa);
err:
   if (der != NULL) {
       OPENSSL_free(der);
   }
   if (s != NULL) {
       ECDSA_SIG_free(s);
   }
   return ret;
}

#endif /* LUNA_OSSL_ECDSA */

/* prompt for passphrase (no echo) */
static int luna_gets_passphrase(const char *szslotid, char *secretString, unsigned maxlen) {
   char *secretString0 = secretString;
   unsigned ii = 0;
   unsigned len = 0; /* running total length of string */
   char c = 0;       /* character read in from user */
#ifdef LUNA_OSSL_WINDOWS
   DWORD mode = 0;
#endif
   char *rcptr = NULL;
   int pflaglabel = 0;

   if (szslotid == NULL)
      return -1; /* likely */

   rcptr = luna_parse_slotid2(szslotid, &pflaglabel);
   if (rcptr == NULL) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_parse_slotid");
      return -1;
   }

   fflush(stderr);
   if (pflaglabel) {
      fprintf(stdout, "HSM Label is \"%s\". \n", (char *)rcptr);
   } else {
      fprintf(stdout, "HSM Slot Number is %s. \n", (char *)rcptr);
   }
   /* Enter HSM Password */
   if (luna_get_userType() == CKU_LIMITED_USER) {
      fprintf(stdout, "Enter Crypto-User Password: ");
   } else {
      fprintf(stdout, "Enter Crypto-Officer Password: ");
   }
   fflush(stdout);

   OPENSSL_free(rcptr);

#ifdef LUNA_OSSL_WINDOWS
   /* This console mode stuff only applies to windows. */
   if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) {
      if (SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode & (!ENABLE_ECHO_INPUT))) {
         while (c != '\r') {
            /* wait for a character to be hit */
            while (!_kbhit()) {
               luna_sleep_milli(100);
            }
            /* get it */
            c = _getch();

            /* check for carriage return */
            if (c != '\r') {
               /* check for backspace */
               if (c != '\b') {
                  /* neither CR nor BS -- add it to the password string */
                  printf("*");
                  *secretString++ = c;
                  len++;
               } else {
                  /* handle backspace -- delete the last character & erase it from the screen */
                  if (len > 0) {
                     secretString--;
                     len--;
                     printf("\b \b");
                  }
               }
            }
         }
         /* Add the zero-termination */
         (*secretString) = '\0';

         SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
      }
   }

#else  /* LUNA_OSSL_WINDOWS */

   {
      struct termios tio;
      int fd;
      int rc;
      cc_t old_min, old_time;
      char termbuff[200];

      fd = open(ctermid(termbuff), O_RDONLY);
      if (fd == -1) {
         return -2;
      }

      rc = tcgetattr(fd, &tio);
      if (rc == -1) {
         close(fd);
         return -3;
      }

      /* turn off canonical mode & echo */
      old_min = tio.c_cc[VMIN];
      old_time = tio.c_cc[VTIME];
      tio.c_lflag = tio.c_lflag & ~ICANON & ~ECHO;
      tio.c_cc[VMIN] = 1;
      tio.c_cc[VTIME] = 0;

      rc = tcsetattr(fd, TCSADRAIN, &tio);
      if (rc == -1) {
         close(fd);
         return -4;
      }

      /* continue to loop until we get the 'enter' */
      while (c != '\n') {
         /* read in the next char */
         rc = read(fd, &c, 1);
         if (rc != 0) {
            if (c != '\n') {
               /* check for backspace ( and ASCII 127 which is BS in linux) */
               if ((c != '\b') && ((int)c != 127)) {
                  /* neither CR nor BS -- add it to the password string */
                  fprintf(stdout, "*");
                  fflush(stdout);
                  *secretString++ = c;
                  len++;
               } else {
                  /* handle backspace -- delete the last character & erase it from the screen */
                  if (len > 0) {
                     secretString--;
                     len--;
                     fprintf(stdout, "\b \b");
                     fflush(stdout);
                  }
               }
            }
         } else {
            /* we're having problems getting the character */
            close(fd);
            return -5;
         }
      } /* while */

      *secretString++ = '\0';

      /* return terminal to its original state */
      tio.c_lflag = tio.c_lflag | ICANON | ECHO;
      tio.c_cc[VMIN] = old_min;
      tio.c_cc[VTIME] = old_time;

      rc = tcsetattr(fd, TCSADRAIN, &tio);
      if (rc == -1) {
         close(fd);
         return -6;
      }

      close(fd);
   }
#endif /* LUNA_OSSL_WINDOWS */

   /* obscure password length */
   for (ii = len; ii < maxlen; ii++) {
      fprintf(stdout, "*");
   }
   fprintf(stdout, "\n");
   fflush(stdout);

   /* if we didn't get a string, return false */
   if ((len > maxlen) || (len < 4) || (len != strlen(secretString0))) {
      return -8;
   }

   return len;
}

/* replace one item in table of CK_ATTRIBUTE (do not malloc) */
static void luna_ckatab_replace(CK_ATTRIBUTE *tab, CK_ULONG tabsize, CK_ATTRIBUTE_TYPE type,
                                CK_BYTE_PTR pValue, /* can be null */
                                CK_ULONG ulValueLen) {
   CK_ULONG ii = 0;

   if (ulValueLen < 1)
      goto err;

   for (ii = 0; ii < tabsize; ii++) {
      if (tab[ii].type == type) {
         tab[ii].pValue = pValue;
         tab[ii].ulValueLen = ulValueLen;
         return;
      }
   }

err:
   LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
   ERR_add_error_data(1, "BUG: luna_ckatab_replace");
   LUNA_ERRORLOG(LUNA_FUNC_NAME ": BUG: luna_ckatab_replace");
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_keygen"

/* generate rsa key in hardware */
static int luna_rsa_keygen_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb,
        int flagSessionObject) {
   CK_RV retCode = CKR_OK;
   CK_ULONG ulTemp = 0;
   CK_ULONG ulModBits = bits;
   EVP_PKEY *pkey = NULL;
   /*CK_BBOOL bFalse = 0;*/
   CK_BBOOL bTrue = CK_TRUE;
   CK_BBOOL bModifiable = CK_TRUE;
   CK_BBOOL bExtractable = CK_TRUE;
   CK_BBOOL bTokenObject = (flagSessionObject ? CK_FALSE : CK_TRUE);

   CK_OBJECT_HANDLE priv_handle = LUNA_INVALID_HANDLE;
   CK_OBJECT_HANDLE pub_handle = LUNA_INVALID_HANDLE;

   CK_MECHANISM rsa_key_gen_mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   CK_ATTRIBUTE pub_template[] = {
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_ENCRYPT, 0, 0},
       {CKA_VERIFY, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_MODULUS_BITS, 0, 0},
       {CKA_PUBLIC_EXPONENT, 0, 0},
       {CKA_LABEL, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_ATTRIBUTE pub_template_pa[] = {
       {CKA_CLASS, 0, 0}, {CKA_KEY_TYPE, 0, 0}, {CKA_MODULUS_BITS, 0, 0}, {CKA_LABEL, 0, 0},
   };

   CK_ATTRIBUTE priv_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_SENSITIVE, 0, 0},
       {CKA_DECRYPT, 0, 0},
       {CKA_SIGN, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_EXTRACTABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_ATTRIBUTE priv_template_pa[] = {
       {CKA_CLASS, 0, 0}, {CKA_LABEL, 0, 0}, {CKA_PRIVATE, 0, 0}, {CKA_SENSITIVE, 0, 0}, {CKA_DECRYPT, 0, 0}};

   CK_BYTE bufTemp[512];
   CK_BYTE bufId[20];
   char bufLabelPublic[80 + 1];
   char bufLabelPrivate[80 + 1];

   char itoabuf[LUNA_ATOI_BYTES];

   int pubTemplateSize;
   int privTemplateSize;

   CK_ATTRIBUTE_PTR pubTemplatePtr;
   CK_ATTRIBUTE_PTR privTemplatePtr;

   int testrc;

   memset(itoabuf, 0, sizeof(itoabuf));
   memset(bufLabelPublic, 0, sizeof(bufLabelPublic));
   memset(bufLabelPrivate, 0, sizeof(bufLabelPrivate));

   /* check bare minimum rsa key size (1024) */
   if (ulModBits < LUNA_RSA_KEYSIZE_MIN) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
      goto err;
   }

   /* generate random bytes which serve as CKA_ID, CKA_LABEL */
   if (luna_RAND_bytes(bufTemp, sizeof(bufTemp)) != 1) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
      goto err;
   }

   if (luna_SHA1(bufTemp, sizeof(bufTemp), bufId) != 1) {
      goto err;
   }

   if (luna_pa_check_lib()) {
      luna_strncpy(bufLabelPublic, "rsa-", sizeof(bufLabelPublic));
      (void)luna_sprintf_hex(&bufLabelPublic[4], bufId, sizeof(bufId));
      luna_strncpy(bufLabelPrivate, "rsa-", sizeof(bufLabelPrivate));
      (void)luna_sprintf_hex(&bufLabelPrivate[4], bufId, sizeof(bufId));
   } else {
      luna_strncpy(bufLabelPublic, "rsa-public-", sizeof(bufLabelPublic));
      (void)luna_sprintf_hex(&bufLabelPublic[11], bufId, sizeof(bufId));
      luna_strncpy(bufLabelPrivate, "rsa-private-", sizeof(bufLabelPrivate));
      (void)luna_sprintf_hex(&bufLabelPrivate[12], bufId, sizeof(bufId));
   }

   /* set exponent */
   if (((ulTemp = BN_num_bytes(e)) > sizeof(bufTemp)) || ((ulTemp = BN_bn2bin(e, bufTemp)) > sizeof(bufTemp))) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(2, "BN_num_bytes", luna_itoa(itoabuf, ulTemp));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": BN_num_bytes", ulTemp);
      goto err;
   }

   pubTemplateSize = 0;
   privTemplateSize = 0;
   pubTemplatePtr = NULL;
   privTemplatePtr = NULL;
   if (luna_pa_check_lib()) {
      CK_OBJECT_CLASS rsapubkeyclass = CKO_PUBLIC_KEY;
      CK_OBJECT_CLASS rsaprivkeyclass = CKO_PRIVATE_KEY;
      CK_KEY_TYPE rsakeytype = CKK_RSA;

      pubTemplateSize = LUNA_DIM(pub_template_pa);
      privTemplateSize = LUNA_DIM(priv_template_pa);
      pubTemplatePtr = pub_template_pa;
      privTemplatePtr = priv_template_pa;

      /* fill template (pub) */
      luna_ckatab_replace(pub_template_pa, LUNA_DIM(pub_template_pa), CKA_CLASS, (CK_BYTE_PTR)&rsapubkeyclass,
                          sizeof(rsapubkeyclass));
      luna_ckatab_replace(pub_template_pa, LUNA_DIM(pub_template_pa), CKA_KEY_TYPE, (CK_BYTE_PTR)&rsakeytype,
                          sizeof(rsakeytype));
      luna_ckatab_replace(pub_template_pa, LUNA_DIM(pub_template_pa), CKA_MODULUS_BITS, (CK_BYTE_PTR)&ulModBits,
                          sizeof(ulModBits));
      luna_ckatab_replace(pub_template_pa, LUNA_DIM(pub_template_pa), CKA_LABEL, (CK_BYTE_PTR)bufLabelPublic,
                          (CK_ULONG)strlen(bufLabelPublic));

      /* fill template (priv) */
      luna_ckatab_replace(priv_template_pa, LUNA_DIM(priv_template_pa), CKA_CLASS, (CK_BYTE_PTR)&rsaprivkeyclass,
                          sizeof(rsaprivkeyclass));
      luna_ckatab_replace(priv_template_pa, LUNA_DIM(priv_template_pa), CKA_LABEL, (CK_BYTE_PTR)bufLabelPrivate,
                          (CK_ULONG)strlen(bufLabelPrivate));
      luna_ckatab_replace(priv_template_pa, LUNA_DIM(priv_template_pa), CKA_PRIVATE, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(priv_template_pa, LUNA_DIM(priv_template_pa), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(priv_template_pa, LUNA_DIM(priv_template_pa), CKA_DECRYPT, &bTrue, sizeof(bTrue));
   } else {
      pubTemplateSize = LUNA_DIM(pub_template);
      privTemplateSize = LUNA_DIM(priv_template);
      pubTemplatePtr = pub_template;
      privTemplatePtr = priv_template;

      /* fill template (pub) */
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_TOKEN, &bTokenObject, sizeof(bTrue));
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_PRIVATE, &bTrue,
                          sizeof(bTrue)); /* private=1 for access control */
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_ENCRYPT, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_MODULUS_BITS, (CK_BYTE_PTR)&ulModBits,
                          sizeof(ulModBits));
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)bufTemp, ulTemp);
      luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_LABEL, (CK_BYTE_PTR)bufLabelPublic,
                          (CK_ULONG)strlen(bufLabelPublic));

      /* fill template (priv) */
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_LABEL, (CK_BYTE_PTR)bufLabelPrivate,
                          (CK_ULONG)strlen(bufLabelPrivate));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_TOKEN, &bTokenObject, sizeof(bTrue));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_DECRYPT, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_EXTRACTABLE, &bExtractable, sizeof(bExtractable));
      luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_ID, bufId, sizeof(bufId));
   }

   /* Always generate keys on the primary HSM; otherwise, we may lose track of keys. */
   if (luna_open_context_ndx(&ctx, 0) == 0) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_open_context");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_open_context");
      goto err;
   }

   /* Pre-test uniqueness of key */
   if (luna_ckatab_pre_keygen(ctx.hSession, privTemplatePtr, privTemplateSize)) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_ckatab_pre_keygen");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ckatab_pre_keygen");
      goto err;
   }

   /* C_GenerateKeyPair */
   retCode = p11.std->C_GenerateKeyPair(ctx.hSession, &rsa_key_gen_mech, pubTemplatePtr, pubTemplateSize,
                                        privTemplatePtr, privTemplateSize, &pub_handle, &priv_handle);

   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_GenerateKeyPair=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_GenerateKeyPair", retCode);
      goto err;
   }

   if (luna_pa_check_lib()) {
      pkey = luna_load_rsa(NULL, &ctx, pub_handle, CKO_PRIVATE_KEY, 0); /* TODO: verify this inconsistency */
   } else {
      pkey = luna_load_rsa(NULL, &ctx, priv_handle, CKO_PRIVATE_KEY, 0);
   }

   if (pkey == NULL) {
      LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_load_rsa");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_load_rsa");
      goto err;
   }

   /* copy pkey to rsa (safely) and delete pkey */
   {
      if (LUNA_RSA_copy_from_pkey(rsa, pkey) <= 0) {
         LUNACA3err(LUNACA3_F_RSA_KEYGEN, LUNACA3_R_EENGINE);
         ERR_add_error_data(1, "LUNA_RSA_copy_from_pkey");
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_RSA_copy_from_pkey");
         goto err;
      }

      if (luna_pa_check_lib()) {
         char tmpLabel[80 + 1] = "";

         /* cp the key label into p so future uses of the key
         allow a label rather than a lookup based upon
         modulus and public exponent which are not possible in KeSecure
         at this time */
         BN_free(LUNA_RSA_GET_p(rsa));
         if (!LUNA_RSA_SET_p_q(rsa, BN_bin2bn((unsigned char *)bufLabelPublic, (int)strlen(bufLabelPrivate), NULL), NULL)) {
            printf("Got BN_bin2bn error\n");
         }
         testrc = 0;
         testrc = BN_bn2bin(LUNA_RSA_GET_p(rsa), (unsigned char *)tmpLabel);
         if (0 == testrc) {
            printf("Got BN_bn2bin error\n");
         }
      }
   }

   if (pkey)
      EVP_PKEY_free(pkey);
   luna_close_context(&ctx);
   return 1;

err:
   if (pkey)
      EVP_PKEY_free(pkey);
   luna_close_context_w_err(&ctx, -1, retCode);
   return 0;
}

static int luna_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb) {
   int flagSessionObject = luna_get_token_object() ? 0 : 1;
   int rc = luna_rsa_keygen_ex(rsa, bits, e, cb, flagSessionObject);
   return rc;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_label_to_slotid"

/* search for token with label and return slot id; return 1 on success */
static int luna_label_to_slotid(const char *tokenlabel, CK_SLOT_ID *pslotid) {
   size_t slen = 0;
   CK_RV rv = CKR_OK;
   CK_ULONG ii = 0;
   CK_ULONG jj = 0;
   CK_ULONG kk = 0;
   CK_ULONG ulCount = 0;
   CK_ULONG ulCount2 = 0;
   CK_SLOT_ID *tab = NULL;

   CK_TOKEN_INFO infot;
   CK_BYTE norm1[LUNA_MAX_LABEL + 8];
   CK_BYTE norm2[LUNA_MAX_LABEL + 8];

   memset(&infot, 0, sizeof(infot));
   memset(norm1, 0, sizeof(norm1));
   memset(norm2, 0, sizeof(norm2));

   if ((slen = strlen(tokenlabel)) > LUNA_MAX_LABEL)
      goto err;
   if (slen < 1)
      goto err;

   rv = p11.std->C_GetSlotList(TRUE, NULL, &ulCount);
   if ((rv != CKR_OK) || (ulCount < 1))
      goto err;

   tab = (CK_SLOT_ID *)LUNA_malloc(sizeof(CK_SLOT_ID) * ulCount);
   if (tab == NULL)
      goto err;

   ulCount2 = ulCount;
   rv = p11.std->C_GetSlotList(TRUE, tab, &ulCount2);
   if ((rv != CKR_OK) || (ulCount2 != ulCount))
      goto err;

   memset(norm1, ' ', LUNA_MAX_LABEL);
   memcpy(norm1, tokenlabel, slen);
   norm1[LUNA_MAX_LABEL] = '\"';
   norm1[LUNA_MAX_LABEL + 1] = 0;
   for (ii = 0; ii < ulCount; ii++) {
      memset(&infot, 0, sizeof(infot));
      rv = p11.std->C_GetTokenInfo(tab[ii], &infot);
      if (rv != CKR_OK)
         goto err;

      memset(norm2, ' ', LUNA_MAX_LABEL);
      memcpy(norm2, infot.label, LUNA_MAX_LABEL);
      norm2[LUNA_MAX_LABEL] = '\"';
      norm2[LUNA_MAX_LABEL + 1] = 0;
      /* enforce label padded with space (not '\0') */
      for (jj = 0, kk = 0; jj < LUNA_MAX_LABEL; jj++) {
         if (kk || (norm2[jj] == '\0')) {
            kk = 1;
            norm2[jj] = ' ';
         }
      }

      if (memcmp(norm1, norm2, LUNA_MAX_LABEL) == 0) {
         (*pslotid) = tab[ii];
         LUNA_free(tab);
         return 1;
      }
   }

err:
   LUNA_free(tab);

   LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
   ERR_add_error_data(2, "token not found \"", norm1);
   LUNA_ERRORLOG(LUNA_FUNC_NAME ": token not found");

   (*pslotid) = 0;
   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_dsa_keygen"

/* generate dsa key in hardware */
static int luna_dsa_keygen_ex(DSA *dsa, int flagSessionObject) {
   CK_RV retCode = CKR_OK;
   EVP_PKEY *pkey = NULL;
   /*CK_BBOOL bFalse = 0;*/
   CK_BBOOL bTrue = CK_TRUE;
   CK_BBOOL bModifiable = CK_TRUE;
   CK_BBOOL bExtractable = CK_TRUE;
   CK_BBOOL bTokenObject = (flagSessionObject ? CK_FALSE : CK_TRUE);

   CK_OBJECT_HANDLE priv_handle = LUNA_INVALID_HANDLE;
   CK_OBJECT_HANDLE pub_handle = LUNA_INVALID_HANDLE;

   CK_BYTE_PTR bufP = NULL;
   CK_BYTE_PTR bufQ = NULL;
   CK_BYTE_PTR bufG = NULL;
   CK_ULONG lenbufP = 0;
   CK_ULONG lenbufQ = 0;
   CK_ULONG lenbufG = 0;

   CK_MECHANISM dsa_key_gen_mech = {CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0};

   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   CK_ATTRIBUTE pub_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_PRIME, 0, 0},
       {CKA_SUBPRIME, 0, 0},
       {CKA_BASE, 0, 0},
       {CKA_VERIFY, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_ATTRIBUTE priv_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_SENSITIVE, 0, 0},
       {CKA_SIGN, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_EXTRACTABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_BYTE bufTemp[512];
   CK_BYTE bufId[20];
   char bufLabelPublic[80 + 1];
   char bufLabelPrivate[80 + 1];

   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   memset(bufLabelPublic, 0, sizeof(bufLabelPublic));
   memset(bufLabelPrivate, 0, sizeof(bufLabelPrivate));

   /* check dsa */
   if (dsa == NULL) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "(dsa == NULL)");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": (dsa == NULL)");
      goto err;
   }

   /* generate random bytes which serve as CKA_ID, CKA_LABEL */
   if (luna_RAND_bytes(bufTemp, sizeof(bufTemp)) != 1) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      goto err;
   }

   if (luna_SHA1(bufTemp, sizeof(bufTemp), bufId) != 1) {
      goto err;
   }

   luna_strncpy(bufLabelPublic, "dsa-public-", sizeof(bufLabelPublic));
   (void)luna_sprintf_hex(&bufLabelPublic[11], bufId, sizeof(bufId));
   luna_strncpy(bufLabelPrivate, "dsa-private-", sizeof(bufLabelPrivate));
   (void)luna_sprintf_hex(&bufLabelPrivate[12], bufId, sizeof(bufId));

   /* NOTE: the input parameters including keysize are mandatory */

   /* if any of {p,q,g} is NULL then fail */
   if ((!LUNA_DSA_GET_p(dsa)) || (!LUNA_DSA_GET_q(dsa)) || (!LUNA_DSA_GET_g(dsa))) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "(! p) || (! q) || (! g)");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": (! p) || (! q) || (! g)");
      goto err;
   }

   bufP = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_p(dsa)));
   lenbufP = BN_bn2bin(LUNA_DSA_GET_p(dsa), bufP);
   bufQ = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_q(dsa)));
   lenbufQ = BN_bn2bin(LUNA_DSA_GET_q(dsa), bufQ);
   bufG = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(LUNA_DSA_GET_g(dsa)));
   lenbufG = BN_bn2bin(LUNA_DSA_GET_g(dsa), bufG);
   if (!bufP || !bufQ || !bufG) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      goto err;
   }

   /* check bare minimum dsa key size (1024) */
   if ( (lenbufP < (LUNA_DSA_KEYSIZE_MIN / 8))
           || (lenbufQ < (LUNA_DSA_QBITS_MIN / 8))
           || (lenbufG < (LUNA_DSA_KEYSIZE_MIN / 8)) ) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      goto err;
   }

   /* fill template (pub) */
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_LABEL, (CK_BYTE_PTR)bufLabelPublic,
                       (CK_ULONG)strlen(bufLabelPublic));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_TOKEN, &bTokenObject, sizeof(bTrue));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_PRIVATE, &bTrue,
                       sizeof(bTrue)); /* private=1 for access control */
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_PRIME, bufP, lenbufP);
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_SUBPRIME, bufQ, lenbufQ);
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_BASE, bufG, lenbufG);
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_ID, bufId, sizeof(bufId));

   /* fill template (priv) */
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_LABEL, (CK_BYTE_PTR)bufLabelPrivate,
                       (CK_ULONG)strlen(bufLabelPrivate));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_TOKEN, &bTokenObject, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_EXTRACTABLE, &bExtractable, sizeof(bExtractable));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_ID, bufId, sizeof(bufId));

   /* Always generate keys on the primary HSM; otherwise, we may lose track of keys. */
   if (luna_open_context_ndx(&ctx, 0) == 0) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_open_context");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_open_context");
      goto err;
   }

   /* Pre-test uniqueness of key */
   if (luna_ckatab_pre_keygen(ctx.hSession, priv_template, LUNA_DIM(priv_template))) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_ckatab_pre_keygen");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ckatab_pre_keygen");
      goto err;
   }

   /* C_GenerateKeyPair */
   retCode = p11.std->C_GenerateKeyPair(ctx.hSession, &dsa_key_gen_mech, pub_template, LUNA_DIM(pub_template),
                                        priv_template, LUNA_DIM(priv_template), &pub_handle, &priv_handle);

   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_GenerateKeyPair=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_GenerateKeyPair", retCode);
      goto err;
   }

   pkey = luna_load_dsa(NULL, &ctx, pub_handle, CKO_PUBLIC_KEY, 0);
   if (pkey == NULL) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_load_dsa");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_load_dsa");
      goto err;
   }

   /* copy pkey to dsa (safely) and delete pkey */
   if (LUNA_DSA_copy_from_pkey(dsa, pkey) <= 0) {
      LUNACA3err(LUNACA3_F_DSA_KEYGEN, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "LUNA_DSA_copy_from_pkey");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_DSA_copy_from_pkey");
      goto err;
   }

   if (bufP)
      OPENSSL_free(bufP);
   if (bufQ)
      OPENSSL_free(bufQ);
   if (bufG)
      OPENSSL_free(bufG);
   if (pkey)
      EVP_PKEY_free(pkey);
   luna_close_context(&ctx);
   return 1;

err:
   if (bufP)
      OPENSSL_free(bufP);
   if (bufQ)
      OPENSSL_free(bufQ);
   if (bufG)
      OPENSSL_free(bufG);
   if (pkey)
      EVP_PKEY_free(pkey);
   luna_close_context_w_err(&ctx, -1, retCode);
   return 0;
}

static int luna_dsa_keygen(DSA *dsa) {
   int flagSessionObject = luna_get_token_object() ? 0 : 1;
   int rc = luna_dsa_keygen_ex(dsa, flagSessionObject);
   return rc;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ckatab_test_unique"

/* test attribute for match against any object on token */
static int luna_ckatab_test_unique(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *tab) {
   CK_RV retCode = CKR_OK;
   CK_ULONG obj_count = 0;
#ifdef LUNA_OSSL_FIND_2_OBJECTS
   CK_OBJECT_HANDLE handles[2] = {LUNA_INVALID_HANDLE, LUNA_INVALID_HANDLE};
#else
   CK_OBJECT_HANDLE handles[1] = {LUNA_INVALID_HANDLE}; /* OPTIMIZE */
#endif
   char itoabuf[LUNA_ATOI_BYTES];

   memset(&handles, 0, sizeof(handles));
   memset(itoabuf, 0, sizeof(itoabuf));

   if (tab->ulValueLen < LUNA_MIN_LABEL) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "ulValueLen=0x", luna_itoa(itoabuf, tab->ulValueLen));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": ulValueLen", tab->ulValueLen);
      return 1;
   }

   retCode = p11.std->C_FindObjectsInit(hSession, tab, 1);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_FindObjectsInit=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_FindObjectsInit", retCode);
      return 1;
   }

   obj_count = 0;
   retCode = p11.std->C_FindObjects(hSession, &handles[0], LUNA_DIM(handles), &obj_count);
   if (((retCode != CKR_OK) && (!luna_pa_check_lib())) ||
       /*QQQ ProtectApp bundles key not found error in with general error
         so we need to consider a general error 'OK'*/
       (((retCode != CKR_GENERAL_ERROR) && (retCode != CKR_OK)) && (luna_pa_check_lib()))) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_FindObjects=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_FindObjects", retCode);
      return 1;
   }

   if (obj_count != 0) {
      LUNACA3err(LUNACA3_F_FINDOBJECT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "obj_count=0x", luna_itoa(itoabuf, obj_count));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": obj_count", obj_count);
      return 1;
   }

   return 0;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ckatab_pre_keygen"

/* test attribute list before key gen */
static int luna_ckatab_pre_keygen(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *tab, CK_ULONG tabsize) {
   int have_attr = 0;
   CK_ULONG ii = 0;
   CK_ATTRIBUTE attr;

   memset(&attr, 0, sizeof(attr));
   have_attr = 0;
   for (ii = 0; ii < tabsize; ii++) {
      if (tab[ii].type == CKA_LABEL) {
         if (have_attr)
            return -1;
         attr = tab[ii];
         have_attr = 1;
      }
   }

   if (have_attr == 0)
      return -2;
   if (luna_ckatab_test_unique(hSession, &attr))
      return -3;

   if (!luna_pa_check_lib()) {
      memset(&attr, 0, sizeof(attr));
      have_attr = 0;
      for (ii = 0; ii < tabsize; ii++) {
         if (tab[ii].type == CKA_ID) {
            if (have_attr)
               return -4;
            attr = tab[ii];
            have_attr = 1;
         }
      }

      if (have_attr == 0)
         return -5;

      if (luna_ckatab_test_unique(hSession, &attr))
         return -6;
   }

   return 0;
}

#define LOCAL_HLEN (20)
#define LOCAL_ITERATIONS (5)

/* key derive function; return 1 on success */
static int LUNA_PBKDF2_F(unsigned char *P, const unsigned char *S, unsigned c, unsigned ii, unsigned char *U) {
   unsigned jj;
   unsigned char *mdptr;
   unsigned char md[LOCAL_HLEN];

   /* compute U0 = S concat INT(ii); */
   memcpy(U, S, 16);
   U[16] = (unsigned)((ii >> 24) & 255);
   U[17] = (unsigned)((ii >> 16) & 255);
   U[18] = (unsigned)((ii >> 8) & 255);
   U[19] = (unsigned)((ii >> 0) & 255);

   /* compute Ux */
   for (; c > 0; c--) {
      /* underlying pseudorandom function (PRF; output length is 20 bytes) */
      memset(&md, 0, sizeof(md));
      if (luna_SHA1too(P, 20, U, LOCAL_HLEN, md) != 1)
         return 0;
      mdptr = md;
      for (jj = 0; jj < LOCAL_HLEN; jj++, mdptr++) {
         U[jj] ^= (*mdptr);
      }
   }

   return 1;
}

/* derive a masking key (of length dkLen); return 1 on success */
static int LUNA_PBKDF2_main(unsigned char *P, const unsigned char *S, unsigned c, unsigned dkLen,
                            unsigned char *maskout) {
   /* P is assumed to 20 bytes (based on SHA1). */
   /* S is assumed to 16 bytes or more. */
   if (P == NULL)
      return -1;
   if (S == NULL)
      return -1;
   if (c < LOCAL_ITERATIONS)
      return -1;
   if (dkLen % LOCAL_HLEN) {
      return -1;
   }

   {
      unsigned l = (dkLen / LOCAL_HLEN), it = 1;

      for (; l > 0; l--, it++, maskout += LOCAL_HLEN) {
         if (LUNA_PBKDF2_F(P, S, c, it, maskout) != 1) {
            LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
            return -2;
         }
      }
   }

   return 1;
}

/* passphrase mask; return 1 on success */
static int LUNA_pw_mask(luna_passphrase_t *ppw, unsigned char *dest, const unsigned char *src) {
   unsigned ii = 0;
   struct {
      void *addr1;
      void *addr2;
   } param1;
   unsigned char baMask[LUNA_PASSWD_MAXBLK];
   unsigned char baSha1[20];
   unsigned char baSha2[20];

   memset(&param1, 0xff, sizeof(param1));
   memset(&baMask, 0, sizeof(baMask));
   memset(&baSha1, 0, sizeof(baSha1));
   memset(&baSha2, 0, sizeof(baSha2));
   param1.addr1 = ppw;
   if (luna_SHA1((unsigned char *)&param1, sizeof(param1), baSha1) != 1) {
      return 0;
   }
   param1.addr2 = ppw->szPass;
   if (luna_SHA1((unsigned char *)&param1, sizeof(param1), baSha2) != 1) {
      return 0;
   }
   if (LUNA_PBKDF2_main(baSha1, baSha2, LOCAL_ITERATIONS, sizeof(baMask), baMask) != 1) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      return 0;
   }

   for (ii = 0; ii < LUNA_PASSWD_MAXBLK; ii++) {
      dest[ii] = (src[ii] ^ baMask[ii]);
   }
   memset(&param1, 0, sizeof(param1));
   memset(&baMask, 0, sizeof(baMask));
   memset(&baSha1, 0, sizeof(baSha1));
   memset(&baSha2, 0, sizeof(baSha2));
   return 1;
}

/* passphrase malloc */
static void LUNA_pw_malloc(luna_passphrase_t *ppw, char *szpw) {
   size_t len = 0;
   unsigned char shaPw[20];
   unsigned char blkPw[LUNA_PASSWD_MAXBLK];

   memset(&shaPw, 0, sizeof(shaPw));
   memset(&blkPw, 0, sizeof(blkPw));
   if (ppw == NULL)
      return;

   memset(ppw, 0, sizeof(*ppw));
   if ((len = strlen(szpw)) > LUNA_PASSWD_MAXLEN)
      return;
   if (len < 4)
      return;
   if ((ppw->szPass = (char *)LUNA_malloc(LUNA_PASSWD_MAXBLK)) == NULL)
      return;

   memcpy(&(blkPw[LUNA_PASSWD_MAXBLK - LUNA_PASSWD_MAXLEN - 1]), szpw, (len + 1)); /* include end of string */
   if (luna_SHA1((unsigned char *)&(blkPw[LUNA_PASSWD_MAXBLK - LUNA_PASSWD_MAXLEN - 1]), (LUNA_PASSWD_MAXLEN + 1), shaPw) != 1)
      return;
   memcpy(&(blkPw[LUNA_PASSWD_MAXBLK - LUNA_PASSWD_MAXLEN - 1 - sizeof(shaPw)]), shaPw, sizeof(shaPw));

   if (LUNA_pw_mask(ppw, (unsigned char *)ppw->szPass, blkPw) != 1)
      return;
   ppw->boolInit = 1;
   memset(&shaPw, 0, sizeof(shaPw));
   memset(&blkPw, 0, sizeof(blkPw));
   return;
}

/* passphrase free */
static void LUNA_pw_free(luna_passphrase_t *ppw) {
   if (ppw == NULL)
      return;
   if (ppw->szPass != NULL) {
      LUNA_cleanse(ppw->szPass, LUNA_PASSWD_MAXBLK);
      LUNA_free(ppw->szPass);
      ppw->szPass = NULL;
   }
   memset(ppw, 0, sizeof(*ppw));
}

/* passphrase login */
static CK_RV LUNA_pw_login(luna_passphrase_t *ppw, CK_SESSION_HANDLE hSession) {
   CK_RV rv2;
   char *szpw = NULL;
   CK_USER_TYPE userType = luna_get_userType();
   unsigned char shaPw[20];
   unsigned char blkPw[LUNA_PASSWD_MAXBLK];
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   memset(&shaPw, 0, sizeof(shaPw));
   memset(&blkPw, 0, sizeof(blkPw));
   if (ppw == NULL)
      return CKR_GENERAL_ERROR;
   if (ppw->szPass == NULL)
      return CKR_GENERAL_ERROR;
   if (ppw->boolInit != 1)
      return CKR_GENERAL_ERROR;

   if (LUNA_pw_mask(ppw, blkPw, (unsigned char *)ppw->szPass) != 1) {
      return CKR_GENERAL_ERROR;
   }

   if (luna_SHA1((unsigned char *)&(blkPw[LUNA_PASSWD_MAXBLK - LUNA_PASSWD_MAXLEN - 1]), (LUNA_PASSWD_MAXLEN + 1), shaPw) != 1) {
      return CKR_GENERAL_ERROR;
   }

   if (memcmp(shaPw, &(blkPw[LUNA_PASSWD_MAXBLK - LUNA_PASSWD_MAXLEN - 1 - sizeof(shaPw)]), sizeof(shaPw)) != 0) {
      memset(&shaPw, 0, sizeof(shaPw));
      memset(&blkPw, 0, sizeof(blkPw));
      return CKR_GENERAL_ERROR;
   }

   szpw = (char *)&(blkPw[LUNA_PASSWD_MAXBLK - LUNA_PASSWD_MAXLEN - 1]);
   rv2 = p11.std->C_Login(hSession, userType, (CK_BYTE_PTR)szpw, (CK_ULONG)strlen(szpw));
   rv2 = (rv2 == CKR_USER_ALREADY_LOGGED_IN) ? CKR_OK : rv2;
   if (rv2 != CKR_OK) {
      ppw->boolInit = 2; /* prevent further login */
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_Login=0x", luna_itoa(itoabuf, rv2));
      LUNA_ERRORLOG("LUNA_pw_login: C_Login");
   }

   memset(&shaPw, 0, sizeof(shaPw));
   memset(&blkPw, 0, sizeof(blkPw));

   return rv2;
}

/* query is protect server library */
static int luna_ps_check_lib(void) {
   if ((p11.ext.CT_HsmIdFromSlotId != NULL) && (p11.ext.CT_HsmIdFromSlotId != STUB_CT_HsmIdFromSlotId)) {
      return 1;
   }

   return 0;
}

/* query for ProtectApp Appliance setting */
static int luna_pa_check_lib(void) {
   if ((g_config.Appliance != NULL) && (strstr(g_config.Appliance, ENGINE_KEY_SECURE) != NULL))
      return 1;
   else
      return 0;
}

#ifdef LUNA_OSSL_PKEY_METHS

/* max 4 including { NID_rsaEncryption, NID_rsassaPss, NID_dsa, NID_ec } */
#define LUNA_PKEY_METH_NIDS_MAX_COUNT 4

static int luna_pkey_meth_nids_count = 0;
static int luna_pkey_meth_nids[LUNA_PKEY_METH_NIDS_MAX_COUNT + 1] = {
    0 /* zero-terminated */
};

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_pkey_meths"

/* redirect pkey methods to software */
static int luna_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid) {
   if (pmeth == NULL) {
      (*nids) = luna_pkey_meth_nids;
      return luna_pkey_meth_nids_count;
   }

   IF_LUNA_DEBUG(luna_dump_l("luna_pkey_meths: nid", nid));
   IF_LUNA_DEBUG(luna_dump_s("luna_pkey_meths: OBJ_nid2sn(nid)", OBJ_nid2sn(nid)));
   switch (nid) {
#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
      case NID_rsaEncryption:
         (*pmeth) = p_luna_evp_pkey_rsaenc;
         break;
      case NID_rsassaPss:
         (*pmeth) = p_luna_evp_pkey_rsapss;
         break;
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */
#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
      case NID_dsa:
         (*pmeth) = p_luna_evp_pkey_dsa;
         break;
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */
#ifdef LUNA_EC_USE_EVP_PKEY_METHS
      case NID_ec:
         (*pmeth) = p_luna_evp_pkey_ec;
         break;
#endif /* LUNA_EC_USE_EVP_PKEY_METHS */
      default:
         (*pmeth) = NULL;
         break;
   }

   return ( ((*pmeth) == NULL) ? 0 : 1 );
}

static int luna_pkey_asn1_meth_nids_count = 0;
static int luna_pkey_asn1_meth_nids[LUNA_PKEY_METH_NIDS_MAX_COUNT + 1] = {
    0 /* zero-terminated */
};

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_pkey_asn1_meths"

/* redirect pkey asni methods to software */
static int luna_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid) {
   if (ameth == NULL) {
      (*nids) = luna_pkey_asn1_meth_nids;
      return luna_pkey_asn1_meth_nids_count;
   }

   IF_LUNA_DEBUG(luna_dump_l("luna_pkey_asn1_meths: nid", nid));
   IF_LUNA_DEBUG(luna_dump_s("luna_pkey_asn1_meths: OBJ_nid2sn(nid)", OBJ_nid2sn(nid)));
   switch (nid) {
#ifdef LUNA_RSA_USE_EVP_ASN1_METHS
      case NID_rsaEncryption:
         (*ameth) = p_luna_asn1_rsaenc;
         break;
      case NID_rsassaPss:
         (*ameth) = p_luna_asn1_rsapss;
         break;
#endif /* LUNA_RSA_USE_EVP_ASN1_METHS */
#ifdef LUNA_DSA_USE_EVP_ASN1_METHS
      case NID_dsa:
         (*ameth) = p_luna_asn1_dsa;
         break;
#endif /* LUNA_DSA_USE_EVP_ASN1_METHS */
#ifdef LUNA_EC_USE_EVP_ASN1_METHS
      case NID_ec:
         (*ameth) = p_luna_asn1_ec;
         break;
#endif /* LUNA_EC_USE_EVP_ASN1_METHS */
      default:
         (*ameth) = NULL;
         break;
   }

   return ( ((*ameth) == NULL) ? 0 : 1);
}

/* setup pkey method array based on compile time and runtime configuration */
static void luna_pkey_init_meth_table(void) {
   luna_pkey_meth_nids_count = 0;
   luna_pkey_asn1_meth_nids_count = 0;

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
   /* avoid enabling the pkey rsa method if the base rsa method is disabled! */
   if ( ! luna_get_disable_rsa() ) {
      if (p_luna_evp_pkey_rsaenc != NULL) {
         luna_pkey_meth_nids[luna_pkey_meth_nids_count++] = NID_rsaEncryption;
#ifdef LUNA_RSA_USE_EVP_ASN1_METHS
         if (p_luna_asn1_rsaenc != NULL) {
            luna_pkey_asn1_meth_nids[luna_pkey_asn1_meth_nids_count++] = NID_rsaEncryption;
         }
#endif /* LUNA_RSA_USE_EVP_ASN1_METHS */
      }

      if (p_luna_evp_pkey_rsapss != NULL) {
         luna_pkey_meth_nids[luna_pkey_meth_nids_count++] = NID_rsassaPss;
#ifdef LUNA_RSA_USE_EVP_ASN1_METHS
         if (p_luna_asn1_rsapss != NULL) {
            luna_pkey_asn1_meth_nids[luna_pkey_asn1_meth_nids_count++] = NID_rsassaPss;
         }
#endif /* LUNA_RSA_USE_EVP_ASN1_METHS */
      }
   }
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
   /* avoid enabling the pkey dsa method if the base dsa method is disabled! */
   if ( ! luna_get_disable_dsa() ) {
      if (p_luna_evp_pkey_dsa != NULL) {
         luna_pkey_meth_nids[luna_pkey_meth_nids_count++] = NID_dsa;
#ifdef LUNA_DSA_USE_EVP_ASN1_METHS
         if (p_luna_asn1_dsa != NULL) {
            luna_pkey_asn1_meth_nids[luna_pkey_asn1_meth_nids_count++] = NID_dsa;
         }
#endif /* LUNA_DSA_USE_EVP_ASN1_METHS */
      }
   }
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */

#ifdef LUNA_EC_USE_EVP_PKEY_METHS
   /* avoid enabling the pkey ec method if the base ec method is disabled! */
   if ( ! luna_get_disable_ec() ) {
      if (p_luna_evp_pkey_ec != NULL) {
         luna_pkey_meth_nids[luna_pkey_meth_nids_count++] = NID_ec;
#ifdef LUNA_EC_USE_EVP_ASN1_METHS
         if (p_luna_asn1_ec != NULL) {
            luna_pkey_asn1_meth_nids[luna_pkey_asn1_meth_nids_count++] = NID_ec;
         }
#endif /* LUNA_EC_USE_EVP_ASN1_METHS */
      }
   }
#endif /* LUNA_EC_USE_EVP_PKEY_METHS */

   /* zero terminate */
   luna_pkey_meth_nids[luna_pkey_meth_nids_count] = 0;
   luna_pkey_asn1_meth_nids[luna_pkey_asn1_meth_nids_count] = 0;
}

static void luna_pkey_fini_meth_table(void) {
   /* zeroize table */
   luna_pkey_meth_nids[luna_pkey_meth_nids_count = 0] = 0;
   luna_pkey_asn1_meth_nids[luna_pkey_asn1_meth_nids_count = 0] = 0;

   /* zeroize meth pointers */
#ifdef LUNA_RSA_USE_EVP_PKEY_METHS
   if (p_luna_evp_pkey_rsaenc != NULL) {
      /* confirmed: openssl owns the pointer, so cannot call EVP_PKEY_meth_free for rsa, dsa, ec */
      p_luna_evp_pkey_rsaenc = NULL;
   }
   if (p_luna_evp_pkey_rsapss != NULL) {
      p_luna_evp_pkey_rsapss = NULL;
   }
#ifdef LUNA_RSA_USE_EVP_ASN1_METHS
   if (p_luna_asn1_rsaenc != NULL) {
      /* confirmed: openssl owns the pointer, so cannot call EVP_PKEY_asn1_free for rsa, dsa, ec */
      p_luna_asn1_rsaenc = NULL;
   }
   if (p_luna_asn1_rsapss != NULL) {
      p_luna_asn1_rsapss = NULL;
   }
#endif /* LUNA_RSA_USE_EVP_ASN1_METHS */
#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS
   if (p_luna_evp_pkey_dsa != NULL) {
      p_luna_evp_pkey_dsa = NULL;
   }
#ifdef LUNA_DSA_USE_EVP_ASN1_METHS
   if (p_luna_asn1_dsa != NULL) {
      p_luna_asn1_dsa = NULL;
   }
#endif /* LUNA_DSA_USE_EVP_ASN1_METHS */
#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */

#ifdef LUNA_EC_USE_EVP_PKEY_METHS
   if (p_luna_evp_pkey_ec != NULL) {
      p_luna_evp_pkey_ec = NULL;
   }
#ifdef LUNA_EC_USE_EVP_ASN1_METHS
   if (p_luna_asn1_ec != NULL) {
      p_luna_asn1_ec = NULL;
   }
#endif /* LUNA_EC_USE_EVP_ASN1_METHS */
#endif /* LUNA_EC_USE_EVP_PKEY_METHS */
}

#endif /* LUNA_OSSL_PKEY_METHS */

static int luna_digest_nids[] = {
    /* NOTE: vendor-specific algorithms here? */
    0 /* zero-terminated */
};

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_digests"

/* redirect digests to software */
static int luna_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid) {
   if (digest == NULL) {
      (*nids) = luna_digest_nids;
      return 0;
   }

   IF_LUNA_DEBUG(luna_dump_l("luna_digests: nid", nid));
   IF_LUNA_DEBUG(luna_dump_s("luna_digests: OBJ_nid2sn(nid)", OBJ_nid2sn(nid)));
   switch (nid) {
      default:
         (*digest) = NULL;
         break;
   }

   return ( ((*digest) == NULL) ? 0 : 1 );
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_gets_passfile"

/* read password from file */
static int luna_gets_passfile(const char *filename, char *password, unsigned maxlen) {
   FILE *fp = NULL;
   char *ptr = NULL;

   /* check input */
   if (filename == NULL)
      return 0;
   if (password == NULL)
      return 0;
   if ((fp = fopen(filename, "r")) == NULL)
      return 0;

   /* read file */
   ptr = fgets(password, maxlen, fp);
   fclose(fp);
   if (ptr == NULL)
      return 0;

   /* clean end of string */
   if ((ptr = strstr(password, "\r")) != NULL)
      ptr[0] = '\0';
   if ((ptr = strstr(password, "\n")) != NULL)
      ptr[0] = '\0';

   return (int)strlen(password);
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_parse_password"

/* Parse string, gather password */
/* NOTE: this is done prior to C_Initialize! */
static int luna_parse_password(const char *arg, char **password) {
   char *s0 = NULL, *sslot = NULL, *hi = NULL, *lo = NULL, *spwd = NULL;
   char *ptr = NULL;

   if (arg == NULL)
      return -1; /* likely */

   /* Parse string format:  "slotid:appidhi:appidlo"ENGINE_ENGINE_INIT_PASSWORD_SZ */
   sslot = s0 = BUF_strdup(arg);
   if (s0 == NULL)
      goto err;

   /* eat whitespace */
   for (; *sslot; sslot++) {
      if (!luna_isspace(*sslot))
         break;
   }

   /* look for starting quote and ending quote (or alternative quote) */
   if ((((*sslot) == '\"') && ((ptr = strstr((sslot + 1), "\":")) != NULL)) ||
       (((*sslot) == '@') && ((ptr = strstr((sslot + 1), "@:")) != NULL)) ||
       (((*sslot) == '#') && ((ptr = strstr((sslot + 1), "#:")) != NULL)) ||
       (((*sslot) == '%') && ((ptr = strstr((sslot + 1), "%:")) != NULL)) ||
       (((*sslot) == '^') && ((ptr = strstr((sslot + 1), "^:")) != NULL)) ||
       (((*sslot) == '~') && ((ptr = strstr((sslot + 1), "~:")) != NULL))) {
      /* Init string slotid */
      sslot++;
      (*ptr) = 0;
      ptr++;
      (*ptr) = 0;
      ptr++;
      hi = ptr;
   } else {
      /* Init numeric slotid */
      if ((ptr = strchr(sslot, ':')) == NULL)
         goto err;
      (*ptr) = 0;
      ptr++;
      hi = ptr;
   }

   if ((lo = strchr(hi, ':')) == NULL)
      goto err;
   /* Extract minor appid */
   *lo = 0;
   lo++;
   /* Extract password */
   if ((spwd = strchr(lo, ':')) != NULL) {
      *spwd = 0;
      spwd++;
      if (strncmp(spwd, "passfile=", 9) == 0) {
         char buf[LUNA_FILENAME_MAXLEN + 1];
         memset(buf, 0, sizeof(buf));
         spwd += 9;
         if (luna_gets_passfile(spwd, buf, LUNA_FILENAME_MAXLEN) < 4) {
            goto err;
         }
         if ((strlen(buf) > 0) && (strcmp(buf, "NULL"))) {
            (*password) = BUF_strdup(buf);
            if (!(*password))
               goto err;
         }
      } else if (strncmp(spwd, "passenv=", 8) == 0) {
         char *envvar = NULL;
         spwd += 8;
         if ((envvar = getenv(spwd)) == NULL) {
            goto err;
         }
         if ((strlen(envvar) > 0) && (strcmp(envvar, "NULL"))) {
            (*password) = BUF_strdup(envvar);
            if (!(*password))
               goto err;
         }
      } else if (strncmp(spwd, "passdev=", 8) == 0) {
         if (strncmp(spwd, "passdev=console", 15) == 0) {
            char buf[LUNA_PASSWD_MAXLEN + 1];
            memset(buf, 0, sizeof(buf));
            if (luna_gets_passphrase(arg, buf, LUNA_PASSWD_MAXLEN) < 4) {
               goto err;
            }

            if ((strlen(buf) > 0) && (strcmp(buf, "NULL"))) {
               (*password) = BUF_strdup(buf);
               if (!(*password))
                  goto err;
            }
         } else {
            goto err;
         }
      } else if (strncmp(spwd, "password=", 9) == 0) {
         spwd += 9;
         if ((strlen(spwd) > 0) && (strcmp(spwd, "NULL"))) {
            (*password) = BUF_strdup(spwd);
            if (!(*password))
               goto err;
         }
      } else if (strncmp(spwd, "passdll=", 8) == 0) {
         char buf[LUNA_PASSWD_MAXLEN + 1];
         memset(buf, 0, sizeof(buf));
         if (luna_gets_passdll(arg, buf, LUNA_PASSWD_MAXLEN, &spwd[8]) < 4) {
            goto err;
         }

         if ((strlen(buf) > 0) && (strcmp(buf, "NULL"))) {
            (*password) = BUF_strdup(buf);
            if (!(*password))
               goto err;
         }
      } else {
         /* NOTE: do not treat ordinary string as a password */
         goto err;
      }
   }
   /* Init the structure (remaining) */
   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return 1;

err:
   if (s0 != NULL) {
      LUNA_free(s0);
   }
   return 0;
}

typedef struct luna_passdllapi_s {
   luna_passdll_version_f version_f;
   luna_passdll_passphrase_f passphrase_f;
} luna_passdllapi_t;

static luna_passdllapi_t luna_passdllapi = {NULL, NULL};
static LUNA_DSO_T luna_passdll = NULL;
static int luna_passdlltrap = 0;

/* implement passdll */
static int luna_gets_passdll(const char *szslotid, char *secretString0, unsigned maxlen, const char *szdll) {
   char *rcptr = NULL;
   int have_label = 0;
   int rc_passphrase = 0;
   int rc_version = 0;
   unsigned pinlen = 0;

   luna_passdll_t cmd;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(&cmd, 0, sizeof(cmd));
   memset(&itoabuf, 0, sizeof(itoabuf));

   /* check input values (return quietly) */
   if (szslotid == NULL)
      return -1;
   if (secretString0 == NULL)
      return -1;
   if (maxlen > sizeof(cmd.pin))
      return -1;
   if (szdll == NULL)
      return -1;
   if (strlen(szdll) < 3)
      return -1;
   if (luna_passdlltrap)
      return -1;

   /* load library */
   if (luna_passdll == NULL) {
      luna_passdll = luna_dso_load(szdll);
      if (luna_passdll == NULL) {
         LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
         ERR_add_error_data(2, "luna_dso_load:", szdll);
         luna_passdlltrap = -1;
         goto err;
      }

      /* bind library function luna_passdll_version */
      luna_passdllapi.version_f = (luna_passdll_version_f)luna_dso_bind_func(luna_passdll, "luna_passdll_version");
      if (luna_passdllapi.version_f == NULL) {
         LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
         ERR_add_error_data(2, "luna_dso_bind_func:", "luna_passdll_version");
         luna_passdlltrap = -1;
         goto err;
      }

      /* bind library function luna_passdll_passphrase */
      luna_passdllapi.passphrase_f = (luna_passdll_passphrase_f)luna_dso_bind_func(luna_passdll, "luna_passdll_passphrase");
      if (luna_passdllapi.passphrase_f == NULL) {
         LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
         ERR_add_error_data(2, "luna_dso_bind_func:", "luna_passdll_passphrase");
         luna_passdlltrap = -1;
         goto err;
      }

      /* call library function luna_passdll_version */
      if ((rc_version = luna_passdllapi.version_f(NULL)) < LUNA_PASSDLL_VERSION_1) {
         LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
         ERR_add_error_data(2, "luna_passdll_version=0x", luna_itoa(itoabuf, rc_version));
         luna_passdlltrap = -1;
         goto err;
      }
   }

   /* parse slotid */
   rcptr = luna_parse_slotid2(szslotid, &have_label);
   if (rcptr == NULL) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_parse_slotid");
      luna_passdlltrap = -1;
      goto err;
   }

   /* populate cmd structure */
   cmd.version = LUNA_PASSDLL_VERSION_1;
   cmd.size = sizeof(cmd);
   cmd.user_type = luna_get_userType();
   if (have_label) {
      cmd.have_slotid = 0;
      cmd.slotid = ~((CK_ULONG)0); /* set to invalid value */
      luna_strncpy((char *)cmd.label, rcptr, sizeof(cmd.label));
   } else {
      cmd.have_slotid = 1;
      cmd.slotid = atoi(rcptr);
      memset(cmd.label, ' ', sizeof(cmd.label)); /* set to invalid value */
   }

   OPENSSL_free(rcptr);

   /* call library function luna_passdll_passphrase */
   if ((rc_passphrase = luna_passdllapi.passphrase_f(&cmd)) != 0) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(2, "luna_passdll_passphrase=0x", luna_itoa(itoabuf, rc_passphrase));
      goto err;
   }

   /* check pin length */
   pinlen = cmd.pin_length;
   if ((pinlen > maxlen) || (pinlen < 4) || (pinlen != strlen((char *)cmd.pin))) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(2, "pin_length=0x", luna_itoa(itoabuf, pinlen));
      goto err;
   }

   /* return success */
   luna_strncpy(secretString0, (char *)cmd.pin, (maxlen + 1));
   memset(&cmd, 0, sizeof(cmd));
   return pinlen;

err:
   /* return failure */
   LUNA_ERRORLOG("luna_gets_passdll");
   memset(&cmd, 0, sizeof(cmd));
   return -1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE

/* OPENSSL_NO_DYNAMIC_ENGINE is not defined meaning this is a dynamic engine and
 * we are free to call the EVP functions for SHA1 and RAND_bytes because those are defined
 * before we init the engine
 */

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_SHA1"

/* compute sha1 in software; return 1 on success */
static int luna_SHA1(const unsigned char *d, size_t n, unsigned char *md) {
   int ret = EVP_Digest(d, n, md, NULL, EVP_sha1(), NULL);
   if (ret != 1) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_SHA1");
      LUNA_ERRORLOG(LUNA_FUNC_NAME "luna_SHA1");
   }
   return ret;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_SHA1too"

/* compute sha1 in software (multipart); return 1 on success */
static int luna_SHA1too(const unsigned char *d1, size_t n1, const unsigned char *d2, size_t n2, unsigned char *md) {
   int ret = 0;
   EVP_MD_CTX *pctx = LUNA_EVP_MD_CTX_new();
   if (pctx != NULL) {
      EVP_MD_CTX_init(pctx);
      ret = EVP_DigestInit_ex(pctx, EVP_sha1(), NULL) && EVP_DigestUpdate(pctx, d1, n1) &&
         EVP_DigestUpdate(pctx, d2, n2) && EVP_DigestFinal_ex(pctx, md, NULL);
      LUNA_EVP_MD_CTX_free(pctx);
   }

   if (ret != 1) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_SHA1too");
      LUNA_ERRORLOG(LUNA_FUNC_NAME "luna_SHA1too");
   }
   return ret;
}

static int luna_RAND_bytes(unsigned char *buf, int num) {
   return RAND_bytes(buf, num);
}

#endif /* OPENSSL_NO_DYNAMIC_ENGINE */

/* Get attribute value(s) faster */
static int luna_attribute_malloc_FAST(luna_context_t *ctx, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pAttrs,
                                      unsigned nAttrs) {
   CK_RV retCode = CKR_OK;
   unsigned ii = 0;
   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   for (ii = 0; ii < nAttrs; ii++) {
      /* assert input values: pValue == NULL, and, ulValueLen > 0 */
      if (!(pAttrs[ii].pValue == NULL))
         return 0;
      if (!(pAttrs[ii].ulValueLen > 0))
         return 0;
   }

   for (ii = 0; ii < nAttrs; ii++) {
      pAttrs[ii].pValue = (CK_BYTE_PTR)LUNA_malloc(pAttrs[ii].ulValueLen);
      if (pAttrs[ii].pValue == NULL)
         goto err;
   }

   retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttrs, nAttrs);
   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_GETATTRVALUE, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_GetAttributeValue=0x", luna_itoa(itoabuf, retCode));
      goto err;
   }
   return 1;
err:
   for (ii = 0; ii < nAttrs; ii++) {
      if (pAttrs[ii].pValue != NULL)
         LUNA_free(pAttrs[ii].pValue);
      pAttrs[ii].ulValueLen = 0;
      pAttrs[ii].pValue = 0;
   }
   luna_context_set_last_error(ctx, retCode);
   return 0;
}

/* get user type; default is CKU_USER */
static CK_USER_TYPE luna_get_userType(void) {
   int flags = (g_config.EnableLimitedUser != NULL) ? atoi(g_config.EnableLimitedUser) : 0;
   CK_USER_TYPE ret = flags ? CKU_LIMITED_USER : CKU_USER;
   return ret;
}

/* get rsa pkcs padding type done in the engine; default is none (meaning do padding in hardware) */
static int luna_get_rsaPkcsPaddingType(void) {
   int ret = (g_config.EnableRsaPkcsPadding != NULL) ? atoi(g_config.EnableRsaPkcsPadding) : 0;
   return ret;
}

/* exit pending flag indicates the application is running in the context of exit() */
static volatile int luna_flag_exit = 0;

/* get the exit pending flag */
static int luna_get_flag_exit(void) {
   return luna_flag_exit;
}

/* atexit handler sets the exit pending flag */
/* NOTE: this handler runs BEFORE the openssl handler that tries to cleanup */
static void luna_atexit_handler(void) {
   luna_flag_exit = 1;
}

/* register atexit handler */
static void luna_register_atexit_handler(void) {
#ifdef LUNA_AUTO_DEINIT
   if (atexit(luna_atexit_handler) != 0) {
      /* atexit failed - set the exit pending flag now as a last resort to avoid crash later */
      LUNA_ERRORLOG("luna_register_atexit_handler: atexit");
      luna_flag_exit = 1;
   }
#endif /* LUNA_AUTO_DEINIT */
}

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_decrypt"

static int luna_rsa_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
   EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
   /*printf("luna_rsa_decrypt: ctx = %p, out = %p, outlen = %p (%u), in = %p, inlen = %u \n",
           ctx, out, outlen, (unsigned)(outlen==NULL?0:*outlen), in, (unsigned)inlen);*/
   if (pkey == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": pkey is null");
      return -1;
   }
   /* TODO: should we call EVP_PKEY_get1_RSA or EVP_PKEY_get0_RSA here?
    * Historically, this code just wants to peek at the key structure without
    * changing the reference count. So, calling EVP_PKEY_get0_RSA makes sense for now.
    */
   RSA *rsa = LUNA_EVP_PKEY_get0_RSA(pkey);
   if (rsa == NULL) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": rsa is null");
      return -1;
   }

   int padding = 0;
   if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
      LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": get_rsa_padding failed");
      return -1;
   }

   /* checkout output buffer length */
   size_t rsasize = (size_t)RSA_size(rsa);
   if (out == NULL) {
      *outlen = rsasize; // success
      return 1;
   }

   if (*outlen < rsasize) {
      return -1;
   }

   /* NOTE: RSA_PKCS1_OAEP_PADDING is the only padding type implemented correctly here */
   if (padding != RSA_PKCS1_OAEP_PADDING) {
      if (saved_rsaenc.decrypt != NULL) {
         return saved_rsaenc.decrypt(ctx, out, outlen, in, inlen);
      } else {
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": saved_rsaenc.decrypt is null");
         return -1;
      }
   }

   switch (luna_rsa_check_private(rsa)) {
      case 0: /* hardware */
         break;
      case 1: /* software */
         if (saved_rsaenc.decrypt != NULL) {
            return saved_rsaenc.decrypt(ctx, out, outlen, in, inlen);
         } else {
            LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINVAL);
            LUNA_ERRORLOG(LUNA_FUNC_NAME ": saved_rsaenc.decrypt is null");
            return -1;
         }
      default: /* error */
         LUNACA3err(LUNACA3_F_RSA_PRIVATE_DECRYPT, LUNACA3_R_EINKEY);
         LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_rsa_check");
         return -1;
   }

    // return 1 on success; return 0 or negative number on failure
    // side-effect outlen on success only
    int ret = -1;
    luna_oaep_params oaep_params;
    memset(&oaep_params, 0, sizeof(oaep_params));
    if (luna_to_oaep_params(&oaep_params, ctx) == 1) {
        int rcLen = luna_rsa_priv_dec_x509(&oaep_params, (int) inlen, in, *outlen, out, rsa, padding);
        ret = (rcLen > 0) ? 1 : -1;
        if (ret == 1) {
            *outlen = (size_t) rcLen; // success
        }
    }

   if (ret <= 0) {
      LUNA_ERRORLOGL("luna_rsa_decrypt: ret", ret);
   }

   return ret;
}

#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

#if defined(LUNA_OSSL_ECDSA)

static int luna_ec_keygen_hw_ex(EC_KEY *key, int flagSessionObject, int flagDerive);

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_keygen"

static int luna_ecdsa_keygen(EC_KEY *key) {
   /* check configuration for ec keygen in hardware */
   if (! luna_get_enable_ec_gen_key_pair()) {
      /* generate keypair in software */
      if (saved_ecdsa_keygen != NULL) {
         return saved_ecdsa_keygen(key);
      }
      return 0;
   }

   /* generate keypair in hardware */
   int flagSessionObject;
   int flagDerive;
   if (luna_get_token_object()) {
      flagSessionObject = 0;
      flagDerive = 0;
   } else {
      flagSessionObject = 1;
      flagDerive = 1;
   }
   return luna_ec_keygen_hw_ex(key, flagSessionObject, flagDerive);
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ecdsa_compute_key"

static int luna_ecdsa_compute_key(unsigned char **psec, size_t *pseclen,
                                  const EC_POINT *pub_key, const EC_KEY *ecdh) {
   switch (luna_ecdsa_check_private((EC_KEY *)ecdh)) {
   case 0: /* hardware key */
      break;
   case 1: /* software key */
      if (saved_ecdsa_compute_key != NULL) {
         return saved_ecdsa_compute_key(psec, pseclen, pub_key, ecdh);
      }
      /* fall through */
   default: /* error */
      LUNACA3err(LUNACA3_F_EC_COMPUTE_KEY, LUNACA3_R_EINKEY);
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ecdsa_check_private");
      return 0;
   }

   /* TODO: derive key in hardware if configured */
   LUNACA3err(LUNACA3_F_EC_COMPUTE_KEY, LUNACA3_R_ENOSYS);
   LUNA_ERRORLOG(LUNA_FUNC_NAME ": not implemented");
   return 0;
}

#endif /* LUNA_OSSL_ECDSA */

#ifdef OPENSSL_NO_DYNAMIC_ENGINE

/* OPENSSL_NO_DYNAMIC_ENGINE is defined meaning this is a static engine and
 * we cannot call the EVP functions for SHA1 and RAND_bytes because
 * those are not yet defined before we init the provider; i.e., we must call
 * the internal (non-EVP) functions insteads
 */

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_SHA1"

/* compute sha1 in software; return 1 on success */
static int luna_SHA1(const unsigned char *d, size_t n, unsigned char *md) {
   return luna_SHA1too(d, n, NULL, 0, md);
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_SHA1too"

/* compute sha1 in software (multipart); return 1 on success */
static int luna_SHA1too(const unsigned char *d1, size_t n1, const unsigned char *d2, size_t n2, unsigned char *md) {
   int ret = 0;
   SHA_CTX c;
   ret = SHA1_Init(&c) && SHA1_Update(&c, d1, n1) &&
      SHA1_Update(&c, d2, n2) && SHA1_Final(md, &c);
   if (ret != 1) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_SHA1too");
      LUNA_ERRORLOG(LUNA_FUNC_NAME "luna_SHA1too");
   }
   return ret;
}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_RAND_bytes"

static int luna_RAND_bytes(unsigned char *buf, int num) {
   int ret = 0;
   const RAND_METHOD *meth = RAND_OpenSSL();
   if ( (meth != NULL) && (meth->bytes != NULL) )
      ret = meth->bytes(buf, num);
   if (ret != 1) {
      LUNACA3err(LUNACA3_F_INIT, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_RAND_bytes");
      LUNA_ERRORLOG(LUNA_FUNC_NAME "luna_RAND_bytes");
   }
   return ret;
}

#endif /* OPENSSL_NO_DYNAMIC_ENGINE */

/* fixup pkey when loading the key using keyform=ENGINE */
static void luna_fixup_pkey_load(EVP_PKEY **ppkey, CK_ULONG ckKeyType, ENGINE *e, int hintPublic) {
   EVP_PKEY *pkey = (ppkey == NULL) ? NULL : *ppkey;

#ifdef LUNA_CONFIG_OSSL_PROVIDER
   if (pkey == NULL)
      return;
#else
   if (pkey == NULL || e == NULL)
       return;
#endif

#ifdef LUNA_OSSL3
   /* openssl3: downgrade the key to use legacy methods */
   if (ckKeyType == CKK_UNDEFINED) {
      if (EVP_PKEY_get_base_id(pkey) == EVP_PKEY_RSA) {
         ckKeyType = CKK_RSA;
      } else if (EVP_PKEY_get_base_id(pkey) == EVP_PKEY_DSA) {
         ckKeyType = CKK_DSA;
      } else if (EVP_PKEY_get_base_id(pkey) == EVP_PKEY_EC) {
         ckKeyType = CKK_ECDSA;
      } else {
         return;
      }
   }

   if (ckKeyType == CKK_RSA) {
      RSA *rsa = EVP_PKEY_get1_RSA(pkey);
      EVP_PKEY_free(pkey);
      *ppkey = pkey = NULL;
      if (rsa != NULL) {
         *ppkey = pkey = EVP_PKEY_new();
         if (pkey != NULL) {
            if (EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa) <= 0) {
               EVP_PKEY_free(pkey);
               *ppkey = NULL;
            }
         }
      }
   } else if (ckKeyType == CKK_DSA) {
      DSA *dsa = EVP_PKEY_get1_DSA(pkey);
      EVP_PKEY_free(pkey);
      *ppkey = pkey = NULL;
      if (dsa != NULL) {
         *ppkey = pkey = EVP_PKEY_new();
         if (pkey != NULL) {
            if (EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa) <= 0) {
               EVP_PKEY_free(pkey);
               *ppkey = NULL;
            }
         }
      }
   } else if (ckKeyType == CKK_ECDSA) {
      EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
      EVP_PKEY_free(pkey);
      *ppkey = pkey = NULL;
      if (ec_key != NULL) {
         *ppkey = pkey = EVP_PKEY_new();
         if (pkey != NULL) {
            if (EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec_key) <= 0) {
               EVP_PKEY_free(pkey);
               *ppkey = NULL;
            }
         }
      }
   }
#endif // LUNA_OSSL3
}

#ifdef LUNA_RSA_USE_EVP_PKEY_METHS

#ifndef RSA_PKCS1_WITH_TLS_PADDING
#define RSA_PKCS1_WITH_TLS_PADDING 7
#endif

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_rsa_ctrl"

/*
 * RSA ctrl request handler
 * possible return codes for such EVP_PKEY_METHOD member functions
 *   1 everything is good
 *   0 the request type is ok but the params (p1, p2, ctx) are inconsistent
 *  -1 not used here but it means error, retry if possible; e.g., the params need translation
 *  -2 fatal error, no retry; e.g., unknown request type
 */
static int luna_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
   int rc = -2;

   /* detect rsa_keygen_bits = {1024,2048,3072,4096,6144,8192}, rsa_keygen_primes = {2} */
   /* FIXME: checking type==0 is a tad ambiguous */
   if ( type == 0 && (p1 == 8192 || p1 == 6144 || p1 == 4096 || p1 == 3072 || p1 == 2048 || p1 == 1024) ) {
      if (saved_rsaenc.ctrl != NULL) {
         rc = saved_rsaenc.ctrl(ctx, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, p1, NULL);
      }
   } else if ( type == 0 && p1 == 2 ) {
      if (saved_rsaenc.ctrl != NULL) {
         rc = saved_rsaenc.ctrl(ctx, EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, p1, NULL);
      }
#if 0
   /* TODO: disabled until there is a known version of openssl that fixes RSA_PKCS1_WITH_TLS_PADDING for engines.
    * Meaning, translate messages (OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION and OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION).
    * Otherwise a soft error turns into a hard error (assertion failure) at runtime.
    */
   } else if ( type == EVP_PKEY_CTRL_RSA_PADDING && p1 == RSA_PKCS1_WITH_TLS_PADDING ) {
      /* LUNA-31156: tls 1.2 fails unless we set RSA_PKCS1_PADDING here */
      if (saved_rsaenc.ctrl != NULL) {
         rc = saved_rsaenc.ctrl(ctx, type, RSA_PKCS1_PADDING,  NULL);
      }
#endif
   } else {
      if (saved_rsaenc.ctrl != NULL) {
         rc = saved_rsaenc.ctrl(ctx, type, p1, p2);
      }
   }
   /* printf(LUNA_FUNC_NAME ": rc = %d: ctx = %p, type = %d, p1 = %d, p2 = %p \n", rc, ctx, type, p1, p2); */
   return rc;
}

#endif /* LUNA_RSA_USE_EVP_PKEY_METHS */

#ifdef LUNA_DSA_USE_EVP_PKEY_METHS

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_dsa_ctrl"

static int luna_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
   int rc = -2;

   /* detect dsa_paramgen_bits = {1024,2048,3072}, dsa_paramgen_q_bits = {160,224,256} */
   /* NOTE: luna firmware supports 1024-160 (160 q bits), 2048-224, 2048-256, 3072-256 */
   /* FIXME: checking type==0 is a tad ambiguous */
   if ( type == 0 && (p1 == 3072 || p1 == 2048 || p1 == 1024) ) {
      if (saved_dsa.ctrl != NULL) {
         rc = saved_dsa.ctrl(ctx, EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, p1, NULL);
      }
   } else if ( type == 0 && (p1 == 256 || p1 == 224 || p1 == 160) ) {
      if (saved_dsa.ctrl != NULL) {
         rc = saved_dsa.ctrl(ctx, EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, p1, NULL);
      }
   } else {
      if (saved_dsa.ctrl != NULL) {
         rc = saved_dsa.ctrl(ctx, type, p1, p2);
      }
   }
   return rc;
}

#endif /* LUNA_DSA_USE_EVP_PKEY_METHS */


#if defined(LUNA_OSSL_ECDSA)

static int luna_ec_CKA_ECDSA_PARAMS(EC_KEY *dsa, CK_BYTE **bufG, CK_ULONG *lenbufG);

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME "luna_ec_keygen_hw_ex"

/* generate ec key in hardware */
static int luna_ec_keygen_hw_ex(EC_KEY *dsa, int flagSessionObject, int flagDerive) {
   int rc = 0;

   CK_RV retCode = CKR_OK;
   EVP_PKEY *pkey = NULL;
   CK_BBOOL bTrue = 1;
   CK_BBOOL bTokenObject = (flagSessionObject ? 0 : 1);
   CK_BBOOL bDerive = (flagDerive ? 1 : 0);
   CK_BBOOL bModifiable = CK_TRUE;
   CK_BBOOL bExtractable = CK_TRUE;

   CK_OBJECT_HANDLE priv_handle = LUNA_INVALID_HANDLE;
   CK_OBJECT_HANDLE pub_handle = LUNA_INVALID_HANDLE;

   CK_BYTE_PTR bufG = NULL;
   CK_ULONG lenbufG = 0;

   CK_MECHANISM ec_key_gen_mech = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

   luna_context_t ctx = LUNA_CONTEXT_T_INIT;

   CK_ATTRIBUTE pub_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_ECDSA_PARAMS, 0, 0},
       {CKA_VERIFY, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_ATTRIBUTE priv_template[] = {
       {CKA_LABEL, 0, 0},
       {CKA_TOKEN, 0, 0},
       {CKA_PRIVATE, 0, 0},
       {CKA_SENSITIVE, 0, 0},
       {CKA_SIGN, 0, 0},
       {CKA_DERIVE, 0, 0},
       {CKA_MODIFIABLE, 0, 0},
       {CKA_EXTRACTABLE, 0, 0},
       {CKA_ID, 0, 0},
   };

   CK_BYTE bufTemp[512];
   CK_BYTE bufId[20];
   CK_ULONG bufIdLen = sizeof(bufId);
   char bufLabelPublic[80 + 1];
   char bufLabelPrivate[80 + 1];

   char itoabuf[LUNA_ATOI_BYTES];

   memset(itoabuf, 0, sizeof(itoabuf));
   memset(bufLabelPublic, 0, sizeof(bufLabelPublic));
   memset(bufLabelPrivate, 0, sizeof(bufLabelPrivate));

   if (dsa == NULL) {
      LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
      goto err;
   }

   /* OPTIMIZATION: session objects do not require unique label */
   if (! flagSessionObject) {

       /* generate random bytes which serve as CKA_ID, CKA_LABEL */
       if (luna_RAND_bytes(bufTemp, sizeof(bufTemp)) != 1) {
          LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
          ERR_add_error_data(1, "luna_RAND_bytes");
          LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_RAND_bytes");
          goto err;
       }

       if (luna_SHA1(bufTemp, sizeof(bufTemp), bufId) != 1) {
          LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
          ERR_add_error_data(1, "luna_SHA1");
          LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_SHA1");
          goto err;
       }

       bufIdLen = sizeof(bufId);

       luna_strncpy(bufLabelPublic, "ecdsa-public-", sizeof(bufLabelPublic));
       (void)luna_sprintf_hex(&bufLabelPublic[13], bufId, bufIdLen);
       luna_strncpy(bufLabelPrivate, "ecdsa-private-", sizeof(bufLabelPrivate));
       (void)luna_sprintf_hex(&bufLabelPrivate[14], bufId, bufIdLen);

   } else {
       /* use minimal-sized CKA_ID, CKA_LABEL */
       memset(bufId, 0xFF, 4);
       bufIdLen = 4;
       luna_strncpy(bufLabelPublic, "temp", sizeof(bufLabelPublic));
       luna_strncpy(bufLabelPrivate, "temp", sizeof(bufLabelPrivate));
   }

   /* get bytes for CKA_ECDSA_PARAMS */
   if (!luna_ec_CKA_ECDSA_PARAMS(dsa, &bufG, &lenbufG)) {
      LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_ec_curve_bytes");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ec_curve_bytes");
      goto err;
   }

   /* fill template (pub) */
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_LABEL, (CK_BYTE_PTR)bufLabelPublic,
                       (CK_ULONG)strlen(bufLabelPublic));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_TOKEN, &bTokenObject, sizeof(bTokenObject));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_PRIVATE, &bTrue,
                       sizeof(bTrue)); /* private=1 for access control */
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_ECDSA_PARAMS, bufG, lenbufG);
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   luna_ckatab_replace(pub_template, LUNA_DIM(pub_template), CKA_ID, bufId, bufIdLen);

   /* fill template (priv) */
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_LABEL, (CK_BYTE_PTR)bufLabelPrivate,
                       (CK_ULONG)strlen(bufLabelPrivate));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_TOKEN, &bTokenObject, sizeof(bTokenObject));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_DERIVE, &bDerive, sizeof(bDerive));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_MODIFIABLE, &bModifiable, sizeof(bModifiable));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_EXTRACTABLE, &bExtractable, sizeof(bExtractable));
   luna_ckatab_replace(priv_template, LUNA_DIM(priv_template), CKA_ID, bufId, bufIdLen);

   /* Always generate keys on the primary HSM; otherwise, we may lose track of keys. */
   if (luna_open_context_ndx(&ctx, 0) == 0) {
      LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_open_context");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_open_context");
      goto err;
   }

   /* OPTIMIZATION: session objects do not require unique label */
   if (! flagSessionObject) {
       /* Pre-test uniqueness of key */
       if (luna_ckatab_pre_keygen(ctx.hSession, priv_template, LUNA_DIM(priv_template))) {
          LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
          ERR_add_error_data(1, "luna_ckatab_pre_keygen");
          LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_ckatab_pre_keygen");
          goto err;
       }
   }

   /* C_GenerateKeyPair */
   retCode = p11.std->C_GenerateKeyPair(ctx.hSession, &ec_key_gen_mech, pub_template, LUNA_DIM(pub_template),
                                        priv_template, LUNA_DIM(priv_template), &pub_handle, &priv_handle);

   if (retCode != CKR_OK) {
      LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EPKCS11);
      ERR_add_error_data(2, "C_GenerateKeyPair=0x", luna_itoa(itoabuf, retCode));
      LUNA_ERRORLOGL(LUNA_FUNC_NAME ": C_GenerateKeyPair", retCode);
      goto err;
   }

   pkey = luna_load_ecdsa_FAST(NULL, &ctx, pub_handle, priv_handle, 0);
   if (pkey == NULL) {
      LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "luna_load_ecdsa");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": luna_load_ecdsa");
      goto err;
   }

   /* copy pkey to ec key (safely) and delete pkey */
   if (LUNA_EC_copy_from_pkey(dsa, pkey) <= 0) {
      LUNACA3err(LUNACA3_F_EC_GENERATE_KEY, LUNACA3_R_EENGINE);
      ERR_add_error_data(1, "LUNA_EC_copy_from_pkey");
      LUNA_ERRORLOG(LUNA_FUNC_NAME ": LUNA_EC_copy_from_pkey");
      goto err;
   }

   rc = 1;

err:
   if (bufG)
      OPENSSL_free(bufG);
   if (pkey)
      EVP_PKEY_free(pkey);
   luna_close_context_w_err( &ctx, (rc < 1), retCode );
   return rc;
}

#define LUNA_EC_CURVE_MAX_BYTES (64)

/* get bytes for CKA_ECDSA_PARAMS */
static int luna_ec_CKA_ECDSA_PARAMS(EC_KEY *dsa, CK_BYTE **bufG, CK_ULONG *lenbufG) {
    int rc = 0;

    const EC_GROUP *group = NULL;
    int nid = 0;
    size_t curveCount = 0;
    EC_builtin_curve *curves = NULL;
    size_t i = 0;
    size_t field_len = 0;

    int curve_len = 0;
    CK_BYTE curve_data[LUNA_EC_CURVE_MAX_BYTES] = {0};

    if ((group = EC_KEY_get0_group(dsa)) == NULL)
        goto err;
    if (EC_GROUP_check(group, NULL) < 1)
        goto err;
    if ((nid = EC_GROUP_get_curve_name(group)) < 1)
        goto err;
    /* check bare minimum ec key size (160) */
    if (!(field_len = LUNA_EC_GROUP_get_field_len(group)))
       goto err;
    if ( field_len < ((LUNA_EC_KEYSIZE_MIN + 7) / 8) )
       goto err;
    if ((curveCount = EC_get_builtin_curves(NULL, 0)) < 1)
        goto err;
    curves = (EC_builtin_curve *)OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * curveCount));
    if (curves == NULL)
        goto err;
    if (EC_get_builtin_curves(curves, curveCount) < 1)
        goto err;

    for (i = 0; i < curveCount; i++) {
       ASN1_OBJECT *asnobj = NULL;
       if (curves[i].nid == nid) {
          asnobj = OBJ_nid2obj(curves[i].nid);
          if (asnobj == NULL)
              goto err;
          curve_len = (LUNA_ASN1_OBJECT_GET_length(asnobj) + 2);
          if (curve_len > sizeof(curve_data))
              goto err;
          curve_data[0] = 0x06;
          curve_data[1] = LUNA_ASN1_OBJECT_GET_length(asnobj);
          memcpy(&curve_data[2], LUNA_ASN1_OBJECT_GET_data(asnobj), LUNA_ASN1_OBJECT_GET_length(asnobj));
          if ( (*bufG = (CK_BYTE*)OPENSSL_malloc(curve_len)) == NULL )
              goto err;
          memcpy(*bufG, curve_data, curve_len);
          *lenbufG = curve_len;
          rc = 1;
          break;
       }
    }

err:
    if (curves != NULL) {
        OPENSSL_free(curves);
    }
    return rc;
}

#endif // LUNA_OSSL_ECDSA


#ifdef LUNA_OSSL_ASN1_SET_SECURITY_BITS

static int luna_rsa_security_bits(const EVP_PKEY *pkey) {
    RSA *rsa0 = LUNA_EVP_PKEY_get0_RSA((EVP_PKEY *)pkey);
    if (rsa0 == NULL)
        return 0;
    return RSA_security_bits(rsa0);
}

static int luna_dsa_security_bits(const EVP_PKEY *pkey) {
    DSA *dsa0 = LUNA_EVP_PKEY_get0_DSA((EVP_PKEY *)pkey);
    if (dsa0 == NULL)
        return 0;
    return DSA_security_bits(dsa0);
}

static int luna_ec_bits(const EVP_PKEY *pkey) {
    EC_KEY *ec0 = LUNA_EVP_PKEY_get0_EC_KEY((EVP_PKEY *)pkey);
    if (ec0 == NULL)
        return 0;
    return EC_GROUP_order_bits(EC_KEY_get0_group(ec0));
}

static int luna_ec_security_bits(const EVP_PKEY *pkey) {
    int ecbits = luna_ec_bits(pkey);
    if (ecbits >= 512)
        return 256;
    if (ecbits >= 384)
        return 192;
    if (ecbits >= 256)
        return 128;
    if (ecbits >= 224)
        return 112;
    if (ecbits >= 160)
        return 80;
    return ecbits / 2;
}

#endif


static char *luna_strncpy(char *dest, const char *src, size_t n) {
    if (dest == NULL || n < 1)
        return NULL;
    dest[0] = 0;
    if (src != NULL)
        strncpy(dest, src, (n - 1));
    dest[n - 1] = 0;
    return dest;
}

#if defined(LUNA_OSSL_METH_SET_CHECK_KEYPAIR) || defined(LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR)

static int luna_rsa_check_keypair0(EVP_PKEY *pkey) {
    RSA *rsa = LUNA_EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL)
        return 0;
    const int rc_check = luna_rsa_check_private(rsa);
    if (rc_check == LUNA_CHECK_IS_SOFTWARE) {
        return RSA_check_key(rsa);
    } else if (rc_check == LUNA_CHECK_IS_HARDWARE) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}

static int luna_dsa_check_keypair0(EVP_PKEY *pkey) {
    DSA *dsa = LUNA_EVP_PKEY_get0_DSA(pkey);
    if (dsa == NULL)
        return 0;
    const int rc_check = luna_dsa_check_private(dsa);
    if (rc_check == LUNA_CHECK_IS_SOFTWARE) {
        return 1; /* no such routine for DSA */
    } else if (rc_check == LUNA_CHECK_IS_HARDWARE) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}

static int luna_ec_check_keypair0(EVP_PKEY *pkey) {
    EC_KEY *eckey = LUNA_EVP_PKEY_get0_EC_KEY(pkey);
    if (eckey == NULL)
        return 0;
    const int rc_check = luna_ecdsa_check_private(eckey);
    if (rc_check == LUNA_CHECK_IS_SOFTWARE) {
        return EC_KEY_check_key(eckey);
    } else if (rc_check == LUNA_CHECK_IS_HARDWARE) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}

#endif /* LUNA_OSSL_METH_SET_CHECK_KEYPAIR || LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR */

#ifdef LUNA_OSSL_ASN1_SET_CHECK_KEYPAIR
static int luna_rsa_check_keypair1(const EVP_PKEY *pkey) {
    return luna_rsa_check_keypair0((EVP_PKEY *)pkey);
}
static int luna_dsa_check_keypair1(const EVP_PKEY *pkey) {
    return luna_dsa_check_keypair0((EVP_PKEY *)pkey);
}
static int luna_ec_check_keypair1(const EVP_PKEY *pkey) {
    return luna_ec_check_keypair0((EVP_PKEY *)pkey);
}
#endif


/*****************************************************************************/

/* For CodeWarrior */
#if 0
extern "C" {
#endif

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

/* TODO: bad style */
#include "e_gem_err.c"
#include "e_gem_compat.c"

#endif /* !NO_HW_LUNACA3 */
#endif /* !NO_HW */
