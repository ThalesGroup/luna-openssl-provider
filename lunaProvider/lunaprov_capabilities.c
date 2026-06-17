// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * ToDo: Interop testing.
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>

/* For TLS1_VERSION etc */
#include <openssl/params.h>
#include <openssl/ssl.h>

// internal, but useful OSSL define:
#ifndef OSSL_NELEM
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))
#endif

//#include "oqs_prov.h"
#include "lunaCommon.h"

// tlsgroups.h
# define OSSL_TLS_GROUP_ID_secp256r1        0x0017
# define OSSL_TLS_GROUP_ID_secp384r1        0x0018
# define OSSL_TLS_GROUP_ID_secp521r1        0x0019
# define OSSL_TLS_GROUP_ID_brainpoolP256r1  0x001A
# define OSSL_TLS_GROUP_ID_brainpoolP384r1  0x001B
# define OSSL_TLS_GROUP_ID_brainpoolP512r1  0x001C
# define OSSL_TLS_GROUP_ID_x25519           0x001D
# define OSSL_TLS_GROUP_ID_x448             0x001E

// enable old tls groups, consistent with pqc hybrid
#define LUNA_TLS_GROUPS_OLD 1

// tls group name is mandatory (report standard groups)
#define LUNA_CAPABILITY_TLS_GROUP_NAME 1

// tls sigalg name is optional (report new algorithms - there are none)
#undef LUNA_CAPABILITY_TLS_SIGALG_NAME

#ifdef LUNA_CAPABILITY_TLS_GROUP_NAME
// group constant
typedef struct oqs_group_constants_st {
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;            /* Always set */
} OQS_GROUP_CONSTANTS;

static OQS_GROUP_CONSTANTS oqs_group_list[] = {
    // ad-hoc assignments - take from OQS generate data structures

#ifdef LUNA_TLS_GROUPS_OLD
    #define LUNA_GRP0 0
    // compile ALL of the groups here
    { OSSL_TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 }, // [0]
    { OSSL_TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
    { OSSL_TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
    { OSSL_TLS_GROUP_ID_brainpoolP256r1, 128, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_brainpoolP384r1, 192, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION, 0 },
    { OSSL_TLS_GROUP_ID_brainpoolP512r1, 256, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION, 0 },
    // NOTE: list x25519 and x448 despite not implementing in hsm.
    //  Compare with oqsprov_capabilities.c that does implement.
    { OSSL_TLS_GROUP_ID_x25519, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
    { OSSL_TLS_GROUP_ID_x448, 224, TLS1_VERSION, 0, DTLS1_VERSION, 0, 0 },
#endif /* LUNA_TLS_GROUPS_OLD */

};

// Adds entries for tlsname, `ecx`_tlsname and `ecp`_tlsname
#define OQS_GROUP_ENTRY(tlsname, realname, algorithm, idx)                    \
    {                                                                         \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, #tlsname,      \
                               sizeof(#tlsname)),                             \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,   \
                                   #realname, sizeof(#realname)),             \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, #algorithm, \
                                   sizeof(#algorithm)),                       \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                     \
                            (unsigned int *)&oqs_group_list[idx].group_id),   \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,          \
                            (unsigned int *)&oqs_group_list[idx].secbits),    \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                 \
                           (unsigned int *)&oqs_group_list[idx].mintls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                 \
                           (unsigned int *)&oqs_group_list[idx].maxtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                \
                           (unsigned int *)&oqs_group_list[idx].mindtls),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                \
                           (unsigned int *)&oqs_group_list[idx].maxdtls),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                  \
                           (unsigned int *)&oqs_group_list[idx].is_kem),      \
            OSSL_PARAM_END                                                    \
    }

static const OSSL_PARAM oqs_param_group_list[][11] = {

#ifdef LUNA_TLS_GROUPS_OLD
    // compile all or some of the groups here
    OQS_GROUP_ENTRY(secp256r1, prime256v1, EC, LUNA_GRP0+0),
    OQS_GROUP_ENTRY(P-256, prime256v1, EC, LUNA_GRP0+0), /* Alias of above */
    OQS_GROUP_ENTRY(secp384r1, secp384r1, EC, LUNA_GRP0+1),
    OQS_GROUP_ENTRY(P-384, secp384r1, EC, LUNA_GRP0+1), /* Alias of above */
    OQS_GROUP_ENTRY(secp521r1, secp521r1, EC, LUNA_GRP0+2),
    OQS_GROUP_ENTRY(P-521, secp521r1, EC, LUNA_GRP0+2), /* Alias of above */
    OQS_GROUP_ENTRY(brainpoolP256r1, brainpoolP256r1, EC, LUNA_GRP0+3),
    OQS_GROUP_ENTRY(brainpoolP384r1, brainpoolP384r1, EC, LUNA_GRP0+4),
    OQS_GROUP_ENTRY(brainpoolP512r1, brainpoolP512r1, EC, LUNA_GRP0+5),
    OQS_GROUP_ENTRY(x25519, X25519, X25519, LUNA_GRP0+6),
    OQS_GROUP_ENTRY(x448, X448, X448, LUNA_GRP0+7),
#endif /* LUNA_TLS_GROUPS_OLD */

};

typedef struct oqs_sigalg_constants_st {
    unsigned int code_point; /* Code point */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} OQS_SIGALG_CONSTANTS;

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(oqs_param_group_list); i++) {
        if (!cb(oqs_param_group_list[i], arg))
            return 0;
    }

    return 1;
}
#endif /* LUNA_CAPABILITY_TLS_GROUP_NAME */

#ifdef LUNA_CAPABILITY_TLS_SIGALG_NAME
static OQS_SIGALG_CONSTANTS oqs_sigalg_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
};
#    define OQS_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx)          \
        {                                                                     \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,      \
                                   #tlsname, sizeof(#tlsname)),               \
                OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,       \
                                       #tlsname, sizeof(#tlsname)),           \
                OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, #oid,  \
                                       sizeof(#oid)),                         \
                OSSL_PARAM_uint(                                              \
                    OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,                    \
                    (unsigned int *)&oqs_sigalg_list[idx].code_point),        \
                OSSL_PARAM_uint(                                              \
                    OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,                 \
                    (unsigned int *)&oqs_sigalg_list[idx].secbits),           \
                OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,            \
                               (unsigned int *)&oqs_sigalg_list[idx].mintls), \
                OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,            \
                               (unsigned int *)&oqs_sigalg_list[idx].maxtls), \
                OSSL_PARAM_END                                                \
        }

static const OSSL_PARAM oqs_param_sigalg_list[][12] = {
    // TODO: why are we adding groups but no signature algorithms?
};

static int oqs_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    // relaxed assertion for the case that not all algorithms are enabled
    assert(OSSL_NELEM(oqs_param_sigalg_list) <= OSSL_NELEM(oqs_sigalg_list));
    for (i = 0; i < OSSL_NELEM(oqs_param_sigalg_list); i++) {
        if (!cb(oqs_param_sigalg_list[i], arg))
            return 0;
    }

    return 1;
}
#endif /* LUNA_CAPABILITY_TLS_SIGALG_NAME */

int luna_classic_provider_get_capabilities(void *provctx_unused, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg)
{
#ifdef LUNA_CAPABILITY_TLS_GROUP_NAME
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return oqs_group_capability(cb, arg);
#endif /* LUNA_CAPABILITY_TLS_GROUP_NAME */

#ifdef LUNA_CAPABILITY_TLS_SIGALG_NAME
    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return oqs_sigalg_capability(cb, arg);
#endif /* LUNA_CAPABILITY_TLS_SIGALG_NAME */

    /* We don't support this capability */
    return 0;
}
