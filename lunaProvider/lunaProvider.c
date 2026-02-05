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

#include <string.h>
#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "lunaCommon.h"

/* luna provider details as of toolkit 1.6 */
#define LUNA_PROV_NAME_SZ "Thales Luna Provider"
#define LUNA_PROV_VERSION_SZ "1.7.5.0"
#define LUNA_PROV_SZ "lunaprov"
#define LUNA_PROV_CONCAT_SZ(a_, b_) a_ b_

/* luna build info */
#ifdef LUNA_OQS
#define LUNA_PROV_BUILDINFO_SZ LUNA_PROV_VERSION_SZ " based on liboqs " OQS_VERSION_TEXT
#else
#define LUNA_PROV_BUILDINFO_SZ LUNA_PROV_VERSION_SZ
#endif

/* fips property */
#ifdef LUNA_FIPS
#define LUNA_PROV_EQUALS_SZ "provider=lunaprov,fips=yes"
#else
#define LUNA_PROV_EQUALS_SZ "provider=lunaprov"
#endif

/*
 * Luna provider context
 */
typedef struct luna_prov_ctx_st {
    /* same members as in prov_ctx_st, though the source code should not be assuming that */
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    BIO_METHOD *corebiometh;

    /* members added for luna, oqs */
    int magic;
#ifdef LUNA_OQS
    PROV_OQS_CTX *oqsctx;
#endif

} luna_prov_ctx;

#ifdef NDEBUG
#    define OQS_PROV_PRINTF(a)
#    define OQS_PROV_PRINTF2(a, b)
#    define OQS_PROV_PRINTF3(a, b, c)
#else
#    define OQS_PROV_PRINTF(a) \
        if (getenv("OQSPROV")) \
        printf(a)
#    define OQS_PROV_PRINTF2(a, b) \
        if (getenv("OQSPROV"))     \
        printf(a, b)
#    define OQS_PROV_PRINTF3(a, b, c) \
        if (getenv("OQSPROV"))        \
        printf(a, b, c)
#endif // NDEBUG

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn luna_gettable_params;
static OSSL_FUNC_provider_get_params_fn luna_get_params;
static OSSL_FUNC_provider_query_operation_fn luna_query;

extern const OSSL_DISPATCH luna_file_store_functions[];

#ifdef LUNA_OQS
/*
 * List of all algorithms with given OIDs
 */
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_START

#ifdef OQS_KEM_ENCODERS
#    define OQS_OID_CNT 202
#else
#    define OQS_OID_CNT 96
#endif /* OQS_KEM_ENCODERS */
const char *oqs_oid_alg_list[OQS_OID_CNT] = {

#ifdef OQS_KEM_ENCODERS

    "1.3.9999.99.17",
    "frodo640aes",
    "1.3.9999.99.16",
    "p256_frodo640aes",
    "1.3.9999.99.1",
    "x25519_frodo640aes",
    "1.3.9999.99.19",
    "frodo640shake",
    "1.3.9999.99.18",
    "p256_frodo640shake",
    "1.3.9999.99.2",
    "x25519_frodo640shake",
    "1.3.9999.99.21",
    "frodo976aes",
    "1.3.9999.99.20",
    "p384_frodo976aes",
    "1.3.9999.99.3",
    "x448_frodo976aes",
    "1.3.9999.99.23",
    "frodo976shake",
    "1.3.9999.99.22",
    "p384_frodo976shake",
    "1.3.9999.99.4",
    "x448_frodo976shake",
    "1.3.9999.99.25",
    "frodo1344aes",
    "1.3.9999.99.24",
    "p521_frodo1344aes",
    "1.3.9999.99.27",
    "frodo1344shake",
    "1.3.9999.99.26",
    "p521_frodo1344shake",
    "1.3.6.1.4.1.2.267.8.2.2",
    "kyber512",
    "1.3.9999.99.28",
    "p256_kyber512",
    "1.3.9999.99.5",
    "x25519_kyber512",
    "1.3.6.1.4.1.2.267.8.3.3",
    "kyber768",
    "1.3.9999.99.29",
    "p384_kyber768",
    "1.3.9999.99.6",
    "x448_kyber768",
    "1.3.9999.99.7",
    "x25519_kyber768",
    "1.3.9999.99.8",
    "p256_kyber768",
    "1.3.6.1.4.1.2.267.8.4.4",
    "kyber1024",
    "1.3.9999.99.30",
    "p521_kyber1024",
    "2.16.840.1.101.3.4.4.1",
    "mlkem512",
    "1.3.6.1.4.1.22554.5.7.1",
    "p256_mlkem512",
    "1.3.6.1.4.1.22554.5.8.1",
    "x25519_mlkem512",
    "2.16.840.1.101.3.4.4.2",
    "mlkem768",
    "1.3.9999.99.31",
    "p384_mlkem768",
    "1.3.9999.99.9",
    "x448_mlkem768",
    "1.3.9999.99.10",
    "x25519_mlkem768",
    "1.3.9999.99.11",
    "p256_mlkem768",
    "2.16.840.1.101.3.4.4.3",
    "mlkem1024",
    "1.3.9999.99.32",
    "p521_mlkem1024",
    "1.3.6.1.4.1.42235.6",
    "p384_mlkem1024",
    "1.3.9999.99.34",
    "bikel1",
    "1.3.9999.99.33",
    "p256_bikel1",
    "1.3.9999.99.12",
    "x25519_bikel1",
    "1.3.9999.99.36",
    "bikel3",
    "1.3.9999.99.35",
    "p384_bikel3",
    "1.3.9999.99.13",
    "x448_bikel3",
    "1.3.9999.99.38",
    "bikel5",
    "1.3.9999.99.37",
    "p521_bikel5",
    "1.3.9999.99.40",
    "hqc128",
    "1.3.9999.99.39",
    "p256_hqc128",
    "1.3.9999.99.14",
    "x25519_hqc128",
    "1.3.9999.99.42",
    "hqc192",
    "1.3.9999.99.41",
    "p384_hqc192",
    "1.3.9999.99.15",
    "x448_hqc192",
    "1.3.9999.99.44",
    "hqc256",
    "1.3.9999.99.43",
    "p521_hqc256",

#endif /* OQS_KEM_ENCODERS */

    "1.3.6.1.4.1.2.267.7.4.4",
    "dilithium2",
    "1.3.9999.2.7.1",
    "p256_dilithium2",
    "1.3.9999.2.7.2",
    "rsa3072_dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5",
    "dilithium3",
    "1.3.9999.2.7.3",
    "p384_dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7",
    "dilithium5",
    "1.3.9999.2.7.4",
    "p521_dilithium5",
    LUNA_OID_ML_DSA_44,
    LUNA_SN_ML_DSA_44,
    "1.3.9999.7.1",
    "p256_mldsa44",
    "1.3.9999.7.2",
    "rsa3072_mldsa44",
    "2.16.840.1.114027.80.8.1.1",
    "mldsa44_pss2048",
    "2.16.840.1.114027.80.8.1.2",
    "mldsa44_rsa2048",
    "2.16.840.1.114027.80.8.1.3",
    "mldsa44_ed25519",
    "2.16.840.1.114027.80.8.1.4",
    "mldsa44_p256",
    "2.16.840.1.114027.80.8.1.5",
    "mldsa44_bp256",
    LUNA_OID_ML_DSA_65,
    LUNA_SN_ML_DSA_65,
    "1.3.9999.7.3",
    "p384_mldsa65",
    "2.16.840.1.114027.80.8.1.6",
    "mldsa65_pss3072",
    "2.16.840.1.114027.80.8.1.7",
    "mldsa65_rsa3072",
    "2.16.840.1.114027.80.8.1.8",
    "mldsa65_p256",
    "2.16.840.1.114027.80.8.1.9",
    "mldsa65_bp256",
    "2.16.840.1.114027.80.8.1.10",
    "mldsa65_ed25519",
    LUNA_OID_ML_DSA_87,
    LUNA_SN_ML_DSA_87,
    "1.3.9999.7.4",
    "p521_mldsa87",
    "2.16.840.1.114027.80.8.1.11",
    "mldsa87_p384",
    "2.16.840.1.114027.80.8.1.12",
    "mldsa87_bp384",
    "2.16.840.1.114027.80.8.1.13",
    "mldsa87_ed448",
    "1.3.9999.3.11",
    "falcon512",
    "1.3.9999.3.12",
    "p256_falcon512",
    "1.3.9999.3.13",
    "rsa3072_falcon512",
    "1.3.9999.3.16",
    "falconpadded512",
    "1.3.9999.3.17",
    "p256_falconpadded512",
    "1.3.9999.3.18",
    "rsa3072_falconpadded512",
    "1.3.9999.3.14",
    "falcon1024",
    "1.3.9999.3.15",
    "p521_falcon1024",
    "1.3.9999.3.19",
    "falconpadded1024",
    "1.3.9999.3.20",
    "p521_falconpadded1024",
    "1.3.9999.6.4.13",
    "sphincssha2128fsimple",
    "1.3.9999.6.4.14",
    "p256_sphincssha2128fsimple",
    "1.3.9999.6.4.15",
    "rsa3072_sphincssha2128fsimple",
    "1.3.9999.6.4.16",
    "sphincssha2128ssimple",
    "1.3.9999.6.4.17",
    "p256_sphincssha2128ssimple",
    "1.3.9999.6.4.18",
    "rsa3072_sphincssha2128ssimple",
    "1.3.9999.6.5.10",
    "sphincssha2192fsimple",
    "1.3.9999.6.5.11",
    "p384_sphincssha2192fsimple",
    "1.3.9999.6.7.13",
    "sphincsshake128fsimple",
    "1.3.9999.6.7.14",
    "p256_sphincsshake128fsimple",
    "1.3.9999.6.7.15",
    "rsa3072_sphincsshake128fsimple",
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END
};

static int oqs_patch_oids(void) {
///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_START
    {
        const char *envval = NULL;

#ifdef OQS_KEM_ENCODERS

        if ((envval = getenv("OQS_OID_FRODO640AES")))
            oqs_oid_alg_list[0] = envval;

        if ((envval = getenv("OQS_OID_P256_FRODO640AES")))
            oqs_oid_alg_list[2] = envval;
        if ((envval = getenv("OQS_OID_X25519_FRODO640AES")))
            oqs_oid_alg_list[4] = envval;
        if ((envval = getenv("OQS_OID_FRODO640SHAKE")))
            oqs_oid_alg_list[6] = envval;

        if ((envval = getenv("OQS_OID_P256_FRODO640SHAKE")))
            oqs_oid_alg_list[8] = envval;
        if ((envval = getenv("OQS_OID_X25519_FRODO640SHAKE")))
            oqs_oid_alg_list[10] = envval;
        if ((envval = getenv("OQS_OID_FRODO976AES")))
            oqs_oid_alg_list[12] = envval;

        if ((envval = getenv("OQS_OID_P384_FRODO976AES")))
            oqs_oid_alg_list[14] = envval;
        if ((envval = getenv("OQS_OID_X448_FRODO976AES")))
            oqs_oid_alg_list[16] = envval;
        if ((envval = getenv("OQS_OID_FRODO976SHAKE")))
            oqs_oid_alg_list[18] = envval;

        if ((envval = getenv("OQS_OID_P384_FRODO976SHAKE")))
            oqs_oid_alg_list[20] = envval;
        if ((envval = getenv("OQS_OID_X448_FRODO976SHAKE")))
            oqs_oid_alg_list[22] = envval;
        if ((envval = getenv("OQS_OID_FRODO1344AES")))
            oqs_oid_alg_list[24] = envval;

        if ((envval = getenv("OQS_OID_P521_FRODO1344AES")))
            oqs_oid_alg_list[26] = envval;
        if ((envval = getenv("OQS_OID_FRODO1344SHAKE")))
            oqs_oid_alg_list[28] = envval;

        if ((envval = getenv("OQS_OID_P521_FRODO1344SHAKE")))
            oqs_oid_alg_list[30] = envval;
        if ((envval = getenv("OQS_OID_KYBER512")))
            oqs_oid_alg_list[32] = envval;

        if ((envval = getenv("OQS_OID_P256_KYBER512")))
            oqs_oid_alg_list[34] = envval;
        if ((envval = getenv("OQS_OID_X25519_KYBER512")))
            oqs_oid_alg_list[36] = envval;
        if ((envval = getenv("OQS_OID_KYBER768")))
            oqs_oid_alg_list[38] = envval;

        if ((envval = getenv("OQS_OID_P384_KYBER768")))
            oqs_oid_alg_list[40] = envval;
        if ((envval = getenv("OQS_OID_X448_KYBER768")))
            oqs_oid_alg_list[42] = envval;
        if ((envval = getenv("OQS_OID_X25519_KYBER768")))
            oqs_oid_alg_list[44] = envval;
        if ((envval = getenv("OQS_OID_P256_KYBER768")))
            oqs_oid_alg_list[46] = envval;
        if ((envval = getenv("OQS_OID_KYBER1024")))
            oqs_oid_alg_list[48] = envval;

        if ((envval = getenv("OQS_OID_P521_KYBER1024")))
            oqs_oid_alg_list[50] = envval;
        if ((envval = getenv("OQS_OID_MLKEM512")))
            oqs_oid_alg_list[52] = envval;

        if ((envval = getenv("OQS_OID_P256_MLKEM512")))
            oqs_oid_alg_list[54] = envval;
        if ((envval = getenv("OQS_OID_X25519_MLKEM512")))
            oqs_oid_alg_list[56] = envval;
        if ((envval = getenv("OQS_OID_MLKEM768")))
            oqs_oid_alg_list[58] = envval;

        if ((envval = getenv("OQS_OID_P384_MLKEM768")))
            oqs_oid_alg_list[60] = envval;
        if ((envval = getenv("OQS_OID_X448_MLKEM768")))
            oqs_oid_alg_list[62] = envval;
        if ((envval = getenv("OQS_OID_X25519_MLKEM768")))
            oqs_oid_alg_list[64] = envval;
        if ((envval = getenv("OQS_OID_P256_MLKEM768")))
            oqs_oid_alg_list[66] = envval;
        if ((envval = getenv("OQS_OID_MLKEM1024")))
            oqs_oid_alg_list[68] = envval;

        if ((envval = getenv("OQS_OID_P521_MLKEM1024")))
            oqs_oid_alg_list[70] = envval;
        if ((envval = getenv("OQS_OID_P384_MLKEM1024")))
            oqs_oid_alg_list[72] = envval;
        if ((envval = getenv("OQS_OID_BIKEL1")))
            oqs_oid_alg_list[74] = envval;

        if ((envval = getenv("OQS_OID_P256_BIKEL1")))
            oqs_oid_alg_list[76] = envval;
        if ((envval = getenv("OQS_OID_X25519_BIKEL1")))
            oqs_oid_alg_list[78] = envval;
        if ((envval = getenv("OQS_OID_BIKEL3")))
            oqs_oid_alg_list[80] = envval;

        if ((envval = getenv("OQS_OID_P384_BIKEL3")))
            oqs_oid_alg_list[82] = envval;
        if ((envval = getenv("OQS_OID_X448_BIKEL3")))
            oqs_oid_alg_list[84] = envval;
        if ((envval = getenv("OQS_OID_BIKEL5")))
            oqs_oid_alg_list[86] = envval;

        if ((envval = getenv("OQS_OID_P521_BIKEL5")))
            oqs_oid_alg_list[88] = envval;
        if ((envval = getenv("OQS_OID_HQC128")))
            oqs_oid_alg_list[90] = envval;

        if ((envval = getenv("OQS_OID_P256_HQC128")))
            oqs_oid_alg_list[92] = envval;
        if ((envval = getenv("OQS_OID_X25519_HQC128")))
            oqs_oid_alg_list[94] = envval;
        if ((envval = getenv("OQS_OID_HQC192")))
            oqs_oid_alg_list[96] = envval;

        if ((envval = getenv("OQS_OID_P384_HQC192")))
            oqs_oid_alg_list[98] = envval;
        if ((envval = getenv("OQS_OID_X448_HQC192")))
            oqs_oid_alg_list[100] = envval;
        if ((envval = getenv("OQS_OID_HQC256")))
            oqs_oid_alg_list[102] = envval;

        if ((envval = getenv("OQS_OID_P521_HQC256")))
            oqs_oid_alg_list[104] = envval;

#    define OQS_KEMOID_CNT 104 + 2
#else
#    define OQS_KEMOID_CNT 0
#endif /* OQS_KEM_ENCODERS */
        if ((envval = getenv("OQS_OID_DILITHIUM2")))
            oqs_oid_alg_list[0 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_DILITHIUM2")))
            oqs_oid_alg_list[2 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_DILITHIUM2")))
            oqs_oid_alg_list[4 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_DILITHIUM3")))
            oqs_oid_alg_list[6 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P384_DILITHIUM3")))
            oqs_oid_alg_list[8 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_DILITHIUM5")))
            oqs_oid_alg_list[10 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P521_DILITHIUM5")))
            oqs_oid_alg_list[12 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_MLDSA44")))
            oqs_oid_alg_list[14 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_MLDSA44")))
            oqs_oid_alg_list[16 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_MLDSA44")))
            oqs_oid_alg_list[18 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_MLDSA65")))
            oqs_oid_alg_list[20 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P384_MLDSA65")))
            oqs_oid_alg_list[22 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_MLDSA87")))
            oqs_oid_alg_list[24 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P521_MLDSA87")))
            oqs_oid_alg_list[26 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_FALCON512")))
            oqs_oid_alg_list[28 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_FALCON512")))
            oqs_oid_alg_list[30 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_FALCON512")))
            oqs_oid_alg_list[32 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_FALCONPADDED512")))
            oqs_oid_alg_list[34 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_FALCONPADDED512")))
            oqs_oid_alg_list[36 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_FALCONPADDED512")))
            oqs_oid_alg_list[38 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_FALCON1024")))
            oqs_oid_alg_list[40 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P521_FALCON1024")))
            oqs_oid_alg_list[42 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_FALCONPADDED1024")))
            oqs_oid_alg_list[44 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P521_FALCONPADDED1024")))
            oqs_oid_alg_list[46 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_SPHINCSSHA2128FSIMPLE")))
            oqs_oid_alg_list[48 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_SPHINCSSHA2128FSIMPLE")))
            oqs_oid_alg_list[50 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_SPHINCSSHA2128FSIMPLE")))
            oqs_oid_alg_list[52 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_SPHINCSSHA2128SSIMPLE")))
            oqs_oid_alg_list[54 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_SPHINCSSHA2128SSIMPLE")))
            oqs_oid_alg_list[56 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_SPHINCSSHA2128SSIMPLE")))
            oqs_oid_alg_list[58 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_SPHINCSSHA2192FSIMPLE")))
            oqs_oid_alg_list[60 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P384_SPHINCSSHA2192FSIMPLE")))
            oqs_oid_alg_list[62 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_SPHINCSSHAKE128FSIMPLE")))
            oqs_oid_alg_list[64 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_P256_SPHINCSSHAKE128FSIMPLE")))
            oqs_oid_alg_list[66 + OQS_KEMOID_CNT] = envval;
        if ((envval = getenv("OQS_OID_RSA3072_SPHINCSSHAKE128FSIMPLE")))
            oqs_oid_alg_list[68 + OQS_KEMOID_CNT] = envval;
    } ///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_END
   return 1;
}

#ifdef USE_ENCODING_LIB
const char *oqs_alg_encoding_list[OQS_OID_CNT] = {0};

int oqs_patch_encodings(void)
{
    ///// OQS_TEMPLATE_FRAGMENT_ENCODING_PATCHING_START
    {
        const char *envval = NULL;
        if ((envval = getenv("OQS_ENCODING_DILITHIUM2")))
            oqs_alg_encoding_list[0] = envval;
        if ((envval = getenv("OQS_ENCODING_DILITHIUM2_ALGNAME")))
            oqs_alg_encoding_list[1] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_DILITHIUM2")))
            oqs_alg_encoding_list[2] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_DILITHIUM2_ALGNAME")))
            oqs_alg_encoding_list[3] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_DILITHIUM2")))
            oqs_alg_encoding_list[4] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_DILITHIUM2_ALGNAME")))
            oqs_alg_encoding_list[5] = envval;
        if ((envval = getenv("OQS_ENCODING_DILITHIUM3")))
            oqs_alg_encoding_list[6] = envval;
        if ((envval = getenv("OQS_ENCODING_DILITHIUM3_ALGNAME")))
            oqs_alg_encoding_list[7] = envval;
        if ((envval = getenv("OQS_ENCODING_P384_DILITHIUM3")))
            oqs_alg_encoding_list[8] = envval;
        if ((envval = getenv("OQS_ENCODING_P384_DILITHIUM3_ALGNAME")))
            oqs_alg_encoding_list[9] = envval;
        if ((envval = getenv("OQS_ENCODING_DILITHIUM5")))
            oqs_alg_encoding_list[10] = envval;
        if ((envval = getenv("OQS_ENCODING_DILITHIUM5_ALGNAME")))
            oqs_alg_encoding_list[11] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_DILITHIUM5")))
            oqs_alg_encoding_list[12] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_DILITHIUM5_ALGNAME")))
            oqs_alg_encoding_list[13] = envval;
        if ((envval = getenv("OQS_ENCODING_MLDSA44")))
            oqs_alg_encoding_list[14] = envval;
        if ((envval = getenv("OQS_ENCODING_MLDSA44_ALGNAME")))
            oqs_alg_encoding_list[15] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_MLDSA44")))
            oqs_alg_encoding_list[16] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_MLDSA44_ALGNAME")))
            oqs_alg_encoding_list[17] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_MLDSA44")))
            oqs_alg_encoding_list[18] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_MLDSA44_ALGNAME")))
            oqs_alg_encoding_list[19] = envval;
        if (getenv("OQS_ENCODING_MLDSA44_PSS2048"))
            oqs_alg_encoding_list[20] = getenv("OQS_ENCODING_MLDSA44_PSS2048");
        if (getenv("OQS_ENCODING_MLDSA44_PSS2048_ALGNAME"))
            oqs_alg_encoding_list[21]
                = getenv("OQS_ENCODING_MLDSA44_PSS2048_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA44_RSA2048"))
            oqs_alg_encoding_list[22] = getenv("OQS_ENCODING_MLDSA44_RSA2048");
        if (getenv("OQS_ENCODING_MLDSA44_RSA2048_ALGNAME"))
            oqs_alg_encoding_list[23]
                = getenv("OQS_ENCODING_MLDSA44_RSA2048_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA44_ED25519"))
            oqs_alg_encoding_list[24] = getenv("OQS_ENCODING_MLDSA44_ED25519");
        if (getenv("OQS_ENCODING_MLDSA44_ED25519_ALGNAME"))
            oqs_alg_encoding_list[25]
                = getenv("OQS_ENCODING_MLDSA44_ED25519_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA44_P256"))
            oqs_alg_encoding_list[26] = getenv("OQS_ENCODING_MLDSA44_P256");
        if (getenv("OQS_ENCODING_MLDSA44_P256_ALGNAME"))
            oqs_alg_encoding_list[27]
                = getenv("OQS_ENCODING_MLDSA44_P256_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA44_BP256"))
            oqs_alg_encoding_list[28] = getenv("OQS_ENCODING_MLDSA44_BP256");
        if (getenv("OQS_ENCODING_MLDSA44_BP256_ALGNAME"))
            oqs_alg_encoding_list[29]
                = getenv("OQS_ENCODING_MLDSA44_BP256_ALGNAME");
        if ((envval = getenv("OQS_ENCODING_MLDSA65")))
            oqs_alg_encoding_list[30] = envval;
        if ((envval = getenv("OQS_ENCODING_MLDSA65_ALGNAME")))
            oqs_alg_encoding_list[31] = envval;
        if ((envval = getenv("OQS_ENCODING_P384_MLDSA65")))
            oqs_alg_encoding_list[32] = envval;
        if ((envval = getenv("OQS_ENCODING_P384_MLDSA65_ALGNAME")))
            oqs_alg_encoding_list[33] = envval;
        if (getenv("OQS_ENCODING_MLDSA65_PSS3072"))
            oqs_alg_encoding_list[34] = getenv("OQS_ENCODING_MLDSA65_PSS3072");
        if (getenv("OQS_ENCODING_MLDSA65_PSS3072_ALGNAME"))
            oqs_alg_encoding_list[35]
                = getenv("OQS_ENCODING_MLDSA65_PSS3072_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA65_RSA3072"))
            oqs_alg_encoding_list[36] = getenv("OQS_ENCODING_MLDSA65_RSA3072");
        if (getenv("OQS_ENCODING_MLDSA65_RSA3072_ALGNAME"))
            oqs_alg_encoding_list[37]
                = getenv("OQS_ENCODING_MLDSA65_RSA3072_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA65_P256"))
            oqs_alg_encoding_list[38] = getenv("OQS_ENCODING_MLDSA65_P256");
        if (getenv("OQS_ENCODING_MLDSA65_P256_ALGNAME"))
            oqs_alg_encoding_list[39]
                = getenv("OQS_ENCODING_MLDSA65_P256_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA65_BP256"))
            oqs_alg_encoding_list[40] = getenv("OQS_ENCODING_MLDSA65_BP256");
        if (getenv("OQS_ENCODING_MLDSA65_BP256_ALGNAME"))
            oqs_alg_encoding_list[41]
                = getenv("OQS_ENCODING_MLDSA65_BP256_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA65_ED25519"))
            oqs_alg_encoding_list[42] = getenv("OQS_ENCODING_MLDSA65_ED25519");
        if (getenv("OQS_ENCODING_MLDSA65_ED25519_ALGNAME"))
            oqs_alg_encoding_list[43]
                = getenv("OQS_ENCODING_MLDSA65_ED25519_ALGNAME");
        if ((envval = getenv("OQS_ENCODING_MLDSA87")))
            oqs_alg_encoding_list[44] = envval;
        if ((envval = getenv("OQS_ENCODING_MLDSA87_ALGNAME")))
            oqs_alg_encoding_list[45] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_MLDSA87")))
            oqs_alg_encoding_list[46] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_MLDSA87_ALGNAME")))
            oqs_alg_encoding_list[47] = envval;
        if (getenv("OQS_ENCODING_MLDSA87_P384"))
            oqs_alg_encoding_list[48] = getenv("OQS_ENCODING_MLDSA87_P384");
        if (getenv("OQS_ENCODING_MLDSA87_P384_ALGNAME"))
            oqs_alg_encoding_list[49]
                = getenv("OQS_ENCODING_MLDSA87_P384_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA87_BP384"))
            oqs_alg_encoding_list[50] = getenv("OQS_ENCODING_MLDSA87_BP384");
        if (getenv("OQS_ENCODING_MLDSA87_BP384_ALGNAME"))
            oqs_alg_encoding_list[51]
                = getenv("OQS_ENCODING_MLDSA87_BP384_ALGNAME");
        if (getenv("OQS_ENCODING_MLDSA87_ED448"))
            oqs_alg_encoding_list[52] = getenv("OQS_ENCODING_MLDSA87_ED448");
        if (getenv("OQS_ENCODING_MLDSA87_ED448_ALGNAME"))
            oqs_alg_encoding_list[53]
                = getenv("OQS_ENCODING_MLDSA87_ED448_ALGNAME");
        if ((envval = getenv("OQS_ENCODING_FALCON512")))
            oqs_alg_encoding_list[54] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCON512_ALGNAME")))
            oqs_alg_encoding_list[55] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_FALCON512")))
            oqs_alg_encoding_list[56] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_FALCON512_ALGNAME")))
            oqs_alg_encoding_list[57] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_FALCON512")))
            oqs_alg_encoding_list[58] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_FALCON512_ALGNAME")))
            oqs_alg_encoding_list[59] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCONPADDED512")))
            oqs_alg_encoding_list[60] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCONPADDED512_ALGNAME")))
            oqs_alg_encoding_list[61] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_FALCONPADDED512")))
            oqs_alg_encoding_list[62] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_FALCONPADDED512_ALGNAME")))
            oqs_alg_encoding_list[63] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_FALCONPADDED512")))
            oqs_alg_encoding_list[64] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_FALCONPADDED512_ALGNAME")))
            oqs_alg_encoding_list[65] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCON1024")))
            oqs_alg_encoding_list[66] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCON1024_ALGNAME")))
            oqs_alg_encoding_list[67] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_FALCON1024")))
            oqs_alg_encoding_list[68] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_FALCON1024_ALGNAME")))
            oqs_alg_encoding_list[69] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCONPADDED1024")))
            oqs_alg_encoding_list[70] = envval;
        if ((envval = getenv("OQS_ENCODING_FALCONPADDED1024_ALGNAME")))
            oqs_alg_encoding_list[71] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_FALCONPADDED1024")))
            oqs_alg_encoding_list[72] = envval;
        if ((envval = getenv("OQS_ENCODING_P521_FALCONPADDED1024_ALGNAME")))
            oqs_alg_encoding_list[73] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHA2128FSIMPLE")))
            oqs_alg_encoding_list[74] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHA2128FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[75] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_SPHINCSSHA2128FSIMPLE")))
            oqs_alg_encoding_list[76] = envval;
        if ((envval
             = getenv("OQS_ENCODING_P256_SPHINCSSHA2128FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[77] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE")))
            oqs_alg_encoding_list[78] = envval;
        if ((envval
             = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[79] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHA2128SSIMPLE")))
            oqs_alg_encoding_list[80] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHA2128SSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[81] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_SPHINCSSHA2128SSIMPLE")))
            oqs_alg_encoding_list[82] = envval;
        if ((envval
             = getenv("OQS_ENCODING_P256_SPHINCSSHA2128SSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[83] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE")))
            oqs_alg_encoding_list[84] = envval;
        if ((envval
             = getenv("OQS_ENCODING_RSA3072_SPHINCSSHA2128SSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[85] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHA2192FSIMPLE")))
            oqs_alg_encoding_list[86] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHA2192FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[87] = envval;
        if ((envval = getenv("OQS_ENCODING_P384_SPHINCSSHA2192FSIMPLE")))
            oqs_alg_encoding_list[88] = envval;
        if ((envval
             = getenv("OQS_ENCODING_P384_SPHINCSSHA2192FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[89] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHAKE128FSIMPLE")))
            oqs_alg_encoding_list[90] = envval;
        if ((envval = getenv("OQS_ENCODING_SPHINCSSHAKE128FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[91] = envval;
        if ((envval = getenv("OQS_ENCODING_P256_SPHINCSSHAKE128FSIMPLE")))
            oqs_alg_encoding_list[92] = envval;
        if ((envval
             = getenv("OQS_ENCODING_P256_SPHINCSSHAKE128FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[93] = envval;
        if ((envval = getenv("OQS_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE")))
            oqs_alg_encoding_list[94] = envval;
        if ((envval
             = getenv("OQS_ENCODING_RSA3072_SPHINCSSHAKE128FSIMPLE_ALGNAME")))
            oqs_alg_encoding_list[95] = envval;
    }
    ///// OQS_TEMPLATE_FRAGMENT_ENCODING_PATCHING_END
    return 1;
}
#endif /* USE_ENCODING_LIB */


#define SIGALG(NAMES, SECBITS, FUNC)                                          \
    {                                                                         \
        NAMES, "provider=lunaprov,lunaprov.security_bits=" #SECBITS "", \
            FUNC                                                              \
    }
#define KEMBASEALG(NAMES, SECBITS)                                  \
    {"" #NAMES "",                                                  \
     "provider=lunaprov,lunaprov.security_bits=" #SECBITS "", \
     oqs_generic_kem_functions},

#define KEMHYBALG(NAMES, SECBITS)                                   \
    {"" #NAMES "",                                                  \
     "provider=lunaprov,lunaprov.security_bits=" #SECBITS "", \
     oqs_hybrid_kem_functions},

#define KEMKMALG(NAMES, SECBITS)                                    \
    {"" #NAMES "",                                                  \
     "provider=lunaprov,lunaprov.security_bits=" #SECBITS "", \
     oqs_##NAMES##_keymgmt_functions},

#define KEMKMHYBALG(NAMES, SECBITS, HYBTYPE)                        \
    {"" #NAMES "",                                                  \
     "provider=lunaprov,lunaprov.security_bits=" #SECBITS "", \
     oqs_##HYBTYPE##_##NAMES##_keymgmt_functions},

#endif /* LUNA_OQS */

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM luna_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

#ifdef LUNA_OQS

// get the last number on the composite OID
int get_composite_idx(int idx)
{
    char *s;
    int i, len, ret = -1, count = 0;

    if ( (idx < 0) || (idx >= (OQS_OID_CNT / 2)) )
        return 0;
    s = (char *)oqs_oid_alg_list[idx * 2];
    len = strlen(s);

    for (i = 0; i < len; i++) {
        if (s[i] == '.') {
            count += 1;
        }
        if (count == 8) { // 8 dots in composite OID
            errno = 0;
            ret = strtol(s + i + 1, NULL, 10);
            if (errno == ERANGE)
                ret = -1;
            break;
        }
    }
    return ret;
}

#endif

static const OSSL_PARAM *luna_gettable_params(void *provctx)
{
    return luna_param_types;
}

static int luna_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, LUNA_PROV_NAME_SZ))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, LUNA_PROV_VERSION_SZ))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, LUNA_PROV_BUILDINFO_SZ))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, luna_prov_is_running()))
        return 0;
    return 1;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 *
 * Algorithm names are case insensitive, but we use all caps in our "canonical"
 * names for consistency.
 */
static const OSSL_ALGORITHM luna_digests[] = {
    /* Our primary name:NIST name[:our older names] */

#if 0 // NOTE: disabled for now
    { PROV_NAMES_SHA1, LUNA_PROV_EQUALS_SZ, luna_sha1_functions },
    { PROV_NAMES_SHA2_224, LUNA_PROV_EQUALS_SZ, luna_sha224_functions },
    { PROV_NAMES_SHA2_256, LUNA_PROV_EQUALS_SZ, luna_sha256_functions },
    { PROV_NAMES_SHA2_384, LUNA_PROV_EQUALS_SZ, luna_sha384_functions },
    { PROV_NAMES_SHA2_512, LUNA_PROV_EQUALS_SZ, luna_sha512_functions },

    /* We agree with NIST here, so one name only */
    { PROV_NAMES_SHA3_224, LUNA_PROV_EQUALS_SZ, luna_sha3_224_functions },
    { PROV_NAMES_SHA3_256, LUNA_PROV_EQUALS_SZ, luna_sha3_256_functions },
    { PROV_NAMES_SHA3_384, LUNA_PROV_EQUALS_SZ, luna_sha3_384_functions },
    { PROV_NAMES_SHA3_512, LUNA_PROV_EQUALS_SZ, luna_sha3_512_functions },

#ifndef OPENSSL_NO_SM3
    { PROV_NAMES_SM3, LUNA_PROV_EQUALS_SZ, luna_ossl_sm3_functions },
#endif /* OPENSSL_NO_SM3 */

    { PROV_NAMES_NULL, LUNA_PROV_EQUALS_SZ, luna_ossl_nullmd_functions },
#endif

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE luna_ciphers[] = {
    // NOTE: empty for now
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_ciphers[OSSL_NELEM(luna_ciphers)];

static const OSSL_ALGORITHM luna_macs[] = {
    // NOTE: empty for now
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM luna_kdfs[] = {
    // NOTE: empty for now
    { NULL, NULL, NULL }
};

// list of key exchange algorithms reported to application
static const OSSL_ALGORITHM luna_keyexch[] = {
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_ECDH, LUNA_PROV_EQUALS_SZ, luna_ecdh_keyexch_functions },
# ifdef LUNA_OQS
    { PROV_NAMES_X25519, LUNA_PROV_EQUALS_SZ, luna_x25519_keyexch_functions },
    { PROV_NAMES_X448, LUNA_PROV_EQUALS_SZ, luna_x448_keyexch_functions },
# endif /* LUNA_OQS */
#endif /* OPENSSL_NO_EC */
    // NOTE: { PROV_NAMES_HKDF, LUNA_PROV_EQUALS_SZ, luna_ossl_kdf_hkdf_keyexch_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM luna_rands[] = {
#if 0 // NOTE: disabled for now
    { PROV_NAMES_CTR_DRBG, LUNA_PROV_EQUALS_SZ, luna_ossl_drbg_ctr_functions },
    { PROV_NAMES_HASH_DRBG, LUNA_PROV_EQUALS_SZ, luna_ossl_drbg_hash_functions },
    { PROV_NAMES_HMAC_DRBG, LUNA_PROV_EQUALS_SZ, luna_ossl_drbg_ossl_hmac_functions },
    { PROV_NAMES_SEED_SRC, LUNA_PROV_EQUALS_SZ, luna_ossl_seed_src_functions },
    { PROV_NAMES_TEST_RAND, LUNA_PROV_EQUALS_SZ, luna_ossl_test_rng_functions },
#endif
    { NULL, NULL, NULL }
};

// list of signature algorithms reported to application
// NOTE: the signing keys (persistent keys) must be in HSM
static const OSSL_ALGORITHM luna_signature[] = {
#ifndef OPENSSL_NO_DSA
    { PROV_NAMES_DSA, LUNA_PROV_EQUALS_SZ, luna_dsa_signature_functions },
#endif
    { PROV_NAMES_RSA, LUNA_PROV_EQUALS_SZ, luna_rsa_signature_functions },
#ifndef OPENSSL_NO_EC
# ifdef LUNA_OQS
    { PROV_NAMES_ED25519, LUNA_PROV_EQUALS_SZ, luna_ed25519_signature_functions },
    { PROV_NAMES_ED448, LUNA_PROV_EQUALS_SZ, luna_ed448_signature_functions },
# endif /* LUNA_OQS */
    { PROV_NAMES_ECDSA, LUNA_PROV_EQUALS_SZ, luna_ec_signature_functions },
# ifndef OPENSSL_NO_SM2
    //{ PROV_NAMES_SM2, LUNA_PROV_EQUALS_SZ, luna_sm2_signature_functions },
# endif /* OPENSSL_NO_SM2 */
#endif /* OPENSSL_NO_EC */
#ifdef LUNA_OQS
#ifdef OQS_ENABLE_SIG_dilithium_2
    SIGALG("dilithium2", 128, oqs_signature_functions),
    SIGALG("p256_dilithium2", 128, oqs_signature_functions),
    SIGALG("rsa3072_dilithium2", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
    SIGALG("dilithium3", 192, oqs_signature_functions),
    SIGALG("p384_dilithium3", 192, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
    SIGALG("dilithium5", 256, oqs_signature_functions),
    SIGALG("p521_dilithium5", 256, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_44
    SIGALG(LUNA_PROV_NAMES_ML_DSA_44, 128, oqs_signature_functions),
    SIGALG("p256_mldsa44", 128, oqs_signature_functions),
    SIGALG("rsa3072_mldsa44", 128, oqs_signature_functions),
    SIGALG("mldsa44_pss2048", 112, oqs_signature_functions),
    SIGALG("mldsa44_rsa2048", 112, oqs_signature_functions),
    SIGALG("mldsa44_ed25519", 128, oqs_signature_functions),
    SIGALG("mldsa44_p256", 128, oqs_signature_functions),
    SIGALG("mldsa44_bp256", 256, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65
    SIGALG(LUNA_PROV_NAMES_ML_DSA_65, 192, oqs_signature_functions),
    SIGALG("p384_mldsa65", 192, oqs_signature_functions),
    SIGALG("mldsa65_pss3072", 128, oqs_signature_functions),
    SIGALG("mldsa65_rsa3072", 128, oqs_signature_functions),
    SIGALG("mldsa65_p256", 128, oqs_signature_functions),
    SIGALG("mldsa65_bp256", 256, oqs_signature_functions),
    SIGALG("mldsa65_ed25519", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87
    SIGALG(LUNA_PROV_NAMES_ML_DSA_87, 256, oqs_signature_functions),
    SIGALG("p521_mldsa87", 256, oqs_signature_functions),
    SIGALG("mldsa87_p384", 192, oqs_signature_functions),
    SIGALG("mldsa87_bp384", 384, oqs_signature_functions),
    SIGALG("mldsa87_ed448", 192, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    SIGALG("falcon512", 128, oqs_signature_functions),
    SIGALG("p256_falcon512", 128, oqs_signature_functions),
    SIGALG("rsa3072_falcon512", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_512
    SIGALG("falconpadded512", 128, oqs_signature_functions),
    SIGALG("p256_falconpadded512", 128, oqs_signature_functions),
    SIGALG("rsa3072_falconpadded512", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    SIGALG("falcon1024", 256, oqs_signature_functions),
    SIGALG("p521_falcon1024", 256, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_1024
    SIGALG("falconpadded1024", 256, oqs_signature_functions),
    SIGALG("p521_falconpadded1024", 256, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
    SIGALG("sphincssha2128fsimple", 128, oqs_signature_functions),
    SIGALG("p256_sphincssha2128fsimple", 128, oqs_signature_functions),
    SIGALG("rsa3072_sphincssha2128fsimple", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
    SIGALG("sphincssha2128ssimple", 128, oqs_signature_functions),
    SIGALG("p256_sphincssha2128ssimple", 128, oqs_signature_functions),
    SIGALG("rsa3072_sphincssha2128ssimple", 128, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
    SIGALG("sphincssha2192fsimple", 192, oqs_signature_functions),
    SIGALG("p384_sphincssha2192fsimple", 192, oqs_signature_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
    SIGALG("sphincsshake128fsimple", 128, oqs_signature_functions),
    SIGALG("p256_sphincsshake128fsimple", 128, oqs_signature_functions),
    SIGALG("rsa3072_sphincsshake128fsimple", 128, oqs_signature_functions),
#endif
#endif /* LUNA_OQS */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM luna_asym_cipher[] = {
    { PROV_NAMES_RSA, LUNA_PROV_EQUALS_SZ, luna_rsa_asym_cipher_functions },
#ifndef OPENSSL_NO_SM2
    // NOTE: { PROV_NAMES_SM2, LUNA_PROV_EQUALS_SZ, luna_sm2_asym_cipher_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM luna_asym_kem[] = {
    // NOTE: { PROV_NAMES_RSA, LUNA_PROV_EQUALS_SZ, luna_rsa_asym_kem_functions },
#ifdef LUNA_OQS
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMBASEALG(kyber512, 128)
    KEMHYBALG(p256_kyber512, 128)
    KEMHYBALG(x25519_kyber512, 128)
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMBASEALG(kyber768, 192)
    KEMHYBALG(p384_kyber768, 192)
    KEMHYBALG(x448_kyber768, 192)
    KEMHYBALG(x25519_kyber768, 128)
    KEMHYBALG(p256_kyber768, 128)
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMBASEALG(kyber1024, 256)
    KEMHYBALG(p521_kyber1024, 256)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
    KEMBASEALG(mlkem512, 128)
    KEMHYBALG(p256_mlkem512, 128)
    KEMHYBALG(x25519_mlkem512, 128)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    KEMBASEALG(mlkem768, 192)
    KEMHYBALG(p384_mlkem768, 192)
    KEMHYBALG(x448_mlkem768, 192)
    KEMHYBALG(x25519_mlkem768, 128)
    KEMHYBALG(p256_mlkem768, 128)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    KEMBASEALG(mlkem1024, 256)
    KEMHYBALG(p521_mlkem1024, 256)
    KEMHYBALG(p384_mlkem1024, 192)
#endif
#endif /* LUNA_OQS */
    { NULL, NULL, NULL }
};

// list of keymgmt algorithms reported to application
// NOTE: the signing keys (persistent keys) must be in HSM
static const OSSL_ALGORITHM luna_keymgmt[] = {
#ifndef OPENSSL_NO_DSA
    { PROV_NAMES_DSA, LUNA_PROV_EQUALS_SZ, luna_dsa_keymgmt_functions,
      PROV_DESCS_DSA},
#endif
    { PROV_NAMES_RSA, LUNA_PROV_EQUALS_SZ, luna_rsa_keymgmt_functions,
      PROV_DESCS_RSA },
    { PROV_NAMES_RSA_PSS, LUNA_PROV_EQUALS_SZ, luna_rsapss_keymgmt_functions,
      PROV_DESCS_RSA_PSS },
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_EC, LUNA_PROV_EQUALS_SZ, luna_ec_keymgmt_functions,
      PROV_DESCS_EC },
# ifndef OPENSSL_NO_ECX
#  ifdef LUNA_OQS
    { PROV_NAMES_X25519, LUNA_PROV_EQUALS_SZ, luna_x25519_keymgmt_functions, PROV_DESCS_X25519 },
    { PROV_NAMES_X448, LUNA_PROV_EQUALS_SZ, luna_x448_keymgmt_functions, PROV_DESCS_X448 },
    { PROV_NAMES_ED25519, LUNA_PROV_EQUALS_SZ, luna_ed25519_keymgmt_functions,
      PROV_DESCS_ED25519 },
    { PROV_NAMES_ED448, LUNA_PROV_EQUALS_SZ, luna_ed448_keymgmt_functions,
      PROV_DESCS_ED448 },
#  endif /* LUNA_OQS */
# endif /* OPENSSL_NO_ECX */
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_SM2
    //{ PROV_NAMES_SM2, LUNA_PROV_EQUALS_SZ, luna_sm2_keymgmt_functions, PROV_DESCS_SM2 },
#endif

#ifdef LUNA_OQS
#ifdef OQS_ENABLE_SIG_dilithium_2
    SIGALG("dilithium2", 128, oqs_dilithium2_keymgmt_functions),
    SIGALG("p256_dilithium2", 128, oqs_p256_dilithium2_keymgmt_functions),
    SIGALG("rsa3072_dilithium2", 128, oqs_rsa3072_dilithium2_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
    SIGALG("dilithium3", 192, oqs_dilithium3_keymgmt_functions),
    SIGALG("p384_dilithium3", 192, oqs_p384_dilithium3_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
    SIGALG("dilithium5", 256, oqs_dilithium5_keymgmt_functions),
    SIGALG("p521_dilithium5", 256, oqs_p521_dilithium5_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_44
    SIGALG(LUNA_PROV_NAMES_ML_DSA_44, 128, oqs_mldsa44_keymgmt_functions),
    SIGALG("p256_mldsa44", 128, oqs_p256_mldsa44_keymgmt_functions),
    SIGALG("rsa3072_mldsa44", 128, oqs_rsa3072_mldsa44_keymgmt_functions),
    SIGALG("mldsa44_pss2048", 112, oqs_mldsa44_pss2048_keymgmt_functions),
    SIGALG("mldsa44_rsa2048", 112, oqs_mldsa44_rsa2048_keymgmt_functions),
    SIGALG("mldsa44_ed25519", 128, oqs_mldsa44_ed25519_keymgmt_functions),
    SIGALG("mldsa44_p256", 128, oqs_mldsa44_p256_keymgmt_functions),
    SIGALG("mldsa44_bp256", 256, oqs_mldsa44_bp256_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65
    SIGALG(LUNA_PROV_NAMES_ML_DSA_65, 192, oqs_mldsa65_keymgmt_functions),
    SIGALG("p384_mldsa65", 192, oqs_p384_mldsa65_keymgmt_functions),
    SIGALG("mldsa65_pss3072", 128, oqs_mldsa65_pss3072_keymgmt_functions),
    SIGALG("mldsa65_rsa3072", 128, oqs_mldsa65_rsa3072_keymgmt_functions),
    SIGALG("mldsa65_p256", 128, oqs_mldsa65_p256_keymgmt_functions),
    SIGALG("mldsa65_bp256", 256, oqs_mldsa65_bp256_keymgmt_functions),
    SIGALG("mldsa65_ed25519", 128, oqs_mldsa65_ed25519_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87
    SIGALG(LUNA_PROV_NAMES_ML_DSA_87, 256, oqs_mldsa87_keymgmt_functions),
    SIGALG("p521_mldsa87", 256, oqs_p521_mldsa87_keymgmt_functions),
    SIGALG("mldsa87_p384", 192, oqs_mldsa87_p384_keymgmt_functions),
    SIGALG("mldsa87_bp384", 384, oqs_mldsa87_bp384_keymgmt_functions),
    SIGALG("mldsa87_ed448", 192, oqs_mldsa87_ed448_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    SIGALG("falcon512", 128, oqs_falcon512_keymgmt_functions),
    SIGALG("p256_falcon512", 128, oqs_p256_falcon512_keymgmt_functions),
    SIGALG("rsa3072_falcon512", 128, oqs_rsa3072_falcon512_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_512
    SIGALG("falconpadded512", 128, oqs_falconpadded512_keymgmt_functions),
    SIGALG("p256_falconpadded512", 128, oqs_p256_falconpadded512_keymgmt_functions),
    SIGALG("rsa3072_falconpadded512", 128, oqs_rsa3072_falconpadded512_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    SIGALG("falcon1024", 256, oqs_falcon1024_keymgmt_functions),
    SIGALG("p521_falcon1024", 256, oqs_p521_falcon1024_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_1024
    SIGALG("falconpadded1024", 256, oqs_falconpadded1024_keymgmt_functions),
    SIGALG("p521_falconpadded1024", 256, oqs_p521_falconpadded1024_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
    SIGALG("sphincssha2128fsimple", 128, oqs_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("p256_sphincssha2128fsimple", 128, oqs_p256_sphincssha2128fsimple_keymgmt_functions),
    SIGALG("rsa3072_sphincssha2128fsimple", 128, oqs_rsa3072_sphincssha2128fsimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
    SIGALG("sphincssha2128ssimple", 128, oqs_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("p256_sphincssha2128ssimple", 128, oqs_p256_sphincssha2128ssimple_keymgmt_functions),
    SIGALG("rsa3072_sphincssha2128ssimple", 128, oqs_rsa3072_sphincssha2128ssimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
    SIGALG("sphincssha2192fsimple", 192, oqs_sphincssha2192fsimple_keymgmt_functions),
    SIGALG("p384_sphincssha2192fsimple", 192, oqs_p384_sphincssha2192fsimple_keymgmt_functions),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
    SIGALG("sphincsshake128fsimple", 128, oqs_sphincsshake128fsimple_keymgmt_functions),
    SIGALG("p256_sphincsshake128fsimple", 128, oqs_p256_sphincsshake128fsimple_keymgmt_functions),
    SIGALG("rsa3072_sphincsshake128fsimple", 128, oqs_rsa3072_sphincsshake128fsimple_keymgmt_functions),
#endif

#ifdef OQS_ENABLE_KEM_kyber_512
    KEMKMALG(kyber512, 128)

    KEMKMHYBALG(p256_kyber512, 128, ecp)
    KEMKMHYBALG(x25519_kyber512, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMKMALG(kyber768, 192)

    KEMKMHYBALG(p384_kyber768, 192, ecp)
    KEMKMHYBALG(x448_kyber768, 192, ecx)
    KEMKMHYBALG(x25519_kyber768, 128, ecx)
    KEMKMHYBALG(p256_kyber768, 128, ecp)
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMKMALG(kyber1024, 256)

    KEMKMHYBALG(p521_kyber1024, 256, ecp)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
    KEMKMALG(mlkem512, 128)

    KEMKMHYBALG(p256_mlkem512, 128, ecp)
    KEMKMHYBALG(x25519_mlkem512, 128, ecx)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    KEMKMALG(mlkem768, 192)

    KEMKMHYBALG(p384_mlkem768, 192, ecp)
    KEMKMHYBALG(x448_mlkem768, 192, ecx)
    KEMKMHYBALG(x25519_mlkem768, 128, ecx)
    KEMKMHYBALG(p256_mlkem768, 128, ecp)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    KEMKMALG(mlkem1024, 256)

    KEMKMHYBALG(p521_mlkem1024, 256, ecp)
    KEMKMHYBALG(p384_mlkem1024, 192, ecp)
#endif
#endif  /* LUNA_OQS */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM luna_encoder[] = {
#define ENCODER_PROVIDER LUNA_PROV_SZ
#include "luna_encoders.inc"
#ifdef LUNA_OQS
#undef ENCODER
#undef ENCODER_TEXT
#undef ENCODER_w_structure
#include "oqsencoders.inc"
#endif
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM luna_decoder[] = {
#define DECODER_PROVIDER LUNA_PROV_SZ
#include "luna_decoders.inc"
#ifdef LUNA_OQS
#undef DECODER
#undef DECODER_TEXT
#undef DECODER_w_structure
#include "oqsdecoders.inc"
#endif
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};

static const OSSL_ALGORITHM luna_store[] = {
    { "file", LUNA_PROV_EQUALS_SZ, luna_file_store_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *luna_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return luna_digests;
    case OSSL_OP_CIPHER:
        return exported_ciphers;
    case OSSL_OP_MAC:
        return luna_macs;
    case OSSL_OP_KDF:
        return luna_kdfs;
    case OSSL_OP_RAND:
        return luna_rands;
    case OSSL_OP_KEYMGMT:
        return luna_keymgmt;
    case OSSL_OP_KEYEXCH:
        return luna_keyexch;
    case OSSL_OP_SIGNATURE:
        return luna_signature;
    case OSSL_OP_ASYM_CIPHER:
        return luna_asym_cipher;
    case OSSL_OP_KEM:
        return luna_asym_kem;
    case OSSL_OP_ENCODER:
        return luna_encoder;
    case OSSL_OP_DECODER:
        return luna_decoder;
    case OSSL_OP_STORE:
        return luna_store;
    default:
        LUNA_PRINTF(("Unknown operation %d requested from OQS provider\n", operation_id));
        break;
    }
    return NULL;
}

static luna_prov_ctx *luna_prov_ctx_new(
    OSSL_LIB_CTX *libctx,
    const OSSL_CORE_HANDLE *handle,
    BIO_METHOD *corebiometh) {
    luna_prov_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    // for reference:
    //   ossl_prov_ctx_set0_libctx(ctx, (OSSL_LIB_CTX *)c_get_libctx(handle));
    //   ossl_prov_ctx_set0_handle(ctx, handle);
    //   ossl_prov_ctx_set0_core_bio_method(ctx, corebiometh);
    ctx->libctx = libctx;
    ctx->handle = handle;
    ctx->corebiometh = corebiometh;
#ifdef LUNA_OQS
    ctx->oqsctx = oqsx_newprovctx(libctx, handle, corebiometh);
#endif
    return ctx;
}

static void luna_prov_ctx_free(luna_prov_ctx *ctx) {
    if (ctx == NULL)
        return;
#ifdef LUNA_OQS
    if (ctx->oqsctx != NULL) {
        ctx->oqsctx->corebiometh = NULL; /* avoid double deletion */
        ctx->oqsctx->handle = NULL;
        ctx->oqsctx->libctx = NULL;
        oqsx_freeprovctx(ctx->oqsctx);
    }
#endif
    OSSL_LIB_CTX_free(ctx->libctx);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}

static void luna_teardown(void *provctx)
{
    luna_prov_ctx *ctx = (luna_prov_ctx*)provctx;
    if (ctx == NULL)
        return;
    luna_prov_engine_fini();
    luna_prov_ctx_free(ctx);
}

#ifdef LUNA_OQS

static
int luna_prov_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg)
{
    luna_prov_ctx *lunactx = (luna_prov_ctx *)provctx;
    extern OSSL_FUNC_provider_get_capabilities_fn luna_oqs_provider_get_capabilities;
    return luna_oqs_provider_get_capabilities(lunactx->oqsctx, capability, cb, arg);
}

#else /* LUNA_OQS */

#include "lunaprov_capabilities.c"

static
int luna_prov_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg)
{
    luna_prov_ctx *lunactx = (luna_prov_ctx *)provctx;
    return luna_classic_provider_get_capabilities(lunactx, capability, cb, arg);
}

#endif /* LUNA_OQS */

/* Functions we provide to the core */
static const OSSL_DISPATCH luna_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))luna_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))luna_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))luna_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))luna_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))luna_prov_get_capabilities },
    { 0, NULL }
};

static
int luna_provider_init(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            luna_prov_ctx **pprovctx)
{
    const OSSL_DISPATCH *orig_in = in;
    int rc = 0;

    BIO_METHOD *corebiometh = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

#ifdef LUNA_OSSL_3_2
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    int i = 0;
#endif

    char *opensslv = NULL;
    const char *ossl_versionp = NULL;
    OSSL_PARAM version_request[] = {{"openssl-version", OSSL_PARAM_UTF8_PTR,
                                     &opensslv, sizeof(void*), 0},
                                    {NULL, 0, NULL, 0, 0}};

    luna_getenv_LUNAPROV_init();
    LUNA_PRINTF(("loading...\n"));

    // pre, warn if default or fips provider are present
    if (!OSSL_PROVIDER_available(libctx, "default")
        && !OSSL_PROVIDER_available(libctx, "fips")) {
        OQS_PROV_PRINTF("OQS PROV: pre: Default and FIPS provider not available.\n");
    } else {
        OQS_PROV_PRINTF("OQS PROV: pre: Default or FIPS provider available.\n");
    }

#ifdef LUNA_OQS
    // init liboqs
    OQS_init();
#endif

    if (!ossl_prov_bio_from_dispatch(in))
        goto end_init;

#if 0
    // NOTE: lost and found
    if (!ossl_prov_seeding_from_dispatch(in))
        goto end_init;
#endif

#ifdef LUNA_OQS
    if (!oqs_prov_bio_from_dispatch(in))
        goto end_init;

    if (!oqs_patch_codepoints())
        goto end_init;

    if (!oqs_patch_oids())
        goto end_init;

#ifdef USE_ENCODING_LIB
    if (!oqs_patch_encodings())
        goto end_init;
#endif /* USE_ENCODING_LIB */

#endif

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
#ifdef LUNA_OSSL_3_2
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
#endif
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        goto end_init;

#ifdef LUNA_OSSL_3_2
    if (c_obj_create == NULL || c_obj_add_sigid==NULL || c_get_params == NULL)
        goto end_init;

    // we need to know the version of the calling core to activate
    // suitable bug workarounds
    if (c_get_params(handle, version_request)) {
        ossl_versionp = *(void **)version_request[0].data;
    }
#endif /* LUNA_OSSL_3_2 */

#ifdef LUNA_OQS
    // insert all OIDs to the global objects list
    for (i = 0; i < OQS_OID_CNT; i += 2) {
        if (!c_obj_create(handle, oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
                          oqs_oid_alg_list[i + 1])) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            fprintf(stderr, "error registering NID for %s\n",
                    oqs_oid_alg_list[i + 1]);
            goto end_init;
        }

        /* create object (NID) again to avoid setup corner case problems
         * see https://github.com/openssl/openssl/discussions/21903
         * Not testing for errors is intentional.
         * At least one core version hangs up; so don't do this there:
         */
        if ( (ossl_versionp != NULL) && (strcmp("3.1.0", ossl_versionp) != 0) ) {
            OBJ_create(oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
                       oqs_oid_alg_list[i + 1]);
        }

        /* NOTE: openssl 3.5: update internal table of NIDs, check for algorithm naming consistency */
        if (!oqs_set_nid((char *)oqs_oid_alg_list[i + 1],
                         OBJ_sn2nid(oqs_oid_alg_list[i + 1]))) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            goto end_init;
        }

        if (!c_obj_add_sigid(handle, oqs_oid_alg_list[i + 1], "",
                             oqs_oid_alg_list[i + 1])) {
            fprintf(stderr, "error registering %s with no hash\n",
                    oqs_oid_alg_list[i + 1]);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            goto end_init;
        }

        if (OBJ_sn2nid(oqs_oid_alg_list[i + 1]) != 0) {
            OQS_PROV_PRINTF3(
                "OQS PROV: successfully registered %s with NID %d\n",
                oqs_oid_alg_list[i + 1], OBJ_sn2nid(oqs_oid_alg_list[i + 1]));
        } else {
            fprintf(stderr,
                    "OQS PROV: Impossible error: NID unregistered for %s.\n",
                    oqs_oid_alg_list[i + 1]);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
            goto end_init;
        }
    }
#endif /* LUNA_OQS */

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     */
    if ( ((corebiometh = ossl_bio_prov_init_bio_method()) == NULL) ||
         ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
         ((*pprovctx = luna_prov_ctx_new(libctx, handle, corebiometh)) == NULL) ) {
        LUNA_PRINTF(("error creating provider context\n"));
        goto end_init;
    }

    LUNA_PRINTF(("luna_prov_engine_init...\n"));
    if (luna_prov_engine_init() != 1) {
        goto end_init;
    }

    *out = luna_dispatch_table;
    // NOTE: lost and found: ossl_prov_cache_exported_algorithms(luna_ciphers, exported_ciphers);

    LUNA_PRINTF(("done.\n"));

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(libctx, "default")
        && !OSSL_PROVIDER_available(libctx, "fips")) {
        OQS_PROV_PRINTF(
            "OQS PROV: post: Default and FIPS provider not available. Errors may result.\n");
    } else {
        OQS_PROV_PRINTF("OQS PROV: post: Default or FIPS provider available.\n");
    }
    rc = 1;

end_init:
    if (!rc) {
        if (ossl_versionp) {
            OQS_PROV_PRINTF2(
                "oqsprovider init failed for OpenSSL core version %s\n",
                ossl_versionp);
        } else {
            OQS_PROV_PRINTF("oqsprovider init failed for OpenSSL\n");
        }

        if (libctx) {
            OSSL_LIB_CTX_free(libctx);
        }

        if (pprovctx && *pprovctx) {
            luna_prov_ctx_free(*pprovctx);
            *pprovctx = NULL;
        }
    }
    return rc;
}

/* the one and only entry function of our provider */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    luna_prov_ctx **pprovctx = (luna_prov_ctx**)provctx;
    return luna_provider_init(handle, in, out, pprovctx);
}

