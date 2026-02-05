// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 *
 * ToDo: Adding hybrid alg support; More testing with more key types.
 */

#include "oqs_prov.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

#include "../luna_prov_minimal.h"

#ifdef NDEBUG
#    define OQS_KEM_PRINTF(a)
#    define OQS_KEM_PRINTF2(a, b)
#    define OQS_KEM_PRINTF3(a, b, c)
#else
#    define OQS_KEM_PRINTF(a) \
        if (getenv("OQSKEM")) \
        printf(a)
#    define OQS_KEM_PRINTF2(a, b) \
        if (getenv("OQSKEM"))     \
        printf(a, b)
#    define OQS_KEM_PRINTF3(a, b, c) \
        if (getenv("OQSKEM"))        \
        printf(a, b, c)
#endif // NDEBUG

static OSSL_FUNC_kem_newctx_fn oqs_kem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn oqs_kem_encaps_init;
static OSSL_FUNC_kem_encapsulate_fn oqs_qs_kem_encaps;
static OSSL_FUNC_kem_encapsulate_fn oqs_hyb_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_qs_kem_decaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_hyb_kem_decaps;
static OSSL_FUNC_kem_freectx_fn oqs_kem_freectx;

static void oqs_debug_secret(const char *fn, int rc, const unsigned char *secret, const size_t *secretlen);

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    OQSX_KEY *kem;
} PROV_OQSKEM_CTX;

/// Common KEM functions

static void *oqs_kem_newctx(void *provctx)
{
    PROV_OQSKEM_CTX *pkemctx = OPENSSL_zalloc(sizeof(PROV_OQSKEM_CTX));

    OQS_KEM_PRINTF("OQS KEM provider called: newctx\n");
    if (pkemctx == NULL)
        return NULL;
    pkemctx->libctx = PROV_OQS_LIBCTX_OF(provctx);
    // kem will only be set in init

    return pkemctx;
}

static void oqs_kem_freectx(void *vpkemctx)
{
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF("OQS KEM provider called: freectx\n");
    oqsx_key_free(pkemctx->kem);
    OPENSSL_free(pkemctx);
}

static int oqs_kem_decapsencaps_init(void *vpkemctx, void *vkem, int operation)
{
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF3("OQS KEM provider called: _init : New: %p; old: %p \n",
                    vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !oqsx_key_up_ref(vkem))
        return 0;
    oqsx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int oqs_kem_encaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[])
{
    OQS_KEM_PRINTF("OQS KEM provider called: encaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int oqs_kem_decaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[])
{
    OQS_KEM_PRINTF("OQS KEM provider called: decaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

// OPTIMIZATION: estimate buffer size
// NOTE: we need this because C_EncapsulateKey has no pkcs#11 calling convention to query length!?
#define LUNA_OQS_NO_QUERY_BUFFER_LEN 1

/// Quantum-Safe KEM functions (OQS)

static int oqs_qs_kem_encaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, unsigned char *secret,
                                     size_t *secretlen, int keyslot)
{
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *key = pkemctx->kem;

    OQS_KEM_PRINTF("OQS KEM provider called: encaps\n");
    if (key == NULL) {
        OQS_KEM_PRINTF("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }

#ifndef LUNA_OQS_NO_QUERY_BUFFER_LEN
    if (LUNA_OQS_QUERY_KEM_encaps(key->lunakeyctx) == LUNA_OQS_OK) {
        /* NOTE: LUNA_OQS_KEM_encaps will retrieve 'key->comp_pubkey[keyslot]' */
        return OQS_SUCCESS == LUNA_OQS_KEM_encaps(key->lunakeyctx,
            out, outlen,
            secret, secretlen);
    }
#endif

    if (pkemctx->kem->comp_pubkey == NULL
        || pkemctx->kem->comp_pubkey[keyslot] == NULL) {
        OQS_KEM_PRINTF("OQS Warning: public key is NULL\n");
        return -1;
    }

    const OQS_KEM *kem_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    if (out == NULL || secret == NULL) {
        if (outlen != NULL) {
            *outlen = kem_ctx->length_ciphertext;
        }
        if (secretlen != NULL) {
            *secretlen = kem_ctx->length_shared_secret;
        }
        OQS_KEM_PRINTF3("KEM returning lengths %ld and %ld\n",
                        kem_ctx->length_ciphertext,
                        kem_ctx->length_shared_secret);
        return 1;
    }
    if (outlen == NULL) {
        OQS_KEM_PRINTF("OQS Warning: outlen is NULL\n");
        return -1;
    }
    if (secretlen == NULL) {
        OQS_KEM_PRINTF("OQS Warning: secretlen is NULL\n");
        return -1;
    }
    if (*outlen < kem_ctx->length_ciphertext) {
        OQS_KEM_PRINTF("OQS Warning: out buffer too small\n");
        return -1;
    }
    if (*secretlen < kem_ctx->length_shared_secret) {
        OQS_KEM_PRINTF("OQS Warning: secret buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_ciphertext;
    *secretlen = kem_ctx->length_shared_secret;

#ifdef LUNA_OQS_NO_QUERY_BUFFER_LEN
    if (LUNA_OQS_QUERY_KEM_encaps(key->lunakeyctx) == LUNA_OQS_OK) {
        /* NOTE: LUNA_OQS_KEM_encaps will retrieve 'key->comp_pubkey[keyslot]' */
        return OQS_SUCCESS == LUNA_OQS_KEM_encaps(key->lunakeyctx,
            out, outlen,
            secret, secretlen);
    }
#endif

    return OQS_SUCCESS
           == OQS_KEM_encaps(kem_ctx, out, secret,
                             pkemctx->kem->comp_pubkey[keyslot]);
}

static int oqs_qs_kem_decaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, const unsigned char *in,
                                     size_t inlen, int keyslot)
{
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *key = pkemctx->kem;

    OQS_KEM_PRINTF("OQS KEM provider called: decaps\n");
    if (key == NULL) {
        OQS_KEM_PRINTF("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }

#ifndef LUNA_OQS_NO_QUERY_BUFFER_LEN
    if (LUNA_OQS_QUERY_KEM_decaps(key->lunakeyctx) == LUNA_OQS_OK) {
        /* NOTE: LUNA_OQS_KEM_decaps will retrieve 'key->comp_privkey[keyslot]' */
        return OQS_SUCCESS == LUNA_OQS_KEM_decaps(key->lunakeyctx,
            out, outlen,
            in, inlen);
    }
#endif

    if (pkemctx->kem->comp_privkey == NULL
        || pkemctx->kem->comp_privkey[keyslot] == NULL) {
        OQS_KEM_PRINTF("OQS Warning: private key is NULL\n");
        return -1;
    }

    const OQS_KEM *kem_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    if (out == NULL) {
        if (outlen != NULL) {
            *outlen = kem_ctx->length_shared_secret;
        }
        OQS_KEM_PRINTF2("KEM returning length %ld\n",
                        kem_ctx->length_shared_secret);
        return 1;
    }
    if (inlen != kem_ctx->length_ciphertext) {
        OQS_KEM_PRINTF("OQS Warning: wrong input length\n");
        return 0;
    }
    if (in == NULL) {
        OQS_KEM_PRINTF("OQS Warning: in is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        OQS_KEM_PRINTF("OQS Warning: outlen is NULL\n");
        return -1;
    }
    if (*outlen < kem_ctx->length_shared_secret) {
        OQS_KEM_PRINTF("OQS Warning: out buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_shared_secret;

#ifdef LUNA_OQS_NO_QUERY_BUFFER_LEN
    if (LUNA_OQS_QUERY_KEM_decaps(key->lunakeyctx) == LUNA_OQS_OK) {
        /* NOTE: LUNA_OQS_KEM_decaps will retrieve 'key->comp_privkey[keyslot]' */
        return OQS_SUCCESS == LUNA_OQS_KEM_decaps(key->lunakeyctx,
            out, outlen,
            in, inlen);
    }
#endif

    return OQS_SUCCESS
           == OQS_KEM_decaps(kem_ctx, out, in,
                             pkemctx->kem->comp_privkey[keyslot]);
}

static int oqs_qs_kem_encaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             unsigned char *secret, size_t *secretlen)
{
    /* NOTE: keyslot=0 is ok, because this function is called for the non-hybrid testcase only */
    int rc =  oqs_qs_kem_encaps_keyslot(vpkemctx, out, outlen, secret, secretlen, 0);
    oqs_debug_secret("oqs_qs_kem_encaps:out:", rc, out, outlen);
    oqs_debug_secret("oqs_qs_kem_encaps:secret:", rc, secret, secretlen);
    return rc;
}

static int oqs_qs_kem_decaps(void *vpkemctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen)
{
    /* NOTE: keyslot=0 is ok, because this function is called for the non-hybrid testcase only */
    oqs_debug_secret("oqs_qs_kem_decaps:in:", 1, in, &inlen);
    int rc = oqs_qs_kem_decaps_keyslot(vpkemctx, out, outlen, in, inlen, 0);
    oqs_debug_secret("oqs_qs_kem_decaps:out:", rc, out, outlen);
    return rc;
}

/// EVP KEM functions

static int oqs_evp_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct,
                                      size_t *ctlen, unsigned char *secret,
                                      size_t *secretlen, int keyslot,
                                      int flagPqcKeyInHardware)
{
    int ret = OQS_SUCCESS, ret2 = 0;

    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;

    size_t pubkey_kexlen = 0;
    size_t kexDeriveLen = 0, pkeylen = 0;
    unsigned char *pubkey_kex = pkemctx->kem->comp_pubkey[keyslot];

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL, *kgctx = NULL;
    EVP_PKEY *pkey = NULL, *peerpk = NULL;
    unsigned char *ctkex_encoded = NULL;

    int lunaflags = LUNA_PROV_FLAGS_SESSION_OBJECT;

    pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    kexDeriveLen = evp_ctx->evp_info->kex_length_secret;

    *ctlen = pubkey_kexlen;
    *secretlen = kexDeriveLen;

    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("EVP KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    peerpk = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpk, ret, -1, err);

    ret2 = EVP_PKEY_copy_parameters(peerpk, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpk, pubkey_kex, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, err);

    kgctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, err);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    /* NOTE: derive using a private key, will not work for hardware keys, unless
     * the engine implements the EC 'compute_key' method,
     * AND the engine generates the EC keypair as temporary (session) objects,
     * AND this provider checks that the PQC part of the KEM algorithm is also implemented in hardware.
     * For now, we force this temporary EC keypair to software; i.e.,
     * override engine setting EnableEcGenKeyPair, which is meant for persistent (token) objects.
     */
    LUNA_PRINTF(("EVP_PKEY_keygen\n"));
    if (flagPqcKeyInHardware == 0)
        lunaflags |= LUNA_PROV_FLAGS_SOFTWARE_OBJECT;
    ret2 = lunax_oqsx_EVP_PKEY_keygen_ex(kgctx, &pkey, lunaflags);
    ON_ERR_SET_GOTO(ret2 != 1, ret, -1, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -1, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    ret = EVP_PKEY_derive_set_peer(ctx, peerpk);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    LUNA_PRINTF(("EVP_PKEY_derive\n"));
    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err);

    pkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &ctkex_encoded);
    ON_ERR_SET_GOTO(pkeylen <= 0 || !ctkex_encoded || pkeylen != pubkey_kexlen,
                    ret, -1, err);

    memcpy(ct, ctkex_encoded, pkeylen);

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerpk);
    OPENSSL_free(ctkex_encoded);
    return ret;
}

static int oqs_evp_kem_decaps_keyslot(void *vpkemctx, unsigned char *secret,
                                      size_t *secretlen,
                                      const unsigned char *ct, size_t ctlen,
                                      int keyslot)
{
    OQS_KEM_PRINTF("OQS KEM provider called: oqs_hyb_kem_decaps\n");

    int ret = OQS_SUCCESS, ret2 = 0;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;

    size_t pubkey_kexlen = evp_ctx->evp_info->length_public_key;
    size_t kexDeriveLen = evp_ctx->evp_info->kex_length_secret;
    unsigned char *privkey_kex = pkemctx->kem->comp_privkey[keyslot];
    size_t privkey_kexlen = evp_ctx->evp_info->length_private_key;

    // Free at err:
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerpkey = NULL;

    *secretlen = kexDeriveLen;
    if (secret == NULL)
        return 1;

    if (evp_ctx->evp_info->raw_key_support) {
        pkey = EVP_PKEY_new_raw_private_key(evp_ctx->evp_info->keytype, NULL,
                                            privkey_kex, privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -10, err);
    } else {
        pkey = d2i_AutoPrivateKey(&pkey, (const unsigned char **)&privkey_kex,
                                  privkey_kexlen);
        ON_ERR_SET_GOTO(!pkey, ret, -2, err);
    }

    peerpkey = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!peerpkey, ret, -3, err);

    ret2 = EVP_PKEY_copy_parameters(peerpkey, evp_ctx->keyParam);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -4, err);

    ret2 = EVP_PKEY_set1_encoded_public_key(peerpkey, ct, pubkey_kexlen);
    ON_ERR_SET_GOTO(ret2 <= 0 || !peerpkey, ret, -5, err);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    ON_ERR_SET_GOTO(!ctx, ret, -6, err);

    ret = EVP_PKEY_derive_init(ctx);
    ON_ERR_SET_GOTO(ret <= 0, ret, -7, err);
    ret = EVP_PKEY_derive_set_peer(ctx, peerpkey);
    ON_ERR_SET_GOTO(ret <= 0, ret, -8, err);

    /* NOTE: derive using a public key, should work for hardware key,
     * assuming the pkey is populated correctly by the engine.
     */
    LUNA_PRINTF(("EVP_PKEY_derive\n"));
    ret = EVP_PKEY_derive(ctx, secret, &kexDeriveLen);
    ON_ERR_SET_GOTO(ret <= 0, ret, -9, err);

err:
    EVP_PKEY_free(peerpkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/// Hybrid KEM functions

static int oqs_hyb_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                              unsigned char *secret, size_t *secretlen)
{
    int ret = OQS_SUCCESS;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    unsigned char *ct0, *ct1, *secret0, *secret1;
    const int flagPqcKeyInHardware = (LUNA_OQS_QUERY_KEM_keypair(pkemctx->kem->lunakeyctx) == LUNA_OQS_OK);

    ret = oqs_evp_kem_encaps_keyslot(vpkemctx, NULL, &ctLen0, NULL, &secretLen0,
                                     0, flagPqcKeyInHardware);
    oqs_debug_secret("oqs_hyb_kem_encaps:ct0:", ret, NULL, &ctLen0);
    oqs_debug_secret("oqs_hyb_kem_encaps:secret0:", ret, NULL, &secretLen0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLen1, NULL, &secretLen1,
                                    1);
    oqs_debug_secret("oqs_hyb_kem_encaps:ct1:", ret, NULL, &ctLen1);
    oqs_debug_secret("oqs_hyb_kem_encaps:secret1:", ret, NULL, &secretLen1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *ctlen = ctLen0 + ctLen1;
    *secretlen = secretLen0 + secretLen1;

    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("HYB KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    if (pkemctx->kem->keytype == KEY_TYPE_ECX_HYB_KEM)
    {
        // special case of reverse keyshare for KEY_TYPE_ECX_HYB_KEM
        ct1 = ct;
        ct0 = ct + ctLen1;
        secret1 = secret;
        secret0 = secret + secretLen1;
    }
    else
    {
        ct0 = ct;
        ct1 = ct + ctLen0;
        secret0 = secret;
        secret1 = secret + secretLen0;
    }

    ret = oqs_evp_kem_encaps_keyslot(vpkemctx, ct0, &ctLen0, secret0,
                                     &secretLen0, 0, flagPqcKeyInHardware);
    oqs_debug_secret("oqs_hyb_kem_encaps:ct0:", ret, ct0, &ctLen0);
    oqs_debug_secret("oqs_hyb_kem_encaps:secret0:", ret, secret0, &secretLen0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, ct1, &ctLen1, secret1,
                                    &secretLen1, 1);
    oqs_debug_secret("oqs_hyb_kem_encaps:ct1:", ret, ct1, &ctLen1);
    oqs_debug_secret("oqs_hyb_kem_encaps:secret1:", ret, secret1, &secretLen1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

static int oqs_hyb_kem_decaps(void *vpkemctx, unsigned char *secret,
                              size_t *secretlen, const unsigned char *ct,
                              size_t ctlen)
{
    int ret = OQS_SUCCESS;
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQSX_EVP_CTX *evp_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_evp_ctx;
    const OQS_KEM *qs_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;

    size_t secretLen0 = 0, secretLen1 = 0;
    size_t ctLen0 = 0, ctLen1 = 0;
    const unsigned char *ct0, *ct1;
    unsigned char *secret0, *secret1;

    oqs_debug_secret("oqs_hyb_kem_decaps:ct:", 1, ct, &ctlen);
    ret = oqs_evp_kem_decaps_keyslot(vpkemctx, NULL, &secretLen0, NULL, 0, 0);
    oqs_debug_secret("oqs_hyb_kem_decaps:secret0:", ret, NULL, &secretLen0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLen1, NULL, 0, 1);
    oqs_debug_secret("oqs_hyb_kem_decaps:secret1:", ret, NULL, &secretLen1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    *secretlen = secretLen0 + secretLen1;

    if (secret == NULL)
        return 1;

    ctLen0 = evp_ctx->evp_info->length_public_key;
    ctLen1 = qs_ctx->length_ciphertext;

    ON_ERR_SET_GOTO(ctLen0 + ctLen1 != ctlen, ret, OQS_ERROR, err);

    if (pkemctx->kem->keytype == KEY_TYPE_ECX_HYB_KEM)
    {
        // special case of reverse keyshare for KEY_TYPE_ECX_HYB_KEM
        ct1 = ct;
        ct0 = ct + ctLen1;
        secret1 = secret;
        secret0 = secret + secretLen1;
    }
    else
    {
        ct0 = ct;
        ct1 = ct + ctLen0;
        secret0 = secret;
        secret1 = secret + secretLen0;
    }

    ret = oqs_evp_kem_decaps_keyslot(vpkemctx, secret0, &secretLen0, ct0,
                                     ctLen0, 0);
    oqs_debug_secret("oqs_hyb_kem_decaps:secret0:", ret, secret0, &secretLen0);
    oqs_debug_secret("oqs_hyb_kem_decaps:ct0:", ret, ct0, &ctLen0);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, secret1, &secretLen1, ct1, ctLen1,
                                    1);
    oqs_debug_secret("oqs_hyb_kem_decaps:secret1:", ret, secret1, &secretLen1);
    oqs_debug_secret("oqs_hyb_kem_decaps:ct1:", ret, ct1, &ctLen1);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

err:
    return ret;
}

#define MAKE_KEM_FUNCTIONS(alg)                                                \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_qs_kem_encaps},        \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_qs_kem_decaps},        \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx},              \
        {0, NULL}};

#define MAKE_HYB_KEM_FUNCTIONS(alg)                                            \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_kem_newctx},                \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_hyb_kem_encaps},       \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_hyb_kem_decaps},       \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_kem_freectx},              \
        {0, NULL}};

// keep this just in case we need to become ALG-specific at some point in time
MAKE_KEM_FUNCTIONS(generic)
MAKE_HYB_KEM_FUNCTIONS(hybrid)

//
static void oqs_debug_secret(const char *fn, int rc, const unsigned char *secret, const size_t *secretlen)
{
#ifdef DEBUG
    if (! luna_getenv_LUNAPROV())
        return;
    if (secret != NULL && secretlen != NULL && *secretlen >= 4 && rc > 0) {
        size_t slen = *secretlen;
        printf("\n%s: rc = %d, slen = %u, s = { %02x %02x ... %02x %02x } \n",
            fn, rc,
            (unsigned)slen,
            (unsigned)secret[0],
            (unsigned)secret[1],
            (unsigned)secret[slen-2],
            (unsigned)secret[slen-1]
            );
    } else {
        printf("\n%s: rc = %d, slen = %u, s = { ?? ?? ... ?? ?? } \n", fn, rc,
            (unsigned)(secretlen?*secretlen:0));
    }
#endif
}
