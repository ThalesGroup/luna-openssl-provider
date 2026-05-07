/*
 * Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This file has quite some overlap with engines/e_loader_attic.c */

#include <string.h>
#include <sys/stat.h>
#include <ctype.h>  /* isdigit */
#include <assert.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/decoder.h>
#include <openssl/proverr.h>
#include <openssl/store.h>       /* The OSSL_STORE_INFO type numbers */
#ifndef LUNA_OQS
#include "internal/cryptlib.h"
#endif
#include "internal/o_dir.h"
#include "crypto/decoder.h"
//#include "crypto/ctype.h"        /* ossl_isdigit() */
//#include "prov/implementations.h"
//#include "prov/bio.h"

#include "lunaCommon.h"
#include "lunaFileStore.h"

#define LUNA_ASSERT(_expr) \
    ((!(_expr)) ? (fprintf(stderr, "LUNA_ASSERT: %s: %u: %s.\n", __FILE__, __LINE__, #_expr), (exit(-1), -1)) : 0)

DEFINE_STACK_OF(OSSL_STORE_INFO)

#ifdef _WIN32
# define stat _stat
#endif

#ifndef S_ISDIR
# define S_ISDIR(a) (((a) & S_IFMT) == S_IFDIR)
#endif

static OSSL_FUNC_store_open_fn file_open;
static OSSL_FUNC_store_attach_fn file_attach;
static OSSL_FUNC_store_settable_ctx_params_fn file_settable_ctx_params;
static OSSL_FUNC_store_set_ctx_params_fn file_set_ctx_params;
static OSSL_FUNC_store_load_fn file_load;
static OSSL_FUNC_store_eof_fn file_eof;
static OSSL_FUNC_store_close_fn file_close;

/*
 * This implementation makes full use of OSSL_DECODER, and then some.
 * It uses its own internal decoder implementation that reads DER and
 * passes that on to the data callback; this decoder is created with
 * internal OpenSSL functions, thereby bypassing the need for a surrounding
 * provider.  This is ok, since this is a local decoder, not meant for
 * public consumption.
 * Finally, it sets up its own construct and cleanup functions.
 *
 * Essentially, that makes this implementation a kind of glorified decoder.
 */

struct file_ctx_st {
    void *provctx;
    char *uri;                   /* The URI we currently try to load */
    enum {
        IS_FILE = 0,             /* Read file and pass results */
        IS_DIR = 1,              /* Pass directory entry names */
        IS_PKCS11 = 2            /* pkcs11 find object by label, etc */
    } type;

    union {
        /* Used with |IS_FILE| */
        struct {
            BIO *file;

            OSSL_DECODER_CTX *decoderctx;
            char *input_type;
            char *propq;    /* The properties we got as a parameter */
        } file;

        /* Used with |IS_DIR| */
        struct {
            OPENSSL_DIR_CTX *ctx;
            int end_reached;

            /*
             * When a search expression is given, these are filled in.
             * |search_name| contains the file basename to look for.
             * The string is exactly 8 characters long.
             */
            char search_name[9];

            /*
             * The directory reading utility we have combines opening with
             * reading the first name.  To make sure we can detect the end
             * at the right time, we read early and cache the name.
             */
            const char *last_entry;
            int last_errno;
        } dir;

        /* Used with IS_PKCS11 */
        struct {
            LUNA_FIND_CTX *find_ctx;
            int no_more_objects;
        } pkcs11;

    } _;

    /* Expected object type.  May be unspecified */
    int expected_type;
};

static void free_file_ctx(struct file_ctx_st *ctx)
{
    LUNA_PRINTF(("\n"));
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->uri);
    if (ctx->type == IS_FILE) {
        OSSL_DECODER_CTX_free(ctx->_.file.decoderctx);
        OPENSSL_free(ctx->_.file.propq);
        OPENSSL_free(ctx->_.file.input_type);
    }
    if (ctx->type == IS_PKCS11) {
        LUNA_FIND_CTX_free(ctx->_.pkcs11.find_ctx);
    }
    OPENSSL_free(ctx);
}

static struct file_ctx_st *new_file_ctx(int type, const char *uri,
                                        void *provctx)
{
    struct file_ctx_st *ctx = NULL;

    LUNA_PRINTF(("\n"));
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) != NULL
        && (uri == NULL || (ctx->uri = OPENSSL_strdup(uri)) != NULL)) {
        ctx->type = type;
        ctx->provctx = provctx;
        return ctx;
    }
    free_file_ctx(ctx);
    return NULL;
}

static OSSL_DECODER_CONSTRUCT file_load_construct;
static OSSL_DECODER_CLEANUP file_load_cleanup;

/*-
 *  Opening / attaching streams and directories
 *  -------------------------------------------
 */

/*
 * Function to service both file_open() and file_attach()
 *
 *
 */
static struct file_ctx_st *file_open_stream(BIO *source, const char *uri,
                                            void *provctx)
{
    struct file_ctx_st *ctx;

    LUNA_PRINTF(("\n"));
    if ((ctx = new_file_ctx(IS_FILE, uri, provctx)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PROV_LIB);
        goto err;
    }

    ctx->_.file.file = source;

    return ctx;
 err:
    free_file_ctx(ctx);
    return NULL;
}

static void *file_open_dir(const char *path, const char *uri, void *provctx)
{
    struct file_ctx_st *ctx;

    LUNA_PRINTF(("\n"));
    if ((ctx = new_file_ctx(IS_DIR, uri, provctx)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PROV_LIB);
        return NULL;
    }

    ctx->_.dir.last_entry = OPENSSL_DIR_read(&ctx->_.dir.ctx, path);
    ctx->_.dir.last_errno = errno;
    if (ctx->_.dir.last_entry == NULL) {
        if (ctx->_.dir.last_errno != 0) {
            ERR_raise_data(ERR_LIB_SYS, ctx->_.dir.last_errno,
                           "Calling OPENSSL_DIR_read(\"%s\")", path);
            goto err;
        }
        ctx->_.dir.end_reached = 1;
    }
    return ctx;
 err:
    file_close(ctx);
    return NULL;
}

static struct file_ctx_st *file_open_pkcs11(const char *uri,
                                            void *provctx)
{
    struct file_ctx_st *ctx;

    LUNA_PRINTF(("\n"));
    if ((ctx = new_file_ctx(IS_PKCS11, uri, provctx)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PROV_LIB);
        goto err;
    }
    if ( (ctx->_.pkcs11.find_ctx = LUNA_FIND_CTX_new(uri)) == NULL ) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PROV_LIB);
        goto err;
    }
    return ctx;
 err:
    free_file_ctx(ctx);
    return NULL;
}

#ifndef LUNA_OSSL_3_2

/* Check if |pre|, which must be a string literal, is a prefix of |str| */
#define HAS_PREFIX(str, pre) (strncmp(str, pre "", sizeof(pre) - 1) == 0)
/* As before, and if check succeeds, advance |str| past the prefix |pre| */
#define CHECK_AND_SKIP_PREFIX(str, pre) \
    (HAS_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)
/* Check if the string literal |p| is a case-insensitive prefix of |s| */
#define HAS_CASE_PREFIX(s, p) (OPENSSL_strncasecmp(s, p "", sizeof(p) - 1) == 0)
/* As before, and if check succeeds, advance |str| past the prefix |pre| */
#define CHECK_AND_SKIP_CASE_PREFIX(str, pre) \
    (HAS_CASE_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)
/* Check if the string literal |suffix| is a case-insensitive suffix of |str| */
#define HAS_CASE_SUFFIX(str, suffix) (strlen(str) < sizeof(suffix) - 1 ? 0 : \
    OPENSSL_strcasecmp(str + strlen(str) - sizeof(suffix) + 1, suffix "") == 0)

#endif // LUNA_OSSL_3_2

static void *file_open(void *provctx, const char *uri)
{
    struct file_ctx_st *ctx = NULL;
    struct stat st;
    struct {
        const char *path;
        unsigned int check_absolute:1;
    } path_data[2];
    size_t path_data_n = 0, i;
    const char *path, *p = uri, *q;
    BIO *bio;

    LUNA_PRINTF(("\n"));
    ERR_set_mark();

    /*
     * First step, just take the URI as is.
     */
    path_data[path_data_n].check_absolute = 0;
    path_data[path_data_n++].path = uri;

    /*
     * Second step, if the URI appears to start with the "file" scheme,
     * extract the path and make that the second path to check.
     * There's a special case if the URI also contains an authority, then
     * the full URI shouldn't be used as a path anywhere.
     */
    if (CHECK_AND_SKIP_CASE_PREFIX(p, "file:")) {
        q = p;
        if (CHECK_AND_SKIP_CASE_PREFIX(q, "//")) {
            path_data_n--;           /* Invalidate using the full URI */
            if (CHECK_AND_SKIP_CASE_PREFIX(q, "localhost/")
                    || CHECK_AND_SKIP_CASE_PREFIX(q, "/")) {
                p = q - 1;
            } else {
                ERR_clear_last_mark();
                ERR_raise(ERR_LIB_PROV, PROV_R_URI_AUTHORITY_UNSUPPORTED);
                return NULL;
            }
        }

        path_data[path_data_n].check_absolute = 1;
#ifdef _WIN32
        /* Windows "file:" URIs with a drive letter start with a '/' */
        if (p[0] == '/' && p[2] == ':' && p[3] == '/') {
            char c = tolower(p[1]);

            if (c >= 'a' && c <= 'z') {
                p++;
                /* We know it's absolute, so no need to check */
                path_data[path_data_n].check_absolute = 0;
            }
        }
#endif
        path_data[path_data_n++].path = p;
    }

    for (i = 0, path = NULL; path == NULL && i < path_data_n; i++) {
        /*
         * If the scheme "file" was an explicit part of the URI, the path must
         * be absolute.  So says RFC 8089
         */
        if (path_data[i].check_absolute && path_data[i].path[0] != '/') {
            ERR_clear_last_mark();
            ERR_raise_data(ERR_LIB_PROV, PROV_R_PATH_MUST_BE_ABSOLUTE,
                           "Given path=%s", path_data[i].path);
            return NULL;
        }

        if (stat(path_data[i].path, &st) < 0) {
            ERR_raise_data(ERR_LIB_SYS, errno,
                           "calling stat(%s)",
                           path_data[i].path);
        } else {
            path = path_data[i].path;
        }
    }
    if (path == NULL) {
        ERR_clear_last_mark();
        return NULL;
    }

    /* Successfully found a working path, clear possible collected errors */
    ERR_pop_to_mark();

    if (S_ISDIR(st.st_mode))
        ctx = file_open_dir(path, uri, provctx);
    else if ((bio = BIO_new_file(path, "rb")) == NULL
             || (ctx = file_open_stream(bio, uri, provctx)) == NULL)
        BIO_free_all(bio);

    return ctx;
}

static
void *file_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    struct file_ctx_st *ctx;
    LUNA_PRINTF(("\n"));
    BIO *new_bio = ossl_bio_new_from_core_bio(provctx, cin);

    if (new_bio == NULL)
        return NULL;

    ctx = file_open_stream(new_bio, NULL, provctx);
    if (ctx == NULL)
        BIO_free(new_bio);
    return ctx;
}

/*-
 *  Setting parameters
 *  ------------------
 */

static const OSSL_PARAM *file_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
        OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_END
    };
    LUNA_PRINTF(("\n"));
    return known_settable_ctx_params;
}

static int file_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    struct file_ctx_st *ctx = loaderctx;
    const OSSL_PARAM *p;

    LUNA_PRINTF(("\n"));
    if (params == NULL)
        return 1;

    if (ctx->type == IS_FILE) {
        /* these parameters are ignored for directories */
        p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES);
        if (p != NULL) {
            OPENSSL_free(ctx->_.file.propq);
            ctx->_.file.propq = NULL;
            if (!OSSL_PARAM_get_utf8_string(p, &ctx->_.file.propq, 0))
                return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_INPUT_TYPE);
        if (p != NULL) {
            OPENSSL_free(ctx->_.file.input_type);
            ctx->_.file.input_type = NULL;
            if (!OSSL_PARAM_get_utf8_string(p, &ctx->_.file.input_type, 0))
                return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->expected_type))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT);
    if (p != NULL) {
        const unsigned char *der = NULL;
        size_t der_len = 0;
        X509_NAME *x509_name;
        unsigned long hash;
        int ok;

        if (ctx->type != IS_DIR) {
            ERR_raise(ERR_LIB_PROV,
                      PROV_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES);
            return 0;
        }

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&der, &der_len)
            || (x509_name = d2i_X509_NAME(NULL, &der, der_len)) == NULL)
            return 0;
        hash = X509_NAME_hash_ex(x509_name,
                                 ossl_prov_ctx_get0_libctx(ctx->provctx), NULL,
                                 &ok);
        BIO_snprintf(ctx->_.dir.search_name, sizeof(ctx->_.dir.search_name),
                     "%08lx", hash);
        X509_NAME_free(x509_name);
        if (ok == 0)
            return 0;
    }
    return 1;
}

/*-
 *  Loading an object from a stream
 *  -------------------------------
 */

/* copied from "store_local.h" */
struct ossl_load_result_data_st {
    OSSL_STORE_INFO *v;          /* To be filled in */
    OSSL_STORE_CTX *ctx;
};

struct file_load_data_st {
    OSSL_CALLBACK *object_cb;
    void *object_cbarg;
};

static int luna_store_handle_load_result(const OSSL_PARAM params[], struct file_load_data_st *data);

static int file_load_construct(OSSL_DECODER_INSTANCE *decoder_inst,
                               const OSSL_PARAM *params, void *construct_data)
{
    struct file_load_data_st *data = (struct file_load_data_st *)construct_data;

    /*
     * At some point, we may find it justifiable to recognise PKCS#12 and
     * handle it specially here, making |file_load()| return pass its
     * contents one piece at ta time, like |e_loader_attic.c| does.
     *
     * However, that currently means parsing them out, which converts the
     * DER encoded PKCS#12 into a bunch of EVP_PKEYs and X509s, just to
     * have to re-encode them into DER to create an object abstraction for
     * each of them.
     * It's much simpler (less churn) to pass on the object abstraction we
     * get to the load_result callback and leave it to that one to do the
     * work.  If that's libcrypto code, we know that it has much better
     * possibilities to handle the EVP_PKEYs and X509s without the extra
     * churn.
     */

    /* call ossl_store_handle_load_result (for example) */
    int rc_cb = data->object_cb(params, data->object_cbarg);
    LUNA_PRINTF(("rc_cb = %d\n", rc_cb));
    if (rc_cb == 0) {
        rc_cb = luna_store_handle_load_result(params, data);
        LUNA_PRINTF(("rc_cb@2 = %d\n", rc_cb));
        return rc_cb;
    }

    /* NOTE: at minimum we should inspect the keypair (ed25519/ed448)
     * for hsm-wise keypair consistency; i.e., the openssl ecx backend tends to
     * derive the public key from private key, thus defeating storage of the
     * hsm pseudo private key in the keyfile.
     */

    struct ossl_load_result_data_st *cbdata = data->object_cbarg;
    OSSL_STORE_INFO **v = &cbdata->v;
    OSSL_STORE_INFO *info = *v;
    if (info != NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            EVP_PKEY *pk = OSSL_STORE_INFO_get0_PKEY(info);
            const int pktype = EVP_PKEY_get_id(pk);
            LUNA_PRINTF(("pktype = %d\n", pktype));
#ifdef LUNA_OQS
            if (pktype == EVP_PKEY_ED25519 || pktype == EVP_PKEY_ED448
                    || pktype == EVP_PKEY_X25519 || pktype == EVP_PKEY_X448) {
                const ECX_KEY *ecx = NULL;
                LUNA_PRINTF(("luna_prov_ecx_fix_public...\n"));
                if (pktype == EVP_PKEY_ED25519) {
                    ecx = ossl_evp_pkey_get1_ED25519(pk);
                } else if (pktype == EVP_PKEY_ED448) {
                    ecx = ossl_evp_pkey_get1_ED448(pk);
                } else if (pktype == EVP_PKEY_X25519) {
                    ecx = ossl_evp_pkey_get1_X25519(pk);
                } else if (pktype == EVP_PKEY_X448) {
                    ecx = ossl_evp_pkey_get1_X448(pk);
                }
                LUNA_ASSERT(ecx != NULL);
                (void)luna_prov_ecx_fix_public((ECX_KEY *)ecx);
                LUNA_PRINTF(("luna_prov_ecx_fix_public... ok.\n"));

                /* NOTE: We must create a new EVP_PKEY that is associated with our provider.
                 * Otherwise, the ecx_backend will clobber the public key using the EVP_PKEY
                 * that it created.
                 *
                 * Note the gem engine does a similar thing when loading keys in openssl3.
                 * I know this is very non-intuitive - but "that's just the way it is".
                 */
                EVP_PKEY *pk_new = EVP_PKEY_new();
                LUNA_ASSERT(pk_new != NULL);
                LUNA_ASSERT(EVP_PKEY_assign(pk_new, pktype, (ECX_KEY *)ecx) > 0);
                OSSL_STORE_INFO *info_new = OSSL_STORE_INFO_new_PKEY(pk_new);
                LUNA_ASSERT(info_new != NULL);
                *v = info_new;

                /* free the old store info */
                //FIXME:OSSL_STORE_INFO_free(info);

            } else if (pktype == EVP_PKEY_DSA) {
#else // LUNA_OQS
            if (pktype == EVP_PKEY_DSA) {
#endif // LUNA_OQS
                const DSA *ecx = EVP_PKEY_get0_DSA(pk);
                LUNA_ASSERT(ecx != NULL);

                /* create a new EVP_PKEY that is associated with our provider. */
                EVP_PKEY *pk_new = EVP_PKEY_new();
                LUNA_ASSERT(pk_new != NULL);
                LUNA_ASSERT(EVP_PKEY_assign(pk_new, pktype, (DSA *)ecx) > 0);
                OSSL_STORE_INFO *info_new = OSSL_STORE_INFO_new_PKEY(pk_new);
                LUNA_ASSERT(info_new != NULL);
                *v = info_new;

                /* free the old store info */
                //FIXME:OSSL_STORE_INFO_free(info);

            } else if (pktype == EVP_PKEY_EC) {
                const EC_KEY *ecx = EVP_PKEY_get0_EC_KEY(pk);
                LUNA_ASSERT(ecx != NULL);

                /* create a new EVP_PKEY that is associated with our provider. */
                EVP_PKEY *pk_new = EVP_PKEY_new();
                LUNA_ASSERT(pk_new != NULL);
                LUNA_ASSERT(EVP_PKEY_assign(pk_new, pktype, (EC_KEY *)ecx) > 0);
                OSSL_STORE_INFO *info_new = OSSL_STORE_INFO_new_PKEY(pk_new);
                LUNA_ASSERT(info_new != NULL);
                *v = info_new;

                /* free the old store info */
                //FIXME:OSSL_STORE_INFO_free(info);

            } else if (pktype == EVP_PKEY_RSA) {
                const RSA *rsa = EVP_PKEY_get0_RSA(pk);
                LUNA_ASSERT(rsa != NULL);

                /* create a new EVP_PKEY that is associated with our provider. */
                EVP_PKEY *pk_new = EVP_PKEY_new();
                LUNA_ASSERT(pk_new != NULL);
                LUNA_ASSERT(EVP_PKEY_assign(pk_new, pktype, (RSA *)rsa) > 0);
                OSSL_STORE_INFO *info_new = OSSL_STORE_INFO_new_PKEY(pk_new);
                LUNA_ASSERT(info_new != NULL);
                *v = info_new;

                /* free the old store info */
                //FIXME:OSSL_STORE_INFO_free(info);
            }
        }
    }

    return rc_cb;
}

static
void file_load_cleanup(void *construct_data)
{
    /* Nothing to do */
    LUNA_PRINTF(("\n"));
}

static int file_setup_decoders(struct file_ctx_st *ctx)
{
    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(ctx->provctx);
    const OSSL_ALGORITHM *to_algo = NULL;
    int ok = 0;

    LUNA_PRINTF(("\n"));
    /* Setup for this session, so only if not already done */
    if (ctx->_.file.decoderctx == NULL) {
        if ((ctx->_.file.decoderctx = OSSL_DECODER_CTX_new()) == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto err;
        }

        /* Make sure the input type is set */
        if (!OSSL_DECODER_CTX_set_input_type(ctx->_.file.decoderctx,
                                             ctx->_.file.input_type)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto err;
        }

        /*
         * Where applicable, set the outermost structure name.
         * The goal is to avoid the STORE object types that are
         * potentially password protected but aren't interesting
         * for this load.
         */
        switch (ctx->expected_type) {
        case OSSL_STORE_INFO_CERT:
            if (!OSSL_DECODER_CTX_set_input_structure(ctx->_.file.decoderctx,
                                                      "Certificate")) {
                ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
                goto err;
            }
            break;
        case OSSL_STORE_INFO_CRL:
            if (!OSSL_DECODER_CTX_set_input_structure(ctx->_.file.decoderctx,
                                                      "CertificateList")) {
                ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
                goto err;
            }
            break;
        default:
            break;
        }

        for (to_algo = luna_any_to_obj_algorithm;
             to_algo->algorithm_names != NULL;
             to_algo++) {
            OSSL_DECODER *to_obj = NULL;
            OSSL_DECODER_INSTANCE *to_obj_inst = NULL;

            /*
             * Create the internal last resort decoder implementation
             * together with a "decoder instance".
             * The decoder doesn't need any identification or to be
             * attached to any provider, since it's only used locally.
             */
            to_obj = ossl_decoder_from_algorithm(0, to_algo, NULL);
            if (to_obj != NULL)
                to_obj_inst = ossl_decoder_instance_new(to_obj, ctx->provctx);
            OSSL_DECODER_free(to_obj);
            if (to_obj_inst == NULL)
                goto err;

            if (!ossl_decoder_ctx_add_decoder_inst(ctx->_.file.decoderctx,
                                                   to_obj_inst)) {
                ossl_decoder_instance_free(to_obj_inst);
                ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
                goto err;
            }
        }
        /* Add on the usual extra decoders */
        if (!OSSL_DECODER_CTX_add_extra(ctx->_.file.decoderctx,
                                        libctx, ctx->_.file.propq)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto err;
        }

        /*
         * Then install our constructor hooks, which just passes decoded
         * data to the load callback
         */
        if (!OSSL_DECODER_CTX_set_construct(ctx->_.file.decoderctx,
                                            file_load_construct)
            || !OSSL_DECODER_CTX_set_cleanup(ctx->_.file.decoderctx,
                                             file_load_cleanup)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_OSSL_DECODER_LIB);
            goto err;
        }
    }

    ok = 1;
 err:
    return ok;
}

static int file_load_file(struct file_ctx_st *ctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct file_load_data_st data;
    int ret, err;

    /* Setup the decoders (one time shot per session */

    LUNA_PRINTF(("\n"));
    if (!file_setup_decoders(ctx))
        return 0;

    /* Setup for this object */

    data.object_cb = object_cb;
    data.object_cbarg = object_cbarg;
    OSSL_DECODER_CTX_set_construct_data(ctx->_.file.decoderctx, &data);
    OSSL_DECODER_CTX_set_passphrase_cb(ctx->_.file.decoderctx, pw_cb, pw_cbarg);

    /* Launch */

    ERR_set_mark();
    ret = OSSL_DECODER_from_bio(ctx->_.file.decoderctx, ctx->_.file.file); /* TODO: DECODER_from_pkcs11 */
    if (BIO_eof(ctx->_.file.file)
        && ((err = ERR_peek_last_error()) != 0)
        && ERR_GET_LIB(err) == ERR_LIB_OSSL_DECODER
        && ERR_GET_REASON(err) == ERR_R_UNSUPPORTED)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return ret;
}

static int file_load_pkcs11_object(struct file_ctx_st *ctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg);

/*-
 *  Loading a name object from a directory
 *  --------------------------------------
 */

static char *file_name_to_uri(struct file_ctx_st *ctx, const char *name)
{
    char *data = NULL;

    LUNA_PRINTF(("\n"));
    assert(name != NULL);
    {
        const char *pathsep = ossl_ends_with_dirsep(ctx->uri) ? "" : "/";
        long calculated_length = strlen(ctx->uri) + strlen(pathsep)
            + strlen(name) + 1 /* \0 */;

        data = OPENSSL_zalloc(calculated_length);
        if (data == NULL)
            return NULL;

        OPENSSL_strlcat(data, ctx->uri, calculated_length);
        OPENSSL_strlcat(data, pathsep, calculated_length);
        OPENSSL_strlcat(data, name, calculated_length);
    }
    return data;
}

static int file_name_check(struct file_ctx_st *ctx, const char *name)
{
    const char *p = NULL;
    LUNA_PRINTF(("\n"));
    size_t len = strlen(ctx->_.dir.search_name);

    /* If there are no search criteria, all names are accepted */
    if (ctx->_.dir.search_name[0] == '\0')
        return 1;

    /* If the expected type isn't supported, no name is accepted */
    if (ctx->expected_type != 0
        && ctx->expected_type != OSSL_STORE_INFO_CERT
        && ctx->expected_type != OSSL_STORE_INFO_CRL)
        return 0;

    /*
     * First, check the basename
     */
    if (OPENSSL_strncasecmp(name, ctx->_.dir.search_name, len) != 0
        || name[len] != '.')
        return 0;
    p = &name[len + 1];

    /*
     * Then, if the expected type is a CRL, check that the extension starts
     * with 'r'
     */
    if (*p == 'r') {
        p++;
        if (ctx->expected_type != 0
            && ctx->expected_type != OSSL_STORE_INFO_CRL)
            return 0;
    } else if (ctx->expected_type == OSSL_STORE_INFO_CRL) {
        return 0;
    }

    /*
     * Last, check that the rest of the extension is a decimal number, at
     * least one digit long.
     */
    if (!isdigit((unsigned char)*p))
        return 0;
    while (isdigit((unsigned char)*p))
        p++;

#ifdef __VMS
    /*
     * One extra step here, check for a possible generation number.
     */
    if (*p == ';')
        for (p++; *p != '\0'; p++)
            if (!ossl_isdigit((unsigned char)*p))
                break;
#endif

    /*
     * If we've reached the end of the string at this point, we've successfully
     * found a fitting file name.
     */
    return *p == '\0';
}

static int file_load_dir_entry(struct file_ctx_st *ctx,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    /* Prepare as much as possible in advance */
    static const int object_type = OSSL_OBJECT_NAME;
    OSSL_PARAM object[] = {
        OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, (int *)&object_type),
        OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA, NULL, 0),
        OSSL_PARAM_END
    };
    char *newname = NULL;
    int ok;

    LUNA_PRINTF(("\n"));
    /* Loop until we get an error or until we have a suitable name */
    do {
        if (ctx->_.dir.last_entry == NULL) {
            if (!ctx->_.dir.end_reached) {
                assert(ctx->_.dir.last_errno != 0);
                ERR_raise(ERR_LIB_SYS, ctx->_.dir.last_errno);
            }
            /* file_eof() will tell if EOF was reached */
            return 0;
        }

        /* flag acceptable names */
        if (ctx->_.dir.last_entry[0] != '.'
            && file_name_check(ctx, ctx->_.dir.last_entry)) {

            /* If we can't allocate the new name, we fail */
            if ((newname =
                 file_name_to_uri(ctx, ctx->_.dir.last_entry)) == NULL)
                return 0;
        }

        /*
         * On the first call (with a NULL context), OPENSSL_DIR_read()
         * cares about the second argument.  On the following calls, it
         * only cares that it isn't NULL.  Therefore, we can safely give
         * it our URI here.
         */
        ctx->_.dir.last_entry = OPENSSL_DIR_read(&ctx->_.dir.ctx, ctx->uri);
        ctx->_.dir.last_errno = errno;
        if (ctx->_.dir.last_entry == NULL && ctx->_.dir.last_errno == 0)
            ctx->_.dir.end_reached = 1;
    } while (newname == NULL);

    object[1].data = newname;
    object[1].data_size = strlen(newname);
    ok = object_cb(object, object_cbarg);
    OPENSSL_free(newname);
    return ok;
}

/*-
 *  Loading, local dispatcher
 *  -------------------------
 */

static int file_load(void *loaderctx,
                     OSSL_CALLBACK *object_cb, void *object_cbarg,
                     OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct file_ctx_st *ctx = loaderctx;

    LUNA_PRINTF(("\n"));
    switch (ctx->type) {
    case IS_FILE:
        return file_load_file(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
    case IS_DIR:
        return
            file_load_dir_entry(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
    case IS_PKCS11:
        return file_load_pkcs11_object(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg);
    default:
        break;
    }

    /* ctx->type has an unexpected value */
    assert(0);
    return 0;
}

/*-
 *  Eof detection and closing
 *  -------------------------
 */

static int file_eof(void *loaderctx)
{
    struct file_ctx_st *ctx = loaderctx;

    LUNA_PRINTF(("\n"));
    switch (ctx->type) {
    case IS_DIR:
        return ctx->_.dir.end_reached;
    case IS_FILE:
        /*
         * BIO_pending() checks any filter BIO.
         * BIO_eof() checks the source BIO.
         */
        return !BIO_pending(ctx->_.file.file)
            && BIO_eof(ctx->_.file.file);
    case IS_PKCS11:
        return ctx->_.pkcs11.no_more_objects;
    }

    /* ctx->type has an unexpected value */
    assert(0);
    return 1;
}

static int file_close_dir(struct file_ctx_st *ctx)
{
    LUNA_PRINTF(("\n"));
    if (ctx->_.dir.ctx != NULL)
        OPENSSL_DIR_end(&ctx->_.dir.ctx);
    free_file_ctx(ctx);
    return 1;
}

static int file_close_stream(struct file_ctx_st *ctx)
{
    LUNA_PRINTF(("\n"));
    /*
     * This frees either the provider BIO filter (for file_attach()) OR
     * the allocated file BIO (for file_open()).
     */
    BIO_free(ctx->_.file.file);
    ctx->_.file.file = NULL;

    free_file_ctx(ctx);
    return 1;
}

static int file_close_pkcs11(struct file_ctx_st *ctx)
{
    LUNA_PRINTF(("\n"));
    free_file_ctx(ctx);
    return 1;
}

static int file_close(void *loaderctx)
{
    struct file_ctx_st *ctx = loaderctx;

    LUNA_PRINTF(("\n"));
    switch (ctx->type) {
    case IS_DIR:
        return file_close_dir(ctx);
    case IS_FILE:
        return file_close_stream(ctx);
    case IS_PKCS11:
        return file_close_pkcs11(ctx);
    }

    /* ctx->type has an unexpected value */
    assert(0);
    return 1;
}

static OSSL_FUNC_store_open_fn luna_uri_open;

const OSSL_DISPATCH luna_file_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))luna_uri_open },
    { OSSL_FUNC_STORE_ATTACH, (void (*)(void))file_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
      (void (*)(void))file_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))file_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))file_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))file_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))file_close },
    OSSL_DISPATCH_END,
};

#include "lunaFileAny2obj.c"

//
// find object from URI
//
// goals:
// - parse uri such as "pkcs11:mylabel".
// - open pkcs11 session.
// - find object:
//   - find keypair (aka OSSL_STORE_INFO_PKEY).
//   - and/or find public key only (aka OSSL_STORE_INFO_PUBKEY).
// - if dnssec bind then:
//   - populate the store with both OSSL_STORE_INFO_PKEY and OSSL_STORE_INFO_PUBKEY.
// - close pkcs11 session.
//

static void *luna_pkcs11_open(void *provctx, const char *uri);

// URI prefix can be "file:" or "pkcs11:"
static void *luna_uri_open(void *provctx, const char *uri)
{
    if ( (provctx == NULL) || (uri == NULL) )
        return NULL;
    LUNA_PRINTF(("uri=%s\n",uri));
    if (strncmp(uri, "pkcs11:", 7) == 0)
        return luna_pkcs11_open(provctx, &uri[7]); /* exclude prefix */
    return file_open(provctx, &uri[0]); /* include prefix */
}

static void *luna_pkcs11_open(void *provctx, const char *uri)
{
    LUNA_PRINTF(("uri=%s\n",uri));
    return file_open_pkcs11(uri, provctx);
}

// load one object (implies external iterator)
static int file_load_pkcs11_object(struct file_ctx_st *ctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    LUNA_ASSERT(ctx->_.pkcs11.no_more_objects == 0);
    LUNA_FIND_CTX *find_ctx = ctx->_.pkcs11.find_ctx;
    if (LUNA_FIND_CTX_next(find_ctx) != 1) {
        ctx->_.pkcs11.no_more_objects = 1;
        return 0;
    }

    LUNA_PKEY_CTX *pkctx = find_ctx->current;
    LUNA_ASSERT(pkctx != NULL);
    EVP_PKEY *pkey = pkctx->pkey;
    LUNA_ASSERT(pkey != NULL);

    const int pktype = EVP_PKEY_get_id(pkey);
    LUNA_PRINTF(("pktype = %d\n", pktype));
    int object_type = OSSL_OBJECT_PKEY;
    char *data_type = NULL;
    void *reference = NULL;
    size_t reference_sz = 0;
    switch (pktype) {
    case EVP_PKEY_RSA:
        data_type = "RSA"; // TODO: "RSA-PSS" ?
        pkctx->kk.rsa = EVP_PKEY_get1_RSA(pkey);
        LUNA_ASSERT(pkctx->kk.rsa != NULL);
        reference = (void*)&pkctx->kk.rsa;
        reference_sz = sizeof(reference);
        break;
    case EVP_PKEY_DSA:
        data_type = "DSA";
        pkctx->kk.dsa = EVP_PKEY_get1_DSA(pkey);
        LUNA_ASSERT(pkctx->kk.dsa != NULL);
        reference = (void*)&pkctx->kk.dsa;
        reference_sz = sizeof(reference);
        break;
    case EVP_PKEY_EC:
        data_type = "EC";
        pkctx->kk.ec = EVP_PKEY_get1_EC_KEY(pkey);
        LUNA_ASSERT(pkctx->kk.ec != NULL);
        reference = (void*)&pkctx->kk.ec;
        reference_sz = sizeof(reference);
        break;
    default:
        // TODO: PQC keytypes
        return 0;
    }

    LUNA_ASSERT(object_type != 0);
    LUNA_ASSERT(data_type != NULL);
    LUNA_ASSERT(reference != NULL);
    LUNA_ASSERT(reference_sz != 0);
    LUNA_PRINTF(("reference = 0x%p\n", reference));
    LUNA_PRINTF(("reference_sz = %lu\n", reference_sz));
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, reference, reference_sz);
    params[3] = OSSL_PARAM_construct_end();
    int rc = object_cb(params, object_cbarg);
    LUNA_PRINTF(("rc = %d\n", rc));
    return rc;
}

struct extracted_param_data_st {
    int object_type;
    const char *data_type;
    const char *input_type;
    const char *data_structure;
    const char *utf8_data;
    const void *octet_data;
    size_t octet_data_size;
    const void *ref;
    size_t ref_size;
    const char *desc;
};

static int luna_store_handle_load_result(const OSSL_PARAM params[], struct file_load_data_st *data)
{
#ifdef LUNA_OQS
    struct ossl_load_result_data_st *cbdata = data->object_cbarg;
    const OSSL_PARAM *p = NULL;
    struct extracted_param_data_st helper_data;

    memset(&helper_data, 0, sizeof(helper_data));
    helper_data.object_type = OSSL_OBJECT_UNKNOWN;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_TYPE)) != NULL
        && !OSSL_PARAM_get_int(p, &helper_data.object_type))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    if (p != NULL
        && !OSSL_PARAM_get_utf8_string_ptr(p, &helper_data.data_type))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA);
    if (p != NULL
        && !OSSL_PARAM_get_octet_string_ptr(p, &helper_data.octet_data,
            &helper_data.octet_data_size)
        && !OSSL_PARAM_get_utf8_string_ptr(p, &helper_data.utf8_data))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE);
    if (p != NULL
        && !OSSL_PARAM_get_utf8_string_ptr(p, &helper_data.data_structure))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_INPUT_TYPE);
    if (p != NULL
        && !OSSL_PARAM_get_utf8_string_ptr(p, &helper_data.input_type))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p, &helper_data.ref, &helper_data.ref_size))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DESC);
    if (p != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &helper_data.desc))
        return 0;

    LUNA_PRINTF(("object_type = %d\n", helper_data.object_type));
    LUNA_PRINTF(("data_type = %s\n", helper_data.data_type));
    LUNA_PRINTF(("input_type = %s\n", helper_data.input_type));
    LUNA_PRINTF(("data_structure = %s\n", helper_data.data_structure));
    LUNA_PRINTF(("utf8_data = %s\n", helper_data.utf8_data));
    LUNA_PRINTF(("octet_data = %p : %lu\n", helper_data.octet_data, helper_data.octet_data_size));
    LUNA_PRINTF(("ref = %p : %lu\n", helper_data.ref, helper_data.ref_size));
    LUNA_PRINTF(("desc = %s\n", helper_data.desc));

    OQSX_KEY *key = NULL;

    if ( helper_data.object_type == OSSL_OBJECT_PKEY &&
            !strcmp(helper_data.data_structure, "PrivateKeyInfo") &&
            helper_data.octet_data != NULL ) {
        PKCS8_PRIV_KEY_INFO *p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL,
                ((const unsigned char**)(&helper_data.octet_data)), helper_data.octet_data_size);
        LUNA_PRINTF(("p8inf = %p\n", p8inf));
        if (p8inf != NULL) {
            key = oqsx_key_from_pkcs8(p8inf, NULL/*TODO:PROV_OQS_LIBCTX_OF(provctx)*/, NULL);
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            p8inf = 0;
        }
    } else if ( helper_data.object_type == OSSL_OBJECT_PKEY &&
            !strcmp(helper_data.data_structure, "SubjectPublicKeyInfo") &&
            helper_data.octet_data != NULL ) {
        key = oqsx_d2i_PUBKEY(NULL,
                ((const unsigned char **)(&helper_data.octet_data)), helper_data.octet_data_size);
    }

    LUNA_PRINTF(("key = %p\n", key));
    if (key != NULL) {
        void *reference = &key;
        size_t reference_sz = sizeof(reference);
        OSSL_PARAM outParams[4];
        outParams[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &helper_data.object_type);
        // NOTE: use the same tls_name as in lunaCommon::algtab
        outParams[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, key->tls_name, 0);
        outParams[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, reference, reference_sz);
        outParams[3] = OSSL_PARAM_construct_end();
        return data->object_cb(outParams, data->object_cbarg);
    }
#endif // LUNA_OQS

    return 0;
}

