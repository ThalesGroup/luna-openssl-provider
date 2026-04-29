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

#define LUNA_PQC_SIGNATURE_BYTES_MIN 64 /* artificial limit to check for */
#define LUNA_PQC_PRIVATEBLOB_BYTES_64 64 /* observed limit based on sphincs to check for */
#define LUNA_PQC_PRIVATEBLOB_BYTES_32 32 /* observed limit based on ed25519 to check for */

// definitions for encoding templates (necessary for finding private key by label)
// must fit within LUNA_PQC_PRIVATEBLOB_BYTES_64
//
// version 1 (exactly 64-bytes as in LUNA_PQC_PRIVATEBLOB_BYTES_64, for pqc keys)
//   reserved xx xx xx xx                     (4 bytes, big endian) reserved
//   priv    "sk112233445566778899aabbccddee" (30 bytes) label for private or secret key
//   pub     "pk112233445566778899aabbccddee" (30 bytes) label for public key
#define LUNA_PQC_ENCODING_ID_BYTES_V1 14 /* 14 meaning not to be confused with ouid(12), engine(20), fingerprint(32) */
#define LUNA_PQC_ENCODING_LABEL_OFFSET_V1 2 /* 2 meaning two chars such as "sk" */
#define LUNA_PQC_ENCODING_LABEL_BYTES_V1 (LUNA_PQC_ENCODING_LABEL_OFFSET_V1 + (LUNA_PQC_ENCODING_ID_BYTES_V1 * 2))
// version 2 (exactly 32-bytes as in LUNA_PQC_PRIVATEBLOB_BYTES_32, for ed keys)
//   reserved xx xx xx xx                     (4 bytes, big endian) reserved
//   magic    xx xx xx xx                     (4 bytes, big endian) magic value
//   priv    "sk1234567890ABCDEabcde-_"       (24 bytes) label for private or secret key (no public key label)
#define LUNA_PQC_ENCODING_MAGIC 0x80cafe82
#define LUNA_PQC_ENCODING_ID_BYTES_V2 16 /* 16 meaning not to be confused with ouid(12), engine(20), fingerprint(32) */
#define LUNA_PQC_ENCODING_LABEL_OFFSET_V2 2 /* 2 meaning two chars such as "sk" */
#define LUNA_PQC_ENCODING_LABEL_BYTES_V2 (LUNA_PQC_ENCODING_LABEL_OFFSET_V2 + 22)

typedef struct luna_encoding_v1_st {
    uint32_t _reserved;
    unsigned char priv[LUNA_PQC_ENCODING_LABEL_BYTES_V1];
    unsigned char pub[LUNA_PQC_ENCODING_LABEL_BYTES_V1];
} luna_encoding_v1;

//#define SIZEOF_luna_encoding_v1 (sizeof(struct luna_encoding_v1_st))
#define SIZEOF_luna_encoding_v1 ( 4 + ( LUNA_PQC_ENCODING_LABEL_BYTES_V1 * 2 ) )
#if (SIZEOF_luna_encoding_v1 != LUNA_PQC_PRIVATEBLOB_BYTES_64)
#error "assertion failed: SIZEOF_luna_encoding_v1"
#endif

typedef struct luna_encoding_v2_st {
    // header
    uint32_t _reserved;
    uint32_t magic;
    // misc
    struct luna_encoding_label_v2_st {
        unsigned char value[LUNA_PQC_ENCODING_LABEL_BYTES_V2];
    } label;
} luna_encoding_v2;

//#define SIZEOF_luna_encoding_v2 (sizeof(struct luna_encoding_v2_st))
#define SIZEOF_luna_encoding_v2 ( 4 + 4 + ( LUNA_PQC_ENCODING_LABEL_BYTES_V2 ) )
#if (SIZEOF_luna_encoding_v2 != LUNA_PQC_PRIVATEBLOB_BYTES_32)
#error "assertion failed: SIZEOF_luna_encoding_v2"
#endif

static unsigned luna_encode_uint32(unsigned rvalue) {
    unsigned lvalue = 0;
    CK_BYTE *plvalue = (CK_BYTE *)&lvalue;
    ENCODE_UINT32(plvalue, rvalue);
    return lvalue;
}

#define LUNA_BIG_ENDIAN(_a) luna_encode_uint32(_a)

// return 0 if ch is an acceptable utf8 character
static int luna_prov_test_utf8(unsigned char ch) {
    if (ch == '\0')
        return -1;
    if (ch < 0x20)
        return -1;
    return (ch <= 126) ? 0 : -1;
}

// return 0 if buf points to an acceptable utf8 character buffer of length 1 or more
static int luna_prov_test_utf8_buffer(const unsigned char *buf, unsigned buflen) {
    int beyondEndOfString = 0;
    int count = 0;
    unsigned i;
    for (i = 0; i < buflen; i++) {
        if (beyondEndOfString) {
            // must be padded with zero beyond end of string
            if (buf[i] != '\0') {
                return -1;
            }
        } else {
            if (buf[i] == '\0') {
                beyondEndOfString = 1;
            } else {
                if (luna_prov_test_utf8(buf[i])) {
                    return -1;
                }
                count++;
            }
        }
    }
    return (count >= 1 ? 0 : -1);
}

// encode template (cannot fail)
static void LunaPqcEncodeTemplateV2(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    const CK_ATTRIBUTE *pPublic, const CK_ATTRIBUTE *pPrivate) {
    CK_BYTE *dest = (CK_BYTE*)pkeyinfo->privkey;
    LUNA_ASSERT(dest != NULL);
    LUNA_ASSERT ( (pPublic[0].type == CKA_LABEL) && (pPrivate[0].type == CKA_LABEL) );
    luna_encoding_v2 encoded;
    memset(&encoded, 0, sizeof(encoded));
    //encoded._reserved = do not touch
    encoded.magic = LUNA_BIG_ENDIAN(LUNA_PQC_ENCODING_MAGIC);
    // NOTE: encoded using private key label, padded with zero if shorter than buffer
    LUNA_ASSERT ( pPublic[0].ulValueLen <= sizeof(encoded.label.value) );
    LUNA_ASSERT ( pPrivate[0].ulValueLen <= sizeof(encoded.label.value) );
    memcpy(encoded.label.value, pPrivate[0].pValue, pPrivate[0].ulValueLen);
    LUNA_ASSERT( luna_prov_test_utf8_buffer(encoded.label.value, sizeof(encoded.label.value)) == 0);
    LUNA_PRINTF(("privkeylen = %u\n", (unsigned)pkeyinfo->privkeylen));
    LUNA_PRINTF(("sizeof(encoded) = %u\n", (unsigned)sizeof(encoded)));
    LUNA_ASSERT(pkeyinfo->privkeylen >= sizeof(encoded));
    memcpy(dest, &encoded, sizeof(encoded));
    // cleanse
    memset(&encoded, 0, sizeof(encoded));
}

// decode template (can fail)
static CK_RV LunaPqcDecodeTemplateV2(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    CK_BYTE *src = (CK_BYTE*)pkeyinfo->privkey;
    if (src == NULL)
        return CKR_ARGUMENTS_BAD;
    if ( (pPublic[0].type != CKA_LABEL) || (pPrivate[0].type != CKA_LABEL) )
        return CKR_ARGUMENTS_BAD;
    // read and endian convert
    luna_encoding_v2 encoded;
    if (pkeyinfo->privkeylen < sizeof(encoded))
        return CKR_OBJECT_DECODING_FAILED;
    memcpy(&encoded, src, sizeof(encoded));
    //encoded._reserved = do not touch
    encoded.magic = LUNA_BIG_ENDIAN(encoded.magic);
    // check
    if (encoded.magic != LUNA_PQC_ENCODING_MAGIC)
        return CKR_OBJECT_DECODING_FAILED;
    // populate cka_label (input label does NOT have end-of-string char)
    // test utf8 buffer
    if ( luna_prov_test_utf8_buffer(encoded.label.value, sizeof(encoded.label.value)) )
        return CKR_OBJECT_DECODING_FAILED;
    pPrivate[0].ulValueLen = strnlen((char*)encoded.label.value, sizeof(encoded.label.value));
    pPrivate[0].pValue = OPENSSL_memdup(encoded.label.value, pPrivate[0].ulValueLen);
    // NOTE: originally encoded using private key not public key; rename "sk" to "pk"
    if (encoded.label.value[0] == 's' && encoded.label.value[1] == 'k')
        encoded.label.value[0] = 'p';
    pPublic[0].ulValueLen = pPrivate[0].ulValueLen;
    pPublic[0].pValue = OPENSSL_memdup(encoded.label.value, pPublic[0].ulValueLen);
    // cleanse
    memset(&encoded, 0, sizeof(encoded));
    return CKR_OK;
}

// encode template (cannot fail)
static void LunaPqcEncodeTemplateV1(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    const CK_ATTRIBUTE *pPublic, const CK_ATTRIBUTE *pPrivate) {
    CK_BYTE *dest = (CK_BYTE*)pkeyinfo->privkey;
    LUNA_ASSERT(dest != NULL);
    LUNA_ASSERT ( (pPublic[0].type == CKA_LABEL) && (pPrivate[0].type == CKA_LABEL) );
    luna_encoding_v1 encoded;
    memset(&encoded, 0, sizeof(encoded));
    //encoded._reserved = do not touch
    // NOTE: both private and public labels are encoded, padded with zero if shorter than buffer
    LUNA_ASSERT ( pPublic[0].ulValueLen <= sizeof(encoded.pub) );
    LUNA_ASSERT ( pPrivate[0].ulValueLen <= sizeof(encoded.priv) );
    memcpy(encoded.priv, pPrivate[0].pValue, pPrivate[0].ulValueLen);
    memcpy(encoded.pub, pPublic[0].pValue, pPublic[0].ulValueLen);
    LUNA_ASSERT( luna_prov_test_utf8_buffer(encoded.priv, sizeof(encoded.priv)) == 0);
    LUNA_ASSERT( luna_prov_test_utf8_buffer(encoded.pub, sizeof(encoded.pub)) == 0);
    LUNA_PRINTF(("privkeylen = %u\n", (unsigned)pkeyinfo->privkeylen));
    LUNA_PRINTF(("sizeof(encoded) = %u\n", (unsigned)sizeof(encoded)));
    LUNA_ASSERT(pkeyinfo->privkeylen >= sizeof(encoded));
    memcpy(dest, &encoded, sizeof(encoded));
    // cleanse
    memset(&encoded, 0, sizeof(encoded));
}

// decode template (can fail)
static CK_RV LunaPqcDecodeTemplateV1(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    CK_BYTE *src = (CK_BYTE*)pkeyinfo->privkey;
    if (src == NULL)
        return CKR_ARGUMENTS_BAD;
    if ( (pPublic[0].type != CKA_LABEL) || (pPrivate[0].type != CKA_LABEL) )
        return CKR_ARGUMENTS_BAD;
    // read and endian convert
    luna_encoding_v1 encoded;
    if (pkeyinfo->privkeylen < sizeof(encoded))
        return CKR_OBJECT_DECODING_FAILED;
    memcpy(&encoded, src, sizeof(encoded));
    //encoded._reserved = do not touch
    // populate cka_label (input label does NOT have end-of-string char)
    // test utf8 buffer
    if ( luna_prov_test_utf8_buffer(encoded.priv, sizeof(encoded.priv)) ||
         luna_prov_test_utf8_buffer(encoded.pub, sizeof(encoded.pub)) )
        return CKR_OBJECT_DECODING_FAILED;
    pPrivate[0].ulValueLen = strnlen((char*)encoded.priv, sizeof(encoded.priv));
    pPrivate[0].pValue = OPENSSL_memdup(encoded.priv, pPrivate[0].ulValueLen);
    pPublic[0].ulValueLen = strnlen((char*)encoded.pub, sizeof(encoded.pub));
    pPublic[0].pValue = OPENSSL_memdup(encoded.pub, pPublic[0].ulValueLen);
    // cleanse
    memset(&encoded, 0, sizeof(encoded));
    return CKR_OK;
}

// pad unused key bytes with { 0x00 0x01 RAND_NON_ZERO 0x00 }
static void LunaPqcEncodePadEx(CK_BYTE *buf, size_t buflen_, unsigned fixedlen, CK_BYTE chVersion) {
    unsigned buflen = (unsigned)buflen_;
    LUNA_ASSERT(buflen_ <= LUNA_PROV_MAX_BUFFER);
    LUNA_ASSERT(buflen >= fixedlen);
    unsigned padlen = (buflen - fixedlen);
    if (padlen >= 3) {
        unsigned i, rnglen = (padlen - 3);
        CK_BYTE *p = (buf + fixedlen);
        CK_BYTE chTemp;
        *p++ = 0;
        *p++ = chVersion;
        if (rnglen > 0) {
            LUNA_ASSERT (luna_RAND_bytes(p, rnglen) == 1);
            for (i = 0; i < rnglen; i++) {
                if (p[i] == 0) {
                    chTemp = (CK_BYTE)i;
                    p[i] = (chTemp == 0) ? 0x7f : chTemp;
                }
            }
            p += rnglen;
        }
        *p++ = 0;
    }
}

static void LunaPqcEncodePadV2(CK_BYTE *buf, size_t buflen) {
    LunaPqcEncodePadEx(buf, buflen, LUNA_PQC_PRIVATEBLOB_BYTES_32, 0x02);
}

static void LunaPqcEncodePadV1(CK_BYTE *buf, size_t buflen) {
    LunaPqcEncodePadEx(buf, buflen, LUNA_PQC_PRIVATEBLOB_BYTES_64, 0x01);
}

// encode key bytes
static void LunaPqcEncodeTemplate(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    const CK_ATTRIBUTE *pPublic, const CK_ATTRIBUTE *pPrivate) {
    LUNA_ASSERT (pkeyinfo->privkeylen >= LUNA_PQC_PRIVATEBLOB_BYTES_32);
    if (pkeyinfo->privkeylen < LUNA_PQC_PRIVATEBLOB_BYTES_64) {
        LunaPqcEncodePadV2((CK_BYTE *)pkeyinfo->privkey, pkeyinfo->privkeylen);
        return LunaPqcEncodeTemplateV2(keyctx, pkeyinfo, pPublic, pPrivate);
    }
    LUNA_ASSERT (pkeyinfo->privkeylen >= LUNA_PQC_PRIVATEBLOB_BYTES_64);
    LunaPqcEncodePadV1((CK_BYTE *)pkeyinfo->privkey, pkeyinfo->privkeylen);
    return LunaPqcEncodeTemplateV1(keyctx, pkeyinfo, pPublic, pPrivate);
}

static CK_RV LunaPqcDecodeTemplate(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    // FIXME: for public key crypto it is possible (likely) that the private key blob is not populated.
    // So, we should always populate the private key blob because:
    //   1. the pkcs11 attribute template is encoded in the private key blob
    //   2. we cannot find the public key using the public key blob (i.e., the FM/SHIM cannot do it)
    //   3. assuming the public crypto can be done in software, which is
    //      subject to change if we ever support PQC without the liboqs.
    CK_BYTE *src = (CK_BYTE*)pkeyinfo->privkey;
    if (src == NULL)
        return CKR_ARGUMENTS_BAD;
    if ( (pPublic[0].type != CKA_LABEL) || (pPrivate[0].type != CKA_LABEL) )
        return CKR_ARGUMENTS_BAD;
    if (pkeyinfo->privkeylen < LUNA_PQC_PRIVATEBLOB_BYTES_32)
        return CKR_ARGUMENTS_BAD;
    CK_RV rv = LunaPqcDecodeTemplateV2(keyctx, pkeyinfo, pPublic, pPrivate);
    if (rv == CKR_OBJECT_DECODING_FAILED)
    {
        if (pkeyinfo->privkeylen < LUNA_PQC_PRIVATEBLOB_BYTES_64)
            return CKR_OBJECT_DECODING_FAILED;
        rv = LunaPqcDecodeTemplateV1(keyctx, pkeyinfo, pPublic, pPrivate);
    }
    return rv;
}

static CK_RV LunaPqcFillTemplateEx(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
        CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate, int fBase64url) {
#if (LUNA_PQC_ENCODING_ID_BYTES_V1 > LUNA_PQC_ENCODING_ID_BYTES_V2)
#error "assertion failed: LUNA_PQC_ENCODING_ID_BYTES_V1"
#endif
    unsigned char id[LUNA_PQC_ENCODING_ID_BYTES_V2] = {0};
    CK_ULONG idlen = sizeof(id);
#if (LUNA_PQC_ENCODING_LABEL_BYTES_V1 < LUNA_PQC_ENCODING_LABEL_BYTES_V2)
#error "assertion failed: LUNA_PQC_ENCODING_LABEL_BYTES_V1"
#endif
    char label_priv[LUNA_PQC_ENCODING_LABEL_BYTES_V1 + 1] = {0};
    char label_pub[LUNA_PQC_ENCODING_LABEL_BYTES_V1 + 1] = {0};
    if ( (pPublic[0].type != CKA_LABEL) ||
         (pPrivate[0].type != CKA_LABEL) )
        return CKR_GENERAL_ERROR;
    if (luna_RAND_bytes(id, sizeof(id)) != 1) {
        LUNA_PRINTF(("luna_RAND_bytes\n"));
        return CKR_GENERAL_ERROR;
    }
#if (LUNA_PQC_ENCODING_LABEL_OFFSET_V1 != 2) && (LUNA_PQC_ENCODING_LABEL_OFFSET_V2 != 2)
#error "assertion failed: LUNA_PQC_ENCODING_LABEL_OFFSET_V1"
#endif
    label_priv[0] = 's';
    label_priv[1] = 'k';
    if (fBase64url) {
        idlen = LUNA_PQC_ENCODING_ID_BYTES_V2;
        (void)luna_sprintf_base64url(&label_priv[2], id, idlen);
    } else {
        idlen = LUNA_PQC_ENCODING_ID_BYTES_V1;
        (void)luna_sprintf_hex(&label_priv[2], id, idlen);
    }
    memcpy(label_pub, label_priv, sizeof(label_pub));
    label_pub[0] = 'p';
    label_pub[1] = 'k';
    // populate cka_label (input label has end-of-string char)
    pPublic[0].pValue = OPENSSL_strdup(label_pub);
    pPublic[0].ulValueLen = (CK_ULONG)strlen(pPublic[0].pValue);
    pPrivate[0].pValue = OPENSSL_strdup(label_priv);
    pPrivate[0].ulValueLen = (CK_ULONG)strlen(pPrivate[0].pValue);
    // populate cka_id
    if (pPublic[1].type == CKA_ID) {
        pPublic[1].pValue = OPENSSL_memdup(id, idlen);
        pPublic[1].ulValueLen = idlen;
    }
    if (pPrivate[1].type == CKA_ID) {
        pPrivate[1].pValue = OPENSSL_memdup(id, idlen);
        pPrivate[1].ulValueLen = idlen;
    }
    return CKR_OK;
}

static CK_RV LunaPqcFillTemplateV1(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
        CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    return LunaPqcFillTemplateEx(keyctx, pkeyinfo,
            pPublic, pPrivate, 0);
}

static CK_RV LunaPqcFillTemplateV2(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
        CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    return LunaPqcFillTemplateEx(keyctx, pkeyinfo,
            pPublic, pPrivate, 1);
}

static CK_RV LunaPqcFillTemplate(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
        CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    if (pkeyinfo->privkeylen < LUNA_PQC_PRIVATEBLOB_BYTES_32)
        return CKR_GENERAL_ERROR;
    if (pkeyinfo->privkeylen < LUNA_PQC_PRIVATEBLOB_BYTES_64)
        return LunaPqcFillTemplateV2(keyctx, pkeyinfo,
                pPublic, pPrivate);
    return LunaPqcFillTemplateV1(keyctx, pkeyinfo,
            pPublic, pPrivate);
}

static void LunaPqcCleanTemplate(luna_prov_key_ctx *keyctx, CK_ATTRIBUTE *pPublic, CK_ATTRIBUTE *pPrivate) {
    if (pPublic[0].pValue && pPublic[0].type == CKA_LABEL) {
        OPENSSL_free(pPublic[0].pValue);
        pPublic[0].pValue = 0;
    }
    if (pPrivate[0].pValue && pPrivate[0].type == CKA_LABEL) {
        OPENSSL_free(pPrivate[0].pValue);
        pPrivate[0].pValue = 0;
    }
    if (pPublic[1].pValue && pPublic[1].type == CKA_ID) {
        OPENSSL_free(pPublic[1].pValue);
        pPublic[1].pValue = 0;
    }
    if (pPrivate[1].pValue && pPrivate[1].type == CKA_ID) {
        OPENSSL_free(pPrivate[1].pValue);
        pPrivate[1].pValue = 0;
    }
}

static CK_RV LunaPqcFind(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo) {
    CK_OBJECT_HANDLE publicObjectHandle = 0, privateObjectHandle = 0;
    CK_BBOOL yes = CK_TRUE;

    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_LABEL, 0, 0}, // first
        {CKA_ID, 0, 0}, // second
        {CKA_TOKEN, &yes, sizeof(yes)}
    };

    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_LABEL, 0, 0}, // first
        {CKA_ID, 0, 0}, // second
        {CKA_TOKEN, &yes, sizeof(yes)}
    };

    // NOTE: decode keyblob BEFORE lookup algorithm, to set flag is_hardware properly
    CK_RV rvfill = LunaPqcDecodeTemplate(keyctx, pkeyinfo, publicTemplate, privateTemplate);
    keyctx->is_hardware = 1; // assume hardware
    if (rvfill != CKR_OK) {
        if (rvfill == CKR_OBJECT_DECODING_FAILED) {
            keyctx->is_hardware = 0; // proven not hardware
        }
        return rvfill;
    }

    // NOTE: lookup algorithm AFTER decode keyblob, because LunaLookupAlgName can fail
    CK_RV rvlookup = LunaLookupAlgName(keyctx, NULL, NULL, NULL, NULL, NULL, NULL);
    if (rvlookup != CKR_OK)
        return rvlookup;

    CK_RV rv = LunaFind(keyctx, pkeyinfo, privateTemplate, 1, &privateObjectHandle);
    if (rv == CKR_OK) {
        rv = LunaFind(keyctx, pkeyinfo, publicTemplate, 1, &publicObjectHandle);
    }

    if (rv != CKR_OK) {
        LUNA_PRINTF(("Failed to find PQC keypair: 0x%lx\n", rv));
        keyctx->count_c_init = 0;
    } else {
        LUNA_PRINTF(("PQC keypair find was successful: pub=%lu, priv=%lu\n", publicObjectHandle, privateObjectHandle));
        keyctx->hPublic = publicObjectHandle;
        keyctx->hPrivate = privateObjectHandle;
        keyctx->count_c_init = P11_GET_COUNT();
    }

    if (rvfill == CKR_OK)
        LunaPqcCleanTemplate(keyctx, publicTemplate, privateTemplate);

    return rv;
}

static unsigned char curve_ed25519[] = {
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 /* [613] ed25519 */
};

static unsigned char curve_ed448[] = {
    0x06, 0x03, 0x2B, 0x65, 0x71 /* [639] ed448*/
};

static unsigned char curve_x25519[] = {
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 /* [601] x25519 */
};

static unsigned char curve_x448[] = {
    0x06, 0x03, 0x2B, 0x65, 0x6F /* [634] x448 */
};

static CK_RV LunaPqcGen(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo, int is_kem, int is_ecx) {
    CK_OBJECT_HANDLE publicObjectHandle = 0, privateObjectHandle = 0;
    CK_MECHANISM mechGen = {0, 0, 0};
    CK_KEY_PARAMS params = CKP_INVALID;
    CK_BBOOL yes = CK_TRUE;
    //CK_BBOOL no = CK_FALSE;
    CK_BBOOL ckaSign = CK_FALSE;
    CK_BBOOL ckaVerify = CK_FALSE;
    CK_BBOOL ckaDerivePriv = CK_FALSE;
    CK_BBOOL ckaDerivePub = CK_FALSE;
    CK_BBOOL ckaTokenObject = CK_FALSE;

    CK_ATTRIBUTE publicTemplate[] = {
        {CKA_LABEL, 0, 0}, // first
        {CKA_ID, 0, 0}, // second
        {CKA_TOKEN, &ckaTokenObject, sizeof(ckaTokenObject)},
        {CKA_VERIFY, &ckaVerify, sizeof(ckaVerify)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_MODIFIABLE, &yes, sizeof(yes)},
        {CKA_DERIVE, &ckaDerivePub, sizeof(ckaDerivePub)}, /* optional */
        {CKA_ECDSA_PARAMS, 0, 0} /* last, optional */
    };
    CK_ULONG publicTemplateCount = DIM(publicTemplate) - 2;

    CK_ATTRIBUTE privateTemplate[] = {
        {CKA_LABEL, 0, 0}, // first
        {CKA_ID, 0, 0}, // second
        {CKA_TOKEN, &ckaTokenObject, sizeof(ckaTokenObject)},
        {CKA_SIGN, &ckaSign, sizeof(ckaSign)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_MODIFIABLE, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_DERIVE, &ckaDerivePriv, sizeof(ckaDerivePriv)}, /* optional */
        {CKA_KEY_PARAMS, 0, 0} /* last, optional */
    };
    CK_ULONG privateTemplateCount = DIM(privateTemplate) - 2;

    if (is_kem) {
        ckaDerivePriv = ckaDerivePub = CK_TRUE;
        if (luna_get_pqc_shim() || is_ecx) {
            publicTemplate[publicTemplateCount].type = CKA_DERIVE;
            privateTemplate[privateTemplateCount].type = CKA_DERIVE;
        } else {
            publicTemplate[publicTemplateCount].type = CKA_ENCAPSULATE;
            privateTemplate[privateTemplateCount].type = CKA_DECAPSULATE;
        }
        publicTemplateCount++;
        privateTemplateCount++;
        /* FIXME: this assumes that KEM keys are never persisted */
        /* FIXME: this assumes the session cache is enabled! */
        ckaTokenObject = CK_FALSE;
    } else {
        ckaSign = ckaVerify = CK_TRUE;
        /* FIXME: this assumes that SIG keys are always persisted */
        ckaTokenObject = luna_get_token_object() ? CK_TRUE : CK_FALSE;
    }
    keyctx->is_kem = is_kem;

    CK_RV rvlookup = LunaLookupAlgName(keyctx, NULL, &params, &mechGen, NULL, NULL, NULL);
    if (rvlookup != CKR_OK)
        return rvlookup;
    CK_RV rvfill = LunaPqcFillTemplate(keyctx, pkeyinfo,
            publicTemplate, privateTemplate);
    if (rvfill != CKR_OK)
        return rvfill;
    /* small adjustment to make this code more reusable */
    if (params == CKP_INVALID) {
        if (!strcmp(keyctx->alg_name, "ed25519")) {
            publicTemplate[publicTemplateCount].type = CKA_ECDSA_PARAMS;
            publicTemplate[publicTemplateCount].pValue = &curve_ed25519;
            publicTemplate[publicTemplateCount].ulValueLen = sizeof(curve_ed25519);
            publicTemplateCount++;
        } else if (!strcmp(keyctx->alg_name, "ed448")) {
            publicTemplate[publicTemplateCount].type = CKA_ECDSA_PARAMS;
            publicTemplate[publicTemplateCount].pValue = &curve_ed448;
            publicTemplate[publicTemplateCount].ulValueLen = sizeof(curve_ed448);
            publicTemplateCount++;
        } else if (!strcmp(keyctx->alg_name, "x25519")) {
            publicTemplate[publicTemplateCount].type = CKA_ECDSA_PARAMS;
            publicTemplate[publicTemplateCount].pValue = &curve_x25519;
            publicTemplate[publicTemplateCount].ulValueLen = sizeof(curve_x25519);
            publicTemplateCount++;
        } else if (!strcmp(keyctx->alg_name, "x448")) {
            publicTemplate[publicTemplateCount].type = CKA_ECDSA_PARAMS;
            publicTemplate[publicTemplateCount].pValue = &curve_x448;
            publicTemplate[publicTemplateCount].ulValueLen = sizeof(curve_x448);
            publicTemplateCount++;
        }
    } else {
        if (luna_get_pqc_shim()) {
            privateTemplate[privateTemplateCount].type = CKA_KEY_PARAMS;
            privateTemplate[privateTemplateCount].pValue = &params;
            privateTemplate[privateTemplateCount].ulValueLen = sizeof(params);
            privateTemplateCount++;
        } else {
            // translate to main firmware
            LunaTranslateFM2FW(keyctx, NULL, &params, &mechGen, NULL, NULL, NULL);
            privateTemplate[privateTemplateCount].type = CKA_PARAMETER_SET;
            privateTemplate[privateTemplateCount].pValue = &params;
            privateTemplate[privateTemplateCount].ulValueLen = sizeof(params);
            privateTemplateCount++;
            publicTemplate[publicTemplateCount].type = CKA_PARAMETER_SET;
            publicTemplate[publicTemplateCount].pValue = &params;
            publicTemplate[publicTemplateCount].ulValueLen = sizeof(params);
            publicTemplateCount++;
        }
    }

    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    CK_RV rv = P11->C_GenerateKeyPair(session, &mechGen,
        publicTemplate, publicTemplateCount,
        privateTemplate, privateTemplateCount,
        &publicObjectHandle, &privateObjectHandle);
    if (rv != CKR_OK) {
        LUNA_PRINTF(("Failed to generate keypair: 0x%lx\n", rv));
        keyctx->count_c_init = 0;
    } else {
        LUNA_PRINTF(("Keypair generation was successful: pub=%lu, priv=%lu\n", publicObjectHandle, privateObjectHandle));
        keyctx->is_hardware = 1; // proven hardware
        keyctx->hPublic = publicObjectHandle;
        keyctx->hPrivate = privateObjectHandle;
        keyctx->bTokenObject = ckaTokenObject;
        keyctx->count_c_init = P11_GET_COUNT();
    }

    // encode the template in such a way the keypair can be written to a file (PEM-encoded),
    // so we can find the keypair later
    if (rv == CKR_OK) {
        LunaPqcEncodeTemplate(keyctx, pkeyinfo,
            publicTemplate, privateTemplate);
    }

    if (rvfill == CKR_OK)
        LunaPqcCleanTemplate(keyctx, publicTemplate, privateTemplate);

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

CK_RV LunaPqcSigSign(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_BYTE *signature, CK_ULONG *pulSignatureLen,
    const CK_BYTE *message, CK_ULONG messageLen) {

    CK_OBJECT_HANDLE privateObjectHandle = keyctx->hPrivate;
    CK_MECHANISM mechSig = {0, 0, 0};

    CK_RV rvlookup = LunaLookupAlgName(keyctx, NULL, NULL, NULL, &mechSig, NULL, NULL);
    if (rvlookup != CKR_OK)
        return rvlookup;

    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    CK_RV rv = CKR_OK;

    // check for stale object handle
    if (rv == CKR_OK) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    if (rv == CKR_OK) {
        if (! luna_get_pqc_shim()) {
            LunaTranslateFM2FW(keyctx, NULL, NULL, NULL, &mechSig, NULL, NULL);
        }
        rv = P11->C_SignInit(session, &mechSig, privateObjectHandle);
    }

#if 0
    // NOTE: the old version of the shim/fm required this check, which slows things down:
    // the PQC FM (or SHIM) does not follow pkcs11 calling convention when
    // the application calls C_Sign ONCE with a signatureLen larger than the actual length.
    // Also, the PQC FM (or SHIM) should fail when input is signatureLen=0, signature not NULL.
    // Instead, output is CKR_OK, with signatureLen=4, signature={ 0, 0, 0, 0 }.
    // The code below will guard against funny signatures caused by FM, SHIM, OQS, etc.
    if (rv == CKR_OK && signature != NULL) {
        CK_ULONG ulTempLen = 0;
        rv = P11->C_Sign(session, (CK_BYTE*)message, messageLen, NULL, &ulTempLen);
        if (rv == CKR_OK) {
            if (ulTempLen <= *pulSignatureLen) {
                if (ulTempLen >= LUNA_PQC_SIGNATURE_BYTES_MIN) {
                    *pulSignatureLen = ulTempLen;
                } else {
                    rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
                }
            } else {
                rv = CKR_BUFFER_TOO_SMALL;
            }
        }
    }
#endif

    if (rv == CKR_OK) {
        rv = P11->C_Sign(session, (CK_BYTE*)message, messageLen, signature, pulSignatureLen);
    }

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

CK_RV LunaPqcSigVerify(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    const CK_BYTE *message, CK_ULONG messageLen,
    const CK_BYTE *signature, CK_ULONG signatureLen) {

    CK_OBJECT_HANDLE publicObjectHandle = keyctx->hPublic;
    CK_MECHANISM mechSig = {0, 0, 0};
    CK_RV rvlookup = LunaLookupAlgName(keyctx, NULL, NULL, NULL, &mechSig, NULL, NULL);
    if (rvlookup != CKR_OK)
        return rvlookup;

    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    CK_RV rv = CKR_OK;

    // check for stale object handle
    if (rv == CKR_OK) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    if (rv == CKR_OK) {
        if (! luna_get_pqc_shim()) {
            LunaTranslateFM2FW(keyctx, NULL, NULL, NULL, &mechSig, NULL, NULL);
        }
        rv = P11->C_VerifyInit(session, &mechSig, publicObjectHandle);
    }
    if (rv == CKR_OK) {
        rv = P11->C_Verify(session, (CK_BYTE*)message, messageLen, (CK_BYTE*)signature, signatureLen);
    }

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

