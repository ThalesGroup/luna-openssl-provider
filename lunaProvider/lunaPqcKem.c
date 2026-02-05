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

#ifdef CKK_MLKEM
#define CK_KEYTYPE_IS_PQC_KEM(_t) ( (_t) == CKK_KYBER || (_t) == CKK_MLKEM )
#else
#define CK_KEYTYPE_IS_PQC_KEM(_t) ( (_t) == CKK_KYBER || 0 )
#endif

#define CK_KEYTYPE_IS_ECX_KEM(_t) ( (_t) == CKK_EC_MONTGOMERY )

static CK_RV LunaPqcKemEncap(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    void **ppdata, CK_ULONG *plen, CK_BYTE *psecret, CK_ULONG secretLen) {
    CK_OBJECT_HANDLE encapObjectHandle = 0;
    CK_BYTE_PTR cipherText = NULL;
    CK_ULONG cipherTextLen = 0;

    CK_KEY_TYPE keytype = CKK_INVALID;
    CK_KEY_PARAMS params = CKP_INVALID;
    CK_MECHANISM encapMech = {0,0,0};
    CK_RV rvlookup = LunaLookupAlgName(keyctx, &keytype, &params, NULL, NULL, &encapMech, NULL);
    if (rvlookup != CKR_OK)
        return rvlookup;
    const int isPqcKem = CK_KEYTYPE_IS_PQC_KEM(keytype);
    if ( ! isPqcKem )
        return CKR_ARGUMENTS_BAD;
    if ( ! luna_prov_is_ecdh_len(secretLen) )
        return CKR_ARGUMENTS_BAD;

    // If the public key isn't in the HSM, encapsulation can take a byte array for pPublicKey and
    // the length is specified with ulPubKeyLen. In this case, the params must give the CKP_KYBER_* value as well
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    CK_OBJECT_HANDLE publicObjectHandle = 0;
    CK_KEM_ENCAP_PARAMS kyberEncapParams; /* same as CK_KYBER_ENCAP_PARAMS */
    if (isPqcKem) {
        if (luna_get_pqc_shim()) {
            memset(&kyberEncapParams, 0, sizeof(kyberEncapParams));
            // first, check LUNA_PROV_KEY_REASON_CREATE
            if (keyctx->reason == LUNA_PROV_KEY_REASON_CREATE) {
                LUNA_PRINTF(("fm.encapsulate using created object\n"));
                publicObjectHandle = keyctx->hPublic;
                if (publicObjectHandle == 0) {
                    return CKR_KEY_CHANGED;
                }
                kyberEncapParams.pPublicKey = NULL;
                kyberEncapParams.ulPubKeyLen = 0;
                kyberEncapParams.params = 0;
            } else if (luna_prov_key_reason_pubkey(keyctx->reason)) {
                LUNA_PRINTF(("fm.encapsulate using buffer\n"));
                publicObjectHandle = 0;
                kyberEncapParams.pPublicKey = pkeyinfo->pubkey;
                kyberEncapParams.ulPubKeyLen = pkeyinfo->pubkeylen;
                kyberEncapParams.params = params;
            } else if (keyctx->reason == LUNA_PROV_KEY_REASON_GEN) {
                LUNA_PRINTF(("fm.encapsulate using generated object\n"));
                publicObjectHandle = keyctx->hPublic;
                if (publicObjectHandle == 0) {
                    return CKR_KEY_CHANGED;
                }
                kyberEncapParams.pPublicKey = NULL;
                kyberEncapParams.ulPubKeyLen = 0;
                kyberEncapParams.params = 0;
            } else {
                return CKR_KEY_CHANGED;
            }
            kyberEncapParams.kdfType = CKD_NULL;
            kyberEncapParams.pInfo = NULL;
            kyberEncapParams.ulInfoLen = 0;
            kyberEncapParams.pCiphertext = NULL;
            kyberEncapParams.pulCiphertextLen = &cipherTextLen;

            encapMech.pParameter = &kyberEncapParams;
            encapMech.ulParameterLen = sizeof(kyberEncapParams);

        } else {
            // translate to main firmware
            LunaTranslateFM2FW(keyctx, &keytype, &params, NULL, NULL, &encapMech, NULL);
            // first, check LUNA_PROV_KEY_REASON_CREATE
            if (keyctx->reason == LUNA_PROV_KEY_REASON_CREATE) {
                LUNA_PRINTF(("fw.encapsulate using created object\n"));
                publicObjectHandle = keyctx->hPublic;
                if (publicObjectHandle == 0) {
                    return CKR_KEY_CHANGED;
                }
            } else if (luna_prov_key_reason_pubkey(keyctx->reason)) {
                LUNA_PRINTF(("fw.encapsulate using created object(0)\n"));
                publicObjectHandle = 0;
                // create the public key once
                {
                    CK_ULONG ckoClass = CKO_PUBLIC_KEY;
                    CK_BBOOL yes = CK_TRUE;
                    CK_BBOOL no = CK_FALSE;
                    CK_ATTRIBUTE attr[] = {
                        { CKA_TOKEN, &no, sizeof(no) },
                        { CKA_CLASS, &ckoClass, sizeof(ckoClass) },
                        { CKA_KEY_TYPE, &keytype, sizeof(keytype) },
                        { CKA_ENCAPSULATE, &yes, sizeof(yes) },
                        { CKA_VALUE, 0, 0 },
                        { CKA_PARAMETER_SET, &params, sizeof(params) },
                    };
                    CK_ATTRIBUTE *pattr = &attr[4];
                    pattr->pValue = pkeyinfo->pubkey;
                    pattr->ulValueLen = pkeyinfo->pubkeylen;
                    if ( (P11->C_CreateObject(session, attr, DIM(attr), &publicObjectHandle) != CKR_OK)
                            || (publicObjectHandle == 0) ) {
                        LUNA_PRINTF(("C_CreateObject failed\n"));
                        return CKR_KEY_CHANGED;
                    }
                    keyctx->hPublic = publicObjectHandle;
                    _LUNA_OQS_WRITEKEY(keyctx, LUNA_PROV_KEY_REASON_CREATE);
                }
            } else if (keyctx->reason == LUNA_PROV_KEY_REASON_GEN) {
                LUNA_PRINTF(("fw.encapsulate using generated object\n"));
                publicObjectHandle = keyctx->hPublic;
                if (publicObjectHandle == 0) {
                    return CKR_KEY_CHANGED;
                }
            } else {
                return CKR_KEY_CHANGED;
            }
        }
    }

    CK_ULONG valueLen = secretLen;
    CK_KEY_TYPE aesKeyType = CKK_GENERIC_SECRET;
    char *encapLabel = "temp-luna-kem-encap";

    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG ckoSecret = CKO_SECRET_KEY;
    CK_ATTRIBUTE encapTemplate[] = {
        {CKA_CLASS, &ckoSecret, sizeof(ckoSecret)}, // TODO: CKA_CLASS must be present?
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
        {CKA_MODIFIABLE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
        {CKA_LABEL, encapLabel, strlen(encapLabel)}, // TODO: must be last?
    };

    CK_RV rv = CKR_OK;

    if (plen == NULL)
        return CKR_ARGUMENTS_BAD;

    // check for stale object handle
    if (rv == CKR_OK && publicObjectHandle != 0) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    // Perform the encapsulation using the kyber public key. First get the length of the ciphertext
    if ( ppdata == NULL || psecret == NULL ) {
        if (rv == CKR_OK) {
            if (luna_get_pqc_shim()) {
                rv = P11->C_DeriveKey(session, &encapMech, publicObjectHandle,
                        encapTemplate, DIM(encapTemplate), &encapObjectHandle);
            } else {
                rv = p11.ext.CA_EncapsulateKey(session, &encapMech,
                        publicObjectHandle,
                        encapTemplate, DIM(encapTemplate),
                        NULL, &cipherTextLen,
                        &encapObjectHandle);
            }

            if (rv != CKR_OK) {
                LUNA_PRINTF(("Failed to get ciphertext length: 0x%lx\n", rv));
            } else {
                LUNA_PRINTF(("Ciphertext length: %lu\n", cipherTextLen));
            }
        }

        // always return output length
        LUNA_PRINTF(("Ciphertext output length: %lu\n", cipherTextLen));
        *plen = cipherTextLen;

    } else {
        // input length
        cipherTextLen = *plen;
        LUNA_PRINTF(("Ciphertext input length: %lu\n", cipherTextLen));
        if (cipherTextLen < 32)
            return CKR_ARGUMENTS_BAD;

        if (rv == CKR_OK) {
            //allocate the ciphertext buffer and the derive the key. The cipherText buffer will be populated after this operation.
            cipherText = OPENSSL_malloc(cipherTextLen);
            if (cipherText == NULL)
                return CKR_GENERAL_ERROR;
            kyberEncapParams.pCiphertext = cipherText;
            if (luna_get_pqc_shim()) {
                rv = P11->C_DeriveKey(session, &encapMech, publicObjectHandle,
                        encapTemplate, DIM(encapTemplate), &encapObjectHandle);
            } else {
                rv = p11.ext.CA_EncapsulateKey(session, &encapMech,
                        publicObjectHandle,
                        encapTemplate, DIM(encapTemplate),
                        cipherText, &cipherTextLen,
                        &encapObjectHandle);
            }

            if (rv != CKR_OK) {
                LUNA_PRINTF(("PQC encap failed: 0x%lx\n", rv));
            } else {
                LUNA_PRINTF(("PQC encap was successful: encap=%lu\n", encapObjectHandle));
            }
        }

        // unwrap key and get key bytes
        if (rv == CKR_OK) {
            rv = LunaUnwrapKeyBytes(keyctx, pkeyinfo, encapObjectHandle, psecret, secretLen);
            if (rv != CKR_OK) {
                LUNA_PRINTF(("PQC unwrap failed: 0x%lx\n", rv));
            } else {
                LUNA_PRINTF(("PQC unwrap was successful\n"));
            }
        }

        // clean buffers
        if (rv != CKR_OK) {
            OPENSSL_free(cipherText);
        } else {
            *ppdata = cipherText;
        }

        // clean objects
        if (encapObjectHandle != 0) {
            (void)P11->C_DestroyObject(session, encapObjectHandle);
        }

        // always return output length
        LUNA_PRINTF(("Ciphertext output length: %lu\n", cipherTextLen));
        *plen = cipherTextLen;
    }

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaPqcKemDecap(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo,
    CK_BYTE *psecret, CK_ULONG secretLen, const CK_BYTE *cipherText, CK_ULONG cipherTextLen) {
    CK_RV rv = CKR_OK;

    CK_OBJECT_HANDLE privateObjectHandle = keyctx->hPrivate;
    CK_OBJECT_HANDLE decapObjectHandle = 0;

    CK_ULONG valueLen = secretLen;
    CK_KEY_TYPE aesKeyType = CKK_GENERIC_SECRET;
    char *decapLabel = "temp-luna-kem-decap";

    CK_KEY_TYPE keytype = CKK_INVALID;
    CK_MECHANISM decapMech = {0,0,0};
    CK_RV rvlookup = LunaLookupAlgName(keyctx, &keytype, NULL, NULL, NULL, NULL, &decapMech);
    if (rvlookup != CKR_OK)
        return rvlookup;
    const int isPqcKem = CK_KEYTYPE_IS_PQC_KEM(keytype);
    const int isEcxKem = CK_KEYTYPE_IS_ECX_KEM(keytype);
    if ( ! (isPqcKem || isEcxKem) )
        return CKR_ARGUMENTS_BAD;
    if ( ! luna_prov_is_ecdh_len(secretLen) )
        return CKR_ARGUMENTS_BAD;

    CK_KEM_DECAP_PARAMS kyberDecapParams; /* same as CK_KYBER_DECAP_PARAMS */
    CK_ECDH1_DERIVE_PARAMS ecxDecapParams;
    CK_BYTE bufEcxPubKey[64] = {0};

    if (isPqcKem) {
        if (luna_get_pqc_shim()) {
            memset(&kyberDecapParams, 0, sizeof(kyberDecapParams));
            kyberDecapParams.kdfType = CKD_NULL;
            kyberDecapParams.pCiphertext = (CK_BYTE*)cipherText;
            kyberDecapParams.ulCiphertextLen = cipherTextLen;
            kyberDecapParams.pInfo = NULL;
            kyberDecapParams.ulInfoLen = 0;

            decapMech.pParameter = &kyberDecapParams;
            decapMech.ulParameterLen = sizeof(CK_KYBER_DECAP_PARAMS);
        } else {
            // translate to main firmware
            LunaTranslateFM2FW(keyctx, &keytype, NULL, NULL, NULL, NULL, &decapMech);
        }

    } else if (isEcxKem) {

        LUNA_ASSERT( cipherTextLen <= (sizeof(bufEcxPubKey) - 2) );
        memcpy(&bufEcxPubKey[2], cipherText, cipherTextLen);
        bufEcxPubKey[0] = 0x04;
        bufEcxPubKey[1] = (CK_BYTE)(unsigned)cipherTextLen;
        _LUNA_debug_ex("LunaPqcKemDecap", "bufEcxPubKey", bufEcxPubKey, (cipherTextLen + 2));

        memset(&ecxDecapParams, 0, sizeof(ecxDecapParams));
        ecxDecapParams.kdf = CKD_NULL;
        ecxDecapParams.ulSharedDataLen = 0;
        ecxDecapParams.pSharedData = NULL;
        ecxDecapParams.pPublicData = bufEcxPubKey;
        ecxDecapParams.ulPublicDataLen = (cipherTextLen + 2);

        decapMech.pParameter = &ecxDecapParams;
        decapMech.ulParameterLen = sizeof(ecxDecapParams);
    }

    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG ckoSecret = CKO_SECRET_KEY;
    CK_ATTRIBUTE decapTemplate[] = {
        {CKA_CLASS, &ckoSecret, sizeof(ckoSecret)}, // TODO: CKA_CLASS must be present?
        {CKA_TOKEN, &no, sizeof(no)},
        {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
        {CKA_MODIFIABLE, &no, sizeof(no)},
        {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
        {CKA_LABEL, decapLabel, strlen(decapLabel)}, // TODO: must be last?
    };

    // check for stale object handle
    if (rv == CKR_OK) {
        if (KEYCTX_CHECK_COUNT(keyctx)) {
            rv = CKR_KEY_CHANGED;
            LUNA_PRINTF(("key handle is stale\n"));
        }
    }

    // Perform the decapsulation using the private key
    CK_SESSION_HANDLE session = pkeyinfo->sess.hSession;
    if (rv == CKR_OK) {
        if (isEcxKem || luna_get_pqc_shim()) {
            rv = P11->C_DeriveKey(session, &decapMech, privateObjectHandle,
                    decapTemplate, DIM(decapTemplate), &decapObjectHandle);
        } else {
            rv = p11.ext.CA_DecapsulateKey(session, &decapMech,
                    privateObjectHandle,
                    decapTemplate, DIM(decapTemplate),
                    (CK_BYTE*)cipherText, cipherTextLen,
                    &decapObjectHandle);
        }

        if (rv != CKR_OK) {
            LUNA_PRINTF(("PQC decap failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("PQC decap was successful: hObject=%lu\n", decapObjectHandle));
        }
    }

    // unwrap key and get key bytes
    if (rv == CKR_OK) {
        rv = LunaUnwrapKeyBytes(keyctx, pkeyinfo, decapObjectHandle, psecret, secretLen);
        if (rv != CKR_OK) {
            LUNA_PRINTF(("PQC unwrap failed: 0x%lx\n", rv));
        } else {
            LUNA_PRINTF(("PQC unwrap was successful\n"));
        }
    }

    if (decapObjectHandle != 0) {
        (void)P11->C_DestroyObject(session, decapObjectHandle);
        decapObjectHandle = 0;
    }

    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaExportPublic(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo, CK_ATTRIBUTE_TYPE attrType) {
    CK_OBJECT_HANDLE hPublic = keyctx->hPublic;
    CK_BYTE *pubkey = (CK_BYTE*)pkeyinfo->pubkey;
    CK_ULONG pubkeylen = pkeyinfo->pubkeylen;
    CK_ATTRIBUTE attributeTemplate[] = {
        {0, NULL, 0}
    };
    attributeTemplate[0].type = attrType;
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
        rv = P11->C_GetAttributeValue(session, hPublic,
            attributeTemplate, DIM(attributeTemplate));
    }

    /* check if we are dealing with an encoded attribute (x25519/ed25519) */
    if ( (rv == CKR_OK)
            && ( (attrType == CKA_EC_POINT) && (attributeTemplate[0].ulValueLen == (pubkeylen + 2)))
            ) {
        CK_BYTE bufDebug[64] = {0};
        if (attributeTemplate[0].ulValueLen <= sizeof(bufDebug)) {
            CK_ATTRIBUTE attrDebug;
            attrDebug.type = attrType;
            attrDebug.pValue = bufDebug;
            attrDebug.ulValueLen = attributeTemplate[0].ulValueLen;
            if (P11->C_GetAttributeValue(session, hPublic, &attrDebug, 1) == CKR_OK) {
                _LUNA_debug_ex("LunaExportPublic", "attr.pValue", bufDebug, attrDebug.ulValueLen);
                /* extract the raw attribute */
                if ( (bufDebug[0] == 0x04) && ((CK_ULONG)(bufDebug[1]) == pubkeylen) ) {
                    LUNA_PRINTF(("fixing %lu bytes\n", pubkeylen));
                    memcpy(pubkey, &bufDebug[2], pubkeylen);
                    rv = CKR_OK;
                    luna_context_set_last_error(&pkeyinfo->sess, rv);
                    return rv;
                }
            }
        }
    }

    if (rv != CKR_OK) {
        LUNA_PRINTF(("Failed to get public key value size: rv = 0x%lx, pubkeylen = %u\n",
            rv, (unsigned)pubkeylen));
        luna_context_set_last_error(&pkeyinfo->sess, rv);
        return rv;
    }

    if (attributeTemplate[0].ulValueLen != pubkeylen) {
        if (attributeTemplate[0].ulValueLen < pubkeylen) {
            LUNA_PRINTF(("WARNING: public key value size: expected = %u, actual = %u\n",
                (unsigned)pubkeylen, (unsigned)attributeTemplate[0].ulValueLen));
        } else {
            LUNA_PRINTF(("ERROR: public key value size: expected = %u, actual = %u\n",
                (unsigned)pubkeylen, (unsigned)attributeTemplate[0].ulValueLen));
            rv = CKR_GENERAL_ERROR;
            luna_context_set_last_error(&pkeyinfo->sess, rv);
            return rv;
        }
    }

    CK_ULONG padlen = (pubkeylen - attributeTemplate[0].ulValueLen);
    memset(pubkey, 0, padlen);
    attributeTemplate[0].pValue = &pubkey[padlen];
    attributeTemplate[0].ulValueLen = pubkeylen;
    rv = P11->C_GetAttributeValue(session, hPublic, attributeTemplate, DIM(attributeTemplate));
    luna_context_set_last_error(&pkeyinfo->sess, rv);
    return rv;
}

static CK_RV LunaPqcExportPublic(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo) {
    return LunaExportPublic(keyctx, pkeyinfo, CKA_VALUE);
}

static CK_RV LunaEcxExportPublic(luna_prov_key_ctx *keyctx, luna_prov_keyinfo *pkeyinfo) {
    return LunaExportPublic(keyctx, pkeyinfo, CKA_EC_POINT);
}

