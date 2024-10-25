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

#ifndef H_LUNA_SAUTIL_H
#define H_LUNA_SAUTIL_H

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/

#define OP_OPEN 0x00000001
#define OP_CLOSE 0x00000002
#define OP_GENERATE_RSA_KEY_PAIR 0x00000004
#define OP_GENERATE_DSA_KEY_PAIR 0x00000008
#define OP_GENERATE_DH_KEY_PAIR 0x00000010
#define OP_DELETE_RSA_KEY_PAIR 0x00000020
#define OP_DELETE_DSA_KEY_PAIR 0x00000040
#define OP_GENERATE_ECDSA_KEY_PAIR 0x00000100
#define OP_DELETE_ECDSA_KEY_PAIR 0x00000200
#define OP_RESTORE_KEYFILE 0x00000400
#define OP_GENERATE_PQC_KEY_PAIR 0x00001000
#define OP_DELETE_PQC_KEY_PAIR 0x00002000

static unsigned char dsa_1024_prime[] = {
    0xfc, 0xec, 0x61, 0x82, 0xeb, 0x20, 0x6b, 0x43, 0xc0, 0x3e, 0x36, 0xc0, 0xea, 0xda, 0xbf, 0xf5, 0x6a, 0x0c, 0x2e,
    0x79, 0xde, 0xf4, 0x4b, 0xc8, 0xf2, 0xe5, 0x36, 0x99, 0x09, 0x6d, 0x1f, 0xf2, 0x70, 0xf1, 0x59, 0x78, 0x5d, 0x75,
    0x69, 0x21, 0xdb, 0xff, 0x97, 0x73, 0xae, 0x08, 0x48, 0x3b, 0x66, 0x2f, 0xc0, 0x7d, 0xf7, 0x51, 0x2f, 0xf6, 0x8b,
    0x2e, 0x55, 0x65, 0xfd, 0x79, 0x82, 0xe2, 0x0c, 0x24, 0x48, 0x32, 0xab, 0xa1, 0x21, 0xcc, 0x07, 0x99, 0xcc, 0x09,
    0xf2, 0xd5, 0x41, 0x4d, 0x5f, 0x39, 0x66, 0x21, 0x13, 0x65, 0xf5, 0x1b, 0x83, 0xe9, 0xff, 0xcc, 0xcb, 0x3d, 0x88,
    0xcd, 0xf2, 0x38, 0xf7, 0xc2, 0x73, 0x91, 0x31, 0xca, 0x7a, 0xad, 0xff, 0x66, 0x2f, 0xec, 0x1f, 0xb0, 0xe1, 0xd3,
    0x11, 0xa4, 0x04, 0x26, 0x03, 0x76, 0xfd, 0x01, 0x1f, 0xe0, 0x0d, 0x02, 0x04, 0xc3};

static unsigned char dsa_1024_subPrime[] = {0xd3, 0x80, 0x73, 0x53, 0xb5, 0x1c, 0x5f, 0x71, 0xb2, 0x2a,
                                            0xc3, 0xd0, 0xc7, 0xe3, 0x94, 0x14, 0x8f, 0xce, 0xdc, 0x61};

static unsigned char dsa_1024_base[] = {
    0x42, 0xe3, 0x77, 0x8e, 0x6e, 0xc3, 0x1b, 0x0d, 0xb0, 0x7a, 0x6b, 0x37, 0x0d, 0x7f, 0xb6, 0xfb, 0x4a, 0x0b, 0xca,
    0x6d, 0xea, 0xac, 0x37, 0x1f, 0x6a, 0xdb, 0xcb, 0xeb, 0xa3, 0x8d, 0xdf, 0x76, 0xa4, 0x7c, 0x3c, 0x3d, 0x79, 0x27,
    0x6a, 0x0e, 0x57, 0x9c, 0xe4, 0xe3, 0x47, 0x18, 0x0f, 0xd9, 0xb4, 0xad, 0x46, 0x1d, 0x6c, 0xf0, 0xea, 0xc5, 0x1f,
    0xb0, 0x8c, 0xf4, 0x52, 0xf6, 0x24, 0x57, 0x00, 0x51, 0xe5, 0x18, 0xa7, 0x5a, 0x5b, 0xb9, 0xc3, 0x57, 0x8a, 0x14,
    0xfd, 0x4f, 0x27, 0xf7, 0x95, 0xb2, 0x2a, 0xce, 0xa6, 0x2b, 0x1f, 0xdf, 0x10, 0x32, 0xc1, 0x26, 0x6d, 0xa0, 0x81,
    0xc7, 0xfb, 0x99, 0xc4, 0x26, 0x66, 0x26, 0x58, 0x70, 0x93, 0xfd, 0x38, 0x16, 0x17, 0x23, 0x8e, 0xe1, 0x57, 0x8f,
    0xc3, 0x25, 0x54, 0x8d, 0xc1, 0xc0, 0x8e, 0x5f, 0x93, 0x22, 0xc3, 0xb1, 0x20, 0x5e};

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

#endif
