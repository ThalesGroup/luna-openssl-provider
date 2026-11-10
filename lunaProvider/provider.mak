#!/bin/false
##############################################################################
#
# This file is part of the "Luna OpenSSL for PQC" project.
#
# The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
# following Web site for further details: https://mit-license.org/ ).
#
# Copyright © 2024 Thales Group
#
##############################################################################

# flags consistent with openssl
include ..\win-cl-ssl.mk
# NOTE: providers are compiled with unicode
CNF_CPPFLAGS=$(CNF_CPPFLAGS_BASE) -D"UNICODE" -D"_UNICODE"

# flags consistent with luna
# NOTE: need to build openssl to ensure the static library matches the header files
VERSION=3.5.5
OPENSSL_SOURCE=..\openssl-build\openssl-$(VERSION)
LIB2_STATIC=$(OPENSSL_SOURCE)\libcrypto_static.lib
LIB2_DYNAMIC=$(OPENSSL_SOURCE)\libcrypto.lib
LIBOQS_PREFIX=$(CFG_INSTALLDIR)\..\liboqs001
LUNA_OQS=1
!IF "$(LUNA_OQS)" != "0"
LIB_OQS_STATIC=$(LIBOQS_PREFIX)\lib\oqs.lib
!ELSE
LIB_OQS_STATIC=
!ENDIF

# flags consistent with lunaprov
APPNAME=lunaprov
!IF "$(LUNA_OQS)" != "0"
LUNAPROV_DEFINES=/D"OS_WIN32" /D"LUNA_CLOUDFLARE" /D"OQS_PROVIDER_NOATOMIC" /D"LUNA_OQS"
!ELSE
LUNAPROV_DEFINES=/D"OS_WIN32" /D"LUNA_CLOUDFLARE" /D"OQS_PROVIDER_NOATOMIC"
!ENDIF
CL_OPTS64=$(DSO_CPPFLAGS) $(DSO_CFLAGS) $(LUNAPROV_DEFINES) /D"OS_WIN64"
LD_OPTS64=$(DSO_LDFLAGS) /machine:amd64
LIBSTD=$(DSO_EX_LIBS)

SOURCES=lunaEddsaSig.c lunaEcxGen.c lunaEcx.c lunaEcdh.c lunaFileStore.c lunaCommon.c lunaProvider.c lunaRsaSig.c lunaRsaEnc.c lunaEcSig.c lunaDsaSig.c lunaRsaGen.c lunaEcGen.c lunaDsaGen.c
OBJECTS=lunaEddsaSig.obj lunaEcxGen.obj lunaEcx.obj lunaEcdh.obj lunaFileStore.obj lunaCommon.obj lunaProvider.obj lunaRsaSig.obj lunaRsaEnc.obj lunaEcSig.obj lunaDsaSig.obj lunaRsaGen.obj lunaEcGen.obj lunaDsaGen.obj

!IF "$(LUNA_OQS)" != "0"
OQS_SOURCES=oqsprov2\oqs_decode_der2key.c \
  oqsprov2\oqs_encode_key2any.c \
  oqsprov2\oqs_endecoder_common.c \
  oqsprov2\oqs_kem.c \
  oqsprov2\oqs_kmgmt.c \
  oqsprov2\oqsprov_bio.c \
  oqsprov2\oqsprov_capabilities.c \
  oqsprov2\oqsprov_keys.c \
  oqsprov2\oqs_sig.c
OQS_OBJECTS=oqs_decode_der2key.obj \
  oqs_encode_key2any.obj \
  oqs_endecoder_common.obj \
  oqs_kem.obj \
  oqs_kmgmt.obj \
  oqsprov_bio.obj \
  oqsprov_capabilities.obj \
  oqsprov_keys.obj \
  oqs_sig.obj
!ELSE
OQS_SOURCES=
OQS_OBJECTS=
!ENDIF

# misc include paths
INCLUDES_INTERNAL=-I$(OPENSSL_SOURCE)\include
INCLUDES_INTERNAL_PROV=-I$(OPENSSL_SOURCE)\providers\implementations\include -I$(OPENSSL_SOURCE)\providers\common\include -I$(OPENSSL_SOURCE)\providers\fips\include -I$(OPENSSL_SOURCE)\providers
INCLUDES_ENGINE=-I..\engine
INCLUDES_OQS=-I.\oqsprov2 -I$(LIBOQS_PREFIX)\include
INCLUDES_PROV=$(INCLUDES_ENGINE) $(INCLUDES_OQS) $(INCLUDES_INTERNAL_PROV)
INCLUDES=$(INCLUDES_INTERNAL) $(INCLUDES_PROV)

default0 default64: lunaprov.dll

lunaprov.dll: $(OQS_OBJECTS) $(OBJECTS)
	$(CC) lunaprov_deps.c $(CL_OPTS64) /link $(LD_OPTS64) /DEF:lunaprov_deps.def /OUT:lunaprov_deps.dll $(LIB2_STATIC) $(LIBSTD)
	$(CC) $(OQS_OBJECTS) $(OBJECTS) $(CL_OPTS64) $(INCLUDES) /link $(LD_OPTS64) /DEF:lunaprov.def /OUT:lunaprov.dll $(LIB2_DYNAMIC) lunaprov_deps.lib $(LIB_OQS_STATIC) $(LIBSTD)

clean:
	$(RM) lunaprov.dll lunaprov.pdb
	$(RM) lunaprov_deps.dll lunaprov_deps.pdb
	$(RM) *.obj
	$(RM) *.lib *.ilk *.exp

install:
	$(CP) "lunaprov.dll" "$(CFG_INSTALLDIR)/lib/ossl-modules/"
	$(CP) "lunaprov.pdb" "$(CFG_INSTALLDIR)/lib/ossl-modules/"
	$(CP) "lunaprov_deps.dll" "$(CFG_INSTALLDIR)/lib/ossl-modules/"
	$(CP) "lunaprov_deps.pdb" "$(CFG_INSTALLDIR)/lib/ossl-modules/"

uninstall:
	$(RM) "$(CFG_INSTALLDIR)/lib/ossl-modules/lunaprov.dll"
	$(RM) "$(CFG_INSTALLDIR)/lib/ossl-modules/lunaprov.pdb"
	$(RM) "$(CFG_INSTALLDIR)/lib/ossl-modules/lunaprov_deps.dll"
	$(RM) "$(CFG_INSTALLDIR)/lib/ossl-modules/lunaprov_deps.pdb"

.PHONY: default0 default64 clean install uninstall

# TODO: funny dependencies (and modifying a header file requires a clean build)
lunaCommon.obj: lunaCommon.c ../engine/e_gem.c lunaPqcKem.c lunaPqcSig.c
	$(CC) lunaCommon.c /c $(CL_OPTS64) $(INCLUDES)

lunaEddsaSig.obj: lunaEddsaSig.c
	$(CC) lunaEddsaSig.c /c $(CL_OPTS64) $(INCLUDES)

lunaEcxGen.obj: lunaEcxGen.c
	$(CC) lunaEcxGen.c /c $(CL_OPTS64) $(INCLUDES)

lunaEcx.obj: lunaEcx.c
	$(CC) lunaEcx.c /c $(CL_OPTS64) $(INCLUDES)

lunaEcdh.obj: lunaEcdh.c
	$(CC) lunaEcdh.c /c $(CL_OPTS64) $(INCLUDES)

lunaFileStore.obj: lunaFileStore.c lunaFileAny2obj.c
	$(CC) lunaFileStore.c /c $(CL_OPTS64) $(INCLUDES)

lunaProvider.obj: lunaProvider.c luna_encoders.inc luna_decoders.inc lunaprov_capabilities.c
	$(CC) lunaProvider.c /c $(CL_OPTS64) $(INCLUDES)

lunaRsaSig.obj: lunaRsaSig.c
	$(CC) lunaRsaSig.c /c $(CL_OPTS64) $(INCLUDES)

lunaRsaEnc.obj: lunaRsaEnc.c
	$(CC) lunaRsaEnc.c /c $(CL_OPTS64) $(INCLUDES)

lunaEcSig.obj: lunaEcSig.c
	$(CC) lunaEcSig.c /c $(CL_OPTS64) $(INCLUDES)

lunaDsaSig.obj: lunaDsaSig.c
	$(CC) lunaDsaSig.c /c $(CL_OPTS64) $(INCLUDES)

lunaRsaGen.obj: lunaRsaGen.c
	$(CC) lunaRsaGen.c /c $(CL_OPTS64) $(INCLUDES)

lunaEcGen.obj: lunaEcGen.c
	$(CC) lunaEcGen.c /c $(CL_OPTS64) $(INCLUDES)

lunaDsaGen.obj: lunaDsaGen.c
	$(CC) lunaDsaGen.c /c $(CL_OPTS64) $(INCLUDES)

oqs_decode_der2key.obj: oqsprov2\oqs_decode_der2key.c
	$(CC) oqsprov2\oqs_decode_der2key.c /c $(CL_OPTS64) $(INCLUDES)

oqs_encode_key2any.obj: oqsprov2\oqs_encode_key2any.c
	$(CC) oqsprov2\oqs_encode_key2any.c /c $(CL_OPTS64) $(INCLUDES)

oqs_endecoder_common.obj: oqsprov2\oqs_endecoder_common.c
	$(CC) oqsprov2\oqs_endecoder_common.c /c $(CL_OPTS64) $(INCLUDES)

oqs_kem.obj: oqsprov2\oqs_kem.c
	$(CC) oqsprov2\oqs_kem.c /c $(CL_OPTS64) $(INCLUDES)

oqs_kmgmt.obj: oqsprov2\oqs_kmgmt.c
	$(CC) oqsprov2\oqs_kmgmt.c /c $(CL_OPTS64) $(INCLUDES)

oqsprov_bio.obj: oqsprov2\oqsprov_bio.c
	$(CC) oqsprov2\oqsprov_bio.c /c $(CL_OPTS64) $(INCLUDES)

oqsprov_capabilities.obj: oqsprov2\oqsprov_capabilities.c
	$(CC) oqsprov2\oqsprov_capabilities.c /c $(CL_OPTS64) $(INCLUDES)

oqsprov_keys.obj: oqsprov2\oqsprov_keys.c
	$(CC) oqsprov2\oqsprov_keys.c /c $(CL_OPTS64) $(INCLUDES)

oqs_sig.obj: oqsprov2\oqs_sig.c
	$(CC) oqsprov2\oqs_sig.c /c $(CL_OPTS64) $(INCLUDES)

#eof
