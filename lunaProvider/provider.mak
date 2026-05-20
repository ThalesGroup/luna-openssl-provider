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
!ELSE
OQS_SOURCES=
!ENDIF

# misc include paths
INCLUDES_INTERNAL=-I$(OPENSSL_SOURCE)\include
INCLUDES_INTERNAL_PROV=-I$(OPENSSL_SOURCE)\providers\implementations\include -I$(OPENSSL_SOURCE)\providers\common\include -I$(OPENSSL_SOURCE)\providers\fips\include -I$(OPENSSL_SOURCE)\providers
INCLUDES_ENGINE=-I..\engine
INCLUDES_OQS=-I.\oqsprov2 -I$(LIBOQS_PREFIX)\include
INCLUDES_PROV=$(INCLUDES_ENGINE) $(INCLUDES_OQS) $(INCLUDES_INTERNAL_PROV)
INCLUDES=$(INCLUDES_INTERNAL) $(INCLUDES_PROV)

default0: default64

default64: default64-dynamic

default64-dynamic:
	$(CC) lunaprov_deps.c $(CL_OPTS64) /link $(LD_OPTS64) /DEF:lunaprov_deps.def /OUT:lunaprov_deps.dll $(LIB2_STATIC) $(LIBSTD)
	$(CC) $(OQS_SOURCES) $(SOURCES) $(CL_OPTS64) $(INCLUDES) /link $(LD_OPTS64) /DEF:lunaprov.def /OUT:lunaprov.dll $(LIB2_DYNAMIC) lunaprov_deps.lib $(LIB_OQS_STATIC) $(LIBSTD)

default64-static:
	$(CC) lunaprov_deps.c $(CL_OPTS64) /link $(LD_OPTS64) /DEF:lunaprov_deps.def /OUT:lunaprov_deps.dll $(LIB2_STATIC) $(LIBSTD)
	$(CC) $(OQS_SOURCES) $(SOURCES) $(CL_OPTS64) $(INCLUDES) /link $(LD_OPTS64) /DEF:lunaprov.def /OUT:lunaprov.dll $(LIB2_STATIC) $(LIB_OQS_STATIC) $(LIBSTD)

clean:
	$(RM) lunaprov.dll lunaprov.pdb
	$(RM) lunaprov_deps.dll lunaprov_deps.pdb
	$(RM) *.obj

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

.PHONY: default0 default64 default64-dynamic default64-static clean install uninstall

# TODO: some funny dependencies
lunaCommon.obj: lunaCommon.c lunaCommon.h ../engine/e_gem.c lunaPqcKem.c lunaPqcSig.c oqsprov2/oqs_prov.h

#eof
