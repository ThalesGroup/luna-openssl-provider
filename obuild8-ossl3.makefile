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
#
# Description: build OpenSSL 3 for Windows 64-bit OS.
#


#
# makefile variables
#


# openssl 3.5.5 or higher, with builtin fips module
VERSION=3.5.5


# liboqs 0.15.0 or higher, for ml-dsa
LIBOQS_VERSION=0.15.0


# openssl pre-configure options
CFG_OPTS=
CFG_SUFFIX=win64
CFG_FIPS=enable-fips


# readonly
FILENAME=obuild8-ossl3.makefile


# openssl post-configure options
# NOTE: set --openssldir and --prefix to the same value.
CFG_BASEOPTS_NO=no-asm
CFG_BASEOPTS_YES=$(CFG_FIPS) enable-trace
CFG_INSTALLROOT=c:\cygwin\usr\local
CFG_INSTALLDIR=$(CFG_INSTALLROOT)\ssl
CFG_BASEOPTS=$(CFG_BASEOPTS_YES)  $(CFG_BASEOPTS_NO)  --openssldir=$(CFG_INSTALLDIR) --prefix=$(CFG_INSTALLDIR) --debug
CFG_SAUTILDIR=$(CFG_INSTALLROOT)\ssl\sautil


#
# makefile targets
#


default:
	@echo "Usage:"
	@echo "  nmake /f $(FILENAME) cleanall"
	@echo "  nmake /f $(FILENAME) all-win64"
	@echo
	@echo "Other options:"
	@echo "  nmake /f $(FILENAME) openssl-win64"
	@echo "  nmake /f $(FILENAME) sautil-win64"
	@echo "  nmake /f $(FILENAME) engine-win64"
	@echo "  nmake /f $(FILENAME) liboqs-win64"
	@echo "  nmake /f $(FILENAME) provider-win64"
	@echo
	@echo "NOTE: requires some UNIX commands on Windows platform."
	@echo


# unpack source files
unpack.tmp:
	if not exist openssl-build  mkdir openssl-build
	if not exist LUNAlocal  mkdir LUNAlocal
	cd openssl-build
	  tar xzf "..\openssl-$(VERSION).tar.gz"
	  tar xzf "..\liboqs-$(LIBOQS_VERSION).tar.gz"
	  cd ..
	touch unpack.tmp
	@echo


# patch source files
# NOTE: nothing to patch yet
patch.tmp:  unpack.tmp
	touch patch.tmp
	@echo


# configure openssl
cfg-win64.tmp: patch.tmp
	cd "openssl-build\openssl-$(VERSION)"
	  perl Configure VC-WIN64A  $(CFG_BASEOPTS) $(CFG_OPTS)
	  cd ..\..
	touch cfg-win64.tmp cfg.tmp
	@echo


# prep install directories
prep-install:
	rm -rf "$(CFG_SAUTILDIR)"
	rm -rf "$(CFG_INSTALLDIR)"
	@echo
	if not exist "$(CFG_INSTALLDIR)"                   mkdir "$(CFG_INSTALLDIR)"
	if not exist "$(CFG_INSTALLDIR)\include"           mkdir "$(CFG_INSTALLDIR)\include"
	if not exist "$(CFG_INSTALLDIR)\include\openssl"   mkdir "$(CFG_INSTALLDIR)\include\openssl"
	if not exist "$(CFG_INSTALLDIR)\lib"               mkdir "$(CFG_INSTALLDIR)\lib"
	if not exist "$(CFG_INSTALLDIR)\lib\engines-3"     mkdir "$(CFG_INSTALLDIR)\lib\engines-3"
	if not exist "$(CFG_INSTALLDIR)\lib\ossl-modules"  mkdir "$(CFG_INSTALLDIR)\lib\ossl-modules"
	if not exist "$(CFG_INSTALLDIR)\bin"               mkdir "$(CFG_INSTALLDIR)\bin"
	@echo
	if not exist "$(CFG_SAUTILDIR)"                    mkdir "$(CFG_SAUTILDIR)"
	if not exist "$(CFG_SAUTILDIR)\bin"                mkdir "$(CFG_SAUTILDIR)\bin"
	@echo


# build and install openssl exe, dll, cnf, fips module
openssl-win64:
	cd "openssl-build\openssl-$(VERSION)"
	  nmake build_sw
	  nmake install_sw install_ssldirs install_fips
	  cd ..\..
	@echo


# build libs only (shortcut for debugging libs)
openssl-libs-win64:
	cd "openssl-build\openssl-$(VERSION)"
	  nmake build_libs_nodep
	  nmake install_runtime_libs
	  cd ..\..
	@echo


# build apps only (shortcut for debugging apps)
openssl-apps-win64:
	cd "openssl-build\openssl-$(VERSION)"
	  nmake build_programs_nodep
	  nmake install_programs
	  cd ..\..
	@echo


# clean openssl temporary files
openssl-clean:
	cd "openssl-build\openssl-$(VERSION)"
	  nmake clean
	  cd ..\..
	@echo


# tar all the installed files
post-install ssl-tar:
	rm -f "LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz"
	rm -f "LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz"
	@echo
	tar czvf "LUNAlocal\ssl-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz"  "$(CFG_INSTALLDIR)"
	@echo
	tar czvf "LUNAlocal\sautil-$(CFG_SUFFIX)-openssl-$(VERSION).tar.gz"  "$(CFG_SAUTILDIR)"
	@echo
	touch build.tmp binsave.tmp bininstall.tmp
	@echo


# build and install engine
engine-win64:
	cd engine
	nmake /f engine.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR)
	nmake /f engine.mak install CFG_INSTALLDIR=$(CFG_INSTALLDIR)
	cd ..
	@echo


# build and install provider
provider-win64:
	cd lunaProvider
	nmake /f provider.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR) VERSION=$(VERSION)
	nmake /f provider.mak install CFG_INSTALLDIR=$(CFG_INSTALLDIR) VERSION=$(VERSION)
	cd ..
	@echo


# build and install sautil
sautil-win64:
	cd gem-samples\sautil
	nmake /f sautil.mak clean default64 CFG_INSTALLDIR=$(CFG_INSTALLDIR)
	nmake /f sautil.mak install CFG_INSTALLDIR=$(CFG_INSTALLDIR)
	cd ..\..
	@echo


# definitions for liboqs
MY_OPT_1=-A x64 -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$(CFG_INSTALLROOT)\liboqs001"
MY_OPT_2=-DOQS_ALGS_ENABLED="All"
MY_OPT_3=-DOQS_BUILD_ONLY_LIB=ON
MY_OPT_4=-DOQS_MINIMAL_BUILD="FOO_startoflist;KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_padded_512;SIG_falcon_1024;SIG_falcon_padded_1024;KEM_ml_kem_512_ipd;KEM_ml_kem_512;KEM_ml_kem_768_ipd;KEM_ml_kem_768;KEM_ml_kem_1024_ipd;KEM_ml_kem_1024;SIG_ml_dsa_44_ipd;SIG_ml_dsa_44;SIG_ml_dsa_65_ipd;SIG_ml_dsa_65;SIG_ml_dsa_87_ipd;SIG_ml_dsa_87;SIG_sphincs_sha2_128f_simple;SIG_sphincs_sha2_128s_simple;SIG_sphincs_sha2_192f_simple;SIG_sphincs_sha2_192s_simple;SIG_sphincs_sha2_256f_simple;SIG_sphincs_sha2_256s_simple;SIG_sphincs_shake_128f_simple;SIG_sphincs_shake_128s_simple;SIG_sphincs_shake_192f_simple;SIG_sphincs_shake_192s_simple;SIG_sphincs_shake_256f_simple;SIG_sphincs_shake_256s_simple;"
MY_OPT_5=-DOQS_DIST_BUILD=OFF 
MY_OPT_6=-DOQS_USE_OPENSSL=ON -DOQS_USE_AES_OPENSSL=ON -DOQS_USE_SHA2_OPENSSL=ON -DOQS_USE_SHA3_OPENSSL=ON
MY_OPT_7=-DOPENSSL_ROOT_DIR="$(CFG_INSTALLROOT)\ssl"


# build and install liboqs
liboqs-win64:
	cd "openssl-build\liboqs-$(LIBOQS_VERSION)"
	  if not exist _build001  mkdir _build001
	  cd _build001
	    if not exist ALL_BUILD.vcxproj  cmake $(MY_OPT_1) $(MY_OPT_2) $(MY_OPT_3) $(MY_OPT_4) $(MY_OPT_5) $(MY_OPT_6) $(MY_OPT_7) ..
	    msbuild ALL_BUILD.vcxproj
	    msbuild INSTALL.vcxproj
	    cd ..\..\..
	@echo


# clean liboqs temporary files
liboqs-clean:
	rm -rf "openssl-build\liboqs-$(LIBOQS_VERSION)\_build001"
	@echo


# build and install and tar all
all-win64: cfg-win64.tmp prep-install openssl-win64 sautil-win64 engine-win64 liboqs-win64 provider-win64 post-install
	@echo


# clean tmp (incremental build) files
cleantemp:
	rm -f cfg.tmp build.tmp binsave.tmp bininstall.tmp
	rm -f cfg-win64.tmp
	@echo


# clean all temporary files
cleanall clean: cleantemp
	rm -f unpack.tmp patch.tmp
	rm -rf "openssl-build\openssl-$(VERSION)"
	rm -rf "openssl-build\liboqs-$(LIBOQS_VERSION)"
	@echo


.PHONY: default all-win64 

.PHONY: prep-install openssl-win64 sautil-win64 engine-win64 liboqs-win64 provider-win64 post-install

.PHONY: clean cleanall cleantemp openssl-clean liboqs-clean


#eof
