#!/bin/sh
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
# Description: Script to create a tar ball to be sent to customers
#

# as of openssl3, stop supporting 1.0.2
# as of openssl 3.2.1, stop supporting 32-bit
PACKAGE=package
VERSION=$(cat VERSION)
GEMENGINE=$PACKAGE/gemengine-$VERSION
SAMPLES=gem-samples
WIN_OPENSSL_VERSION=1.1.1w
WIN_OPENSSL_VERSION_2=3.5.5

# package the provider code when it is ready for GA
WANT_PROVIDER="1"

# option "--source-only" creates a package with source code only
# meaning binaries are empty directories/files
SOURCE_ONLY="0"
if [ ! "$1" = "" ] ; then
  if [ "$1" = "--source-only" ] ; then
    SOURCE_ONLY="1"
  else
    echo "ERROR: unknown option $1"
    exit 1
  fi
fi
echo "SOURCE_ONLY = $SOURCE_ONLY"

ginstall()
{
	echo "install $@"
	install "$@"
	if [ $? -ne 0 ]; then
		echo "ERROR: unable to create package!"
		exit 1
	fi
}

if [ -f "$PACKAGE/gemengine-$VERSION.tar.gz" ]; then
  rm "$PACKAGE/gemengine-$VERSION.tar.gz"
  if [ -f "$PACKAGE/gemengine-$VERSION.tar.gz" ]; then
    echo "ERROR: Failed to remove older $PACKAGE/gemengine-$VERSION.tar.gz"
    exit
  fi
fi

if [ -d "$PACKAGE" ]; then
	rm -rf $PACKAGE
	if [ $? -ne 0 ]; then
		echo "ERROR: Unable to clean $PACKAGE."
		exit 1
	fi
fi



mkdir -p -m 775 $GEMENGINE


#Install VERSION file
ginstall -o root -g root -m 0444 VERSION  $GEMENGINE/VERSION

#Install the engine
mkdir -p -m 775 $GEMENGINE/engine

for file in e_gem.c e_gem.h e_gem.ec  e_gem_err.c e_gem_err.h  e_gem_compat.c e_gem_compat.h  engine.mak  makefile.in gem.def ; do
	ginstall -o root -g root -m 0644 engine/$file  $GEMENGINE/engine
done
ginstall -o root -g root -m 0755 engine/configure  $GEMENGINE/engine


#Install the lunaProvider
if [ "$WANT_PROVIDER" = "1" ]; then
mkdir -p -m 775 $GEMENGINE/lunaProvider/include/pkcs11
mkdir -p -m 775 $GEMENGINE/lunaProvider/oqsprov2

LUNAPROV_FILES="include/pkcs11/pkcs11.h \
include/pkcs11/pkcs11f.h \
include/pkcs11/pkcs11t.h \
lunaPqcKem.c \
lunaPqcSig.c \
lunaProvider.c \
lunaRsaEnc.c \
lunaRsaGen.c \
lunaRsaSig.c \
luna_prov_minimal.h \
lunaDsaSig.c \
lunaprov.def \
oqsprov2/LICENSE-oqsprov.txt \
oqsprov2/oqs_decode_der2key.c \
oqsprov2/oqs_encode_key2any.c \
oqsprov2/oqs_endecoder_common.c \
oqsprov2/oqs_endecoder_local.h \
oqsprov2/oqs_kmgmt.c \
oqsprov2/oqsdecoders.inc \
oqsprov2/oqsencoders.inc \
oqsprov2/oqsprov.c \
oqsprov2/oqsprov_bio.c \
oqsprov2/oqsprov_keys.c \
oqsprov2/oqs_sig.c \
oqsprov2/oqsprov_capabilities.c \
oqsprov2/oqs_kem.c \
oqsprov2/oqs_prov.h \
pqcdefs.h \
lunaCommon.h \
provider.mak \
lunaDsaGen.c \
lunaEcGen.c \
lunaEcdh.c \
lunaEcx.c \
lunaEcxGen.c \
lunaEddsaSig.c \
lunaEcSig.c \
makefile.in \
lunaCommon.c \
lunaprov_deps.c \
lunaprov_deps.def \
exports.map \
lunaFileStore.h \
lunaFileAny2obj.c \
luna_decoders.inc \
luna_encoders.inc \
lunaprov_capabilities.c \
lunaFileStore.c"


for file in $LUNAPROV_FILES ; do  
   ginstall -o root -g root -m 0644 lunaProvider/$file  $GEMENGINE/lunaProvider/$file
done
ginstall -o root -g root -m 0755 lunaProvider/configure  $GEMENGINE/lunaProvider


mkdir -p -m 775 $GEMENGINE/tests/

TESTS_FILES="tmpdsaparam.pem \
t_openssl_common.include \
t_openssl_dsa.makefile \
t_openssl_ec.makefile \
t_openssl_ed.makefile \
t_openssl_pqc.makefile \
t_openssl_rsa.makefile \
ext_ca.cnf \
ext_root.cnf \
ext_server.cnf \
ext_client_ca.cnf \
ext_client.cnf \
message20.txt \
message32.txt \
message48.txt \
message64.txt \
t_openssl_tls.makefile \
t_openssl_suite1.makefile"

for file in $TESTS_FILES ; do
   ginstall -o root -g root -m 0644 tests/$file  $GEMENGINE/tests/$file
done

fi


#Install builds
for flavour in rhel ; do
  for bits in 64; do
    for stream in 3.2 1.1.1 ; do
      target=$flavour/$bits/$stream
      if [ ! "$SOURCE_ONLY" = "1" ] ; then
        mkdir -p -m 775 $GEMENGINE/builds/linux/$target
			if [ "$stream" = "1.0.2" ]; then
				ginstall -o root -g root -m 0755 builds/linux/$target/libgem.so  $GEMENGINE/builds/linux/$target
			fi
			if [ "$stream" = "1.1.1" ]; then
				ginstall -o root -g root -m 0755 builds/linux/$target/gem.so  $GEMENGINE/builds/linux/$target
			fi
			# NOTE: stream 3.0 implies provider added, 3.2 implies pqc added
			if [ "$stream" = "3.0" -o "$stream" = "3.2" ]; then
				ginstall -o root -g root -m 0755 builds/linux/$target/gem.so  $GEMENGINE/builds/linux/$target
				if [ "$WANT_PROVIDER" = "1" ]; then
					ginstall -o root -g root -m 0755 builds/linux/$target/lunaprov.so  $GEMENGINE/builds/linux/$target
				fi
			fi
			ginstall -o root -g root -m 0755 builds/linux/$target/sautil  $GEMENGINE/builds/linux/$target
      fi
    done
  done
done

#install gembuild
ginstall -o root -g root -m 0755 gembuild  $GEMENGINE/


#Install windows make files:
ginstall -o root -g root -m 0755 obuild8.makefile $GEMENGINE
#obsolete:ginstall -o root -g root -m 0755 obuild8-fips.makefile $GEMENGINE
ginstall -o root -g root -m 0755 obuild8-ossl3.makefile $GEMENGINE
ginstall -o root -g root -m 0644 win-cl-ssl.mk $GEMENGINE

#Install sautil
mkdir -p -m 775 $GEMENGINE/$SAMPLES/sautil
for file in makefile  sautil  sautil.c  sautil.h  sautil.mak; do
	ginstall -o root -g root -m 0644 $SAMPLES/sautil/$file  $GEMENGINE/$SAMPLES/sautil
done
ginstall -o root -g root -m 0644 engine/e_gem.h  $GEMENGINE/$SAMPLES/sautil
ginstall -o root -g root -m 0755 $SAMPLES/sautil/configure.sh  $GEMENGINE/$SAMPLES/sautil

#Install engineperf
mkdir -p -m 775 $GEMENGINE/$SAMPLES/engineperf
for file in engineperf.c  engineperf.h  engineperf.mak  engineperf-test.bat  engineperf-test.sh  makefile; do
	ginstall -o root -g root -m 0644 $SAMPLES/engineperf/$file  $GEMENGINE/$SAMPLES/engineperf
done
ginstall -o root -g root -m 0644 engine/e_gem.h  $GEMENGINE/$SAMPLES/engineperf
ginstall -o root -g root -m 0755 $SAMPLES/engineperf/configure.sh  $GEMENGINE/$SAMPLES/engineperf

mkdir -p -m 775 $GEMENGINE/$SAMPLES/passdll
for file in makefile  sample_passdll.c  sample_passdll.def  sample_passdll.mak; do
	ginstall -o root -g root -m 0644 $SAMPLES/passdll/$file  $GEMENGINE/$SAMPLES/passdll
done
ginstall -o root -g root -m 0644 engine/e_gem.h  $GEMENGINE/$SAMPLES/passdll
ginstall -o root -g root -m 0755 $SAMPLES/passdll/configure.sh  $GEMENGINE/$SAMPLES/passdll

#Install github licence files
for file in CONTRIBUTING.md LICENSE README.md SECURITY.md LICENCE-FOR-OPENSSL.txt ; do
  ginstall -o root -g root -m 0644 $file  $GEMENGINE
done

#Install coverity related files
for file in build.sh generate.sh ; do
  ginstall -o root -g root -m 0755 $file  $GEMENGINE
done

#Install docs
mkdir -p -m 775 $GEMENGINE/docs
# obsolete: README-KEYSECURE
for file in README-GEMBUILD README-GEM-CONFIG README-OPENSSL-CONFIG README-CMS README-DSA README-ECDSA README-RSA README-ENGINEPERF README-OBUILD README-OPENSSH README-PASSDLL README-SAUTIL README-APACHE README-BIND ; do
	ginstall -o root -g root -m 0644 docs/$file  $GEMENGINE/docs
done
for file in README-PQC README-PQC-BUILD README-PQC-CONFIG ; do
	ginstall -o root -g root -m 0644 docs/$file  $GEMENGINE/docs
done

#Install windows binaries
if [ ! "$SOURCE_ONLY" = "1" ] ; then
  mkdir -p -m 775 $GEMENGINE/builds/win
  for bus in 64; do
    ginstall -o root -g root -m 0644 LUNAlocal/sautil-win${bus}-openssl-${WIN_OPENSSL_VERSION}.tar.gz $GEMENGINE/builds/win
    ginstall -o root -g root -m 0644 LUNAlocal/ssl-win${bus}-openssl-${WIN_OPENSSL_VERSION}.tar.gz $GEMENGINE/builds/win
    ginstall -o root -g root -m 0644 LUNAlocal/sautil-win${bus}-openssl-${WIN_OPENSSL_VERSION_2}.tar.gz $GEMENGINE/builds/win
    ginstall -o root -g root -m 0644 LUNAlocal/ssl-win${bus}-openssl-${WIN_OPENSSL_VERSION_2}.tar.gz $GEMENGINE/builds/win
  done
fi

#mkdir -p -m 775 $GEMENGINE/keysecure
#ginstall -o root -g root -m 0644 keysecure/GemKS_setup.sh  $GEMENGINE/keysecure
#ginstall -o root -g root -m 0644 keysecure/GemKS.properties  $GEMENGINE/keysecure

#Install apache
mkdir -p -m 775 $GEMENGINE/apache
ginstall -o root -g root -m 0644 apache/*.conf  $GEMENGINE/apache/
ginstall -o root -g root -m 0755 Optimize.sh $GEMENGINE

#Install dnssec
mkdir -p -m 775 $GEMENGINE/dnssec
ginstall -o root -g root -m 0755 dnssec/*  $GEMENGINE/dnssec/

cd $PACKAGE
tar cvfz "gemengine-$VERSION.tar.gz" "gemengine-$VERSION"

if [ ! -f "gemengine-$VERSION.tar.gz" ]; then
  echo "ERROR: Failed to generate newer gemengine-$VERSION.tar.gz"
  exit
fi

echo
echo "Generated $GEMENGINE.tar.gz."
echo


