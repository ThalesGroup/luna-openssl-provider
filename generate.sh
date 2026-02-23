#!/bin/bash
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
# Description:
#   Script to build openssl, engine, sautil, liboqs, provider.
#   Calls sub-script 'gembuild'.
#

# as of openssl3, stop supporting 1.0.2
# as of openssl 3.2.1, stop supporting 32-bit
VERSIONS="3.5.1"

LIBOQS_VERSION="0.15.0"

VERSION=""
STREAM=""

OPENSSL_BASE_URL=https://www.openssl.org/source
LIBOQS_BASE_URL=https://github.com/open-quantum-safe/liboqs/archive/refs/tags
OPENSSL_SOURCE_DIR=openssl-source
BUILD_DIR=openssl-build
BUILDS=builds
BASEDIR=$PWD
ENGINE_SO=libgem.so
PROVIDER_SO=lunaprov.so
SKIP_OPENSSL=0
SKIP_LIBOQS=0


usage()
{
	echo 
	echo "Script to generate pre-built dynamic engines shared objects."
	echo
	echo "Usage: ./generate.sh [options] <openssl version 1> [ <openssl version 2> ... ]"
	echo
	echo "Options:"
	echo "  --skip-liboqs   skip liboqs build (implies use existing install)"
	echo "  --skip-openssl  skip openssl build (implies use existing install)"
	echo "  --skip          legacy (same as --skip-openssl)"
	echo
}

SSL_URL=""
SHA1=""

wget_source_openssl()
{
	TARFILE=$1
	SSL_URL=$OPENSSL_BASE_URL/$TARFILE
	echo "wget $SSL_URL"
	wget $SSL_URL
	if [ "$?" -ne 0 ]; then
		SSL_URL=$OPENSSL_BASE_URL/old/$STREAM/$TARFILE
		echo "wget $SSL_URL"
		wget $SSL_URL
	fi;
}

curl_sha1_openssl()
{
	TARFILE=$1
	SHA1=$(curl -f $OPENSSL_BASE_URL/$TARFILE.sha1 2> /dev/null)
	if [ "$?" -ne 0 ]; then
		SHA1=$(curl $OPENSSL_BASE_URL/old/$STREAM/$TARFILE.sha1 2> /dev/null)
	fi;
	echo "SHA1: $SHA1"
}

download_source_openssl()
{
	if [ ! -d $OPENSSL_SOURCE_DIR ]; then
		mkdir $OPENSSL_SOURCE_DIR
	fi	
	cd $OPENSSL_SOURCE_DIR

	TARFILE=openssl-${VERSION}.tar.gz

	curl_sha1_openssl $TARFILE

	if [ -f "$TARFILE" ]; then
		sha_fs=$(sha1sum $TARFILE | awk '{print $1}')
		if [ ! "$SHA1" = "$sha_fs" ]; then
			rm $TARFILE
			wget_source_openssl $TARFILE
		fi
	else
		wget_source_openssl $TARFILE
	fi
	
	sha_fs=$(sha1sum $TARFILE | awk '{print $1}')
	
	if [ ! "$SHA1" = "$sha_fs" ]; then
		echo 
		echo "ERROR: SHA1 did not match for downloaded tar file and value from openssl website."
		echo
		exit 1
	else
		echo "$TARFILE has correct sha1sum... download OK."
	fi
	cd $BASEDIR
}

extract_source_openssl()
{
	if [ ! -d "$BUILD_DIR" ]; then
		mkdir "$BUILD_DIR"
	fi
	SOURCE=$BUILD_DIR/openssl-$VERSION
	if [ -d "$SOURCE" ]; then
		rm -rf "$SOURCE"
	fi
	cd $BUILD_DIR
	tar xfz "../$OPENSSL_SOURCE_DIR/openssl-$VERSION.tar.gz"
	cd $BASEDIR
}

extract_source_liboqs()
{
	if [ ! -d "$BUILD_DIR" ]; then
		mkdir "$BUILD_DIR"
	fi
	SOURCE=$BUILD_DIR/liboqs-$LIBOQS_VERSION
	if [ -d "$SOURCE" ]; then
		rm -rf "$SOURCE"
	fi
	cd $BUILD_DIR
	tar xfz "../$OPENSSL_SOURCE_DIR/liboqs-$LIBOQS_VERSION.tar.gz"
	cd $BASEDIR
}

error_missing_source()
{
	# openssl
	echo "ERROR: You need to download the following source from $OPENSSL_BASE_URL and place in ./$OPENSSL_SOURCE_DIR:"
	for i in $VERSIONS; do
		VERSION=$i
		if [ ! -f "./$OPENSSL_SOURCE_DIR/openssl-$VERSION.tar.gz" ]; then
			echo "./$OPENSSL_SOURCE_DIR/openssl-$VERSION.tar.gz"
		fi
	done

	exit 1
}

check_source()
{
	# openssl
	for i in $VERSIONS; do
		VERSION=$i
		if [ ! -f "./$OPENSSL_SOURCE_DIR/openssl-$VERSION.tar.gz" ]; then
			echo "WARNING: missing openssl version $VERSION" 
			error_missing_source
		fi
	done

	# liboqs
	liboqs_tgz=./$OPENSSL_SOURCE_DIR/liboqs-$LIBOQS_VERSION.tar.gz
	if [ ! -f "$liboqs_tgz" ]; then
		echo "ERROR: You need to download the following source from $LIBOQS_BASE_URL and place in ./$OPENSSL_SOURCE_DIR:"
		echo "  $liboqs_tgz"
		exit 1
	fi
	
}

# configure all
generate_configure_all()
{
	BITS=$1
	FLAVOUR=$2
	SO_VERSION=$3
	INSTALL=$BASEDIR/$BUILD_DIR/usr/$FLAVOUR/$BITS/$VERSION
	ABS_BUILD=$BASEDIR/$BUILD_DIR

	# NOTE: configure with absolute paths!
	./gembuild config --openssl-api=$STREAM --openssl-source=$ABS_BUILD/openssl-$VERSION --liboqs-source=$ABS_BUILD/liboqs-$LIBOQS_VERSION --config-bits=$BITS --prefix=$INSTALL --liboqs-prefix=$INSTALL    

}

# build and install openssl
openssl_build_install()
{
	BITS=$1
	FLAVOUR=$2
	SO_VERSION=$3
	INSTALL=$BASEDIR/$BUILD_DIR/usr/$FLAVOUR/$BITS/$VERSION

	# NOTE: gembuild config moved to generate_configure_all

	if [ "$SKIP_OPENSSL" = "0" ]; then
		SO_VERSION_OPTION=
		if [ "$STREAM" = "1.0.2" ]; then
			SO_VERSION_OPTION=--so-version=$SO_VERSION
		fi
		./gembuild openssl-build $SO_VERSION_OPTION
		if [ -d "$INSTALL/ssl" ]; then
			rm -rf "$INSTALL/ssl"
		fi
		./gembuild openssl-install $SO_VERSION_OPTION
	fi

	# NOTE: the version may show up twice so force it to once
	INSTALLED_VERSION=$(LD_LIBRARY_PATH=$INSTALL/ssl/lib  $INSTALL/ssl/bin/openssl version | awk '{print $2}')
	if [ ! "$INSTALLED_VERSION" = "$VERSION" ]; then
		echo
		echo "ERROR: Compiled openssl version did not match the expected version of openssl."
		echo
		exit 1
	fi

}

# build and install engine
engine_build_copy()
{
	BITS=$1
	FLAVOUR=$2
	SO_VERSION=$3
	INSTALL=$BASEDIR/$BUILD_DIR/usr/$FLAVOUR/$BITS/$VERSION

	./gembuild engine-build
	if [ $? -ne 0 ]; then
		echo "ERROR: engine build failed."
		exit 1
	fi
	PLATFORM=linux
	TARGET=$BUILDS/$PLATFORM/$FLAVOUR/$BITS/$STREAM
	mkdir -p $TARGET

	if [ "$STREAM" = "1.0.2" ]; then
	  cp engine/$ENGINE_SO $TARGET/libgem.so
	  cp engine/$ENGINE_SO $INSTALL/ssl/lib/engines/libgem.so
	else
	  if [ "$STREAM" = "1.1.1" ]; then
	    cp engine/$ENGINE_SO $TARGET/gem.so
	    cp engine/$ENGINE_SO $INSTALL/ssl/lib/engines-1.1/gem.so
          else
	    cp engine/$ENGINE_SO $TARGET/gem.so
	    cp engine/$ENGINE_SO $INSTALL/ssl/lib/engines-3/gem.so
	  fi
	fi

	./gembuild engine-install

	openssl=$INSTALL/ssl/bin/openssl
	supported=`LD_LIBRARY_PATH=$INSTALL/ssl/lib  $openssl engine gem -v | grep "Gem engine support"`
	if [ "$supported" = "" ]; then
		echo
		echo "ERROR: Gem engine verify was not successful."
		echo
		exit 1
	else
		echo "Engine verified: $supported"
	fi
}

# build and install sautil
sautil_build_copy()
{
	BITS=$1
	FLAVOUR=$2
	SO_VERSION=$3
	./gembuild sautil-build
	if [ $? -ne 0 ]; then
		echo "ERROR: sautil build failed."
		exit 1
	fi
	TARGET=$BUILDS/$PLATFORM/$FLAVOUR/$BITS/$STREAM
	cp gem-samples/sautil/sautil $TARGET
}

# build and install liboqs
liboqs_build_install()
{
	BITS=$1
	FLAVOUR=$2
	SO_VERSION=$3
	INSTALL=$BASEDIR/$BUILD_DIR/usr/$FLAVOUR/$BITS/$VERSION

	# NOTE: gembuild config moved to generate_configure_all

	# build and install
	if [ "$SKIP_LIBOQS" = "0" ]; then
		./gembuild liboqs-build
		if [ -d "$INSTALL/liboqs" ]; then
			rm -rf "$INSTALL/liboqs"
		fi
		./gembuild liboqs-install
	fi

	# verify
	liboqs_a=$INSTALL/liboqs/lib64/liboqs.a
	if [ ! -f "$liboqs_a" ]; then
		echo "ERROR: file not found: $liboqs_a"
		exit 1
	fi
}

# build and install provider
provider_build_copy()
{
	BITS=$1
	FLAVOUR=$2
	SO_VERSION=$3
	INSTALL=$BASEDIR/$BUILD_DIR/usr/$FLAVOUR/$BITS/$VERSION

	# build and install
	./gembuild provider-build
	if [ $? -ne 0 ]; then
		echo "ERROR: failed provider-build."
		exit 1
	fi

	PLATFORM=linux
	TARGET=$BUILDS/$PLATFORM/$FLAVOUR/$BITS/$STREAM
	mkdir -p $TARGET
	cp lunaProvider/$PROVIDER_SO $TARGET/$PROVIDER_SO
	cp lunaProvider/$PROVIDER_SO $INSTALL/ssl/lib/ossl-modules/$PROVIDER_SO
	./gembuild provider-install
	if [ $? -ne 0 ]; then
		echo "ERROR: failed provider-install."
		exit 1
	fi

	# verify
	lunaprov_so=$INSTALL/ssl/lib/ossl-modules/$PROVIDER_SO
	if [ ! -f "$lunaprov_so" ]; then
		echo "ERROR: file not found: $lunaprov_so"
		exit 1
	fi
}

# build and install all
generate_build_all()
{
	# now it is a manual process to download the source to save the headache.
	#download_source_openssl
	#download_source_liboqs
	for BITS in 64 ; do
		if [ "$SKIP_OPENSSL" = "0" ]; then
			extract_source_openssl
			if [ $? -ne 0 ]; then
				echo "ERROR: failed extract_source_openssl"
				exit 1
			fi
		fi
		if [ "$SKIP_LIBOQS" = "0" ]; then
			extract_source_liboqs
			if [ $? -ne 0 ]; then
				echo "ERROR: failed extract_source_liboqs"
				exit 1
			fi
		fi
		for FLAVOUR in rhel ; do
			if [ "$FLAVOUR" = "rhel" ]; then
				SO_VERSION=10
			else
				SO_VERSION=1.0.0
			fi
			generate_configure_all $BITS $FLAVOUR $SO_VERSION
			openssl_build_install $BITS $FLAVOUR $SO_VERSION
			engine_build_copy $BITS $FLAVOUR $SO_VERSION
			sautil_build_copy $BITS $FLAVOUR $SO_VERSION
			# NOTE: stream 3.0 implies provider added, 3.2 implies pqc added
			if [ "$STREAM" = "3.2" ]; then
				liboqs_build_install $BITS $FLAVOUR $SO_VERSION
			fi
			if [ "$STREAM" = "3.0" -o "$STREAM" = "3.2" ]; then
				provider_build_copy $BITS $FLAVOUR $SO_VERSION
			fi
		done
	done
}

#
# main
#

if [ "$1" = "--skip" -o "$1" = "--skip-openssl" ]; then
	SKIP_OPENSSL=1
fi

if [ "$1" = "--skip-liboqs" ]; then
	SKIP_LIBOQS=1
fi

check_source
if [ $? -ne 0 ]; then
	echo "ERROR: failed check_source"
	exit 1
fi

for i in $VERSIONS; do
	VERSION=$i
	# NOTE: stream 3.0 implies provider added, 3.2 implies pqc added
	STREAM=$(echo $VERSION | sed -e "s/[a-z]*//g" -e "s/3.[0-1].[0-9]*-*[0-9]*/3.0/g" -e "s/3.[2-9].[0-9]*-*[0-9]*/3.2/g")
	generate_build_all
	if [ $? -ne 0 ]; then
		echo "ERROR: failed generate_build_all"
		exit 1
	fi
done

exit 0

# end main

