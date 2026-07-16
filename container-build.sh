#!/bin/bash

##############################################################################
##
## This file is part of the "Luna OpenSSL for PQC" project.
##
## The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
## following Web site for further details: https://mit-license.org/ ).
##
## Copyright © 2025 Thales Group
##
###############################################################################

set -e

##
## Description:
## This script builds the project inside a Docker image.
## For users who don't want to spend time on environment setup.

# Global variables
PROJECT_PATH=$(dirname "${0}")

PROJECT_NAME="luna-openssl-provider"
SUBPROJECT_NAME="lunabuilder"

BASEOS_NAME="ubi" # Red Hat Universal Base Image
BASEOS_ARCH="amd64"

IMAGE_NAME="${SUBPROJECT_NAME}.${BASEOS_NAME}.${BASEOS_ARCH}"

OCI_RUNNER="docker"
OCI_BUILD="${OCI_RUNNER} build --platform linux/${BASEOS_ARCH} -t ${IMAGE_NAME} ."
OCI_RUN="${OCI_RUNNER} run --rm -t --platform linux/${BASEOS_ARCH} -v ${PROJECT_PATH}:/home/luna/${PROJECT_NAME} ${IMAGE_NAME}"

OPENSSL_VERSION=$(grep '^VERSIONS=' ./generate.sh | cut -d '"' -f2)
OPENSSL_TAR_FILENAME="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${OPENSSL_TAR_FILENAME}"

LIBOQS_VERSION=$(grep '^LIBOQS_VERSION=' ./generate.sh | cut -d '"' -f2)
LIBOQS_TAR_FILENAME="${LIBOQS_VERSION}.tar.gz"
LIBOQS_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_TAR_FILENAME}"

RESULT_PATH="${PROJECT_PATH}/${PROJECT_NAME}-${BASEOS_NAME}-${BASEOS_ARCH}-openssl${OPENSSL_VERSION}-liboqs${LIBOQS_VERSION}.tar.gz"

function usage() {
    echo "Builds the Luna OpenSSL provider, Gem Engine, and sautil inside a Docker container."
    echo
    echo "Usage: ${0} [--rebuild]"
    echo "  --rebuild | -r : Quickly rebuild the Luna artifacts without downloading dependencies and rebuilding the Docker image."
    echo "  --help | -h : Show this help message."
    echo "  If not specified, the script will build the Docker image, download and build dependencies, and then build the Luna artifacts."
}

function download_deps() {
    mkdir -p ./openssl-source

    echo
    echo "Download OpenSSL..."
    curl -o "${PROJECT_PATH}/openssl-source/${OPENSSL_TAR_FILENAME}" -L "${OPENSSL_URL}"

    echo
    echo "Download LibOQS..."
    curl -o "${PROJECT_PATH}/openssl-source/liboqs-${LIBOQS_TAR_FILENAME}" -L "${LIBOQS_URL}"
}

function build_image() {
    echo
    echo "Build the container image..."
    ${OCI_BUILD}
}

function clean() {
    echo
    echo "Clean..."
    ${OCI_RUN} ./build.sh SA64client clean all
}

function build_luna() {
    echo
    echo "Build..."
    ${OCI_RUN} ./build.sh SA64client build "${1}"
}

function pack_tarball() {
    echo
    echo "Create the TARball..."
    tar -czf "${RESULT_PATH}" -C "${PROJECT_PATH}" builds
}

case "$1" in
"rebuild" | "--rebuild" | "-r")
    CLEAN_BUILD=0
    ;;
"help" | "--help" | "-h")
    usage
    exit 1
    ;;
*)
    CLEAN_BUILD=1
    ;;
esac

if [ $CLEAN_BUILD -eq 1 ]; then
    download_deps
    build_image
    clean
    build_luna depends
fi

build_luna all
pack_tarball

echo
echo "Results are available here: ${RESULT_PATH}"
