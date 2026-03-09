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
# test all algorithms (ed, pqc) via openssl command-line

# include common
#include t_openssl_common.include

# sub makefiles
EC_MAK=t_openssl_ed.makefile
RSA_MAK=t_openssl_pqc.makefile

# default target
default0: all
	@echo

# forget DSA
all: prep0 ec0 rsa0
	@echo

#
# test by key type
#

EC_KEY=key0

ec0:
	make -f $(EC_MAK) EC_KEY=$(EC_KEY) all
	@echo

RSA_KEY=key0

rsa0:
	make -f $(RSA_MAK) RSA_KEY=$(RSA_KEY) all
	@echo

# prep temp files
prep0:
	echo "[TOP SECRET MESSAGE 1]" > message.txt
	echo "[PLAINTEXT MESSAGE 1]" > plain.txt
	@echo

prep1:
	echo -n sha1abcdefghijklmnop > message20.txt
	echo -n sha256abcdefghijklmnopqrstuvwxyz > message32.txt
	echo -n sha384abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP > message48.txt
	echo -n sha512abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456 > message64.txt
	@echo

# clean temp files
clean:
	rm -f message.txt plain.txt
	make -f $(EC_MAK) clean
	make -f $(RSA_MAK) clean
	@echo

# clean hsm objects
cleanhsm:
	make -f $(EC_MAK) cleanhsm
	make -f $(RSA_MAK) cleanhsm
	@echo

################################################################################
#
# more specialized testcases
#

# TODO:

#eof

