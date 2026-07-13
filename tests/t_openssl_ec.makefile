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
# test ec keygen
# and ec sign

# include provider, keyform, engine
include t_openssl_common.include

# sender/recipient cert file and key file
KEYF1=tmpec.pkey
CERTF1=tmpec.crt

# CA cert file
# if using self-signed cert then
CERTF2=$(CERTF1)
# otherwise
#CERTF2=tmpecCA.crt

# default target
default0: all
	@echo

EC_KEY=key0

all: $(EC_KEY) check0 req0 sign1
	@echo

# FIXME: broken due to provider load order
all_dgst: check0 sign2
	@echo

# generate key
# NOTE: for keypair in HSM, set GemEngine = { EnableEcGenKeyPair = 1; } - feature available *after* gem 1.6
# NOTE: otherwise, use sautil to generate keypair
# NOTE: it is discouraged to add options after "-pkeyopt OPTIONS" or "-sigopt OPTIONS"
# NOTE: set keysize to prove we can override the default of 256
# NOTE: also set keysize to prove we can support large keys (512 bits and up)

# first choice: generate key via openssl genpkey (openssl3, openssl 1.1.1)
key0: tmpec.pkey.0

tmpec.pkey.0: tmpec.foo
	openssl genpkey $(HW_ENGINE) -algorithm EC -out tmpec.pkey -pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve
	cp tmpec.pkey tmpec.pkey.0
	@echo '--------'

check0:
	openssl pkey -check -in tmpec.pkey $(HW_ENGINE)
	@echo '--------'

# second choice: generate key via sautil
tmpec.pkey.1: tmpec.foo
	sautil -v -s 0 -i 0:0 -o -q -c -m OID_secp521r1 -f tmpec.pkey
	cp tmpec.pkey tmpec.pkey.1
	@echo '--------'

tmpec.foo:
		touch tmpec.foo

# NOTE: set digest to prove we can override the default of sha256
BASE_MD=sha512

PKCS_MD=$(BASE_MD)
#SIGOPT_REQ=-sigopt digest:$(PKCS_MD)
SIGOPT_REQ=
#SIGOPT_X509=-sigopt digest:$(PKCS_MD)
SIGOPT_X509=

# sign cert request
req0:
	rm -f tmp.csr tmpec.crt
	openssl req $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -verbose -new -nodes -key $(KEYF1) -out tmp.csr -verify -subj "/CN=t_openssl_ec" $(SIGOPT_REQ)
	openssl x509 $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -trustout -outform PEM -req -days 7305 -in tmp.csr -signkey $(KEYF1) -out tmpec.crt $(SIGOPT_X509)
	@echo '--------'

EC_MD=$(BASE_MD)
PKEYOPT_EC=-pkeyopt digest:$(EC_MD)
#SIGOPT_EC=-sigopt digest:$(EC_MD)
SIGOPT_EC=

# using pkeyutl
# sign a hash (supplied)
sign1:
	openssl dgst -$(EC_MD) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey tmpec.pkey -out message.sig $(PKEYOPT_EC)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmpec.pkey -sigfile message.sig $(PKEYOPT_EC)
	@echo '--------'

# hash in software, sign in hardware
sign2:
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign tmpec.pkey -$(EC_MD) -out message.sig $(SIGOPT_EC)  message.txt
	openssl dgst $(SW_ENGINE) -prverify tmpec.pkey -$(EC_MD) -signature message.sig $(SIGOPT_EC)  message.txt
	@echo '--------'

# clean all temp files
clean:
	rm -f tmpec.pkey tmp.csr
	rm -f tmpec.foo tmpec.pkey.0 tmpec.pkey.1
	@echo

# clean hsm objects
cleanhsm:
	sautil -v -s 0 -i 0:0 -o -q -c -m 0 -f tmpec.pkey
	@echo

#eof

