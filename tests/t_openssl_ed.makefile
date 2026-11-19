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
# test ed keygen
# and ed sign
#

# include provider, keyform, engine
include t_openssl_common.include

# sender/recipient cert file and key file
KEYF1=tmped.pkey
#KEY_URI_1=$(KEYF1)
#KEY_URI_1=pkcs11:$(KEYF1)
KEY_URI_1=pkcs11:sk4YddbfVjd3jeCDOo7oxnmQ;pk4YddbfVjd3jeCDOo7oxnmQ

CERTF1=tmped.crt

# CA cert file
# if using self-signed cert then
CERTF2=$(CERTF1)
# otherwise
#CERTF2=tmpedCA.crt

# default target
default0: all
	@echo

ED_KEY=key0

all: $(ED_KEY) check0 req0
	@echo

# FIXME: broken due to provider load order
all_dgst: check0 sign1 sign2
	@echo

# generate key
# NOTE: for keypair in HSM, set GemEngine = { EnableEdGenKeyPair = 1; } - available for openssl3.2, provider only
# NOTE: sautil not available for ed keygen
# NOTE: it is discouraged to add options after "-pkeyopt OPTIONS" or "-sigopt OPTIONS"
# NOTE: there are two key sizes ed25519 and ed448

GENPKEY0_ALGORITHM=-algorithm ed25519
#GENPKEY0_ALGORITHM=-algorithm ed448

# first choice: generate key via openssl genpkey (openssl3.2)
key0: tmped.pkey.0

tmped.pkey.0: tmped.foo
	openssl genpkey $(HW_ENGINE) $(GENPKEY0_ALGORITHM) -out tmped.pkey
	cp tmped.pkey tmped.pkey.0
	@echo '--------'

tmped.foo:
		touch tmped.foo

check0:
	openssl pkey -$(HW_ENGINE) -in $(KEY_URI_1) -noout -text -check -pubcheck
	@echo '--------'

# NOTE: set digest to prove we can override the default of sha256
BASE_MD=sha512

PKCS_MD=$(BASE_MD)
#SIGOPT_REQ=-sigopt digest:$(PKCS_MD)
SIGOPT_REQ=
#SIGOPT_X509=-sigopt digest:$(PKCS_MD)
SIGOPT_X509=

# sign cert request
req0:
	rm -f tmp.csr tmped.crt
	openssl req $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -verbose -new -nodes -key $(KEYF1) -out tmp.csr -verify -subj "/CN=t_openssl_ed" $(SIGOPT_REQ)
	openssl x509 $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -trustout -outform PEM -req -days 90 -in tmp.csr -signkey $(KEYF1) -out tmped.crt $(SIGOPT_X509)
	@echo '--------'

ED_MD=$(BASE_MD)
# NOTE: for algorithm ed25519/ed448 the digest is not settable (default provider)
#PKEYOPT_ED=-pkeyopt digest:$(ED_MD)
PKEYOPT_ED=
#SIGOPT_ED=-sigopt digest:$(ED_MD)
SIGOPT_ED=

# sign using pkeyutl
# hash in software, sign in hardware, verify in software
# NOTE: operation not supported (default provider) for this keytype (ed)
sign1:
	openssl dgst -$(ED_MD) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey $(KEY_URI_1) -out message.sig $(PKEYOPT_ED)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmped.pkey -sigfile message.sig $(PKEYOPT_ED)
	@echo '--------'

# sign using dgst
# hash in software, sign in hardware, verify in software
# NOTE: operation not supported (default provider) for this keytype (ed)
sign2:
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign $(KEY_URI_1) -$(ED_MD) -out message.sig $(SIGOPT_ED)  message.txt
	openssl dgst $(SW_ENGINE) -prverify tmped.pkey -$(ED_MD) -signature message.sig $(SIGOPT_ED)  message.txt
	@echo '--------'

# clean all temp files
clean:
	rm -f tmped.pkey tmp.csr
	rm -f tmped.foo tmped.pkey.0 tmped.pkey.1
	@echo

# clean hsm objects
cleanhsm:
	sautil -v -s 0 -i 0:0 -o -q -c -k 0 -f tmped.pkey
	@echo

#eof

