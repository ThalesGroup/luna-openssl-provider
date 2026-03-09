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
# test pqc keygen
# and pqc sign

# include provider, keyform, engine
include t_openssl_common.include

# pqc type
#PQCTYPE=mldsa44
#PQCTYPE=mldsa65
PQCTYPE=mldsa87
# hybrid
#PQCTYPE=p521_mldsa87
# composite
#PQCTYPE=mldsa87_p384
#PQCTYPE=mldsa87_bp384
#PQCTYPE=mldsa87_ed448

# sender/recipient cert file and key file
KEYF1=tmppqc.pkey
CERTF1=tmppqc.crt

# CA cert file
# if using self-signed cert then
CERTF2=$(CERTF1)
# otherwise
#CERTF2=tmppqcCA.crt

# default target
default0: all
	@echo

PQC_KEY=key0

all: $(PQC_KEY) check0 req0 sign1
	@echo

# FIXME: broken due to provider load order
all_dgst: sign2
	@echo

# generate key
# NOTE: for keypair in HSM, set GemEngine = { EnablePqcGenKeyPair = 1; } - feature available *after* gem 1.6
# NOTE: sautil not available for pqc keygen

# first choice: generate key via openssl genpkey (openssl3, openssl 1.1.1)
key0: tmppqc.pkey.0

tmppqc.pkey.0: tmppqc.foo
	openssl genpkey $(HW_ENGINE) -algorithm $(PQCTYPE) -out tmppqc.pkey
	cp tmppqc.pkey tmppqc.pkey.0
	@echo '--------'

check0:
	openssl pkey -check -in tmppqc.pkey $(HW_ENGINE)
	@echo '--------'

tmppqc.foo:
	touch tmppqc.foo

# NOTE: set digest to prove we can override the default of sha256
BASE_MD=sha512

PKCS_MD=$(BASE_MD)
ifneq ($(PKCS_MD),)
PKCS_MD_OPTS=-$(PKCS_MD)
SIGOPT_REQ=-sigopt digest:$(PKCS_MD)
SIGOPT_X509=-sigopt digest:$(PKCS_MD)
else
PKCS_MD_OPTS=
SIGOPT_REQ=
SIGOPT_X509=
endif

# sign cert request
# NOTE: it is discouraged to add options after "-pkeyopt OPTIONS" or "-sigopt OPTIONS"
req0:
	rm -f tmppqc.csr tmppqc.crt
	openssl req $(HW_ENGINE) $(HW_KEYFORM) $(PKCS_MD_OPTS) -verbose -new -nodes -key $(KEYF1) -out tmppqc.csr -subj "/CN=t_openssl_pqc" -verify $(SIGOPT_REQ)
	openssl x509 $(HW_ENGINE) $(HW_KEYFORM) $(PKCS_MD_OPTS) -trustout -outform PEM -req -days 7305 -in tmppqc.csr -signkey $(KEYF1) -out tmppqc.crt $(SIGOPT_X509)
	@echo '--------'

PQC_MD=$(BASE_MD)
ifneq ($(PQC_MD),)
PQC_MD_OPTS=-$(PQC_MD)
PKEYOPT_PQC=-pkeyopt digest:$(PQC_MD)
SIGOPT_PQC=-sigopt digest:$(PQC_MD)
else
PQC_MD_OPTS=
PKEYOPT_PQC=
SIGOPT_PQC=
endif

# using pkeyutl
# digest in software, sign in hardware, verify in software
sign1:
	openssl dgst -$(PQC_MD) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey tmppqc.pkey -out message.sig $(PKEYOPT_PQC)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmppqc.pkey -sigfile message.sig $(PKEYOPT_PQC)
	@echo '--------'

# using dgst
# sign in hardware, verify in software
sign2:
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign tmppqc.pkey $(PQC_MD_OPTS) -out message.sig $(SIGOPT_PQC)  message.txt
	openssl dgst $(SW_ENGINE) -prverify tmppqc.pkey $(PQC_MD_OPTS) -signature message.sig $(SIGOPT_PQC)  message.txt
	@echo '--------'

# clean all temp files
clean:
	rm -f tmppqc.pkey tmppqc.csr
	rm -f tmppqc.foo tmppqc.pkey.0
	@echo

# clean hsm objects
cleanhsm:
	sautil -v -s 0 -i 0:0 -o -q -c -k 0 -f tmppqc.pkey
	@echo

#eof

