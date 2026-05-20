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
# test rsa cms sign (pkcs pss)
# and rsa cms decrypt (pkcs oaep)
#
# but first we need a keypair and certificate
# so, test rsa keygen (2 prime factors)
# and rsa sign (pkcs)

# include provider, keyform, engine
include t_openssl_common.include

# sender/recipient cert file and key file
KEYF1=tmp.pkey
CERTF1=tmp.crt

# CA cert file
# if using self-signed cert then
CERTF2=$(CERTF1)
# otherwise
#CERTF2=tmpCA.crt

# default target
default0: all
	@echo

RSA_KEY=key0

RSA_BITS=3072
#RSA_BITS=4096
#RSA_BITS=6144

all: $(RSA_KEY) check0 req0 misc0 sign1 sign4 decrypt1 decrypt2
	@echo

all_cms: check0 sign0 decrypt0
	@echo

all_dgst: check0 sign2 sign3
	@echo

# generate key
# NOTE: for key in HSM, set GemEngine = { EnableRsaGenKeyPair = 1; }
# NOTE: otherwise, use sautil to generate keypair
# NOTE: it is discouraged to add options after "-pkeyopt OPTIONS"
# NOTE: use keysize 3072 to prove we can override the default of 2048
#
# first choice: generate key via openssl genpkey (openssl 3, openssl 1.1.1)
key0: tmp.pkey.0

tmp.pkey.0: tmp.foo
	openssl genpkey $(HW_ENGINE) -algorithm RSA -out tmp.pkey -pkeyopt rsa_keygen_bits:$(RSA_BITS)
	cp tmp.pkey tmp.pkey.0
	@echo '--------'

check0:
	openssl pkey -check -in tmp.pkey $(HW_ENGINE)
	@echo '--------'

# second choice: generate key via sautil
tmp.pkey.1: tmp.foo
	sautil -v -s 0 -i 0:0 -o -q -c -g $(RSA_BITS) -x 01:00:01 -f tmp.pkey
	cp tmp.pkey tmp.pkey.1
	@echo '--------'

# last choice: generate key via openssl genrsa (openssl 1.0.2)
tmp.pkey.2: tmp.foo
	openssl genrsa $(HW_ENGINE) -f4 -out tmp.pkey $(RSA_BITS)
	cp tmp.pkey tmp.pkey.2
	@echo '--------'

tmp.foo:
	touch tmp.foo

# NOTE: set digest to prove we can override the default of sha256
#BASE_MD=sha3-512
BASE_MD=sha512

PKCS_MD=$(BASE_MD)
#SIGOPT_REQ=-sigopt digest:$(PKCS_MD)
SIGOPT_REQ=
#SIGOPT_X509=-sigopt digest:$(PKCS_MD)
SIGOPT_X509=

# sign cert request
# NOTE: it is discouraged to add options after "-pkeyopt OPTIONS" or "-sigopt OPTIONS"
req0:
	rm -f tmp.csr tmp.crt
	openssl req $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -verbose -new -nodes -key $(KEYF1) -out tmp.csr -verify -subj "/CN=t_openssl_rsa" $(PKEYOPT_PKCS)
	openssl x509 $(HW_ENGINE) $(HW_KEYFORM) -$(PKCS_MD) -trustout -outform PEM -req -days 7305 -in tmp.csr -signkey $(KEYF1) -out tmp.crt -extfile ext_ca.cnf $(SIGOPT_PKCS)
	@echo '--------'

CMS_MD=$(BASE_MD)

PSS_SALT=digest
#PSS_SALT=max
#PSS_SALT=auto
#PSS_SALT=0
#PSS_SALT=64

KEYOPT_CMS_PSS=-keyopt digest:$(CMS_MD) -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:$(PSS_SALT) -keyopt rsa_mgf1_md:$(CMS_MD)

# sign (cms, pss)
# TODO: create proper certs and verify them (see -noverify)
sign0:
	rm -f sendmail.msg
	openssl cms $(HW_ENGINE) $(HW_KEYFORM) -sign -md $(CMS_MD) -binary -nodetach -in message.txt -signer $(CERTF1) -inkey $(KEYF1) -out sendmail.msg $(KEYOPT_CMS_PSS)
	openssl cms $(SW_ENGINE) -verify -noverify -md $(CMS_MD) -binary -content message.txt -signer $(CERTF1) -inkey $(KEYF1) -in sendmail.msg -CAfile $(CERTF2) $(KEYOPT_CMS_PSS)
	@echo ; echo '--------'

KEYOPT_CMS_OAEP=-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:$(CMS_MD) -keyopt rsa_mgf1_md:$(CMS_MD)

# decrypt (cms, oaep)
# TODO: data is decrypted ok, but, with extra cr/lf character (see diff)
decrypt0:
	rm -f mail.msg foo.txt
	openssl cms $(SW_ENGINE) -encrypt -in plain.txt -out mail.msg -recip $(CERTF1) $(KEYOPT_CMS_OAEP)
	openssl cms $(HW_ENGINE) $(HW_KEYFORM) -decrypt -out foo.txt  -in mail.msg  -recip $(CERTF1) -inkey $(KEYF1) $(KEYOPT_CMS_OAEP)
	-diff -q -s plain.txt foo.txt
	@echo '--------'

# misc test (ec key gen in software should work using the same chrystoki config)
misc0:
	rm -f eckey.pem
	openssl genpkey $(SW_ENGINE) -algorithm EC -out eckey.pem -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve
	@echo '--------'

PSS_MD=$(BASE_MD)

PKEYOPT_PSS_MGF1=-pkeyopt rsa_mgf1_md:$(PSS_MD)
PKEYOPT_PSS=-pkeyopt digest:$(PSS_MD) -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$(PSS_SALT) $(PKEYOPT_PSS_MGF1)

SIGOPT_PSS_MGF1=-sigopt rsa_mgf1_md:$(PSS_MD)
SIGOPT_PSS=-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:$(PSS_SALT) $(SIGOPT_PSS_MGF1)

SIGOPT_X931=-sigopt rsa_padding_mode:x931
MD_32=sha256
MD_64=sha512
PKEYOPT_32=-pkeyopt digest:$(MD_32)
PKEYOPT_64=-pkeyopt digest:$(MD_64)
PKEYOPT_X931=-pkeyopt rsa_padding_mode:x931

# using pkeyutl
# digest in software, sign in hardware, verify in software
sign1:
	openssl dgst -$(PSS_MD) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey tmp.pkey -out message.sig $(PKEYOPT_PSS)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmp.pkey -sigfile message.sig $(PKEYOPT_PSS)
	@echo '--------'

# using dgst
# sign in hardware, verify in software
sign2:
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign tmp.pkey -$(PSS_MD) -out message.sig $(SIGOPT_PSS)  message.txt
	openssl dgst $(SW_ENGINE) -prverify tmp.pkey -$(PSS_MD) -signature message.sig $(SIGOPT_PSS)  message.txt
	@echo '--------'

# using dgst (x931)
# sign in hardware, verify in software, also verify in hardware
sign3:
	rm -f message.sig
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign tmp.pkey -$(MD_32) -out message.sig $(SIGOPT_X931)  message32.txt
	openssl dgst $(SW_ENGINE) -prverify tmp.pkey -$(MD_32) -signature message.sig $(SIGOPT_X931)  message32.txt
	openssl dgst $(HW_ENGINE) -prverify tmp.pkey -$(MD_32) -signature message.sig $(SIGOPT_X931)  message32.txt
	@echo '--------'
	rm -f message.sig
	openssl dgst $(HW_ENGINE) $(HW_KEYFORM) -sign tmp.pkey -$(MD_64) -out message.sig $(SIGOPT_X931)  message64.txt
	openssl dgst $(SW_ENGINE) -prverify tmp.pkey -$(MD_64) -signature message.sig $(SIGOPT_X931)  message64.txt
	openssl dgst $(HW_ENGINE) -prverify tmp.pkey -$(MD_64) -signature message.sig $(SIGOPT_X931)  message64.txt
	@echo '--------'

# using pkeyutl (x931)
# digest in software, sign in hardware, verify in software
sign4:
	rm -f message.sig
	openssl dgst -$(MD_32) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey tmp.pkey -out message.sig $(PKEYOPT_32) $(PKEYOPT_X931)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmp.pkey -sigfile message.sig $(PKEYOPT_32) $(PKEYOPT_X931)
	@echo '--------'
	rm -f message.sig
	openssl dgst -$(MD_64) -out message.dig -binary message.txt
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -sign -in message.dig -inkey tmp.pkey -out message.sig $(PKEYOPT_64) $(PKEYOPT_X931)
	openssl pkeyutl $(SW_ENGINE) -verify -in message.dig -inkey tmp.pkey -sigfile message.sig $(PKEYOPT_64) $(PKEYOPT_X931)
	@echo '--------'

# decrypt pkcs1
decrypt1:
	rm -f message.enc message.dec
	openssl pkeyutl $(SW_ENGINE) -encrypt -in message.txt -inkey tmp.pkey -out message.enc
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -decrypt -in message.enc -inkey tmp.pkey -out message.dec
	-diff -q -s message.txt message.dec
	@echo '--------'

OAEP_MD=$(BASE_MD)

#TODO: -pkeyopt digest:$(OAEP_MD) is possible option on openssl3 only
KEYOPT_OAEP=-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$(OAEP_MD) -pkeyopt rsa_mgf1_md:$(OAEP_MD)

# decrypt oaep
decrypt2:
	rm -f message.enc message.dec
	openssl pkeyutl $(SW_ENGINE) -encrypt -in message.txt -inkey tmp.pkey -out message.enc $(KEYOPT_OAEP)
	openssl pkeyutl $(HW_ENGINE) $(HW_KEYFORM) -decrypt -in message.enc -inkey tmp.pkey -out message.dec $(KEYOPT_OAEP)
	-diff -q -s message.txt message.dec
	@echo '--------'

# clean all temp files
clean:
	rm -f tmp.pkey
	rm -f tmp.foo tmp.pkey.0 tmp.pkey.1 tmp.pkey.2
	@echo

# clean hsm objects
cleanhsm:
	sautil -v -s 0 -i 0:0 -o -q -c -g 0 -f tmp.pkey
	@echo

# tls server dependencies (issuer key in software)
HW_ENGINE_ISSUER=
HW_KEYFORM_ISSUER=

tmp1.foo:
	touch tmp1.foo
	@echo

tmp1.pkey: tmp1.foo
	openssl genpkey $(HW_ENGINE_ISSUER) -algorithm RSA -out tmp1.pkey -pkeyopt rsa_keygen_bits:$(RSA_BITS)
	@echo

check1:
	openssl pkey -check -in tmp1.pkey $(HW_ENGINE_ISSUER)
	@echo

tmp1.csr: tmp1.pkey
	openssl req $(HW_ENGINE_ISSUER) $(HW_KEYFORM_ISSUER) -$(PKCS_MD) -verbose -new -nodes -key tmp1.pkey -out tmp1.csr -verify -subj "/CN=t_ca_rsa" $(PKEYOPT_PKCS)
	@echo

# self signed
tmp1.crt: tmp1.csr
	openssl x509 $(HW_ENGINE_ISSUER) $(HW_KEYFORM_ISSUER) -trustout -$(PKCS_MD) -outform PEM -req -days 7305 -in tmp1.csr -signkey tmp1.pkey -out tmp1.crt -extfile ext_ca.cnf $(SIGOPT_PKCS)
	@echo

# tls server dependencies (server key in hardware)
HW_ENGINE_SERVER=$(HW_ENGINE)
HW_KEYFORM_SERVER=$(HW_KEYFORM)

tmp2.foo:
	touch tmp2.foo
	@echo

tmp2.pkey: tmp2.foo
	openssl genpkey $(HW_ENGINE_SERVER) -algorithm RSA -out tmp2.pkey -pkeyopt rsa_keygen_bits:$(RSA_BITS)
	@echo

check2:
	openssl pkey -check -in tmp2.pkey $(HW_ENGINE_SERVER)
	@echo

tmp2.csr: tmp2.pkey
	openssl req $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(PKCS_MD) -verbose -new -nodes -key tmp2.pkey -out tmp2.csr -verify -subj "/CN=t_server_rsa" $(PKEYOPT_PKCS)
	@echo

# not self signed
tmp2.crt: tmp2.csr
	openssl x509 $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(PKCS_MD) -outform PEM -req -days 7305 -in tmp2.csr -CA tmp1.crt -CAkey tmp1.pkey -out tmp2.crt -extfile ext_server.cnf $(SIGOPT_PKCS)
	@echo

# tls server
server: tmp1.crt tmp2.crt
	openssl s_server $(HW_ENGINE_SERVER) -cert tmp2.crt -key tmp2.pkey
	@echo

# tls client
client:
	openssl s_client -CAfile tmp1.crt
	@echo

#eof

