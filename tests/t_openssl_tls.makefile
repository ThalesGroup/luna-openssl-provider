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
# test qtls,
# and mutual authentication,
# and keys in hardware on server AND client
#

###############################################################################

# include provider, keyform, engine
include t_openssl_common.include

# misc options
REQ_DIGEST=sha512
X509_SIGOPT=

# misc preference
PREFER_PQC_CA=0
PREFER_PQC_SERVER=0
PREFER_PQC_GROUP=0
PREFER_ECDHE=0
PREFER_DHE=0
PREFER_EC=0
PREFER_PURE_SIG=1
PREFER_PURE_KEM=0

# root CA cert
ifeq ($(PREFER_PQC_CA),1)
ifeq ($(PREFER_PURE_SIG),1)
GENPKEY1_ALGORITHM=-algorithm mldsa87
else
GENPKEY1_ALGORITHM=-algorithm p521_mldsa87
endif
GENPKEY1_PKEYOPT=
REQ1_SIGOPT=
REQ1_SIGOPT=-sigopt digest:$(REQ_DIGEST)
else
# root CA cert (RSA)
GENPKEY1_ALGORITHM=-algorithm RSA
GENPKEY1_PKEYOPT=-pkeyopt rsa_keygen_bits:3072
REQ1_SIGOPT=
#REQ1_SIGOPT=-sigopt digest:$(REQ_DIGEST)
endif

# intermediate CA cert
ifeq ($(PREFER_PQC_CA),1)
ifeq ($(PREFER_PURE_SIG),1)
GENPKEY2_ALGORITHM=-algorithm mldsa65
else
GENPKEY2_ALGORITHM=-algorithm p384_mldsa65
endif
GENPKEY2_PKEYOPT=
REQ2_SIGOPT=
REQ2_SIGOPT=-sigopt digest:$(REQ_DIGEST)
else
# intermediate CA cert (EC)
GENPKEY2_ALGORITHM=-algorithm EC
GENPKEY2_PKEYOPT=-pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve
REQ2_SIGOPT=
#REQ2_SIGOPT=-sigopt digest:$(REQ_DIGEST)
endif

#
# server cert (PQC)
#

ifneq ($(PREFER_PQC_SERVER),1)

ifneq ($(PREFER_EC),1)
KEYTYPE=RSA
GENPKEY3_ALGORITHM=-algorithm RSA
GENPKEY3_PKEYOPT=-pkeyopt rsa_keygen_bits:3072
REQ3_SIGOPT=
else
KEYTYPE=EC
GENPKEY3_ALGORITHM=-algorithm EC
GENPKEY3_PKEYOPT=-pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve
REQ3_SIGOPT=
endif

else

KEYTYPE=PQC
ifeq ($(PREFER_PURE_SIG),1)
#GENPKEY3_ALGORITHM=-algorithm mldsa65
#GENPKEY3_ALGORITHM=-algorithm ed25519
#GENPKEY3_ALGORITHM=-algorithm ed448
GENPKEY3_ALGORITHM=-algorithm mldsa44
#GENPKEY3_ALGORITHM=-algorithm mldsa87
else
GENPKEY3_ALGORITHM=-algorithm p384_mldsa65
#GENPKEY3_ALGORITHM=-algorithm mldsa65_pss3072
#GENPKEY3_ALGORITHM=-algorithm mldsa65_rsa3072
#GENPKEY3_ALGORITHM=-algorithm mldsa65_p256
#GENPKEY3_ALGORITHM=-algorithm mldsa65_bp256
#GENPKEY3_ALGORITHM=-algorithm mldsa65_ed25519
#GENPKEY3_ALGORITHM=-algorithm p256_mldsa44
#GENPKEY3_ALGORITHM=-algorithm rsa3072_mldsa44
#GENPKEY3_ALGORITHM=-algorithm mldsa44_pss2048
#GENPKEY3_ALGORITHM=-algorithm mldsa44_rsa2048
#GENPKEY3_ALGORITHM=-algorithm mldsa44_ed25519
#GENPKEY3_ALGORITHM=-algorithm mldsa44_p256
#GENPKEY3_ALGORITHM=-algorithm mldsa44_bp256
#GENPKEY3_ALGORITHM=-algorithm p521_mldsa87
#GENPKEY3_ALGORITHM=-algorithm mldsa87_p384
#GENPKEY3_ALGORITHM=-algorithm mldsa87_bp384
#GENPKEY3_ALGORITHM=-algorithm mldsa87_ed448
endif
GENPKEY3_PKEYOPT=
# NOTE: for algorithms {ed,mldsa} the digest is not settable, by lunaprov, and by oqsprovider
REQ3_SIGOPT=
#REQ3_SIGOPT=-sigopt digest:$(REQ_DIGEST)

endif

# server tls1.2 (RSA)
ifneq ($(PREFER_EC),1)
GENPKEY4_ALGORITHM=-algorithm RSA
GENPKEY4_PKEYOPT=-pkeyopt rsa_keygen_bits:3072
REQ4_SIGOPT=
else
GENPKEY4_ALGORITHM=-algorithm EC
GENPKEY4_PKEYOPT=-pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve
REQ4_SIGOPT=
endif

###############################################################################

default0:
	@echo "options:"
	@echo "  s_server[3|2]"
	@echo "  s_client[3|2][_apache2]"
	@echo "  s_time[3|2]"
	@echo

# tls server dependencies (CA key in software)
ifeq ($(PREFER_PQC_CA),1)
HW_ENGINE_CA=$(SW_ENGINE)
HW_KEYFORM_CA=$(SW_KEYFORM)
else
HW_ENGINE_CA=
HW_KEYFORM_CA=
endif

# self signed root ca cert (between 3 and 5 years)
tmp1.foo:
	touch tmp1.foo
	@echo

tmp1.pkey: tmp1.foo
	openssl genpkey $(HW_ENGINE_CA) $(GENPKEY1_ALGORITHM) -out tmp1.pkey $(GENPKEY1_PKEYOPT)
	openssl pkey -check -in tmp1.pkey $(HW_ENGINE_CA)
	@echo

tmp1.csr: tmp1.pkey
	openssl req $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -$(REQ_DIGEST) -verbose -new -nodes -key tmp1.pkey -out tmp1.csr -verify -subj "/CN=t_openssl_tls_root" $(REQ1_SIGOPT)
	@echo

tmp1.crt: tmp1.csr
	openssl x509 $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -trustout -$(REQ_DIGEST) -outform PEM -req -days 1825 -in tmp1.csr -signkey tmp1.pkey -out tmp1.crt -extfile ext_root.cnf $(X509_SIGOPT)
	@echo

# intermediate ca cert (between 2 and 3 years)
tmp2.foo:
	touch tmp2.foo
	@echo

tmp2.pkey: tmp2.foo
	openssl genpkey $(HW_ENGINE_CA) $(GENPKEY2_ALGORITHM) -out tmp2.pkey $(GENPKEY2_PKEYOPT)
	openssl pkey -check -in tmp2.pkey $(HW_ENGINE_CA)
	@echo

tmp2.csr: tmp2.pkey
	openssl req $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -$(REQ_DIGEST) -verbose -new -nodes -key tmp2.pkey -out tmp2.csr -verify -subj "/CN=t_openssl_tls_ca" $(REQ2_SIGOPT)
	@echo

tmp2.crt: tmp2.csr tmp1.crt
	openssl x509 $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -$(REQ_DIGEST) -outform PEM -req -days 1095 -in tmp2.csr -CA tmp1.crt -CAkey tmp1.pkey -out tmp2.crt -extfile ext_ca.cnf $(X509_SIGOPT)
	@echo

# tls server dependencies (server key in hardware)

#HW_ENGINE_SERVER=
#HW_KEYFORM_SERVER=
HW_ENGINE_SERVER=$(HW_ENGINE)
HW_KEYFORM_SERVER=$(HW_KEYFORM)

SW_ENGINE_CLIENT=$(SW_ENGINE)
SW_KEYFORM_CLIENT=$(SW_KEYFORM)
#SW_ENGINE_CLIENT=$(HW_ENGINE)
#SW_KEYFORM_CLIENT=$(HW_KEYFORM)

ifeq ($(PREFER_PQC_GROUP),1)

# google chrome (preferred order of algos)
ifeq ($(PREFER_PURE_KEM),1)
TLSGROUPS=kyber768
else
TLSGROUPS=x25519_kyber768
#TLSGROUPS=p384_kyber768
#TLSGROUPS=x448_kyber768
endif

# mlkem (preferred order of algos)
ifeq ($(PREFER_PURE_KEM),1)
TLSGROUPS=mlkem768
else
#TLSGROUPS=x448_mlkem768
TLSGROUPS=x25519_mlkem768
#TLSGROUPS=p384_mlkem768
#TLSGROUPS=p256_mlkem768
endif

else

#TLSGROUPS=x448
TLSGROUPS=x25519
#TLSGROUPS=P-384
#TLSGROUPS=P-256

endif

ifeq ($(TLSGROUPS),)
  GROUPS_OPTS=
else
  GROUPS_OPTS=-groups $(TLSGROUPS)
endif

# server cert (between 90 and 398 days), tls1.3
tmp3.foo:
	touch tmp3.foo
	@echo

tmp3.pkey: tmp3.foo
	openssl genpkey $(HW_ENGINE_SERVER) $(GENPKEY3_ALGORITHM) -out tmp3.pkey $(GENPKEY3_PKEYOPT)
	openssl pkey -check -in tmp3.pkey $(HW_ENGINE_SERVER)
	@echo

tmp3.csr: tmp3.pkey
	openssl req $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -verbose -new -nodes -key tmp3.pkey -out tmp3.csr -verify -subj "/CN=VirtualHost0" $(REQ3_SIGOPT)
	@echo

tmp3.crt: tmp3.csr tmp2.crt
	openssl x509 $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -outform PEM -req -days 398 -in tmp3.csr -CA tmp2.crt -CAkey tmp2.pkey -out tmp3.crt -extfile ext_server.cnf $(X509_SIGOPT)
	@echo

# server cert (between 90 and 398 days), tls1.2
tmp4.foo:
	touch tmp4.foo
	@echo

tmp4.pkey: tmp4.foo
	openssl genpkey $(HW_ENGINE_SERVER) $(GENPKEY4_ALGORITHM) -out tmp4.pkey $(GENPKEY4_PKEYOPT)
	openssl pkey -check -in tmp4.pkey $(HW_ENGINE_SERVER)
	@echo

tmp4.csr: tmp4.pkey
	openssl req $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -verbose -new -nodes -key tmp4.pkey -out tmp4.csr -verify -subj "/CN=VirtualHost0" $(REQ4_SIGOPT)
	@echo

tmp4.crt: tmp4.csr tmp2.crt
	openssl x509 $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -outform PEM -req -days 398 -in tmp4.csr -CA tmp2.crt -CAkey tmp2.pkey -out tmp4.crt -extfile ext_server.cnf $(X509_SIGOPT)
	@echo

QUIET_SERVER=-quiet -verify_quiet -ign_eof

# tls 1.3 server
s_server: s_server3
	@echo

SERVER_CAFILE=-CAfile tmp11.crt

s_server3: tmp3.crt tmp11.crt
	@echo "INFO: testing client auth using option -CAfile."
	openssl s_server $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) $(QUIET_SERVER) -cert tmp3.crt -key tmp3.pkey -tls1_3 $(GROUPS_OPTS) $(SERVER_CAFILE)
	@echo

# tls 1.2 server
s_server2: tmp4.crt tmp11.crt
	@echo "INFO: testing client auth using option -CAfile."
	openssl s_server $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) $(QUIET_SERVER) -cert tmp4.crt -key tmp4.pkey -tls1_2 $(SERVER_CAFILE)
	@echo

# tls 1.3 client
s_client: s_client3
	@echo

CLIENT_CAFILE=-CAfile tmp3.cafile

s_client3: tmp3.cafile tmp13.crt
	@echo "INFO: testing server auth using option -CAfile."
	openssl s_client $(SW_ENGINE_CLIENT) $(SW_KEYFORM_CLIENT) -tls1_3 $(GROUPS_OPTS) -cert tmp13.crt -key tmp13.pkey $(CLIENT_CAFILE)
	@echo

s_client3_apache2: tmp3.cafile tmp13.crt
	@echo "INFO: testing apache server auth using option -CAfile."
	openssl s_client $(SW_ENGINE_CLIENT) $(SW_KEYFORM_CLIENT) -tls1_3 $(GROUPS_OPTS) -cert tmp13.crt -key tmp13.pkey $(CLIENT_CAFILE) \
	  -connect VirtualHost0:8443 \
	  -security_debug_verbose \
	  -debug \
	  -security_debug \
	  -security_debug_verbose \
	  -tlsextdebug
	@echo

# SSLCipherSuite @SECLEVEL=2:
ifeq ($(PREFER_ECDHE),1)
  ifeq ($(PREFER_EC),1)
    TLSCIPHER=ECDHE-ECDSA-AES256-GCM-SHA384
  else
    TLSCIPHER=ECDHE-RSA-AES256-GCM-SHA384
  endif
else
  ifeq ($(PREFER_DHE),1)
    TLSCIPHER=DHE-RSA-AES256-GCM-SHA384
  else
    TLSCIPHER=AES256-GCM-SHA384
  endif
endif

ifeq ($(TLSCIPHER),)
  CIPHER_OPTS=
else
  CIPHER_OPTS=-cipher $(TLSCIPHER)
endif

# tls 1.2 client
s_client2: tmp3.cafile tmp14.crt
	@echo "INFO: testing server auth using option -CAfile."
	openssl s_client $(SW_ENGINE_CLIENT) $(SW_KEYFORM_CLIENT) -tls1_2 $(CIPHER_OPTS) -cert tmp14.crt -key tmp14.pkey $(CLIENT_CAFILE)
	@echo

s_client2_apache2: tmp3.cafile tmp14.crt
	@echo "INFO: testing server auth using option -CAfile."
	openssl s_client $(SW_ENGINE_CLIENT) $(SW_KEYFORM_CLIENT) -tls1_2 $(CIPHER_OPTS) -cert tmp14.crt -key tmp14.pkey $(CLIENT_CAFILE) \
	  -connect VirtualHost0:8443 \
	  -security_debug_verbose \
	  -debug \
	  -security_debug \
	  -security_debug_verbose \
	  -tlsextdebug
	@echo

tmp3.cafile: tmp1.crt tmp2.crt
	cp tmp2.crt tmp3.cafile
	cat tmp1.crt >> tmp3.cafile
	@echo

# tls client performance
#
# NOTE: for "openssl s_time" the groups options is configured via openssl.cnf; e.g.,
#   openssl_conf = openssl_init
#   ...
#   [ openssl_init ]
#   ssl_conf = ssl_sect
#   ...
#   [ ssl_sect ]
#   system_default = system_default_sect
#   ...
#   [ system_default_sect ]
#   #MinProtocol = TLSv1.2
#   #CipherString = DEFAULT:@SECLEVEL=2
#
#   MinProtocol = TLSv1.3
#   CipherString = DEFAULT:@SECLEVEL=3
#   Groups = x25519_mlkem768:p384_mlkem768
# 
s_time: s_time3
	@echo

s_time3: tmp3.cafile tmp13.crt
	openssl s_time $(SW_ENGINE_CLIENT) $(SW_KEYFORM_CLIENT) -tls1_3 $(GROUPS_OPTS) -cert tmp13.crt -key tmp13.pkey $(CLIENT_CAFILE) \
	  -time 15 -verify 2
	@echo

s_time2: tmp3.cafile tmp14.crt
	openssl s_time $(SW_ENGINE_CLIENT) $(SW_KEYFORM_CLIENT) -tls1_2 $(CIPHER_OPTS) -cert tmp14.crt -key tmp14.pkey $(CLIENT_CAFILE) \
	  -time 15 -verify 2
	@echo

# clean all temp files
clean:
	rm -f tmp?.foo tmp?.pkey tmp?.csr tmp?.crt
	rm -f tmp1?.foo tmp1?.pkey tmp1?.csr tmp1?.crt
	rm -f tmp3.cafile
	@echo

# clean hsm objects
cleanhsm: cleanhsm_$(KEYTYPE)
	sautil -v -s 0 -i 0:0 -o -q -c -g 0 -f tmp4.pkey
	sautil -v -s 0 -i 0:0 -o -q -c -g 0 -f tmp14.pkey
	rm -f tmp4.pkey
	rm -f tmp14.pkey
	@echo

cleanhsm_RSA:
	sautil -v -s 0 -i 0:0 -o -q -c -g 0 -f tmp3.pkey
	sautil -v -s 0 -i 0:0 -o -q -c -g 0 -f tmp13.pkey
	rm -f tmp3.pkey
	rm -f tmp13.pkey
	@echo

cleanhsm_DSA:
	sautil -v -s 0 -i 0:0 -o -q -c -d 0 -f tmp3.pkey
	sautil -v -s 0 -i 0:0 -o -q -c -d 0 -f tmp13.pkey
	rm -f tmp3.pkey
	rm -f tmp13.pkey
	@echo

cleanhsm_EC:
	sautil -v -s 0 -i 0:0 -o -q -c -m 0 -f tmp3.pkey
	sautil -v -s 0 -i 0:0 -o -q -c -m 0 -f tmp13.pkey
	rm -f tmp3.pkey
	rm -f tmp13.pkey
	@echo

cleanhsm_PQC:
	sautil -v -s 0 -i 0:0 -o -q -c -k 0 -f tmp3.pkey
	sautil -v -s 0 -i 0:0 -o -q -c -k 0 -f tmp13.pkey
	rm -f tmp3.pkey
	rm -f tmp13.pkey
	@echo

cleanhsm_ED:
	sautil -v -s 0 -i 0:0 -o -q -c -k 0 -f tmp3.pkey
	sautil -v -s 0 -i 0:0 -o -q -c -k 0 -f tmp13.pkey
	rm -f tmp3.pkey
	rm -f tmp13.pkey
	@echo

# list various
list:
	openssl list $(HW_ENGINE_SERVER) -providers -verbose
	@echo
	openssl list $(HW_ENGINE_SERVER) -kem-algorithms
	@echo
	openssl list $(HW_ENGINE_SERVER) -signature-algorithms
	@echo

#
# added for client auth
#

# self signed root ca cert (between 3 and 5 years)
tmp11.foo:
	touch tmp11.foo
	@echo

tmp11.pkey: tmp11.foo
	openssl genpkey $(HW_ENGINE_CA) $(GENPKEY1_ALGORITHM) -out tmp11.pkey $(GENPKEY1_PKEYOPT)
	openssl pkey -check -in tmp11.pkey $(HW_ENGINE_CA)
	@echo

tmp11.csr: tmp11.pkey
	openssl req $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -$(REQ_DIGEST) -verbose -new -nodes -key tmp11.pkey -out tmp11.csr -verify -subj "/CN=t_tls_client_root" $(REQ1_SIGOPT)
	@echo

tmp11.crt: tmp11.csr
	openssl x509 $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -trustout -$(REQ_DIGEST) -outform PEM -req -days 1825 -in tmp11.csr -signkey tmp11.pkey -out tmp11.crt -extfile ext_root.cnf $(X509_SIGOPT)
	@echo

# intermediate ca cert (between 2 and 3 years)
tmp12.foo:
	touch tmp12.foo
	@echo

tmp12.pkey: tmp12.foo
	openssl genpkey $(HW_ENGINE_CA) $(GENPKEY2_ALGORITHM) -out tmp12.pkey $(GENPKEY2_PKEYOPT)
	openssl pkey -check -in tmp12.pkey $(HW_ENGINE_CA)
	@echo

tmp12.csr: tmp12.pkey
	openssl req $(HW_ENGINE_CA) $(HW_KEYFORM_CA) -$(REQ_DIGEST) -verbose -new -nodes -key tmp12.pkey -out tmp12.csr -verify -subj "/CN=t_tls_client_ca" $(REQ2_SIGOPT)
	@echo

tmp12.crt: tmp12.csr tmp11.crt
	openssl x509 $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -outform PEM -req -days 1095 -in tmp12.csr -CA tmp11.crt -CAkey tmp11.pkey -out tmp12.crt -extfile ext_client_ca.cnf $(X509_SIGOPT)
	@echo

# client cert (between 90 and 398 days), tls1.3
tmp13.foo:
	touch tmp13.foo
	@echo

tmp13.pkey: tmp13.foo
	openssl genpkey $(HW_ENGINE_SERVER) $(GENPKEY3_ALGORITHM) -out tmp13.pkey $(GENPKEY3_PKEYOPT)
	openssl pkey -check -in tmp13.pkey $(HW_ENGINE_SERVER)
	@echo

tmp13.csr: tmp13.pkey
	openssl req $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -verbose -new -nodes -key tmp13.pkey -out tmp13.csr -verify -subj "/CN=t_tls_client" $(REQ3_SIGOPT)
	@echo

tmp13.crt: tmp13.csr tmp12.crt
	openssl x509 $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -outform PEM -req -days 398 -in tmp13.csr -CA tmp12.crt -CAkey tmp12.pkey -out tmp13.crt -extfile ext_client.cnf $(X509_SIGOPT)
	@echo

# client cert (between 90 and 398 days), tls1.2
tmp14.foo:
	touch tmp14.foo
	@echo

tmp14.pkey: tmp14.foo
	openssl genpkey $(HW_ENGINE_SERVER) $(GENPKEY4_ALGORITHM) -out tmp14.pkey $(GENPKEY4_PKEYOPT)
	openssl pkey -check -in tmp14.pkey $(HW_ENGINE_SERVER)
	@echo

tmp14.csr: tmp14.pkey
	openssl req $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -verbose -new -nodes -key tmp14.pkey -out tmp14.csr -verify -subj "/CN=t_ls_client2" $(REQ4_SIGOPT)
	@echo

tmp14.crt: tmp14.csr tmp12.crt
	openssl x509 $(HW_ENGINE_SERVER) $(HW_KEYFORM_SERVER) -$(REQ_DIGEST) -outform PEM -req -days 398 -in tmp14.csr -CA tmp12.crt -CAkey tmp12.pkey -out tmp14.crt -extfile ext_client.cnf $(X509_SIGOPT)
	@echo


#eof

