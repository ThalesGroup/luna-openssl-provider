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
# Description: shared windows compiler settings (little-endian)
#              for openssl engine, provider, sautil, engineperf, etc.
#

# flags consistent with openssl
CC="CL.EXE"
CPP="$(CC)" /EP /C
MT="MT.EXE"
RM0="rm"
RM="$(RM0)" -f
CP0="cp"
CP="$(CP0)"
ASFLAGS=
CPPFLAGS=-D"_CRT_SECURE_NO_WARNINGS"
CFLAGS=/W3 /wd4090 /nologo /Od
LD="LINK.EXE"
LDFLAGS=/nologo /debug
EX_LIBS=

CNF_ASFLAGS=/c /Cp /Cx
CNF_CPPFLAGS_BASE=-D"OPENSSL_SYS_WIN32" -D"WIN32_LEAN_AND_MEAN" -D"_CRT_SECURE_NO_DEPRECATE" -D"_WINSOCK_DEPRECATED_NO_WARNINGS" -D"DEBUG" -D"_DEBUG" -D"L_ENDIAN"
CNF_CPPFLAGS=$(CNF_CPPFLAGS_BASE)
CNF_CFLAGS=/Gs0 /GF /Gy /MDd
CNF_CXXFLAGS=
CNF_LDFLAGS=
CNF_EX_LIBS=ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib

DSO_ASFLAGS=$(CNF_ASFLAGS) $(ASFLAGS)
DSO_CPPFLAGS=$(CNF_CPPFLAGS) $(CPPFLAGS)
DSO_CFLAGS=/Zi $(CNF_CFLAGS) $(CFLAGS)
DSO_LDFLAGS=/dll $(CNF_LDFLAGS) $(LDFLAGS)
DSO_EX_LIBS=$(CNF_EX_LIBS) $(EX_LIBS)

BIN_ASFLAGS=$(CNF_ASFLAGS) $(ASFLAGS)
BIN_CPPFLAGS=$(CNF_CPPFLAGS) $(CPPFLAGS)
BIN_CFLAGS=/Zi /MDd $(CNF_CFLAGS) $(CFLAGS)
BIN_LDFLAGS=setargv.obj /subsystem:console /opt:ref $(CNF_LDFLAGS) $(LDFLAGS)
BIN_EX_LIBS=$(CNF_EX_LIBS) $(EX_LIBS)

# openssl install directory
CFG_INSTALLDIR=c:\cygwin\usr\local\ssl

#eof

