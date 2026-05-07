
@echo off
rem ##############################################################################
rem #
rem # This file is part of the "Luna OpenSSL for PQC" project.
rem #
rem # The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
rem # following Web site for further details: https://mit-license.org/ ).
rem #
rem # Copyright © 2024 Thales Group
rem #
rem ##############################################################################
rem #
rem # PURPOSE:
rem #
rem #  Setup for the engineperf utility.
rem #
rem # DEPENDENCIES
rem #
rem #  "%BINPATH%\ssl\bin\openssl".
rem #  "%BINPATH%\sautil\bin\sautil".
rem #

set ENGINE=gem
set SAUTILARG=-v -s 0 -i 0:0 -o -q -c
set BINPATH=c:\cygwin\usr\local
set SAUTILEXE=%BINPATH%\ssl\sautil\bin\sautil
set OPENSSLEXE=%BINPATH%\ssl\bin\openssl
set IN_SOFTWARE=0
set IN_PROVIDER=0

rem # choose a curve
rem #   common curves { prime256v1 , secp384r1 , secp521r1 }
rem #   less common curves { prime192v1 , secp224r1 , secp256k1 }
rem #   other large curves { sect409r1 , c2tnb431r1 , sect571r1 }
set CURVE_NAME=secp521r1



if "%2" == "" goto ok_provider
if NOT "%2" == "--provider" goto fail_usage
set IN_PROVIDER=1
:ok_provider

if NOT "%1" == "--test-all" goto ok_test_all

echo ""
echo "Generate RSA key and keyfile..."
if EXIST tmprsakey.pem goto ok_tmprsakey 
  if     "%IN_SOFTWARE%" == "1" %OPENSSLEXE% genrsa -out tmprsakey.pem -f4 3072
  if NOT "%IN_SOFTWARE%" == "1" %SAUTILEXE% %SAUTILARG% -f tmprsakey.pem -x 01:00:01 -g 3072
  if NOT errorlevel 0 goto fail_cmd 
:ok_tmprsakey

echo ""
echo "Generate DSA param file..."
if EXIST tmpdsaparam.pem goto ok_tmpdsaparam 
  rem %OPENSSLEXE% dsaparam -out tmpdsaparam.pem 2048
  %OPENSSLEXE% genpkey -genparam -algorithm DSA -out tmpdsaparam.pem -pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256
  if NOT errorlevel 0 goto fail_cmd 
:ok_tmpdsaparam

echo ""
echo "Generate DSA key and keyfile..."
if EXIST tmpdsakey.pem goto ok_tmpdsakey 
  if     "%IN_SOFTWARE%" == "1" %OPENSSLEXE% gendsa -out tmpdsakey.pem tmpdsaparam.pem 
  if NOT "%IN_SOFTWARE%" == "1" %SAUTILEXE% %SAUTILARG% -f tmpdsakey.pem -d 3072:tmpdsaparam.pem 
  if NOT errorlevel 0 goto fail_cmd 
:ok_tmpdsakey

echo ""
echo "Generate EC param file..."
if EXIST tmpecparam.pem goto ok_tmpecparam 
  %OPENSSLEXE% ecparam -out tmpecparam.pem -name %CURVE_NAME%
  if NOT errorlevel 0 goto fail_cmd 
:ok_tmpecparam

echo ""
echo "Generate ECDSA key and keyfile..."
if EXIST tmpecdsakey.pem goto ok_tmpecdsakey 
  if     "%IN_SOFTWARE%" == "1" %OPENSSLEXE% ecparam -in tmpecparam.pem -out tmpecdsakey.pem -genkey 
  if NOT "%IN_SOFTWARE%" == "1" %SAUTILEXE%  %SAUTILARG% -f tmpecdsakey.pem -m OID_:tmpecparam.pem 
  if NOT errorlevel 0 goto fail_cmd 
:ok_tmpecdsakey

echo ""
if NOT "%IN_SOFTWARE%" == "1" goto ok_engineperf_hw
echo "Running engineperf in software..."
if NOT "%IN_PROVIDER%" == "1" .\engineperf --fips=0 --threads=15 --seconds=2 --engine   --software
if     "%IN_PROVIDER%" == "1" .\engineperf --fips=0 --threads=15 --seconds=2 --provider --software
if NOT errorlevel 0 goto fail_cmd 
:ok_engineperf_hw
echo "Running engineperf in hardware..."
if NOT "%IN_PROVIDER%" == "1" .\engineperf --fips=0 --threads=15 --seconds=2 --engine   --load_private
if     "%IN_PROVIDER%" == "1" .\engineperf --fips=0 --threads=15 --seconds=2 --provider
if NOT errorlevel 0 goto fail_cmd 
:ok_engineperf_done

echo "Done."
goto done
:ok_test_all



if NOT "%1" == "--delete-all" goto ok_delete_all
  if NOT EXIST tmprsakey.pem  goto nf_tmprsakey
    if NOT "%IN_SOFTWARE%" == "1"  %SAUTILEXE%  %SAUTILARG% -f tmprsakey.pem -g 0 
    if NOT "%IN_SOFTWARE%" == "1"  if NOT errorlevel 0 goto fail_cmd 
    del tmprsakey.pem 
  :nf_tmprsakey

  if NOT EXIST tmpdsakey.pem  goto nf_tmpdsakey
    if NOT "%IN_SOFTWARE%" == "1"  %SAUTILEXE%  %SAUTILARG% -f tmpdsakey.pem -d 0 
    if NOT "%IN_SOFTWARE%" == "1"  if NOT errorlevel 0 goto fail_cmd 
    del tmpdsakey.pem 
  :nf_tmpdsakey

  if NOT EXIST tmpecdsakey.pem  goto nf_tmpecdsakey
    if NOT "%IN_SOFTWARE%" == "1"  %SAUTILEXE%  %SAUTILARG% -f tmpecdsakey.pem -m 0 
    if NOT "%IN_SOFTWARE%" == "1"  if NOT errorlevel 0 goto fail_cmd 
    del tmpecdsakey.pem 
  :nf_tmpecdsakey

  if EXIST tmpecparam.pem  del tmpecparam.pem
  rem use cached dsa param
  rem if EXIST tmpdsaparam.pem  del tmpdsaparam.pem

echo "Done."
goto done
:ok_delete_all



:fail_usage
echo ""
echo "Unrecognized option: %1 %2"
echo "Usage:"
echo "  cmd /c engineperf-test.bat --test-all [ --provider ]"
echo "  cmd /c engineperf-test.bat --delete-all"
:fail_cmd
echo ""
echo "Command failed."
:done


