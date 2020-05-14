
@echo off
setlocal EnableDelayedExpansion
REM ************************************************************************
REM Script: EncryptPW.bat
REM Author: Richard Knechtel
REM Date: 09/02/2016
REM Description: This script will allow you to 
REM              Encrypt/Decrypt a password or Generate an AES Key File
REM
REM Parameters:
REM            Command (Example: encrpyt/decrypt/generatekey)
REM            Password to Encrypt/Decrypt OR Key File Name
REM            Key Length (Possible values: 128, 192, 256)
REM 
REM Notes:
REM        You MUST change the DRIVE variable for your system.
REM
REM        You must enclose any password to encrypt or decrypt in double Quotes
REM        Example: "mypassword"
REM
REM ************************************************************************

echo Running as user: %USERNAME%
echo.
echo PLEASE NOTE: You must enclose any password to encrypt or decrypt in double Quotes
echo              Example: "mypassword"
echo.

REM Get parameters
set COMMAND=%1
set WAGWOORD=%2
set KEYFILE=%2
set KEYLENGTH=%3
set WAGWOORD2=%3


REM Set default Error Number
set ERRORNUMBER=0

REM Set EncryptionUtils Jar and Class
Set DRIVE=D:
Set ENCRYPTLIBLOC=\opt\Encryption\
Set ENCRYPTLIB=encryption-utils-2.0.0.jar
Set ENCRYPTLIBPATH=%DRIVE%%ENCRYPTLIBLOC%%ENCRYPTLIB%
Set ENCRYPTCLASS=com.rk.encryptionutils.AESEncryptionUtils

REM Check if we got ALL parameters
if "!COMMAND!"=="" goto usage
if "!WAGWOORD!"=="" goto usage
if "!COMMAND!"=="" if "!WAGWOORD!"=="" (
  goto usage
)

if "!COMMAND!"=="encryptwithkey" if "!KEYFILE!"=="" if "!WAGWOORD2!"=="" (
  goto usage
)

if "!COMMAND!"=="decryptwithkey" if "!KEYFILE!"=="" if "!WAGWOORD2!"=="" (
  goto usage
)

if "!COMMAND!"=="generatekey" if "!KEYFILE!"=="" if "!KEYLENGTH!"=="" (
  goto usage
)

if /I "%COMMAND%" == "encrypt"        goto cmdEncrypt
if /I "%COMMAND%" == "encryptwithkey" goto cmdEncryptWithKey
if /I "%COMMAND%" == "decrypt"        goto cmdDecrypt
if /I "%COMMAND%" == "decryptwithkey"  goto cmdDecryptWithKey
if /I "%COMMAND%" == "generatekey"    goto cmdGeneratekey


REM Encrypt WagWoord:
:cmdEncrypt
@Echo Encrypting WagWoord %WAGWOORD%
java -cp %ENCRYPTLIBPATH% %ENCRYPTCLASS% encrypt %WAGWOORD%

REM Lets get out of here!
goto getoutofhere

REM Encrypt With Key File WagWoord:
:cmdEncryptWithKey
@Echo Encrypting With Key File WagWoord %WAGWOORD%
java -cp %ENCRYPTLIBPATH% %ENCRYPTCLASS% encryptwithkey %KEYFILE% %WAGWOORD2%

REM Lets get out of here!
goto getoutofhere

REM Decrypt WagWoord:
:cmdDecrypt
@Echo Decrypting WagWoord %WAGWOORD%
java -cp %ENCRYPTLIBPATH% %ENCRYPTCLASS% decrypt %WAGWOORD%

REM Lets get out of here!
goto getoutofhere

REM Decrypt With a Key File WagWoord:
:cmdDecryptWithKey
@Echo Decrypting With Key File WagWoord %WAGWOORD%
java -cp %ENCRYPTLIBPATH% %ENCRYPTCLASS% decryptwithkey %KEYFILE% %WAGWOORD2%

REM Lets get out of here!
goto getoutofhere

REM Generate key File:
:cmdGeneratekey
@Echo Geneerating Key File  %KEYFILE% with Key Length of %KEYLENGTH%
java -cp %ENCRYPTLIBPATH% %ENCRYPTCLASS% generatekey %KEYFILE% %KEYLENGTH%


REM Lets get out of here!
goto getoutofhere


:usage
set ERRORNUMBER=1
echo [USAGE]: EncryptPW.bat arg1 arg2 arg3
echo arg1 = Command (encrypt / encryptwithkey / decrypt / decryptwithkey / generatekey)
echo arg2 = Password / KeyFileName (if generatekey)
echo arg3 = Key File Length (Possible values: 128, 192, 256)

echo Note: You must enclose any password to encrypt or decrypt in double Quotes
echo        Example: "mypassword"
goto getoutofhere

:getoutofhere
Exit /B %ERRORNUMBER%
