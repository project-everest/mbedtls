/*
 *  A C++ program that includes all of the mbed TLS header files, in order to
 *  test if no errors are raised in the process.
 *
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/des.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md5.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pkcs12.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/version.h"
#include "mbedtls/xtea.h"
#include "mbedtls/aesni.h"
#include "mbedtls/bignum.h"
#include "mbedtls/certs.h"
#include "mbedtls/compat-1.3.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecp_internal.h"
#include "mbedtls/havege.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/arc4.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/padlock.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1.h"
#include "mbedtls/bn_mul.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy_poll.h"
#include "mbedtls/md2.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/rsa_internal.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/threading.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/camellia.h"
#include "mbedtls/cipher_internal.h"
#include "mbedtls/debug.h"
#include "mbedtls/ecjpake.h"
#include "mbedtls/error.h"
#include "mbedtls/md4.h"
#include "mbedtls/net.h"
#include "mbedtls/pkcs11.h"
#include "mbedtls/sha1.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#define mbedtls_exit       exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

int main( int argc, char *argv[] )
{
    (void) argc;
    (void) argv;
}