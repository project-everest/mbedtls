/*
 *  Edwards-curve DSA
 *
 *  Copyright (C) 2018 Microsoft Corporation
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

#if defined(MBEDTLS_EDDSA_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc      calloc
#define mbedtls_free        free
#define mbedtls_time_t      time_t
#define mbedtls_snprintf    snprintf
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/asn1write.h"

#include "everest/Hacl_Curve25519.h"
#include "everest/Hacl_Ed25519.h"

#include "mbedtls/eddsa.h"

void mbedtls_eddsa_init( mbedtls_eddsa_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_eddsa_context ) );
}

void mbedtls_eddsa_free( mbedtls_eddsa_context *ctx )
{
    mbedtls_platform_zeroize( ctx->keys.ed25519.private_, sizeof( ctx->keys.ed25519.private_ ) );
    mbedtls_platform_zeroize( ctx->keys.ed25519.public_, sizeof( ctx->keys.ed25519.public_ ) );
}

int mbedtls_eddsa_sign( mbedtls_eddsa_context *ctx,
                        unsigned char *sig, size_t max_sig_len,
                        const unsigned char *msg, size_t msg_len,
                        int( *f_rng )( void *, unsigned char *, size_t ), void *p_rng )
{
    if( ctx->id != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    // Not required?
    ( void )f_rng;
    ( void )p_rng;

    // preconditions of Hacl_Ed25519_sign
    if( !( sizeof( ctx->keys.ed25519.private_ ) == 32 &&
           msg_len < 4294967232 /* 2^32 - 64 */ ) )
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    // postcondition of Hacl_Ed25519_sign: signature length = 64
    if( max_sig_len < 64 )
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

    Hacl_Ed25519_sign( sig,
                       ctx->keys.ed25519.private_,
                       ( unsigned char* )msg, ( uint32_t )msg_len );

    return( 0 );
}

int mbedtls_eddsa_verify( mbedtls_eddsa_context *ctx,
                          const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len )
{
    if( ctx->id != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    ( void )sig_len; // Not required?

    // preconditions of Hacl_Ed25519_verify
    if( !( sizeof( ctx->keys.ed25519.public_ ) == 32 &&
           sig_len == 64 &&
           msg_len < 4294967232 /* 2^32 - 64 */ ) )
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    if( !Hacl_Ed25519_verify( ( unsigned char* )ctx->keys.ed25519.public_,
        ( unsigned char* )msg, ( uint32_t )msg_len,
        ( unsigned char* )sig ) )
    {
        return MBEDTLS_ERR_ECP_VERIFY_FAILED;
    }

    return( 0 );
}

int mbedtls_eddsa_genkey( mbedtls_eddsa_context *ctx, mbedtls_ecp_group_id gid,
                          int( *f_rng )( void *, unsigned char *, size_t ), void *p_rng )
{
    int ret;

    if( gid != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    ctx->id = gid;

    if( ( ret = f_rng( p_rng, ctx->keys.ed25519.private_, 32 ) ) != 0 )
        return ret;

    /* See also https://tools.ietf.org/html/rfc8032#section-5.1.5 */

    // preconditions of Hacl_Ed25519_secret_to_public_
    if( !( sizeof( ctx->keys.ed25519.public_ ) == 32 &&
          ( ctx->keys.ed25519.public_ <= ctx->keys.ed25519.private_ ||
            ctx->keys.ed25519.public_ >= ctx->keys.ed25519.private_ +
              sizeof( ctx->keys.ed25519.private_ ) ) ) )
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    Hacl_Ed25519_secret_to_public( ctx->keys.ed25519.public_, ctx->keys.ed25519.private_ );

    return( 0 );
}

int mbedtls_eddsa_check_pub_priv( mbedtls_eddsa_context *pub, mbedtls_eddsa_context *prv )
{
    unsigned char tmp[32];

    Hacl_Ed25519_secret_to_public( tmp, prv->keys.ed25519.private_ );

    if( memcmp( pub->keys.ed25519.public_, tmp, 32 ) != 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

static int eddsa_signature_to_asn1( const unsigned char *sig, size_t sig_len,
                                    unsigned char *sig_asn1, size_t *sig_asn1_len )
{
    int ret;
    static unsigned char buf[MBEDTLS_EDDSA_MAX_LEN + 3];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_octet_string( &p, buf, sig, sig_len ) );

    memcpy( sig_asn1, p, len );
    *sig_asn1_len = len;

    return( 0 );
}

int mbedtls_eddsa_write_signature( mbedtls_eddsa_context *ctx,
                                   const unsigned char *msg, size_t msg_len,
                                   unsigned char *sig, size_t max_sig_len, size_t *sig_len,
                                   int( *f_rng )( void *, unsigned char *, size_t ),
                                   void *p_rng )
{
    int ret = 0;

    if( ctx->id != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    if( max_sig_len < sizeof( ctx->tmp ) )
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

    if( !ret ) ret = mbedtls_eddsa_sign( ctx, ctx->tmp, sizeof( ctx->tmp ), msg, msg_len, f_rng, p_rng );
    if( !ret ) ret = eddsa_signature_to_asn1( ctx->tmp, 64, sig, sig_len );

    return( ret );
}

int mbedtls_eddsa_read_signature( mbedtls_eddsa_context *ctx,
                                  const unsigned char *msg, size_t msg_len,
                                  const unsigned char *sig, size_t sig_len )
{
    int ret;
    unsigned char *p = ( unsigned char * )sig;
    const unsigned char *end = sig + sig_len;
    size_t len;

    if( ctx->id != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    if( p + sig_len != end )
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( ret );

    if( p + len != end )
        return MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH;

    if( ( ret = mbedtls_eddsa_verify( ctx, msg, msg_len, p, len ) ) != 0 )
        return( ret );

    return( ret );
}

int mbedtls_eddsa_write_string( const unsigned char *key, size_t key_size,
                                char *buf, size_t buflen, size_t *olen )
{
    size_t i;

    if( buflen < key_size * 2 + 1 )
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

    for( i = 0; i < key_size; i++ ) {
        mbedtls_snprintf( buf, 3, "%02X", key[i] );
        buf += 2;
    }

    *olen = key_size * 2 + 1;

    return ( 0 );
}

#endif /* MBEDTLS_EDDSA_C */
