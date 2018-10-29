/**
 * \file everest.c
 *
 * \brief Interface to Everest code.
 *
 */

 /*
  *  Copyright 2016-2018 INRIA and Microsoft Corporation
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
  *  This file is part of Mbed TLS (https://tls.mbed.org).
  */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)

#include <string.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/gcm.h"

#include "everest/x25519.h"
#include "everest/everest.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include "mbedtls/platform_util.h"

int mbedtls_everest_setup( mbedtls_ecdh_context *ctx, int grp )
{
    if( grp != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    ctx->var = MBEDTLS_ECDH_VARIANT_EVEREST;
    ctx->grp = grp;

    ctx->ctx.everest_ecdh.ctx = mbedtls_calloc( 1, sizeof( mbedtls_x25519_context ) );
    mbedtls_x25519_init( ctx->ctx.everest_ecdh.ctx );

    return 0;
}

void mbedtls_everest_free( mbedtls_ecdh_context *ctx )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;

    mbedtls_x25519_free( x25519_ctx );
    mbedtls_free( x25519_ctx );

    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp = MBEDTLS_ECP_DP_NONE;
}

int mbedtls_everest_make_params( mbedtls_ecdh_context *ctx, size_t *olen,
                                 unsigned char *buf, size_t blen,
                                 int( *f_rng )( void *, unsigned char *, size_t ),
                                 void *p_rng )
{
    int ret = 0;
    size_t grp_len;
    mbedtls_ecp_group grp;
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;

    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST )
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    mbedtls_ecp_group_init( &grp );

    if( ( ret = mbedtls_x25519_make_params( x25519_ctx, olen, buf, blen, f_rng, p_rng ) ) != 0 )
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_CURVE25519 );
    ret = mbedtls_ecp_tls_write_group( &grp, &grp_len, buf, blen );
    mbedtls_ecp_group_free( &grp );
    if (ret != 0)
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( blen < 32 )
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;

    memcpy( x25519_ctx->peer_point, buf, 32 );
    *olen = grp_len + 1 + 32;
    return( ret );
}

int mbedtls_everest_read_params( mbedtls_ecdh_context *ctx,
                                 const unsigned char **buf, const unsigned char *end )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_read_params( x25519_ctx, buf, end );
}

int mbedtls_everest_get_params( mbedtls_ecdh_context *ctx, const mbedtls_ecp_keypair *key,
    int side )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_get_params( x25519_ctx, key, side );
}

int mbedtls_everest_make_public( mbedtls_ecdh_context *ctx, size_t *olen,
                                 unsigned char *buf, size_t blen,
                                 int( *f_rng )( void *, unsigned char *, size_t ),
                                 void *p_rng )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_make_public( x25519_ctx, olen, buf, blen, f_rng, p_rng );
}

int mbedtls_everest_read_public( mbedtls_ecdh_context *ctx,
                                 const unsigned char *buf, size_t blen )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_read_public ( x25519_ctx, buf, blen );
}

int mbedtls_everest_calc_secret( mbedtls_ecdh_context *ctx, size_t *olen,
                                 unsigned char *buf, size_t blen,
                                 int( *f_rng )( void *, unsigned char *, size_t ),
                                 void *p_rng )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_calc_secret( x25519_ctx, olen, buf, blen, f_rng, p_rng );
}


#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_AES_GCM)

void mbedtls_everest_aes_gcm_args_init( everest_aes_gcm_args * args, unsigned int keysize )
{
    args->plain_ptr_size = 0;
    args->auth_ptr_size = 0;
    args->out_ptr_size = 0;
    args->tag_ptr_size = 0;

    args->vale_args.expanded_key_ptr = ( everest_byte * )mbedtls_calloc( 1, keysize * 128 / 8 );
}

void mbedtls_everest_aes_gcm_wipe_key( mbedtls_gcm_context *ctx )
{
    everest_aes_gcm_args * args = ( everest_aes_gcm_args * )ctx->cipher_ctx.cipher_ctx;

    if( args && args->vale_args.expanded_key_ptr )
    {
        switch( ctx->cipher_ctx.cipher_info->type )
        {
        case MBEDTLS_CIPHER_AES_128_GCM: mbedtls_platform_zeroize( args->vale_args.expanded_key_ptr, 11 * 128 / 8 ); break;
        case MBEDTLS_CIPHER_AES_256_GCM: mbedtls_platform_zeroize( args->vale_args.expanded_key_ptr, 15 * 128 / 8 ); break;
        default: break;
        }
        mbedtls_free( args->vale_args.expanded_key_ptr );
        args->vale_args.expanded_key_ptr = NULL;
    }
}

int mbedtls_everest_aes_gcm_setkey( mbedtls_gcm_context *ctx,
                                    const unsigned char *key, unsigned int keybits )
{
    everest_aes_gcm_args * args;

    mbedtls_everest_aes_gcm_wipe_key( ctx );

    switch( ctx->cipher_ctx.cipher_info->type )
    {
    case MBEDTLS_CIPHER_AES_128_GCM:
        if( keybits != 128 )
            return ( MBEDTLS_ERR_GCM_BAD_INPUT );
        args = ( everest_aes_gcm_args * )mbedtls_calloc( 1, sizeof( everest_aes_gcm_args ) );
        mbedtls_everest_aes_gcm_args_init( args, 11 );
        aes128_key_expansion( ( everest_byte * )key, args->vale_args.expanded_key_ptr );
        break;
    case MBEDTLS_CIPHER_AES_256_GCM:
        if( keybits != 256 )
            return ( MBEDTLS_ERR_GCM_BAD_INPUT );
        args = ( everest_aes_gcm_args * )mbedtls_calloc( 1, sizeof( everest_aes_gcm_args ) );
        mbedtls_everest_aes_gcm_args_init( args, 15 );
        aes256_key_expansion( ( everest_byte * )key, args->vale_args.expanded_key_ptr );
        break;
    default:
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    ctx->cipher_ctx.cipher_ctx = args;

    return( 0 );
}

int mbedtls_everest_aes_gcm_free( mbedtls_gcm_context *ctx )
{
    if( ctx->cipher_ctx.cipher_info != NULL &&
        ctx->cipher_ctx.cipher_ctx != NULL &&
        ( ctx->cipher_ctx.cipher_info->type == MBEDTLS_CIPHER_AES_128_GCM ||
          ctx->cipher_ctx.cipher_info->type == MBEDTLS_CIPHER_AES_256_GCM ) )
    {
        everest_aes_gcm_args * args = ( everest_aes_gcm_args * )ctx->cipher_ctx.cipher_ctx;
        mbedtls_everest_aes_gcm_wipe_key( ctx );
        if( args->auth_ptr_size != 0 ) mbedtls_free( args->vale_args.auth_ptr );
        if( args->out_ptr_size!= 0 ) mbedtls_free( args->vale_args.out_ptr );
        if( args->plain_ptr_size != 0 ) mbedtls_free( args->vale_args.plain_ptr );
        if( args->tag_ptr_size != 0 ) mbedtls_free( args->vale_args.tag_ptr );
        mbedtls_platform_zeroize( ctx->cipher_ctx.cipher_ctx, sizeof( everest_aes_gcm_args ) );
        mbedtls_free( ctx->cipher_ctx.cipher_ctx );
        ctx->cipher_ctx.cipher_ctx = NULL;
    }

    return( 0 );
}

void mbedtls_everest_prepare_aes_gcm_buffer(
    unsigned char *inbuf, size_t inbuf_size,
    unsigned char **argbuf, size_t *argbuf_size,
    int needs_copy )
{
    size_t rem;

    if( inbuf_size > 0 )
    {
        if( *argbuf_size == 0 )
        {
            rem = inbuf_size % 16;
            if( rem == 0 )
                *argbuf = inbuf;
            else
            {
                size_t esz = ( inbuf_size + 16 - rem );
                *argbuf = mbedtls_calloc( 1, esz );
                *argbuf_size = esz;
                if( needs_copy ) memcpy( *argbuf, inbuf, inbuf_size );
            }
        }
        else
        {
            if( inbuf_size > *argbuf_size )
            {
                size_t esz = ( inbuf_size + 16 - ( inbuf_size % 16 ) );
                mbedtls_free( *argbuf );
                *argbuf = mbedtls_calloc( 1, esz );
                *argbuf_size = esz;
            }
            if( needs_copy ) memcpy( *argbuf, inbuf, inbuf_size );
        }
    }
    else
        *argbuf_size = 0;
}

void mbedtls_everest_prepare_aes_gcm_buffers(
    everest_aes_gcm_args * args,
    size_t length,
    unsigned char *iv, size_t iv_len,
    unsigned char *add, size_t add_len,
    unsigned char *input,
    unsigned char *output,
    size_t tag_len, unsigned char *tag )
{
    mbedtls_everest_prepare_aes_gcm_buffer( input, length, &args->vale_args.plain_ptr, &args->plain_ptr_size, 1 );
    mbedtls_everest_prepare_aes_gcm_buffer( add, add_len, &args->vale_args.auth_ptr, &args->auth_ptr_size, 1 );
    args->vale_args.iv_ptr = args->iv_buf;
    mbedtls_everest_prepare_aes_gcm_buffer( output, length, &args->vale_args.out_ptr, &args->out_ptr_size, 0 );
    mbedtls_everest_prepare_aes_gcm_buffer( tag, tag_len, &args->vale_args.tag_ptr, &args->tag_ptr_size, 0 );

    memcpy( args->iv_buf, iv, iv_len );
    if( iv_len < 16 ) memset( args->iv_buf + iv_len, 0, 16 - iv_len );

    args->vale_args.plain_num_bytes = length;
    args->vale_args.auth_num_bytes = add_len;
}

#endif /* MBEDTLS_ECDH_VARIANT_EVEREST_AES_GCM */

#endif /* MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED */