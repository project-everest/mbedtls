/*
 *  ECDH with curve-optimized implementation multiplexing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdhopt.h"
#include "Hacl_Curve25519.h"

#include <string.h>

/*
 * Initialize context
 */
void mbedtls_ecdhopt_init( mbedtls_ecdhopt_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_ecdhopt_context ) );
}

/*
 * Free context
 */
void mbedtls_ecdhopt_free( mbedtls_ecdhopt_context *ctx )
{
    if( ctx == NULL ) return;
    switch(ctx->curve)
    {
      case MBEDTLS_ECP_DP_CURVE25519:
        break;
      default:
        mbedtls_ecdh_free(&ctx->ctx.ec);
    }
}

/*
 * Setup and write the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
 int mbedtls_ecdhopt_initiator( mbedtls_ecdhopt_context *octx,
                       mbedtls_ecdhopt_curve g, size_t *olen,
                       unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    octx->curve = g;
    if( g == MBEDTLS_ECP_DP_CURVE25519 )
    {
      uint8_t base[32] = {0};
      int ret;
      mbedtls_ecdhopt_x25519_context ctx = octx->ctx.x25519;

      if( ( ret = f_rng( p_rng, ctx.our_secret, 32 ) ) != 0)
        return ret;

      *olen = 36;
      if( blen < *olen )
          return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

      *buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;
      *buf++ = MBEDTLS_ECP_TLS_CURVE25519 >> 8;
      *buf++ = MBEDTLS_ECP_TLS_CURVE25519 & 0xFF;
      *buf++ = 32;

      base[0] = 9; // generator of x25519
      Hacl_Curve25519_crypto_scalarmult( buf, ctx.our_secret, base );

      base[0] = 0;
      if( memcmp( buf, base, 32) == 0 )
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;

      return( 0 );
    }
    else
    {
      octx->ctx.ec.point_format = octx->point_format;
      return mbedtls_ecdh_make_params( &octx->ctx.ec, olen, buf, blen, f_rng, p_rng );
    }
}

int mbedtls_ecdhopt_read_initiator( mbedtls_ecdhopt_context *ctx,
                      const unsigned char **buf, const unsigned char *end )
{
  size_t blen = end - *buf;
  int ret;
  const mbedtls_ecp_curve_info *curve_info;

  if( ( ret = mbedtls_ecp_tls_read_curve_info( &curve_info, buf, blen )) != 0)
    return( ret );

  if( curve_info->grp_id == MBEDTLS_ECP_DP_CURVE25519 )
  {
    ctx->curve = MBEDTLS_ECP_DP_CURVE25519;

    if( end - *buf < 33 )
      return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( *(*buf)++ != 32 ) )
      return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    memcpy( ctx->ctx.x25519.peer_point, *buf, 32 );
    *buf += 32;
    return( 0 );
  }
  else
  {
    ctx->curve = curve_info->grp_id;

    if ( ( ret = mbedtls_ecp_group_load( &ctx->ctx.ec.grp, curve_info->grp_id )) != 0 )
      return( ret );

    if( ( ret = mbedtls_ecp_tls_read_point( &ctx->ctx.ec.grp, &ctx->ctx.ec.Qp, buf, end - *buf ) ) != 0 )
      return( ret );

    return ( 0 );
  }
}

int mbedtls_ecdhopt_use_static_key( mbedtls_ecdhopt_context *ctx,
                      const mbedtls_ecp_keypair *key, mbedtls_ecdhopt_side side )
{
  /* Squelch unused variable warnings. */
  (void)(ctx);
  (void)(key);
  (void)(side);
  return 1;
}

int mbedtls_ecdhopt_responder( mbedtls_ecdhopt_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
  if( ctx == NULL )
      return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

  if(ctx->curve == MBEDTLS_ECP_DP_CURVE25519)
  {
    unsigned char base[32] = {0};
    *olen = 33;
    if( blen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );
    *buf++ = 32;

    base[0] = 9; // generator of x25519
    Hacl_Curve25519_crypto_scalarmult( buf, ctx->ctx.x25519.our_secret, base );

    base[0] = 0;
    if( memcmp( buf, base, 32) == 0 )
      return MBEDTLS_ERR_ECP_RANDOM_FAILED;

    return ( 0 );
  }
  else
  {
    ctx->ctx.ec.point_format = ctx->point_format;
    return mbedtls_ecdh_make_public( &ctx->ctx.ec, olen, buf, blen, f_rng, p_rng );
  }
}

int mbedtls_ecdhopt_read_responder( mbedtls_ecdhopt_context *ctx,
                      const unsigned char *buf, size_t blen )
{
  if( ctx->curve == MBEDTLS_ECP_DP_CURVE25519 )
  {
    if(blen < 33)
      return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );
    if (*buf++ != MBEDTLS_ECP_TLS_NAMED_CURVE)
      return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    if (*buf++ != MBEDTLS_ECP_TLS_CURVE25519 >> 8)
      return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    if (*buf++ != (MBEDTLS_ECP_TLS_CURVE25519 & 0xFF))
      return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    if( ( *buf++ != 32 ) )
      return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    memcpy( ctx->ctx.x25519.peer_point, buf, 32 );
    return ( 0 );
  }
  else
  {
    return mbedtls_ecdh_read_public( &ctx->ctx.ec, buf, blen );
  }
}

int mbedtls_ecdhopt_shared_secret( mbedtls_ecdhopt_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
  if( ctx->curve == MBEDTLS_ECP_DP_CURVE25519 )
  {
    *olen = 32;

    if( blen < *olen )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    Hacl_Curve25519_crypto_scalarmult( buf, ctx->ctx.x25519.our_secret,
      ctx->ctx.x25519.peer_point);

    // Wipe the DH secret and don't let the peer chose a small subgroup point
    memset( ctx->ctx.x25519.our_secret, 0, 32 );
    if( memcmp( buf, ctx->ctx.x25519.our_secret, 32) == 0 )
      return MBEDTLS_ERR_ECP_RANDOM_FAILED;

    return ( 0 );
  }
  else
  {
    return mbedtls_ecdh_calc_secret( &ctx->ctx.ec, olen, buf, blen, f_rng, p_rng );
  }
}

#endif /* MBEDTLS_ECDH_C */
