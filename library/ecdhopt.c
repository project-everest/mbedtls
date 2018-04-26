/*
 *  Elliptic curve Diffie-Hellman
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

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDHOPT_C)

#include "mbedtls/ecdhopt.h"
#include "mbedtls/x25519.h"

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
        mbedtls_ecdh_free(ctx.ctx.ec);
    }
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
 int mbedtls_ecdhopt_initiator( mbedtls_ecdhopt_context *octx,
                       mbedtls_ecdhopt_curve g, size_t *olen,
                       unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );
{
    octx->curve = g;
    if( g == MBEDTLS_ECP_DP_CURVE25519 )
    {
      uint8_t base = {0};
      mbedtls_ecdhopt_x25519_context ctx = octx->ctx.x25519;

      if( ( ret = f_rng( p_rng, ctx.our_secret, 32 ) ) != 0)
        return ret;

      *olen = 36;
      if( blen < *olen )
          return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

      *buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;
      *buf++ = 0;
      *buf++ = 0x1d;
      *buf++ = 32;

      base[0] = 9; // generator of x25519
      Hacl_Curve25519_crypto_scalarmult( buf, ctx.our_secret, base );

      base[0] = 0;
      if( memcmp( buf, base, 32) == 0 )
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;

      return 0;
    }
    else
    {
      mbedtls_ecdh_make_params( octx->ctx.ec, olen, buf, blen, f_rng, p_rng );
    }
}

#endif /* MBEDTLS_ECDH_C */
