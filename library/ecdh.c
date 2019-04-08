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

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#if !defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key (restartable version)
 *
 * Note: this internal function relies on its caller preserving the value of
 * the output parameter 'd' across continuation calls. This would not be
 * acceptable for a public function but is OK here as we control call sites.
 */
static int ecdh_gen_public_restartable( mbedtls_ecp_group *grp,
                    mbedtls_mpi *d, mbedtls_ecp_point *Q,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret;

    /* If multiplication is in progress, we already generated a privkey */
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( rs_ctx == NULL || rs_ctx->rsm == NULL )
#endif
        MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, d, f_rng, p_rng ) );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul_restartable( grp, Q, d, &grp->G,
                                                  f_rng, p_rng, rs_ctx ) );

cleanup:
    return( ret );
}

/*
 * Generate public key
 */
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    return( ecdh_gen_public_restartable( grp, d, Q, f_rng, p_rng, NULL ) );
}
#endif /* !MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable( mbedtls_ecp_group *grp,
                         mbedtls_mpi *z,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret;
    mbedtls_ecp_point P;

    mbedtls_ecp_point_init( &P );

    MBEDTLS_MPI_CHK( mbedtls_ecp_mul_restartable( grp, &P, d, Q,
                                                  f_rng, p_rng, rs_ctx ) );

    if( mbedtls_ecp_is_zero( &P ) )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( z, &P.X ) );

cleanup:
    mbedtls_ecp_point_free( &P );

    return( ret );
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    return( ecdh_compute_shared_restartable( grp, z, Q, d,
                                             f_rng, p_rng, NULL ) );
}
#endif /* !MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

static void ecdh_init_internal( mbedtls_ecdh_context_mbed *ctx )
{
    mbedtls_ecp_group_init( &ctx->grp );
    mbedtls_mpi_init( &ctx->d  );
    mbedtls_ecp_point_init( &ctx->Q   );
    mbedtls_ecp_point_init( &ctx->Qp  );
    mbedtls_mpi_init( &ctx->z  );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_init( &ctx->rs );
#endif
}

/*
 * Initialize context
 */
void mbedtls_ecdh_init( mbedtls_ecdh_context *ctx )
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    ecdh_init_internal( ctx );
    mbedtls_ecp_point_init( &ctx->Vi  );
    mbedtls_ecp_point_init( &ctx->Vf  );
    mbedtls_mpi_init( &ctx->_d );
#else
    memset( ctx, 0, sizeof( mbedtls_ecdh_context ) );

    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
#endif
    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    ctx->restart_enabled = 0;
#endif
}

static int ecdh_setup_internal( mbedtls_ecdh_context_mbed *ctx,
                                mbedtls_ecp_group_id grp_id )
{
    int ret;

    ret = mbedtls_ecp_group_load( &ctx->grp, grp_id );
    if( ret != 0 )
    {
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}

static int mbedtls_ecdh_setup_internal( mbedtls_ecdh_context *ctx,
                                        mbedtls_ecp_group_id grp )
{
    int ret;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;

    ctx->var = MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
    ctx->grp = grp;
#endif

    ret = mbedtls_ecp_group_load( &real_ctx->grp, grp );
    if( ret != 0 )
    {
        mbedtls_ecdh_free( ctx );
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}

/*
 * Setup context
 */
int mbedtls_ecdh_setup( mbedtls_ecdh_context *ctx, mbedtls_ecp_group_id grp )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_setup_internal( ctx, grp ) );
#else
    switch( grp )
    {
        default:
            return( mbedtls_ecdh_setup_internal( ctx, grp ) );
    }
#endif
}

static void mbedtls_ecdh_free_internal( mbedtls_ecdh_context *ctx )
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;

    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp = MBEDTLS_ECP_DP_NONE;
#endif

    mbedtls_ecp_group_free( &real_ctx->grp );
    mbedtls_ecp_point_free( &real_ctx->Q   );
    mbedtls_ecp_point_free( &real_ctx->Qp  );
    mbedtls_mpi_free( &real_ctx->d  );
    mbedtls_mpi_free( &real_ctx->z  );
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Free context
 */
void mbedtls_ecdh_free( mbedtls_ecdh_context *ctx )
{
    if( ctx == NULL )
        return;

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_free_internal( ctx );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            mbedtls_ecdh_free_internal( ctx );
            break;
        default:
            break;
    }
#endif
}

static int mbedtls_ecdh_make_params_internal( mbedtls_ecdh_context *ctx,
                                              size_t *olen,
                                              unsigned char *buf, size_t blen,
                                              int (*f_rng)(void *,
                                                           unsigned char *,
                                                           size_t),
                                              void *p_rng )
{
    int ret;
    size_t grp_len, pt_len;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;
#endif

    if( real_ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecdh_gen_public( &real_ctx->grp, &real_ctx->d,
                                         &real_ctx->Q, f_rng, p_rng ) ) != 0 )
        return( ret );
#else
    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
                                         f_rng, p_rng ) ) != 0 )
        return( ret );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if( ( ret = mbedtls_ecp_tls_write_group( &real_ctx->grp, &grp_len, buf,
                                             blen ) ) != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( ( ret = mbedtls_ecp_tls_write_point( &real_ctx->grp, &real_ctx->Q,
                                             ctx->point_format, &pt_len, buf,
                                             blen ) ) != 0 )
        return( ret );

    *olen = grp_len + pt_len;
    return( 0 );
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int mbedtls_ecdh_make_params( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_make_params_internal( ctx, olen, buf, blen, f_rng,
                                               p_rng ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_make_params_internal( ctx, olen, buf, blen,
                                                       f_rng, p_rng ) );
        default:
            return MBEDTLS_ERR_ECDH_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_read_params_internal( mbedtls_ecdh_context *ctx,
                                              const unsigned char **buf,
                                              const unsigned char *end )
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;
#endif

    return( mbedtls_ecp_tls_read_point( &real_ctx->grp, &real_ctx->Qp, buf,
                                        end - *buf ) );
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int mbedtls_ecdh_read_params( mbedtls_ecdh_context *ctx,
                              const unsigned char **buf,
                              const unsigned char *end )
{
    int ret;
    mbedtls_ecp_group_id grp_id;

    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_tls_read_group_id( &grp_id, buf, end - *buf ) )
            != 0 )
        return( ret );

    if( ( ret = mbedtls_ecdh_setup( ctx, grp_id ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_read_params_internal( ctx, buf, end ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_read_params_internal( ctx, buf, end ) );
        default:
            return MBEDTLS_ERR_ECDH_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_get_params_internal( mbedtls_ecdh_context *ctx,
                                             const mbedtls_ecp_keypair *key,
                                             mbedtls_ecdh_side side )
{
    int ret;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;
#endif

    /* If it's not our key, just import the public part as Qp */
    if( side == MBEDTLS_ECDH_THEIRS )
        return( mbedtls_ecp_copy( &real_ctx->Qp, &key->Q ) );

    /* Our key: import public (as Q) and private parts */
    if( side != MBEDTLS_ECDH_OURS )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_copy( &real_ctx->Q, &key->Q ) ) != 0 ||
        ( ret = mbedtls_mpi_copy( &real_ctx->d, &key->d ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Get parameters from a keypair
 */
int mbedtls_ecdh_get_params( mbedtls_ecdh_context *ctx,
                             const mbedtls_ecp_keypair *key,
                             mbedtls_ecdh_side side )
{
    int ret;

    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecdh_setup( ctx, key->grp.id ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_get_params_internal( ctx, key, side ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_get_params_internal( ctx, key, side ) );
        default:
            return MBEDTLS_ERR_ECDH_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_make_public_internal( mbedtls_ecdh_context *ctx,
                                              size_t *olen, unsigned char *buf,
                                              size_t blen,
                                              int (*f_rng)(void *,
                                                           unsigned char *,
                                                           size_t),
                                              void *p_rng )
{
    int ret;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;
#endif

    if( real_ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecdh_gen_public( &real_ctx->grp, &real_ctx->d,
                                         &real_ctx->Q, f_rng, p_rng ) ) != 0 )
        return( ret );
#else
    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
                                         f_rng, p_rng ) ) != 0 )
        return( ret );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    return mbedtls_ecp_tls_write_point( &real_ctx->grp, &real_ctx->Q,
                                        ctx->point_format, olen, buf, blen );
}

/*
 * Setup and export the client public value
 */
int mbedtls_ecdh_make_public( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_make_public_internal( ctx, olen, buf, blen, f_rng,
                                               p_rng ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_make_public_internal( ctx, olen, buf, blen,
                                                       f_rng, p_rng ) );
        default:
            return MBEDTLS_ERR_ECDH_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_read_public_internal( mbedtls_ecdh_context *ctx,
                                              const unsigned char *buf,
                                              size_t blen )
{
    int ret;
    const unsigned char *p = buf;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;
#endif

    if( ( ret = mbedtls_ecp_tls_read_point( &real_ctx->grp, &real_ctx->Qp, &p,
                                            blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Parse and import the client's public value
 */
int mbedtls_ecdh_read_public( mbedtls_ecdh_context *ctx,
                              const unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_read_public_internal( ctx, buf, blen ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_read_public_internal( ctx, buf, blen ) );
        default:
            return MBEDTLS_ERR_ECDH_BAD_INPUT_DATA;
    }
#endif
}

static int mbedtls_ecdh_calc_secret_internal( mbedtls_ecdh_context *ctx,
                                              size_t *olen, unsigned char *buf,
                                              size_t blen,
                                              int (*f_rng)(void *,
                                                           unsigned char *,
                                                           size_t),
                                              void *p_rng )
{
    int ret;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecdh_context *real_ctx = ctx;
#else
    mbedtls_ecdh_context_mbed *real_ctx = &ctx->ctx.mbed_ecdh;
#endif

    if( ( ret = mbedtls_ecdh_compute_shared( &real_ctx->grp, &real_ctx->z,
                                             &real_ctx->Qp, &real_ctx->d, f_rng,
                                             p_rng ) ) != 0 )
    {
        return( ret );
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if( mbedtls_mpi_size( &real_ctx->z ) > blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    *olen = real_ctx->grp.pbits / 8 + ( ( real_ctx->grp.pbits % 8 ) != 0 );
    return mbedtls_mpi_write_binary( &real_ctx->z, buf, *olen );
}

/*
 * Derive and export the shared secret
 */
int mbedtls_ecdh_calc_secret( mbedtls_ecdh_context *ctx, size_t *olen,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( mbedtls_ecdh_calc_secret_internal( ctx, olen, buf, blen, f_rng,
                                               p_rng ) );
#else
    switch( ctx->var )
    {
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( mbedtls_ecdh_calc_secret_internal( ctx, olen, buf, blen,
                                                       f_rng, p_rng ) );
        default:
            return MBEDTLS_ERR_ECDH_BAD_INPUT_DATA;
    }
#endif
}

#endif /* MBEDTLS_ECDH_C */
