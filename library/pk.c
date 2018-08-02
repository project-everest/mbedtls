/*
 *  Public Key abstraction layer
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

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_PK_KEX_SUPPORT)
#include "mbedtls/platform.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"
#include "everest/x25519.h"
#endif

#include <limits.h>
#include <stdint.h>
#include "mbedtls/debug.h"

/*
 * Initialise a mbedtls_pk_context
 */
void mbedtls_pk_init( mbedtls_pk_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a mbedtls_pk_context
 */
void mbedtls_pk_free( mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return;

    ctx->pk_info->ctx_free_func( ctx->pk_ctx );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_pk_context ) );
}

/*
 * Get pk_info structure from type
 */
const mbedtls_pk_info_t * mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return( &mbedtls_rsa_info );
#endif
#if defined(MBEDTLS_ECP_C)
        case MBEDTLS_PK_ECKEY:
            return( &mbedtls_eckey_info );
        case MBEDTLS_PK_ECKEY_DH:
            return( &mbedtls_eckeydh_info );
#endif
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_PK_ECDSA:
            return( &mbedtls_ecdsa_info );
#endif
#if defined(MBEDTLS_PK_KEX_SUPPORT)
        case MBEDTLS_PK_KEX:
            return( &mbedtls_kex_info );
#endif
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        default:
            return( NULL );
    }
}

/*
 * Initialise context
 */
int mbedtls_pk_setup( mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info )
{
    if( ctx == NULL || info == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Initialize an RSA-alt context
 */
int mbedtls_pk_setup_rsa_alt( mbedtls_pk_context *ctx, void * key,
                         mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                         mbedtls_pk_rsa_alt_sign_func sign_func,
                         mbedtls_pk_rsa_alt_key_len_func key_len_func )
{
    mbedtls_rsa_alt_context *rsa_alt;
    const mbedtls_pk_info_t *info = &mbedtls_rsa_alt_info;

    if( ctx == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    rsa_alt = (mbedtls_rsa_alt_context *) ctx->pk_ctx;

    rsa_alt->key = key;
    rsa_alt->decrypt_func = decrypt_func;
    rsa_alt->sign_func = sign_func;
    rsa_alt->key_len_func = key_len_func;

    return( 0 );
}
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

/*
 * Tell if a PK can do the operations of the given type
 */
int mbedtls_pk_can_do( const mbedtls_pk_context *ctx, mbedtls_pk_type_t type )
{
    /* null or NONE context can't do anything */
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->can_do( type ) );
}

/*
 * Helper for mbedtls_pk_sign and mbedtls_pk_verify
 */
static inline int pk_hashlen_helper( mbedtls_md_type_t md_alg, size_t *hash_len )
{
    const mbedtls_md_info_t *md_info;

    if( *hash_len != 0 )
        return( 0 );

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( -1 );

    *hash_len = mbedtls_md_get_size( md_info );
    return( 0 );
}

/*
 * Verify a signature
 */
int mbedtls_pk_verify( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->verify_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->verify_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                       sig, sig_len ) );
}

/*
 * Verify a signature with options
 */
int mbedtls_pk_verify_ext( mbedtls_pk_type_t type, const void *options,
                   mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ! mbedtls_pk_can_do( ctx, type ) )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    if( type == MBEDTLS_PK_RSASSA_PSS )
    {
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
        int ret;
        const mbedtls_pk_rsassa_pss_options *pss_opts;

#if SIZE_MAX > UINT_MAX
        if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

        if( options == NULL )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

        pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;

        if( sig_len < mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

        ret = mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_pk_rsa( *ctx ),
                NULL, NULL, MBEDTLS_RSA_PUBLIC,
                md_alg, (unsigned int) hash_len, hash,
                pss_opts->mgf1_hash_id,
                pss_opts->expected_salt_len,
                sig );
        if( ret != 0 )
            return( ret );

        if( sig_len > mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

        return( 0 );
#else
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
#endif /* MBEDTLS_RSA_C && MBEDTLS_PKCS1_V21 */
    }

    /* General case: no options */
    if( options != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( mbedtls_pk_verify( ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

/*
 * Make a signature
 */
int mbedtls_pk_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->sign_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->sign_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                     sig, sig_len, f_rng, p_rng ) );
}

/*
 * Decrypt message
 */
int mbedtls_pk_decrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->decrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->decrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Encrypt message
 */
int mbedtls_pk_encrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->encrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->encrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Check public-private key pair
 */
int mbedtls_pk_check_pair( const mbedtls_pk_context *pub, const mbedtls_pk_context *prv )
{
    if( pub == NULL || pub->pk_info == NULL ||
        prv == NULL || prv->pk_info == NULL ||
        prv->pk_info->check_pair_func == NULL )
    {
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    }

    if( prv->pk_info->type == MBEDTLS_PK_RSA_ALT )
    {
        if( pub->pk_info->type != MBEDTLS_PK_RSA )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }
    else
    {
        if( pub->pk_info != prv->pk_info )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }

    return( prv->pk_info->check_pair_func( pub->pk_ctx, prv->pk_ctx ) );
}

/*
 * Get key size in bits
 */
size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->get_bitlen( ctx->pk_ctx ) );
}

/*
 * Export debug information
 */
int mbedtls_pk_debug( const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->debug_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    ctx->pk_info->debug_func( ctx->pk_ctx, items );
    return( 0 );
}

/*
 * Access the PK type name
 */
const char *mbedtls_pk_get_name( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( "invalid PK" );

    return( ctx->pk_info->name );
}

/*
 * Access the PK type
 */
mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_PK_NONE );

    return( ctx->pk_info->type );
}

#if defined(MBEDTLS_PK_KEX_SUPPORT)
void mbedtls_pk_kex_setup( mbedtls_pk_context *ctx, mbedtls_group_family family, mbedtls_group *group )
{
    mbedtls_kex_context *kex_ctx = mbedtls_pk_key_exchange( ctx );
    if( kex_ctx->group != NULL )
    {
        switch( kex_ctx->group->family ) {
        case MBEDTLS_GROUP_FAMILY_ECDHE: mbedtls_ecdh_free( kex_ctx->ctx.ecdhe ); break;
        case MBEDTLS_GROUP_FAMILY_FFDHE: mbedtls_dhm_free( kex_ctx->ctx.ffdhe ); break;
        case MBEDTLS_GROUP_FAMILY_X25519: mbedtls_x25519_free( kex_ctx->ctx.x25519 ); break;
        case MBEDTLS_GROUP_FAMILY_NONE: break;
        default: break;
        }
    }
    else
    {
        free( kex_ctx->group );
        kex_ctx->group = NULL;
    }

    switch( family )
    {
    case MBEDTLS_GROUP_FAMILY_ECDHE:
        kex_ctx->ctx.ecdhe = ( mbedtls_ecdh_context * )mbedtls_calloc( 1, sizeof( mbedtls_ecdh_context ) );
        mbedtls_ecdh_init( kex_ctx->ctx.ecdhe );
        break;
    case MBEDTLS_GROUP_FAMILY_FFDHE:
        kex_ctx->ctx.ffdhe = ( mbedtls_dhm_context * )mbedtls_calloc( 1, sizeof( mbedtls_dhm_context ) );
        mbedtls_dhm_init( kex_ctx->ctx.ffdhe );
        break;
    case MBEDTLS_GROUP_FAMILY_X25519:
        kex_ctx->ctx.x25519 = ( mbedtls_x25519_context* )mbedtls_calloc( 1, sizeof( mbedtls_x25519_context ) );
    case MBEDTLS_GROUP_FAMILY_NONE:
    default: break;
    }

    if( group == NULL )
    {
        kex_ctx->group = calloc( 1, sizeof( mbedtls_group ) );
        kex_ctx->group->family = family;
    }
    else
        kex_ctx->group = group;

    kex_ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
}

int mbedtls_pk_kex_initiate( mbedtls_pk_context *ctx, mbedtls_group *group,
                unsigned char *buf, size_t blen, size_t *olen,
                int (*f_rng)(void *, unsigned char *, size_t),
                void *p_rng)
{
    int ret = 0;
    mbedtls_kex_context *kex_ctx = mbedtls_pk_key_exchange( ctx );

    if( ctx == NULL || ctx->pk_info == NULL ||
        group == NULL || blen == 0 ||
        group->family == MBEDTLS_GROUP_FAMILY_NONE )
        return(MBEDTLS_ERR_PK_BAD_INPUT_DATA);

    mbedtls_pk_kex_setup( ctx, group->family, group );

    switch( group->family ) {
    case MBEDTLS_GROUP_FAMILY_ECDHE:
    {
        mbedtls_ecdh_context *ecdh_ctx = kex_ctx->ctx.ecdhe;
        ecdh_ctx->point_format = kex_ctx->point_format;
        if( ret == 0 ) ret = mbedtls_ecp_group_load( &ecdh_ctx->grp, kex_ctx->group->data.ecdhe.id );
        if( ret == 0 ) ret = mbedtls_ecdh_make_params( ecdh_ctx, olen, buf, blen, f_rng, p_rng );
        break;
    }
    case MBEDTLS_GROUP_FAMILY_FFDHE:
    {
        mbedtls_dhm_context *dhm_ctx = kex_ctx->ctx.ffdhe;
        if( ret == 0 ) ret = mbedtls_dhm_set_group( dhm_ctx, &group->data.ffdhe.P, &group->data.ffdhe.G );
        if( ret == 0 ) ret = mbedtls_dhm_make_params( dhm_ctx, ( int )mbedtls_mpi_size( &dhm_ctx->P ), buf, olen, f_rng, p_rng );
        break;
        }
    case MBEDTLS_GROUP_FAMILY_X25519:
    {
        mbedtls_x25519_context *x25519_ctx = kex_ctx->ctx.x25519;
        if( ret == 0 ) ret = mbedtls_x25519_make_params( x25519_ctx, olen, buf, blen, f_rng, p_rng );
        break;
    }
    default:
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    }

    return( ret );
}

int mbedtls_pk_kex_read_public( const mbedtls_pk_context *ctx,
                unsigned char *inbuf, size_t inbuflen,
                unsigned char *outbuf, size_t outbuflen,
                size_t *olen,
                int (*f_rng)(void *, unsigned char *, size_t),
                void *p_rng )
{
    int ret = 0;
    mbedtls_kex_context *kex_ctx = mbedtls_pk_key_exchange( ctx );

    if( ctx == NULL || ctx->pk_info == NULL ||
        kex_ctx == NULL || kex_ctx->group == NULL ||
        outbuflen == 0)
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    switch( kex_ctx->group->family )
    {
    case MBEDTLS_GROUP_FAMILY_ECDHE:
    {
        mbedtls_ecdh_context *ecdh_ctx = kex_ctx->ctx.ecdhe;
        if( ret == 0 ) ret = mbedtls_ecdh_read_public( ecdh_ctx, inbuf, inbuflen );
        if( ret == 0 ) ret = mbedtls_ecdh_calc_secret( ecdh_ctx, olen, outbuf, outbuflen, f_rng, p_rng );
        /* TODO: *_calc_secret saves a TLS-specific serialization of the shared
            secret in the context. Replace with proper, TLS-indepdentent datatype
            for key shares? */
        break;
    }
    case MBEDTLS_GROUP_FAMILY_FFDHE:
    {
        mbedtls_dhm_context *dhm_ctx = kex_ctx->ctx.ffdhe;
        if( ret == 0 ) ret = mbedtls_dhm_read_public( dhm_ctx, inbuf, inbuflen );
        if( ret == 0 ) ret = mbedtls_dhm_calc_secret( dhm_ctx, outbuf, outbuflen, olen, f_rng, p_rng );
        break;
    }
    case MBEDTLS_GROUP_FAMILY_X25519:
    {
        mbedtls_x25519_context *x25519_ctx = kex_ctx->ctx.x25519;
        if( ret == 0 ) ret = mbedtls_x25519_read_public( x25519_ctx, inbuf, inbuflen );
        if( ret == 0 ) ret = mbedtls_x25519_calc_secret( x25519_ctx, olen, outbuf, outbuflen, f_rng, p_rng );
        break;
    }
    default:
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return( ret );
}

int mbedtls_pk_kex_respond( mbedtls_pk_context *ctx, mbedtls_group_family family,
                unsigned char *public_buf, size_t public_buflen, size_t *public_olen,
                unsigned char *secret_buf, size_t secret_buflen, size_t *secret_olen,
                int (*f_rng)(void *, unsigned char *, size_t),
                void *p_rng )
{
    int ret = 0;
    mbedtls_kex_context *kex_ctx = mbedtls_pk_key_exchange( ctx );
    unsigned char *p = kex_ctx->read_params_buf;

    if( ctx == NULL || ctx->pk_info == NULL || kex_ctx == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( family == MBEDTLS_GROUP_FAMILY_ECDHE && kex_ctx->read_params_buf )
    {
        const mbedtls_ecp_curve_info *curve_info;
        const unsigned char *cp = p;
        const unsigned char **rp = ( const unsigned char ** )&cp;
        mbedtls_pk_kex_setup( ctx, family, kex_ctx->group );
        if( ( ret = mbedtls_ecp_tls_read_curve_info( &curve_info, rp, kex_ctx->read_params_end - *rp ) ) != 0 )
            return ret;
        if( curve_info->grp_id == MBEDTLS_ECP_DP_CURVE25519 )
        {
            family = MBEDTLS_GROUP_FAMILY_X25519;
            mbedtls_pk_kex_setup( ctx, family, NULL );
        }
    }

    switch( family )
    {
    case MBEDTLS_GROUP_FAMILY_ECDHE: {
        mbedtls_ecdh_context *ecdh_ctx;
        if( kex_ctx->ctx.ecdhe == NULL )
            mbedtls_pk_kex_setup( ctx, family, kex_ctx->group );
        ecdh_ctx = kex_ctx->ctx.ecdhe;
        if( ret == 0 && kex_ctx->read_params_buf != NULL )
        {
            const unsigned char **rp = ( const unsigned char ** )&p;
            ret = mbedtls_ecdh_read_params( ecdh_ctx, rp, kex_ctx->read_params_end );
            kex_ctx->group->family = kex_ctx->group->family;
            kex_ctx->group->data.ecdhe = ecdh_ctx->grp;
        }
        if( ret == 0 && public_buflen > 0 ) ret = mbedtls_ecdh_make_public( ecdh_ctx, public_olen, public_buf, public_buflen, f_rng, p_rng );
        if( ret == 0 && secret_buflen > 0 ) ret = mbedtls_ecdh_calc_secret( ecdh_ctx, secret_olen, secret_buf, secret_buflen, f_rng, p_rng );
        break;
        }
    case MBEDTLS_GROUP_FAMILY_FFDHE: {
        mbedtls_dhm_context *dhm_ctx;
        if( kex_ctx->ctx.ffdhe == NULL )
            mbedtls_pk_kex_setup( ctx, family, kex_ctx->group );
        dhm_ctx = kex_ctx->ctx.ffdhe;
        if( ret == 0 && kex_ctx->read_params_buf != NULL )
        {
            ret = mbedtls_dhm_read_params( dhm_ctx, &p, kex_ctx->read_params_end );
            kex_ctx->group->data.ffdhe.id = MBEDTLS_DHM_OTHER;
            mbedtls_mpi_copy( &kex_ctx->group->data.ffdhe.P, &dhm_ctx->P );
            mbedtls_mpi_copy( &kex_ctx->group->data.ffdhe.G, &dhm_ctx->G );
        }
        if( public_olen ) *public_olen = dhm_ctx->len;
        if( ret == 0 && public_buflen > 0 ) ret = mbedtls_dhm_make_public( dhm_ctx, dhm_ctx->len, public_buf, dhm_ctx->len, f_rng, p_rng );
        if( ret == 0 && secret_buflen > 0) ret = mbedtls_dhm_calc_secret( dhm_ctx, secret_buf, dhm_ctx->len, secret_olen, f_rng, p_rng );
        break;
        }
    case MBEDTLS_GROUP_FAMILY_X25519:
    {
        mbedtls_x25519_context *x25519_ctx;
        const unsigned char *cp = p + 3;
        const unsigned char **rp = ( const unsigned char ** )&cp;
        if( kex_ctx->ctx.x25519 == NULL )
            mbedtls_pk_kex_setup( ctx, family, kex_ctx->group );
        x25519_ctx = kex_ctx->ctx.x25519;
        if( ret == 0 && kex_ctx->read_params_buf != NULL ) ret = mbedtls_x25519_read_params( x25519_ctx, rp, kex_ctx->read_params_end );
        if( ret == 0 && public_buflen > 0) ret = mbedtls_x25519_make_public( x25519_ctx, public_olen, public_buf, public_buflen, f_rng, p_rng );
        if( ret == 0 && secret_buflen > 0 ) ret = mbedtls_x25519_calc_secret( x25519_ctx, secret_olen, secret_buf, secret_buflen, f_rng, p_rng );
        break;
    }
    default:
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if( kex_ctx->read_params_buf )
        free( kex_ctx->read_params_buf );
    kex_ctx->read_params_buf = 0;
    kex_ctx->read_params_end = 0;
    return( ret );
}

int mbedtls_pk_kex_get_params( mbedtls_pk_context *ctx,
                const mbedtls_ecp_keypair *key, mbedtls_ecdh_side side )
{
    mbedtls_kex_context *kex_ctx = mbedtls_pk_key_exchange( ctx );
    int ret = 0;

    if( ctx == NULL || ctx->pk_info == NULL ||
        kex_ctx->group == NULL || kex_ctx->group->family == MBEDTLS_GROUP_FAMILY_NONE )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    switch( kex_ctx->group->family )
    {
    case MBEDTLS_GROUP_FAMILY_ECDHE: {
        ret = mbedtls_ecdh_get_params( kex_ctx->ctx.ecdhe, key, side );
        if( ret == 0 && kex_ctx->ctx.ecdhe->grp.id == MBEDTLS_ECP_DP_CURVE25519 )
        {
            mbedtls_pk_kex_setup( ctx, MBEDTLS_GROUP_FAMILY_X25519, NULL );
            ret = mbedtls_x25519_get_params( kex_ctx->ctx.x25519, key, side );
        }
        break;
    }
    case MBEDTLS_GROUP_FAMILY_X25519: ret = mbedtls_x25519_get_params( kex_ctx->ctx.x25519, key, side ); break;
    case MBEDTLS_GROUP_FAMILY_FFDHE:
    default:
        ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }
    return ret;
}

#endif

#endif /* MBEDTLS_PK_C */
