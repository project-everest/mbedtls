/**
 * \file eddsa.h
 *
 * \brief This file contains EdDSA definitions and functions.
 *
 */
 /*
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
  *  This file is part of Mbed TLS (https://tls.mbed.org)
  */

#ifndef MBEDTLS_EDDSA_H
#define MBEDTLS_EDDSA_H

#include "ecp.h"
#include "md.h"

#include "everest/x25519.h"

#define MBEDTLS_EDDSA_MAX_LEN 64

typedef struct {
    unsigned char private_[32];
    unsigned char public_[32];
} mbedtls_ed25519_keys;

typedef union {
    mbedtls_ed25519_keys ed25519;
} mbedtls_eddsa_keys;

/**
 * \brief           The EdDSA context structure.
 */
typedef struct {
    mbedtls_ecp_group_id id;
    mbedtls_eddsa_keys keys;
    unsigned char tmp[MBEDTLS_EDDSA_MAX_LEN];
}
mbedtls_eddsa_context;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           This function initializes an EdDSA context.
 *
 * \param ctx       The EdDSA context to initialize.
 */
void mbedtls_eddsa_init( mbedtls_eddsa_context *ctx );

/**
    * \brief           This function frees an EdDSA context.
    *
    * \param ctx       The EdDSA context to free.
    */
void mbedtls_eddsa_free( mbedtls_eddsa_context *ctx );

/**
 * \brief           This function computes an EdDSA signature.
 *
 * \param ctx       The EdDSA context.
 * \param sig       The signature.
 * \param max_sig_len The maximum length of \p sig.
 * \param msg       The message to sign.
 * \param msg_len   The length of \p msg.
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_eddsa_sign( mbedtls_eddsa_context *ctx,
                        unsigned char *sig, size_t max_sig_len,
                        const unsigned char *msg, size_t msg_len,
                        int( *f_rng )( void *, unsigned char *, size_t ), void *p_rng );

/**
 * \brief           This function verifies an EdDSA signature.
 *
 * \param ctx       The EdDSA context.
 * \param msg       The message.
 * \param msg_len   The length of \p msg.
 * \param sig       The signature to verify.
 * \param sig_len   The length of \p sig.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *                  is invalid.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int mbedtls_eddsa_verify( mbedtls_eddsa_context *ctx,
                          const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len );

/**
 * \brief          This function generates an EdDSA keypair on the given curve.
 *
 * \see            ecp.h
 *
 * \param ctx      The EdDSA context to store the keypair in.
 * \param gid      The elliptic curve to use. One of the various
 *                 \c MBEDTLS_ECP_DP_XXX macros depending on configuration.
 * \param f_rng    The RNG function.
 * \param p_rng    The RNG context.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_ECP_XXX code on failure.
 */
int mbedtls_eddsa_genkey( mbedtls_eddsa_context *ctx, mbedtls_ecp_group_id gid,
                          int( *f_rng )( void *, unsigned char *, size_t ), void *p_rng );

/**
 * \brief           This function checks that the keypair objects
 *                  \p pub and \p prv have the same group and the
 *                  same public point, and that the private key in
 *                  \p prv is consistent with the public key.
 *
 * \param pub       The context holding the public key
 * \param prv       The context holding the private key
 *
 * \return          \c 0 on success, meaning that the keys are valid and match.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the keys are invalid or do not match.
 */
int mbedtls_eddsa_check_pub_priv( mbedtls_eddsa_context *pub, mbedtls_eddsa_context *prv );

/**
 * \brief           This function computes the EdDSA signature and writes it
 *                  to a buffer.
 *
 * \param ctx       The EdDSA context.
 * \param msg       The message to sign.
 * \param msg_len   The length of \p msg.
 * \param sig       The buffer that holds the signature.
 * \param max_sig_len The length of the signature buffer \p sig.
 * \param sig_len   The length of the signature written.
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX, \c MBEDTLS_ERR_MPI_XXX or
 *                  \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_eddsa_write_signature( mbedtls_eddsa_context *ctx,
                                   const unsigned char *msg, size_t msg_len,
                                   unsigned char *sig, size_t max_sig_len, size_t *sig_len,
                                   int( *f_rng )( void *, unsigned char *, size_t ),
                                   void *p_rng );

/**
 * \brief           This function reads and verifies an EdDSA signature.
 *
 * \param ctx       The EdDSA context.
 * \param msg       The message.
 * \param msg_len   The size of \p msg.
 * \param sig       The signature to read and verify.
 * \param sig_len   The size of \p sig.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid.
 * \return          #MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig, but its length is less than \p siglen.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_ERR_MPI_XXX
 *                  error code on failure for any other reason.
 */
int mbedtls_eddsa_read_signature( mbedtls_eddsa_context *ctx,
                                  const unsigned char *msg, size_t msg_len,
                                  const unsigned char *sig, size_t sig_len );

/** \brief           This function writes an EdDSA key to a buffer
 *
 * \param key        The key.
 * \param key_size   Size/length of the key.
 * \param buf        The buffer to write to.
 * \param buflen     The size of \p buf.
 * \param olen       The number of characters written to buf.
 *
 * \return           \c 0 on success.
 */
int mbedtls_eddsa_write_string( const unsigned char *key, size_t key_size,
                                char *buf, size_t buflen, size_t *olen );

#ifdef __cplusplus
}
#endif


#endif /* MBEDTLS_EDDSA_H */
