/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef LWCRYPTO_ASCON_HASH_H
#define LWCRYPTO_ASCON_HASH_H

/**
 * \file ascon-hash.h
 * \brief ASCON-HASH and ASCON-HASHA hash algorithms.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#include "ascon-xof.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State information for ASCON-HASH and ASCON-HASHA incremental modes.
 */
typedef ascon_xof_state_t ascon_hash_state_t;

/**
 * \brief Hashes a block of input data with ASCON-HASH.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa ascon_hash_init(), ascon_hash_absorb(), ascon_hash_squeeze()
 */
int ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_hash_update(), ascon_hash_finalize(), ascon_hash()
 */
void ascon_hash_init(ascon_hash_state_t *state);

/**
 * \brief Updates an ASCON-HASH state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hash_init(), ascon_hash_finalize()
 */
void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ascon_hash_init(), ascon_hash_update()
 */
void ascon_hash_finalize(ascon_hash_state_t *state, unsigned char *out);

/**
 * \brief Hashes a block of input data with ASCON-HASHA.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa ascon_hasha_init(), ascon_hasha_absorb(), ascon_hasha_squeeze()
 */
int ascon_hasha(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an ASCON-HASHA hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_hasha_update(), ascon_hasha_finalize(), ascon_hasha()
 */
void ascon_hasha_init(ascon_hash_state_t *state);

/**
 * \brief Updates an ASCON-HASHA state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hasha_init(), ascon_hasha_finalize()
 */
void ascon_hasha_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from an ASCON-HASHA hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ascon_hasha_init(), ascon_hasha_update()
 */
void ascon_hasha_finalize(ascon_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
