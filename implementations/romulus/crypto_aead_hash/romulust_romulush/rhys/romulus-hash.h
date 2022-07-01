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

#ifndef LWCRYPTO_ROMULUS_HASH_H
#define LWCRYPTO_ROMULUS_HASH_H

#include <stddef.h>

/**
 * \file romulus-hash.h
 * \brief Romulus-H hash algorithm.
 *
 * Romulus-H is a hash algorithm based on the block cipher SKINNY-128-384+,
 * using the MDPH construction.  The algorithm produces a 256-bit fixed
 * length output.
 *
 * References: https://romulusae.github.io/romulus/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the fixed-length hash value for Romulus-H.
 */
#define ROMULUS_HASH_SIZE 32

/**
 * \brief Number of bytes in a rate block for Romulus-H.
 */
#define ROMULUS_HASH_RATE 32

/**
 * \brief State information for Romulus-H incremental modes.
 */
typedef union
{
    struct {
        unsigned char tk[48];   /**< Current tweakey state for SKINNY */
        unsigned char h[16];    /**< Next state block to be encrypted */
        unsigned char count;    /**< Number of bytes in the current block */
        unsigned char mode;     /**< Hash mode: 0 for update, 1 for final */
    } s;                        /**< State */
    unsigned long long align;   /**< For alignment of this structure */

} romulus_hash_state_t;

/**
 * \brief Hashes a block of input data with Romulus-H.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ROMULUS_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa romulus_hash_init(), romulus_hash_absorb(), romulus_hash_squeeze()
 */
int romulus_hash
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for a Romulus-H hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa romulus_hash_update(), romulus_hash_finalize(), romulus_hash()
 */
void romulus_hash_init(romulus_hash_state_t *state);

/**
 * \brief Updates a Romulus-H hash state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa romulus_hash_init(), romulus_hash_finalize()
 */
void romulus_hash_update
    (romulus_hash_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from a Romulus-H hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Buffer to receive the hash output which must be at least
 * ROMULUS_HASH_SIZE bytes in length.
 *
 * \sa romulus_hash_init(), romulus_hash_update()
 */
void romulus_hash_finalize(romulus_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
