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

#ifndef LWCRYPTO_XOODYAK_HASH_H
#define LWCRYPTO_XOODYAK_HASH_H

#include <stddef.h>

/**
 * \file xoodyak-hash.h
 * \brief Xoodyak-Hash hash algorithm.
 *
 * Xoodyak-Hash is based around the 384-bit Xoodoo permutation and has a
 * 256-bit output.  Xoodyak-Hash can also be used as an extensible
 * output function (XOF).
 *
 * References: https://keccak.team/xoodyak.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash output for Xoodyak.
 */
#define XOODYAK_HASH_SIZE 32

/**
 * \brief Rate for absorbing and squeezing in Xoodyak's hashing mode.
 */
#define XOODYAK_HASH_RATE 16

/**
 * \brief State information for Xoodyak incremental hashing modes.
 */
typedef union
{
    struct {
        unsigned char state[48]; /**< Current hash state */
        unsigned char count;     /**< Number of bytes in the current block */
        unsigned char mode;      /**< Hash mode: absorb or squeeze */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} xoodyak_hash_state_t;

/**
 * \brief Hashes a block of input data with Xoodyak to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * XOODYAK_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int xoodyak_hash
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for a Xoodyak hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa xoodyak_hash_absorb(), xoodyak_hash_squeeze(), xoodyak_hash()
 */
void xoodyak_hash_init(xoodyak_hash_state_t *state);

/**
 * \brief Aborbs more input data into a Xoodyak hashing state.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa xoodyak_hash_init(), xoodyak_hash_squeeze()
 */
void xoodyak_hash_absorb
    (xoodyak_hash_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output data from a Xoodyak hashing state.
 *
 * \param state Hash state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa xoodyak_hash_init(), xoodyak_hash_absorb()
 */
void xoodyak_hash_squeeze
    (xoodyak_hash_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Returns the final hash value from a Xoodyak hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the hash value.
 *
 * \note This is a wrapper around xoodyak_hash_squeeze() for a fixed length
 * of XOODYAK_HASH_SIZE bytes.
 *
 * \sa xoodyak_hash_init(), xoodyak_hash_absorb()
 */
void xoodyak_hash_finalize
    (xoodyak_hash_state_t *state, unsigned char *out);

/**
 * \brief Absorbs enough zeroes into a Xoodyak hashing state to pad the
 * input to the next multiple of the block rate.
 *
 * \param state The state to pad.  Does nothing if the \a state is
 * already aligned on a multiple of the block rate.
 *
 * This function can avoid unnecessary XOR-with-zero operations
 * to save some time when padding is required.
 */
void xoodyak_hash_pad(xoodyak_hash_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
