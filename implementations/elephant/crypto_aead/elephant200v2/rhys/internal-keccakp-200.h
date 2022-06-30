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

#ifndef LW_INTERNAL_KECCAKP_200_H
#define LW_INTERNAL_KECCAKP_200_H

#include "internal-util.h"

/**
 * \file internal-keccakp-200.h
 * \brief Internal implementation of the Keccak-p[200] permutation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the state for the Keccak-p[200] permutation.
 */
#define KECCAKP_200_STATE_SIZE 25

/**
 * \brief Structure of the internal state of the Keccak-p[200] permutation.
 */
typedef union
{
    uint8_t A[5][5];    /**< Keccak-p[200] state as a 5x5 array of lanes */
    uint8_t B[25];      /**< Keccak-p[200] state as a byte array */

} keccakp_200_state_t;

/**
 * \brief Permutes the Keccak-p[200] state.
 *
 * \param state The Keccak-p[200] state to be permuted.
 */
void keccakp_200_permute(keccakp_200_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
