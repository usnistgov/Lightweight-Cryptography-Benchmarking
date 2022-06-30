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

#include "elephant-jumbo.h"
#include "internal-spongent.h"
#include <string.h>

/**
 * \brief Applies the Jumbo LFSR to the mask.
 *
 * \param out The output mask.
 * \param in The input mask.
 */
static void jumbo_lfsr
    (unsigned char out[SPONGENT176_STATE_SIZE],
     const unsigned char in[SPONGENT176_STATE_SIZE])
{
    unsigned char temp = 
        leftRotate1_8(in[0]) ^ (in[3] << 7) ^ (in[19] >> 7);
    unsigned index;
    for (index = 0; index < SPONGENT176_STATE_SIZE - 1; ++index)
        out[index] = in[index + 1];
    out[SPONGENT176_STATE_SIZE - 1] = temp;
}

/* The actual implementation is in the common "internal-elephant.h" file */
#define ELEPHANT_ALG_NAME jumbo
#define ELEPHANT_STATE_SIZE SPONGENT176_STATE_SIZE
#define ELEPHANT_STATE spongent176_state_t
#define ELEPHANT_KEY_SIZE JUMBO_KEY_SIZE
#define ELEPHANT_NONCE_SIZE JUMBO_NONCE_SIZE
#define ELEPHANT_TAG_SIZE JUMBO_TAG_SIZE
#define ELEPHANT_LFSR jumbo_lfsr
#define ELEPHANT_PERMUTE spongent176_permute
#include "internal-elephant.h"
