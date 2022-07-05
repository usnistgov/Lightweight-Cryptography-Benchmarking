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

#include "xoodyak-hash.h"
#include "internal-xoodoo.h"
#include <string.h>

/**
 * \brief Hash mode just after initialization while absorbing the
 * first block of input data.
 */
#define XOODYAK_HASH_MODE_INIT_ABSORB 0

/**
 * \brief Hash mode for absorbing subsequent blocks of input data.
 */
#define XOODYAK_HASH_MODE_ABSORB 1

/**
 * \brief Hash mode for squeezing data out of the state.
 */
#define XOODYAK_HASH_MODE_SQUEEZE 2

/**
 * \brief Helper macro to permute the hash state.
 *
 * \param state Points to the xoodyak_hash_state_t object that
 * encompasses the Xoodoo hash state.
 */
#define xoodoo_hash_permute(state) \
    xoodoo_permute((xoodoo_state_t *)((state)->s.state))

int xoodyak_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    xoodyak_hash_state_t state;
    xoodyak_hash_init(&state);
    xoodyak_hash_absorb(&state, in, inlen);
    xoodyak_hash_squeeze(&state, out, XOODYAK_HASH_SIZE);
    return 0;
}

void xoodyak_hash_init(xoodyak_hash_state_t *state)
{
    memset(state, 0, sizeof(xoodyak_hash_state_t));
    state->s.mode = XOODYAK_HASH_MODE_INIT_ABSORB;
}

void xoodyak_hash_absorb
    (xoodyak_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    uint8_t domain;
    unsigned temp;

    /* If we were squeezing, then restart the absorb phase */
    if (state->s.mode == XOODYAK_HASH_MODE_SQUEEZE) {
        xoodoo_hash_permute(state);
        state->s.mode = XOODYAK_HASH_MODE_INIT_ABSORB;
        state->s.count = 0;
    }

    /* The first block needs a different domain separator to the others */
    domain = (state->s.mode == XOODYAK_HASH_MODE_INIT_ABSORB) ? 0x01 : 0x00;

    /* Absorb the input data into the state */
    while (inlen > 0) {
        if (state->s.count >= XOODYAK_HASH_RATE) {
            state->s.state[XOODYAK_HASH_RATE] ^= 0x01; /* Padding */
            state->s.state[sizeof(state->s.state) - 1] ^= domain;
            xoodoo_hash_permute(state);
            state->s.mode = XOODYAK_HASH_MODE_ABSORB;
            state->s.count = 0;
            domain = 0x00;
        }
        temp = XOODYAK_HASH_RATE - state->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        lw_xor_block(state->s.state + state->s.count, in, temp);
        state->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void xoodyak_hash_squeeze
    (xoodyak_hash_state_t *state, unsigned char *out, size_t outlen)
{
    uint8_t domain;
    unsigned temp;

    /* If we were absorbing, then terminate the absorb phase */
    if (state->s.mode != XOODYAK_HASH_MODE_SQUEEZE) {
        domain = (state->s.mode == XOODYAK_HASH_MODE_INIT_ABSORB) ? 0x01 : 0x00;
        state->s.state[state->s.count] ^= 0x01; /* Padding */
        state->s.state[sizeof(state->s.state) - 1] ^= domain;
        xoodoo_hash_permute(state);
        state->s.mode = XOODYAK_HASH_MODE_SQUEEZE;
        state->s.count = 0;
    }

    /* Squeeze data out of the state */
    while (outlen > 0) {
        if (state->s.count >= XOODYAK_HASH_RATE) {
            /* Padding is always at index 0 for squeezing subsequent
             * blocks because the number of bytes we have absorbed
             * since the previous block was squeezed out is zero */
            state->s.state[0] ^= 0x01;
            xoodoo_hash_permute(state);
            state->s.count = 0;
        }
        temp = XOODYAK_HASH_RATE - state->s.count;
        if (temp > outlen)
            temp = (unsigned)outlen;
        memcpy(out, state->s.state + state->s.count, temp);
        state->s.count += temp;
        out += temp;
        outlen -= temp;
    }
}

void xoodyak_hash_finalize
    (xoodyak_hash_state_t *state, unsigned char *out)
{
    xoodyak_hash_squeeze(state, out, XOODYAK_HASH_SIZE);
}

void xoodyak_hash_pad(xoodyak_hash_state_t *state)
{
    if (state->s.mode == XOODYAK_HASH_MODE_SQUEEZE) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        xoodyak_hash_absorb(state, 0, 0);
    } else if (state->s.count != 0 && state->s.count != XOODYAK_HASH_RATE) {
        /* Not currently aligned, so finish off the current block */
        state->s.count = XOODYAK_HASH_RATE;
    }
}
