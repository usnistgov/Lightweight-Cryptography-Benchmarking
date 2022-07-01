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

#include "ascon-xof.h"
#include "internal-ascon.h"
#include <string.h>

#if ASCON_SLICED
#define ascon_xof_permute() \
    ascon_permute_sliced((ascon_state_t *)(state->s.state), 0)
#define ascon_xofa_permute() \
    ascon_permute_sliced((ascon_state_t *)(state->s.state), 4)
#else
#define ascon_xof_permute() \
    ascon_permute((ascon_state_t *)(state->s.state), 0)
#define ascon_xofa_permute() \
    ascon_permute((ascon_state_t *)(state->s.state), 4)
#endif

int ascon_xof
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_xof_init(&state);
    ascon_xof_absorb(&state, in, inlen);
    ascon_xof_squeeze(&state, out, 32);
    return 0;
}

void ascon_xof_init(ascon_xof_state_t *state)
{
    /* IV for ASCON-XOF after processing it with the permutation */
    static unsigned char const xof_iv[40] = {
        0xb5, 0x7e, 0x27, 0x3b, 0x81, 0x4c, 0xd4, 0x16,
        0x2b, 0x51, 0x04, 0x25, 0x62, 0xae, 0x24, 0x20,
        0x66, 0xa3, 0xa7, 0x76, 0x8d, 0xdf, 0x22, 0x18,
        0x5a, 0xad, 0x0a, 0x7a, 0x81, 0x53, 0x65, 0x0c,
        0x4f, 0x3e, 0x0e, 0x32, 0x53, 0x94, 0x93, 0xb6
    };
    memcpy(state->s.state, xof_iv, sizeof(xof_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

void ascon_xof_init_fixed(ascon_xof_state_t *state, size_t outlen)
{
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    if (outlen == 0U) {
        /* Output length of zero is equivalent to regular XOF */
        ascon_xof_init(state);
    } else if (outlen == 32U) {
        /* Output length of 32 is equivalent to ASCON-HASH */
        static unsigned char const hash_iv[40] = {
            /* IV for ASCON-HASH after processing it with the permutation */
            0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
            0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
            0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
            0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
            0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
        };
        memcpy(state->s.state, hash_iv, sizeof(hash_iv));
        state->s.count = 0;
        state->s.mode = 0;
    } else {
        /* For all other lengths, we need to run the permutation
         * to get the initial block for the XOF process */
        be_store_word64(state->s.state, 0x00400c0000000000ULL | (outlen * 8UL));
        memset(state->s.state + 8, 0, sizeof(state->s.state) - 8);
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xof_permute();
#endif
        state->s.count = 0;
        state->s.mode = 0;
    }
}

void ascon_xof_absorb
    (ascon_xof_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->s.mode) {
        state->s.mode = 0;
        state->s.count = 0;
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xof_permute();
#endif
    }

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = ASCON_XOF_RATE - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            lw_xor_block(state->s.state + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        lw_xor_block(state->s.state + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
#endif
        ascon_xof_permute();
    } else {
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
#endif
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
#if ASCON_SLICED
    while (inlen >= ASCON_XOF_RATE) {
        ascon_absorb_sliced((ascon_state_t *)(state->s.state), in, 0);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_xof_permute();
    }
    ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
    while (inlen >= ASCON_XOF_RATE) {
        lw_xor_block(state->s.state, in, ASCON_XOF_RATE);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_xof_permute();
    }
#endif

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    lw_xor_block(state->s.state, in, temp);
    state->s.count = temp;
}

void ascon_xof_squeeze
    (ascon_xof_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->s.mode) {
        state->s.state[state->s.count] ^= 0x80;
        state->s.count = 0;
        state->s.mode = 1;
    }

    /* Handle left-over partial blocks from last time */
    if (state->s.count) {
        temp = ASCON_XOF_RATE - state->s.count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            memcpy(out, state->s.state + state->s.count, temp);
            state->s.count += temp;
            return;
        }
        memcpy(out, state->s.state + state->s.count, temp);
        out += temp;
        outlen -= temp;
        state->s.count = 0;
    }

    /* Handle full blocks */
#if ASCON_SLICED
    ascon_to_sliced((ascon_state_t *)(state->s.state));
    while (outlen >= ASCON_XOF_RATE) {
        ascon_xof_permute();
        ascon_squeeze_sliced((ascon_state_t *)(state->s.state), out, 0);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }
#else
    while (outlen >= ASCON_XOF_RATE) {
        ascon_xof_permute();
        memcpy(out, state->s.state, ASCON_XOF_RATE);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }
#endif

    /* Handle the left-over block */
#if ASCON_SLICED
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
        memcpy(out, state->s.state, temp);
        state->s.count = temp;
    } else {
        ascon_from_sliced((ascon_state_t *)(state->s.state));
    }
#else
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_xof_permute();
        memcpy(out, state->s.state, temp);
        state->s.count = temp;
    }
#endif
}

void ascon_xof_pad(ascon_xof_state_t *state)
{
    if (state->s.mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        ascon_xof_absorb(state, 0, 0);
    } else if (state->s.count != 0) {
        /* Not currently aligned, so invoke the permutation */
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xof_permute();
#endif
        state->s.count = 0;
    }
}

int ascon_xofa
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_xofa_init(&state);
    ascon_xofa_absorb(&state, in, inlen);
    ascon_xofa_squeeze(&state, out, 32);
    return 0;
}

void ascon_xofa_init(ascon_xof_state_t *state)
{
    /* IV for ASCON-XOFA after processing it with the permutation */
    static unsigned char const xof_iv[40] = {
        0x44, 0x90, 0x65, 0x68, 0xb7, 0x7b, 0x98, 0x32,
        0xcd, 0x8d, 0x6c, 0xae, 0x53, 0x45, 0x55, 0x32,
        0xf7, 0xb5, 0x21, 0x27, 0x56, 0x42, 0x21, 0x29,
        0x24, 0x68, 0x85, 0xe1, 0xde, 0x0d, 0x22, 0x5b,
        0xa8, 0xcb, 0x5c, 0xe3, 0x34, 0x49, 0x97, 0x3f
    };
    memcpy(state->s.state, xof_iv, sizeof(xof_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

void ascon_xofa_init_fixed(ascon_xof_state_t *state, size_t outlen)
{
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    if (outlen == 0U) {
        /* Output length of zero is equivalent to regular XOF */
        ascon_xofa_init(state);
    } else if (outlen == 32U) {
        /* Output length of 32 is equivalent to ASCON-HASH */
        static unsigned char const hash_iv[40] = {
            /* IV for ASCON-HASHA after processing it with the permutation */
            0x01, 0x47, 0x01, 0x94, 0xfc, 0x65, 0x28, 0xa6,
            0x73, 0x8e, 0xc3, 0x8a, 0xc0, 0xad, 0xff, 0xa7,
            0x2e, 0xc8, 0xe3, 0x29, 0x6c, 0x76, 0x38, 0x4c,
            0xd6, 0xf6, 0xa5, 0x4d, 0x7f, 0x52, 0x37, 0x7d,
            0xa1, 0x3c, 0x42, 0xa2, 0x23, 0xbe, 0x8d, 0x87
        };
        memcpy(state->s.state, hash_iv, sizeof(hash_iv));
        state->s.count = 0;
        state->s.mode = 0;
    } else {
        /* For all other lengths, we need to run the permutation
         * to get the initial block for the XOF process */
        be_store_word64(state->s.state, 0x00400c0400000000ULL | (outlen * 8UL));
        memset(state->s.state + 8, 0, sizeof(state->s.state) - 8);
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xof_permute();
#endif
        state->s.count = 0;
        state->s.mode = 0;
    }
}

void ascon_xofa_absorb
    (ascon_xof_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->s.mode) {
        state->s.mode = 0;
        state->s.count = 0;
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xof_permute();
#endif
    }

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = ASCON_XOF_RATE - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            lw_xor_block(state->s.state + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        lw_xor_block(state->s.state + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
#endif
        ascon_xofa_permute();
    } else {
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
#endif
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
#if ASCON_SLICED
    while (inlen >= ASCON_XOF_RATE) {
        ascon_absorb_sliced((ascon_state_t *)(state->s.state), in, 0);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_xofa_permute();
    }
    ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
    while (inlen >= ASCON_XOF_RATE) {
        lw_xor_block(state->s.state, in, ASCON_XOF_RATE);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_xofa_permute();
    }
#endif

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    lw_xor_block(state->s.state, in, temp);
    state->s.count = temp;
}

void ascon_xofa_squeeze
    (ascon_xof_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->s.mode) {
        state->s.state[state->s.count] ^= 0x80;
        state->s.count = 0;
        state->s.mode = 1;
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xof_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xof_permute();
#endif
    }

    /* Handle left-over partial blocks from last time */
    if (state->s.count) {
        temp = ASCON_XOF_RATE - state->s.count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            memcpy(out, state->s.state + state->s.count, temp);
            state->s.count += temp;
            return;
        }
        memcpy(out, state->s.state + state->s.count, temp);
        out += temp;
        outlen -= temp;
        state->s.count = 0;
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xofa_permute();
#else
        ascon_xofa_permute();
#endif
    } else {
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
#endif
    }

    /* Handle full blocks */
#if ASCON_SLICED
    while (outlen >= ASCON_XOF_RATE) {
        ascon_squeeze_sliced((ascon_state_t *)(state->s.state), out, 0);
        ascon_xofa_permute();
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }
#else
    while (outlen >= ASCON_XOF_RATE) {
        memcpy(out, state->s.state, ASCON_XOF_RATE);
        ascon_xofa_permute();
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }
#endif

    /* Handle the left-over block */
#if ASCON_SLICED
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_from_sliced((ascon_state_t *)(state->s.state));
        memcpy(out, state->s.state, temp);
        state->s.count = temp;
    } else {
        ascon_from_sliced((ascon_state_t *)(state->s.state));
    }
#else
    if (outlen > 0) {
        temp = (unsigned)outlen;
        memcpy(out, state->s.state, temp);
        state->s.count = temp;
    }
#endif
}

void ascon_xofa_pad(ascon_xof_state_t *state)
{
    if (state->s.mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        ascon_xofa_absorb(state, 0, 0);
    } else if (state->s.count != 0) {
        /* Not currently aligned, so invoke the permutation */
#if ASCON_SLICED
        ascon_to_sliced((ascon_state_t *)(state->s.state));
        ascon_xofa_permute();
        ascon_from_sliced((ascon_state_t *)(state->s.state));
#else
        ascon_xofa_permute();
#endif
        state->s.count = 0;
    }
}
