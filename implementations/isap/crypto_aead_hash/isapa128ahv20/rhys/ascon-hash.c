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

#include "ascon-hash.h"
#include <string.h>

int ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_hash_init(&state);
    ascon_xof_absorb(&state, in, inlen);
    ascon_xof_squeeze(&state, out, ASCON_HASH_SIZE);
    return 0;
}

void ascon_hash_init(ascon_hash_state_t *state)
{
    /* IV for ASCON-HASH after processing it with the permutation */
    static unsigned char const hash_iv[40] = {
        0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
        0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
        0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
        0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
        0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
    };
    memcpy(state->s.state, hash_iv, sizeof(hash_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xof_absorb(state, in, inlen);
}

void ascon_hash_finalize(ascon_hash_state_t *state, unsigned char *out)
{
    ascon_xof_squeeze(state, out, ASCON_HASH_SIZE);
}

int ascon_hasha(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_hasha_init(&state);
    ascon_xofa_absorb(&state, in, inlen);
    ascon_xofa_squeeze(&state, out, ASCON_HASH_SIZE);
    return 0;
}

void ascon_hasha_init(ascon_hash_state_t *state)
{
    /* IV for ASCON-HASHA after processing it with the permutation */
    static unsigned char const hash_iv[40] = {
        0x01, 0x47, 0x01, 0x94, 0xfc, 0x65, 0x28, 0xa6,
        0x73, 0x8e, 0xc3, 0x8a, 0xc0, 0xad, 0xff, 0xa7,
        0x2e, 0xc8, 0xe3, 0x29, 0x6c, 0x76, 0x38, 0x4c,
        0xd6, 0xf6, 0xa5, 0x4d, 0x7f, 0x52, 0x37, 0x7d,
        0xa1, 0x3c, 0x42, 0xa2, 0x23, 0xbe, 0x8d, 0x87
    };
    memcpy(state->s.state, hash_iv, sizeof(hash_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

void ascon_hasha_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xofa_absorb(state, in, inlen);
}

void ascon_hasha_finalize(ascon_hash_state_t *state, unsigned char *out)
{
    ascon_xofa_squeeze(state, out, ASCON_HASH_SIZE);
}
