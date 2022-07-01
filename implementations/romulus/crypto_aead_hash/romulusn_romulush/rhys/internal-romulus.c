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

#include "internal-romulus.h"
#include <string.h>

void romulus_update_counter(uint8_t TK1[16])
{
    uint8_t mask = (uint8_t)(((int8_t)(TK1[6])) >> 7);
    TK1[6] = (TK1[6] << 1) | (TK1[5] >> 7);
    TK1[5] = (TK1[5] << 1) | (TK1[4] >> 7);
    TK1[4] = (TK1[4] << 1) | (TK1[3] >> 7);
    TK1[3] = (TK1[3] << 1) | (TK1[2] >> 7);
    TK1[2] = (TK1[2] << 1) | (TK1[1] >> 7);
    TK1[1] = (TK1[1] << 1) | (TK1[0] >> 7);
    TK1[0] = (TK1[0] << 1) ^ (mask & 0x95);
}

void romulus_schedule_init
    (skinny_plus_key_schedule_t *ks,
     const unsigned char *k, const unsigned char *npub)
{
    ks->TK1[0] = 0x01; /* Initialize the 56-bit LFSR counter to 1 */
    memset(ks->TK1 + 1, 0, 15);
    skinny_plus_init_without_tk1(ks, npub, k);
}

void romulus_rho
    (unsigned char S[16], unsigned char C[16], const unsigned char M[16])
{
    unsigned index;
    for (index = 0; index < 16; ++index) {
        unsigned char s = S[index];
        unsigned char m = M[index];
        S[index] ^= m;
        C[index] = m ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
    }
}

void romulus_rho_inverse
    (unsigned char S[16], unsigned char M[16], const unsigned char C[16])
{
    unsigned index;
    for (index = 0; index < 16; ++index) {
        unsigned char s = S[index];
        unsigned char m = C[index] ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
        S[index] ^= m;
        M[index] = m;
    }
}

void romulus_rho_short
    (unsigned char S[16], unsigned char C[16],
     const unsigned char M[16], unsigned len)
{
    unsigned index;
    for (index = 0; index < len; ++index) {
        unsigned char s = S[index];
        unsigned char m = M[index];
        S[index] ^= m;
        C[index] = m ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
    }
    S[15] ^= (unsigned char)len; /* Padding */
}

void romulus_rho_inverse_short
    (unsigned char S[16], unsigned char M[16],
     const unsigned char C[16], unsigned len)
{
    unsigned index;
    for (index = 0; index < len; ++index) {
        unsigned char s = S[index];
        unsigned char m = C[index] ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
        S[index] ^= m;
        M[index] = m;
    }
    S[15] ^= (unsigned char)len; /* Padding */
}

void romulus_generate_tag(unsigned char T[16], const unsigned char S[16])
{
    unsigned index;
    for (index = 0; index < 16; ++index) {
        unsigned char s = S[index];
        T[index] = (s >> 1) ^ (s & 0x80) ^ (s << 7);
    }
}
