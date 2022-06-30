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

#include "internal-spongent.h"

/* Determine if Spongent-pi should be accelerated with assembly code */
#if defined(__AVR__)
#define SPONGENT_ASM 1
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define SPONGENT_ASM 1
#else
#define SPONGENT_ASM 0
#endif

#if !SPONGENT_ASM

/* Determine whether to use the 64-bit or 32-bit bit-sliced C version */
#if defined(LW_UTIL_CPU_IS_64BIT)
#define SPONGENT_SLICED64 1
#else
#define SPONGENT_SLICED64 0
#endif

/**
 * \brief Applies the Spongent-pi S-box in parallel to four words.
 *
 * \param q0 Bit 0 of the parallel S-box outputs.
 * \param q1 Bit 1 of the parallel S-box outputs.
 * \param q2 Bit 2 of the parallel S-box outputs.
 * \param q3 Bit 3 of the parallel S-box outputs.
 * \param b0 Bit 0 of the parallel S-box inputs.
 * \param b1 Bit 1 of the parallel S-box inputs.
 * \param b2 Bit 2 of the parallel S-box inputs.
 * \param b3 Bit 3 of the parallel S-box inputs.
 *
 * Based on the bit-sliced S-box implementation from here:
 * https://github.com/DadaIsCrazy/usuba/blob/master/data/sboxes/spongent.ua
 *
 * Note that spongent.ua numbers bits from highest to lowest, so b0 is the
 * high bit of each nibble and b3 is the low bit.
 */
#define spongent_sbox(type, q0, q1, q2, q3, b0, b1, b2, b3) \
    do { \
        type u0, u1, u2, u3; \
        (q0) = (b0) ^ (b2); \
        (q1) = (b1) ^ (b2); \
        u0 = (q0) & (q1); \
        (q2) = ~((b0) ^ (b1) ^ (b3) ^ u0); \
        u1 = (q2) & ~(b0); \
        (q3) = (b1) ^ u1; \
        u2 = (q3) & ((q3) ^ (b2) ^ (b3) ^ u0); \
        u3 = ((b2) ^ u0) & ~((b1) ^ u0); \
        (q0) = (b1) ^ (b2) ^ (b3) ^ u2; \
        (q1) = (b0) ^ (b2) ^ (b3) ^ u0 ^ u1; \
        (q2) = (b0) ^ (b1) ^ (b2) ^ u1; \
        (q3) = (b0) ^ (b3) ^ u0 ^ u3; \
    } while (0)

/* Utilities for moving bits around for state permutations.
 * BCP = bit copy, BUP = move bit up, BDN = move bit down */
#define BCP32(x, bit) ((x) & (((uint32_t)1) << (bit)))
#define BUP32(x, from, to) \
    (((x) << ((to) - (from))) & (((uint32_t)1) << (to)))
#define BDN32(x, from, to) \
    (((x) >> ((from) - (to))) & (((uint32_t)1) << (to)))
#define BCP64(x, bit) ((x) & (((uint64_t)1) << (bit)))
#define BUP64(x, from, to) \
    (((x) << ((to) - (from))) & (((uint64_t)1) << (to)))
#define BDN64(x, from, to) \
    (((x) >> ((from) - (to))) & (((uint64_t)1) << (to)))

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/* Rerrange the nibbles so that bits 0..3 are scattered to x0..x3.
 * Note that bit 0 for the S-box is in the high bit of each nibble.
 *
 * P = [24 16 8 0 25 17 9 1 26 18 10 2 27 19 11 3
 *      28 20 12 4 29 21 13 5 30 22 14 6 31 23 15 7]
 *
 * Permutation generated with "https://programming.sirrida.de/calcperm.php".
 */
#define PERM(x) \
    do { \
        bit_permute_step((x), 0x0a0a0a0a, 3); \
        bit_permute_step((x), 0x00cc00cc, 6); \
        bit_permute_step((x), 0x0000f0f0, 12); \
        bit_permute_step((x), 0x000000ff, 24); \
    } while (0)
#define INV_PERM(x) \
    do { \
        bit_permute_step((x), 0x00550055, 9); \
        bit_permute_step((x), 0x00003333, 18); \
        bit_permute_step((x), 0x000f000f, 12); \
        bit_permute_step((x), 0x000000ff, 24); \
    } while (0)

/* Bit-sliced round constants for Spongent-pi[176] */
static unsigned char const RC_176[] = {
    0, 3, 0, 1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 2, 0, 2, 0, 1, 1, 2, 1, 2, 2, 0,
    1, 1, 2, 0, 0, 1, 2, 2, 1, 2, 0, 3, 3, 0, 1, 2, 0, 0, 3, 3, 3, 3, 0, 0,
    0, 3, 3, 1, 2, 3, 3, 0, 1, 3, 1, 0, 0, 2, 3, 2, 1, 1, 0, 3, 3, 0, 2, 2,
    1, 0, 3, 2, 1, 3, 0, 2, 0, 3, 2, 3, 3, 1, 3, 0, 1, 2, 3, 0, 0, 3, 1, 2,
    0, 3, 0, 2, 1, 0, 3, 0, 1, 0, 2, 1, 2, 1, 0, 2, 0, 2, 1, 3, 3, 2, 1, 0,
    0, 1, 3, 1, 2, 3, 2, 0, 1, 3, 1, 1, 2, 2, 3, 2, 1, 1, 1, 3, 3, 2, 2, 2,
    1, 1, 3, 2, 1, 3, 2, 2, 1, 3, 2, 3, 3, 1, 3, 2, 1, 2, 3, 2, 1, 3, 1, 2,
    0, 3, 2, 2, 1, 1, 3, 0, 1, 2, 2, 0, 0, 1, 1, 2, 0, 2, 0, 2, 1, 0, 1, 0,
    0, 0, 2, 1, 2, 1, 0, 0, 0, 2, 1, 1, 2, 2, 1, 0, 0, 1, 1, 1, 2, 2, 2, 0,
    1, 1, 1, 0, 0, 2, 2, 2, 1, 1, 0, 2, 1, 0, 2, 2, 1, 0, 2, 2, 1, 1, 0, 2,
    0, 2, 2, 3, 3, 1, 1, 0, 0, 2, 3, 0, 0, 3, 1, 0, 0, 3, 0, 0, 0, 0, 3, 0,
    1, 0, 0, 1, 2, 0, 0, 2, 0, 0, 1, 2, 1, 2, 0, 0, 0, 1, 2, 0, 0, 1, 2, 0,
    1, 2, 0, 1, 2, 0, 1, 2, 0, 0, 1, 3, 3, 2, 0, 0, 0, 1, 3, 0, 0, 3, 2, 0,
    1, 3, 0, 1, 2, 0, 3, 2, 1, 0, 1, 3, 3, 2, 0, 2, 0, 1, 3, 2, 1, 3, 2, 0,
    1, 3, 2, 1, 2, 1, 3, 2, 1, 2, 1, 2, 1, 2, 1, 2, 0, 1, 2, 3, 3, 1, 2, 0,
    1, 2, 3, 1, 2, 3, 1, 2, 0, 3, 1, 2, 1, 2, 3, 0, 1, 1, 2, 1, 2, 1, 2, 2,
    1, 2, 1, 3, 3, 2, 1, 2, 0, 1, 3, 3, 3, 3, 2, 0, 1, 3, 3, 1, 2, 3, 3, 2,
    1, 3, 1, 2, 1, 2, 3, 2, 1, 1, 2, 3, 3, 1, 2, 2, 1, 2, 3, 3, 3, 3, 1, 2,
    0, 3, 3, 2, 1, 3, 3, 0, 1, 3, 2, 0, 0, 1, 3, 2, 1, 2, 0, 2, 1, 0, 1, 2,
    0, 0, 2, 3, 3, 1, 0, 0, 0, 2, 3, 1, 2, 3, 1, 0, 0, 3, 1, 0, 0, 2, 3, 0,
    1, 1, 0, 1, 2, 0, 2, 2, 1, 0, 1, 2, 1, 2, 0, 2, 0, 1, 2, 2, 1, 1, 2, 0,
    1, 2, 2, 1, 2, 1, 1, 2, 0, 2, 1, 2, 1, 2, 1, 0, 0, 1, 2, 1, 2, 1, 2, 0,
    1, 2, 1, 1, 2, 2, 1, 2, 0, 1, 1, 3, 3, 2, 2, 0, 1, 1, 3, 0, 0, 3, 2, 2,
    1, 3, 0, 3, 3, 0, 3, 2, 1, 0, 3, 3, 3, 3, 0, 2, 0, 3, 3, 3, 3, 3, 3, 0,
    1, 3, 3, 0, 0, 3, 3, 2, 1, 3, 0, 2, 1, 0, 3, 2, 1, 0, 2, 3, 3, 1, 0, 2,
    0, 2, 3, 3, 3, 3, 1, 0, 0, 3, 3, 0, 0, 3, 3, 0, 1, 3, 0, 0, 0, 0, 3, 2,
    1, 0, 0, 3, 3, 0, 0, 2, 0, 0, 3, 2, 1, 3, 0, 0, 0, 3, 2, 1, 2, 1, 3, 0,
    1, 2, 1, 0, 0, 2, 1, 2, 0, 1, 0, 3, 3, 0, 2, 0, 1, 0, 3, 0, 0, 3, 0, 2,
    0, 3, 0, 3, 3, 0, 3, 0, 1, 0, 3, 1, 2, 3, 0, 2, 0, 3, 1, 3, 3, 2, 3, 0,
    1, 1, 3, 1, 2, 3, 2, 2, 1, 3, 1, 3, 3, 2, 3, 2, 1, 1, 3, 3, 3, 3, 2, 2
};

/* Bit-sliced round constants for Spongent-pi[160], which are taken from
 * the end of the round constant table for Spongent-pi[176]*/
#define RC_160 (RC_176 + 80)

#if SPONGENT_SLICED64

void spongent160_permute(spongent160_state_t *state)
{
    uint32_t w0, w1, w2, w3, w4;
    uint64_t x0, x1, x2, x3;
    uint64_t t0, t1, t2, t3;
    uint8_t round;
    const unsigned char *rc = RC_160;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    w0 = state->W[0];
    w1 = state->W[1];
    w2 = state->W[2];
    w3 = state->W[3];
    w4 = state->W[4];
#else
    w0 = le_load_word32(state->B);
    w1 = le_load_word32(state->B + 4);
    w2 = le_load_word32(state->B + 8);
    w3 = le_load_word32(state->B + 12);
    w4 = le_load_word32(state->B + 16);
#endif

    /* Rerrange the nibbles so that bits 0..3 are scattered to x0..x3 */
    PERM(w0);
    PERM(w1);
    PERM(w2);
    PERM(w3);
    PERM(w4);
    x0 = (w0 & 0xFFU) | ((w1 & 0xFFU) << 8) | ((w2 & 0xFFU) << 16) |
         ((w3 & 0xFFU) << 24) | (((uint64_t)(w4 & 0xFFU)) << 32);
    x1 = ((w0 & 0xFF00U) >> 8) | (w1 & 0xFF00U) | ((w2 & 0xFF00U) << 8) |
         ((w3 & 0xFF00U) << 16) | (((uint64_t)(w4 & 0xFF00U)) << 24);
    x2 = ((w0 & 0xFF0000U) >> 16) | ((w1 & 0xFF0000U) >> 8) |
         (w2 & 0xFF0000U) | ((w3 & 0xFF0000U) << 8) |
         (((uint64_t)(w4 & 0xFF0000U)) << 16);
    x3 = ((w0 & 0xFF000000U) >> 24) | ((w1 & 0xFF000000U) >> 16) |
         ((w2 & 0xFF000000U) >> 8) | (w3 & 0xFF000000U) |
         (((uint64_t)(w4 & 0xFF000000U)) << 8);

    /* Perform the 80 rounds of Spongent-pi[160] */
    for (round = 0; round < 80; ++round, rc += 8) {
        /* Add the round constants to the front and back of the state */
        x0 ^= rc[0] ^ (((uint64_t)(rc[4])) << 38);
        x1 ^= rc[1] ^ (((uint64_t)(rc[5])) << 38);
        x2 ^= rc[2] ^ (((uint64_t)(rc[6])) << 38);
        x3 ^= rc[3] ^ (((uint64_t)(rc[7])) << 38);

        /* Apply the bit-sliced S-box to all 4-bit groups in the state */
        spongent_sbox(uint64_t, t0, t1, t2, t3, x0, x1, x2, x3);

        /* Permute the bits of the state.  Bit i is moved to (40 * i) % 159
         * for all bits except the last which is left where it is. */
        x0 = BDN64(t3,  3,  0) ^ BUP64(t2,  3, 10) ^ BUP64(t1,  3, 20) ^
             BUP64(t0,  3, 30) ^ BDN64(t3,  7,  1) ^ BUP64(t2,  7, 11) ^
             BUP64(t1,  7, 21) ^ BUP64(t0,  7, 31) ^ BDN64(t3, 11,  2) ^
             BUP64(t2, 11, 12) ^ BUP64(t1, 11, 22) ^ BUP64(t0, 11, 32) ^
             BDN64(t3, 15,  3) ^ BDN64(t2, 15, 13) ^ BUP64(t1, 15, 23) ^
             BUP64(t0, 15, 33) ^ BDN64(t3, 19,  4) ^ BDN64(t2, 19, 14) ^
             BUP64(t1, 19, 24) ^ BUP64(t0, 19, 34) ^ BDN64(t3, 23,  5) ^
             BDN64(t2, 23, 15) ^ BUP64(t1, 23, 25) ^ BUP64(t0, 23, 35) ^
             BDN64(t3, 27,  6) ^ BDN64(t2, 27, 16) ^ BDN64(t1, 27, 26) ^
             BUP64(t0, 27, 36) ^ BDN64(t3, 31,  7) ^ BDN64(t2, 31, 17) ^
             BDN64(t1, 31, 27) ^ BUP64(t0, 31, 37) ^ BDN64(t3, 35,  8) ^
             BDN64(t2, 35, 18) ^ BDN64(t1, 35, 28) ^ BUP64(t0, 35, 38) ^
             BDN64(t3, 39,  9) ^ BDN64(t2, 39, 19) ^ BDN64(t1, 39, 29) ^
             BCP64(t0, 39);
        x1 = BDN64(t3,  2,  0) ^ BUP64(t2,  2, 10) ^ BUP64(t1,  2, 20) ^
             BUP64(t0,  2, 30) ^ BDN64(t3,  6,  1) ^ BUP64(t2,  6, 11) ^
             BUP64(t1,  6, 21) ^ BUP64(t0,  6, 31) ^ BDN64(t3, 10,  2) ^
             BUP64(t2, 10, 12) ^ BUP64(t1, 10, 22) ^ BUP64(t0, 10, 32) ^
             BDN64(t3, 14,  3) ^ BDN64(t2, 14, 13) ^ BUP64(t1, 14, 23) ^
             BUP64(t0, 14, 33) ^ BDN64(t3, 18,  4) ^ BDN64(t2, 18, 14) ^
             BUP64(t1, 18, 24) ^ BUP64(t0, 18, 34) ^ BDN64(t3, 22,  5) ^
             BDN64(t2, 22, 15) ^ BUP64(t1, 22, 25) ^ BUP64(t0, 22, 35) ^
             BDN64(t3, 26,  6) ^ BDN64(t2, 26, 16) ^ BCP64(t1, 26)     ^
             BUP64(t0, 26, 36) ^ BDN64(t3, 30,  7) ^ BDN64(t2, 30, 17) ^
             BDN64(t1, 30, 27) ^ BUP64(t0, 30, 37) ^ BDN64(t3, 34,  8) ^
             BDN64(t2, 34, 18) ^ BDN64(t1, 34, 28) ^ BUP64(t0, 34, 38) ^
             BDN64(t3, 38,  9) ^ BDN64(t2, 38, 19) ^ BDN64(t1, 38, 29) ^
             BUP64(t0, 38, 39);
        x2 = BDN64(t3,  1,  0) ^ BUP64(t2,  1, 10) ^ BUP64(t1,  1, 20) ^
             BUP64(t0,  1, 30) ^ BDN64(t3,  5,  1) ^ BUP64(t2,  5, 11) ^
             BUP64(t1,  5, 21) ^ BUP64(t0,  5, 31) ^ BDN64(t3,  9,  2) ^
             BUP64(t2,  9, 12) ^ BUP64(t1,  9, 22) ^ BUP64(t0,  9, 32) ^
             BDN64(t3, 13,  3) ^ BCP64(t2, 13)     ^ BUP64(t1, 13, 23) ^
             BUP64(t0, 13, 33) ^ BDN64(t3, 17,  4) ^ BDN64(t2, 17, 14) ^
             BUP64(t1, 17, 24) ^ BUP64(t0, 17, 34) ^ BDN64(t3, 21,  5) ^
             BDN64(t2, 21, 15) ^ BUP64(t1, 21, 25) ^ BUP64(t0, 21, 35) ^
             BDN64(t3, 25,  6) ^ BDN64(t2, 25, 16) ^ BUP64(t1, 25, 26) ^
             BUP64(t0, 25, 36) ^ BDN64(t3, 29,  7) ^ BDN64(t2, 29, 17) ^
             BDN64(t1, 29, 27) ^ BUP64(t0, 29, 37) ^ BDN64(t3, 33,  8) ^
             BDN64(t2, 33, 18) ^ BDN64(t1, 33, 28) ^ BUP64(t0, 33, 38) ^
             BDN64(t3, 37,  9) ^ BDN64(t2, 37, 19) ^ BDN64(t1, 37, 29) ^
             BUP64(t0, 37, 39);
        x3 = BCP64(t3,  0)     ^ BUP64(t2,  0, 10) ^ BUP64(t1,  0, 20) ^
             BUP64(t0,  0, 30) ^ BDN64(t3,  4,  1) ^ BUP64(t2,  4, 11) ^
             BUP64(t1,  4, 21) ^ BUP64(t0,  4, 31) ^ BDN64(t3,  8,  2) ^
             BUP64(t2,  8, 12) ^ BUP64(t1,  8, 22) ^ BUP64(t0,  8, 32) ^
             BDN64(t3, 12,  3) ^ BUP64(t2, 12, 13) ^ BUP64(t1, 12, 23) ^
             BUP64(t0, 12, 33) ^ BDN64(t3, 16,  4) ^ BDN64(t2, 16, 14) ^
             BUP64(t1, 16, 24) ^ BUP64(t0, 16, 34) ^ BDN64(t3, 20,  5) ^
             BDN64(t2, 20, 15) ^ BUP64(t1, 20, 25) ^ BUP64(t0, 20, 35) ^
             BDN64(t3, 24,  6) ^ BDN64(t2, 24, 16) ^ BUP64(t1, 24, 26) ^
             BUP64(t0, 24, 36) ^ BDN64(t3, 28,  7) ^ BDN64(t2, 28, 17) ^
             BDN64(t1, 28, 27) ^ BUP64(t0, 28, 37) ^ BDN64(t3, 32,  8) ^
             BDN64(t2, 32, 18) ^ BDN64(t1, 32, 28) ^ BUP64(t0, 32, 38) ^
             BDN64(t3, 36,  9) ^ BDN64(t2, 36, 19) ^ BDN64(t1, 36, 29) ^
             BUP64(t0, 36, 39);
    }

    /* Rearrange the nibbles back into the original order */
    w0 =  (((uint32_t)x0) & 0xFFU) |
         ((((uint32_t)x1) & 0xFFU) << 8) |
         ((((uint32_t)x2) & 0xFFU) << 16) |
         ((((uint32_t)x3) & 0xFFU) << 24);
    w1 = ((((uint32_t)x0) & 0xFF00U) >> 8) |
          (((uint32_t)x1) & 0xFF00U) |
         ((((uint32_t)x2) & 0xFF00U) << 8) |
         ((((uint32_t)x3) & 0xFF00U) << 16);
    w2 = ((((uint32_t)x0) & 0xFF0000U) >> 16) |
         ((((uint32_t)x1) & 0xFF0000U) >> 8) |
          (((uint32_t)x2) & 0xFF0000U) |
         ((((uint32_t)x3) & 0xFF0000U) << 8);
    w3 = ((((uint32_t)x0) & 0xFF000000U) >> 24) |
         ((((uint32_t)x1) & 0xFF000000U) >> 16) |
         ((((uint32_t)x2) & 0xFF000000U) >> 8) |
          (((uint32_t)x3) & 0xFF000000U);
    w4 =  ((uint32_t)(x0 >> 32)) |
         (((uint32_t)(x1 >> 24)) & 0xFF00U) |
         (((uint32_t)(x2 >> 16)) & 0xFF0000U) |
         (((uint32_t)(x3 >> 8))  & 0xFF000000U);
    INV_PERM(w0);
    INV_PERM(w1);
    INV_PERM(w2);
    INV_PERM(w3);
    INV_PERM(w4);

    /* Store the local variables back to the state in little-endian order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = w0;
    state->W[1] = w1;
    state->W[2] = w2;
    state->W[3] = w3;
    state->W[4] = w4;
#else
    le_store_word32(state->B,      w0);
    le_store_word32(state->B +  4, w1);
    le_store_word32(state->B +  8, w2);
    le_store_word32(state->B + 12, w3);
    le_store_word32(state->B + 16, w4);
#endif
}

void spongent176_permute(spongent176_state_t *state)
{
    uint32_t w0, w1, w2, w3, w4, w5;
    uint64_t x0, x1, x2, x3;
    uint64_t t0, t1, t2, t3;
    uint8_t round;
    const unsigned char *rc = RC_176;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    w0 = state->W[0];
    w1 = state->W[1];
    w2 = state->W[2];
    w3 = state->W[3];
    w4 = state->W[4];
    w5 = state->W[5];
#else
    w0 = le_load_word32(state->B);
    w1 = le_load_word32(state->B + 4);
    w2 = le_load_word32(state->B + 8);
    w3 = le_load_word32(state->B + 12);
    w4 = le_load_word32(state->B + 16);
    w5 = le_load_word16(state->B + 20); /* Last word is only 16 bits */
#endif

    /* Rerrange the nibbles so that bits 0..3 are scattered to x0..x3 */
    PERM(w0);
    PERM(w1);
    PERM(w2);
    PERM(w3);
    PERM(w4);
    PERM(w5);
    x0 = (w0 & 0xFFU) | ((w1 & 0xFFU) << 8) | ((w2 & 0xFFU) << 16) |
         ((w3 & 0xFFU) << 24) | (((uint64_t)(w4 & 0xFFU)) << 32) |
         (((uint64_t)(w5 & 0xFFU)) << 40);
    x1 = ((w0 & 0xFF00U) >> 8) | (w1 & 0xFF00U) | ((w2 & 0xFF00U) << 8) |
         ((w3 & 0xFF00U) << 16) | (((uint64_t)(w4 & 0xFF00U)) << 24) |
         (((uint64_t)(w5 & 0xFF00U)) << 32);
    x2 = ((w0 & 0xFF0000U) >> 16) | ((w1 & 0xFF0000U) >> 8) |
         (w2 & 0xFF0000U) | ((w3 & 0xFF0000U) << 8) |
         (((uint64_t)(w4 & 0xFF0000U)) << 16) |
         (((uint64_t)(w5 & 0xFF0000U)) << 24);
    x3 = ((w0 & 0xFF000000U) >> 24) | ((w1 & 0xFF000000U) >> 16) |
         ((w2 & 0xFF000000U) >> 8) | (w3 & 0xFF000000U) |
         (((uint64_t)(w4 & 0xFF000000U)) << 8) |
         (((uint64_t)(w5 & 0xFF000000U)) << 16);

    /* Perform the 90 rounds of Spongent-pi[176] */
    for (round = 0; round < 90; ++round, rc += 8) {
        /* Add the round constants to the front and back of the state */
        x0 ^= rc[0] ^ (((uint64_t)(rc[4])) << 42);
        x1 ^= rc[1] ^ (((uint64_t)(rc[5])) << 42);
        x2 ^= rc[2] ^ (((uint64_t)(rc[6])) << 42);
        x3 ^= rc[3] ^ (((uint64_t)(rc[7])) << 42);

        /* Apply the bit-sliced S-box to all 4-bit groups in the state */
        spongent_sbox(uint64_t, t0, t1, t2, t3, x0, x1, x2, x3);

        /* Permute the bits of the state.  Bit i is moved to (44 * i) % 175
         * for all bits except the last which is left where it is. */
        x0 = BDN64(t3,  3,  0) ^ BUP64(t2,  3, 11) ^ BUP64(t1,  3, 22) ^
             BUP64(t0,  3, 33) ^ BDN64(t3,  7,  1) ^ BUP64(t2,  7, 12) ^
             BUP64(t1,  7, 23) ^ BUP64(t0,  7, 34) ^ BDN64(t3, 11,  2) ^
             BUP64(t2, 11, 13) ^ BUP64(t1, 11, 24) ^ BUP64(t0, 11, 35) ^
             BDN64(t3, 15,  3) ^ BDN64(t2, 15, 14) ^ BUP64(t1, 15, 25) ^
             BUP64(t0, 15, 36) ^ BDN64(t3, 19,  4) ^ BDN64(t2, 19, 15) ^
             BUP64(t1, 19, 26) ^ BUP64(t0, 19, 37) ^ BDN64(t3, 23,  5) ^
             BDN64(t2, 23, 16) ^ BUP64(t1, 23, 27) ^ BUP64(t0, 23, 38) ^
             BDN64(t3, 27,  6) ^ BDN64(t2, 27, 17) ^ BUP64(t1, 27, 28) ^
             BUP64(t0, 27, 39) ^ BDN64(t3, 31,  7) ^ BDN64(t2, 31, 18) ^
             BDN64(t1, 31, 29) ^ BUP64(t0, 31, 40) ^ BDN64(t3, 35,  8) ^
             BDN64(t2, 35, 19) ^ BDN64(t1, 35, 30) ^ BUP64(t0, 35, 41) ^
             BDN64(t3, 39,  9) ^ BDN64(t2, 39, 20) ^ BDN64(t1, 39, 31) ^
             BUP64(t0, 39, 42) ^ BDN64(t3, 43, 10) ^ BDN64(t2, 43, 21) ^
             BDN64(t1, 43, 32) ^ BCP64(t0, 43);
        x1 = BDN64(t3,  2,  0) ^ BUP64(t2,  2, 11) ^ BUP64(t1,  2, 22) ^
             BUP64(t0,  2, 33) ^ BDN64(t3,  6,  1) ^ BUP64(t2,  6, 12) ^
             BUP64(t1,  6, 23) ^ BUP64(t0,  6, 34) ^ BDN64(t3, 10,  2) ^
             BUP64(t2, 10, 13) ^ BUP64(t1, 10, 24) ^ BUP64(t0, 10, 35) ^
             BDN64(t3, 14,  3) ^ BCP64(t2, 14)     ^ BUP64(t1, 14, 25) ^
             BUP64(t0, 14, 36) ^ BDN64(t3, 18,  4) ^ BDN64(t2, 18, 15) ^
             BUP64(t1, 18, 26) ^ BUP64(t0, 18, 37) ^ BDN64(t3, 22,  5) ^
             BDN64(t2, 22, 16) ^ BUP64(t1, 22, 27) ^ BUP64(t0, 22, 38) ^
             BDN64(t3, 26,  6) ^ BDN64(t2, 26, 17) ^ BUP64(t1, 26, 28) ^
             BUP64(t0, 26, 39) ^ BDN64(t3, 30,  7) ^ BDN64(t2, 30, 18) ^
             BDN64(t1, 30, 29) ^ BUP64(t0, 30, 40) ^ BDN64(t3, 34,  8) ^
             BDN64(t2, 34, 19) ^ BDN64(t1, 34, 30) ^ BUP64(t0, 34, 41) ^
             BDN64(t3, 38,  9) ^ BDN64(t2, 38, 20) ^ BDN64(t1, 38, 31) ^
             BUP64(t0, 38, 42) ^ BDN64(t3, 42, 10) ^ BDN64(t2, 42, 21) ^
             BDN64(t1, 42, 32) ^ BUP64(t0, 42, 43);
        x2 = BDN64(t3,  1,  0) ^ BUP64(t2,  1, 11) ^ BUP64(t1,  1, 22) ^
             BUP64(t0,  1, 33) ^ BDN64(t3,  5,  1) ^ BUP64(t2,  5, 12) ^
             BUP64(t1,  5, 23) ^ BUP64(t0,  5, 34) ^ BDN64(t3,  9,  2) ^
             BUP64(t2,  9, 13) ^ BUP64(t1,  9, 24) ^ BUP64(t0,  9, 35) ^
             BDN64(t3, 13,  3) ^ BUP64(t2, 13, 14) ^ BUP64(t1, 13, 25) ^
             BUP64(t0, 13, 36) ^ BDN64(t3, 17,  4) ^ BDN64(t2, 17, 15) ^
             BUP64(t1, 17, 26) ^ BUP64(t0, 17, 37) ^ BDN64(t3, 21,  5) ^
             BDN64(t2, 21, 16) ^ BUP64(t1, 21, 27) ^ BUP64(t0, 21, 38) ^
             BDN64(t3, 25,  6) ^ BDN64(t2, 25, 17) ^ BUP64(t1, 25, 28) ^
             BUP64(t0, 25, 39) ^ BDN64(t3, 29,  7) ^ BDN64(t2, 29, 18) ^
             BCP64(t1, 29)     ^ BUP64(t0, 29, 40) ^ BDN64(t3, 33,  8) ^
             BDN64(t2, 33, 19) ^ BDN64(t1, 33, 30) ^ BUP64(t0, 33, 41) ^
             BDN64(t3, 37,  9) ^ BDN64(t2, 37, 20) ^ BDN64(t1, 37, 31) ^
             BUP64(t0, 37, 42) ^ BDN64(t3, 41, 10) ^ BDN64(t2, 41, 21) ^
             BDN64(t1, 41, 32) ^ BUP64(t0, 41, 43);
        x3 = BCP64(t3,  0)     ^ BUP64(t2,  0, 11) ^ BUP64(t1,  0, 22) ^
             BUP64(t0,  0, 33) ^ BDN64(t3,  4,  1) ^ BUP64(t2,  4, 12) ^
             BUP64(t1,  4, 23) ^ BUP64(t0,  4, 34) ^ BDN64(t3,  8,  2) ^
             BUP64(t2,  8, 13) ^ BUP64(t1,  8, 24) ^ BUP64(t0,  8, 35) ^
             BDN64(t3, 12,  3) ^ BUP64(t2, 12, 14) ^ BUP64(t1, 12, 25) ^
             BUP64(t0, 12, 36) ^ BDN64(t3, 16,  4) ^ BDN64(t2, 16, 15) ^
             BUP64(t1, 16, 26) ^ BUP64(t0, 16, 37) ^ BDN64(t3, 20,  5) ^
             BDN64(t2, 20, 16) ^ BUP64(t1, 20, 27) ^ BUP64(t0, 20, 38) ^
             BDN64(t3, 24,  6) ^ BDN64(t2, 24, 17) ^ BUP64(t1, 24, 28) ^
             BUP64(t0, 24, 39) ^ BDN64(t3, 28,  7) ^ BDN64(t2, 28, 18) ^
             BUP64(t1, 28, 29) ^ BUP64(t0, 28, 40) ^ BDN64(t3, 32,  8) ^
             BDN64(t2, 32, 19) ^ BDN64(t1, 32, 30) ^ BUP64(t0, 32, 41) ^
             BDN64(t3, 36,  9) ^ BDN64(t2, 36, 20) ^ BDN64(t1, 36, 31) ^
             BUP64(t0, 36, 42) ^ BDN64(t3, 40, 10) ^ BDN64(t2, 40, 21) ^
             BDN64(t1, 40, 32) ^ BUP64(t0, 40, 43);
    }

    /* Rearrange the nibbles back into the original order */
    w0 =  (((uint32_t)x0) & 0xFFU) |
         ((((uint32_t)x1) & 0xFFU) << 8) |
         ((((uint32_t)x2) & 0xFFU) << 16) |
         ((((uint32_t)x3) & 0xFFU) << 24);
    w1 = ((((uint32_t)x0) & 0xFF00U) >> 8) |
          (((uint32_t)x1) & 0xFF00U) |
         ((((uint32_t)x2) & 0xFF00U) << 8) |
         ((((uint32_t)x3) & 0xFF00U) << 16);
    w2 = ((((uint32_t)x0) & 0xFF0000U) >> 16) |
         ((((uint32_t)x1) & 0xFF0000U) >> 8) |
          (((uint32_t)x2) & 0xFF0000U) |
         ((((uint32_t)x3) & 0xFF0000U) << 8);
    w3 = ((((uint32_t)x0) & 0xFF000000U) >> 24) |
         ((((uint32_t)x1) & 0xFF000000U) >> 16) |
         ((((uint32_t)x2) & 0xFF000000U) >> 8) |
          (((uint32_t)x3) & 0xFF000000U);
    w4 = (((uint32_t)(x0 >> 32)) & 0xFFU)  |
         (((uint32_t)(x1 >> 24)) & 0xFF00U) |
         (((uint32_t)(x2 >> 16)) & 0xFF0000U) |
         (((uint32_t)(x3 >> 8))  & 0xFF000000U);
    w5 = (((uint32_t)(x0 >> 40)) & 0xFFU)  |
         (((uint32_t)(x1 >> 32)) & 0xFF00U) |
         (((uint32_t)(x2 >> 24)) & 0xFF0000U) |
         (((uint32_t)(x3 >> 16)) & 0xFF000000U);
    INV_PERM(w0);
    INV_PERM(w1);
    INV_PERM(w2);
    INV_PERM(w3);
    INV_PERM(w4);
    INV_PERM(w5);

    /* Store the local variables back to the state in little-endian order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = w0;
    state->W[1] = w1;
    state->W[2] = w2;
    state->W[3] = w3;
    state->W[4] = w4;
    state->W[5] = w5;
#else
    le_store_word32(state->B,      w0);
    le_store_word32(state->B +  4, w1);
    le_store_word32(state->B +  8, w2);
    le_store_word32(state->B + 12, w3);
    le_store_word32(state->B + 16, w4);
    le_store_word16(state->B + 20, w5); /* Last word is only 16 bits */
#endif
}

#else /* !SPONGENT_SLICED64 */

void spongent160_permute(spongent160_state_t *state)
{
    uint32_t x0_l, x1_l, x2_l, x3_l;
    uint32_t x0_h, x1_h, x2_h, x3_h;
    uint32_t t0_l, t1_l, t2_l, t3_l;
    uint32_t t0_h, t1_h, t2_h, t3_h;
    uint8_t round;
    const unsigned char *rc = RC_160;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    t0_l = state->W[0];
    t1_l = state->W[1];
    t2_l = state->W[2];
    t3_l = state->W[3];
    t0_h = state->W[4];
#else
    t0_l = le_load_word32(state->B);
    t1_l = le_load_word32(state->B + 4);
    t2_l = le_load_word32(state->B + 8);
    t3_l = le_load_word32(state->B + 12);
    t0_h = le_load_word32(state->B + 16);
#endif

    /* Rerrange the nibbles so that bits 0..3 are scattered to x0..x3 */
    PERM(t0_l);
    PERM(t1_l);
    PERM(t2_l);
    PERM(t3_l);
    PERM(t0_h);
    x0_l = (t0_l & 0xFFU) | ((t1_l & 0xFFU) << 8) |
           ((t2_l & 0xFFU) << 16) | ((t3_l & 0xFFU) << 24);
    x1_l = ((t0_l & 0xFF00U) >> 8) | (t1_l & 0xFF00U) |
           ((t2_l & 0xFF00U) << 8) | ((t3_l & 0xFF00U) << 16);
    x2_l = ((t0_l & 0xFF0000U) >> 16) | ((t1_l & 0xFF0000U) >> 8) |
           (t2_l & 0xFF0000U) | ((t3_l & 0xFF0000U) << 8);
    x3_l = ((t0_l & 0xFF000000U) >> 24) | ((t1_l & 0xFF000000U) >> 16) |
           ((t2_l & 0xFF000000U) >> 8) | (t3_l & 0xFF000000U);
    x0_h = t0_h & 0xFFU;
    x1_h = (t0_h >> 8) & 0xFFU;
    x2_h = (t0_h >> 16) & 0xFFU;
    x3_h = (t0_h >> 24);

    /* Perform the 80 rounds of Spongent-pi[160] */
    for (round = 0; round < 80; ++round, rc += 8) {
        /* Add the round constants to the front and back of the state */
        x0_l ^= rc[0];
        x1_l ^= rc[1];
        x2_l ^= rc[2];
        x3_l ^= rc[3];
        x0_h ^= ((uint32_t)(rc[4])) << 6;
        x1_h ^= ((uint32_t)(rc[5])) << 6;
        x2_h ^= ((uint32_t)(rc[6])) << 6;
        x3_h ^= ((uint32_t)(rc[7])) << 6;

        /* Apply the bit-sliced S-box to all 4-bit groups in the state */
        spongent_sbox(uint32_t, t0_l, t1_l, t2_l, t3_l, x0_l, x1_l, x2_l, x3_l);
        spongent_sbox(uint32_t, t0_h, t1_h, t2_h, t3_h, x0_h, x1_h, x2_h, x3_h);

        /* Permute the bits of the state.  Bit i is moved to (40 * i) % 159
         * for all bits except the last which is left where it is. */
        x0_l = BDN32(t3_l,  3,  0) ^ BUP32(t2_l,  3, 10) ^ BUP32(t1_l,  3, 20) ^
               BUP32(t0_l,  3, 30) ^ BDN32(t3_l,  7,  1) ^ BUP32(t2_l,  7, 11) ^
               BUP32(t1_l,  7, 21) ^ BUP32(t0_l,  7, 31) ^ BDN32(t3_l, 11,  2) ^
               BUP32(t2_l, 11, 12) ^ BUP32(t1_l, 11, 22) ^ BDN32(t3_l, 15,  3) ^
               BDN32(t2_l, 15, 13) ^ BUP32(t1_l, 15, 23) ^ BDN32(t3_l, 19,  4) ^
               BDN32(t2_l, 19, 14) ^ BUP32(t1_l, 19, 24) ^ BDN32(t3_l, 23,  5) ^
               BDN32(t2_l, 23, 15) ^ BUP32(t1_l, 23, 25) ^ BDN32(t3_l, 27,  6) ^
               BDN32(t2_l, 27, 16) ^ BDN32(t1_l, 27, 26) ^ BDN32(t3_l, 31,  7) ^
               BDN32(t2_l, 31, 17) ^ BDN32(t1_l, 31, 27) ^ BUP32(t3_h,  3,  8) ^
               BUP32(t2_h,  3, 18) ^ BUP32(t1_h,  3, 28) ^ BUP32(t3_h,  7,  9) ^
               BUP32(t2_h,  7, 19) ^ BUP32(t1_h,  7, 29);
        x0_h = BDN32(t0_l, 11,  0) ^ BDN32(t0_l, 15,  1) ^ BDN32(t0_l, 19,  2) ^
               BDN32(t0_l, 23,  3) ^ BDN32(t0_l, 27,  4) ^ BDN32(t0_l, 31,  5) ^
               BUP32(t0_h,  3,  6) ^ BCP32(t0_h,  7);
        x1_l = BDN32(t3_l,  2,  0) ^ BUP32(t2_l,  2, 10) ^ BUP32(t1_l,  2, 20) ^
               BUP32(t0_l,  2, 30) ^ BDN32(t3_l,  6,  1) ^ BUP32(t2_l,  6, 11) ^
               BUP32(t1_l,  6, 21) ^ BUP32(t0_l,  6, 31) ^ BDN32(t3_l, 10,  2) ^
               BUP32(t2_l, 10, 12) ^ BUP32(t1_l, 10, 22) ^ BDN32(t3_l, 14,  3) ^
               BDN32(t2_l, 14, 13) ^ BUP32(t1_l, 14, 23) ^ BDN32(t3_l, 18,  4) ^
               BDN32(t2_l, 18, 14) ^ BUP32(t1_l, 18, 24) ^ BDN32(t3_l, 22,  5) ^
               BDN32(t2_l, 22, 15) ^ BUP32(t1_l, 22, 25) ^ BDN32(t3_l, 26,  6) ^
               BDN32(t2_l, 26, 16) ^ BCP32(t1_l, 26)     ^ BDN32(t3_l, 30,  7) ^
               BDN32(t2_l, 30, 17) ^ BDN32(t1_l, 30, 27) ^ BUP32(t3_h,  2,  8) ^
               BUP32(t2_h,  2, 18) ^ BUP32(t1_h,  2, 28) ^ BUP32(t3_h,  6,  9) ^
               BUP32(t2_h,  6, 19) ^ BUP32(t1_h,  6, 29);
        x1_h = BDN32(t0_l, 10,  0) ^ BDN32(t0_l, 14,  1) ^ BDN32(t0_l, 18,  2) ^
               BDN32(t0_l, 22,  3) ^ BDN32(t0_l, 26,  4) ^ BDN32(t0_l, 30,  5) ^
               BUP32(t0_h,  2,  6) ^ BUP32(t0_h,  6,  7);
        x2_l = BDN32(t3_l,  1,  0) ^ BUP32(t2_l,  1, 10) ^ BUP32(t1_l,  1, 20) ^
               BUP32(t0_l,  1, 30) ^ BDN32(t3_l,  5,  1) ^ BUP32(t2_l,  5, 11) ^
               BUP32(t1_l,  5, 21) ^ BUP32(t0_l,  5, 31) ^ BDN32(t3_l,  9,  2) ^
               BUP32(t2_l,  9, 12) ^ BUP32(t1_l,  9, 22) ^ BDN32(t3_l, 13,  3) ^
               BCP32(t2_l, 13)     ^ BUP32(t1_l, 13, 23) ^ BDN32(t3_l, 17,  4) ^
               BDN32(t2_l, 17, 14) ^ BUP32(t1_l, 17, 24) ^ BDN32(t3_l, 21,  5) ^
               BDN32(t2_l, 21, 15) ^ BUP32(t1_l, 21, 25) ^ BDN32(t3_l, 25,  6) ^
               BDN32(t2_l, 25, 16) ^ BUP32(t1_l, 25, 26) ^ BDN32(t3_l, 29,  7) ^
               BDN32(t2_l, 29, 17) ^ BDN32(t1_l, 29, 27) ^ BUP32(t3_h,  1,  8) ^
               BUP32(t2_h,  1, 18) ^ BUP32(t1_h,  1, 28) ^ BUP32(t3_h,  5,  9) ^
               BUP32(t2_h,  5, 19) ^ BUP32(t1_h,  5, 29);
        x2_h = BDN32(t0_l,  9,  0) ^ BDN32(t0_l, 13,  1) ^ BDN32(t0_l, 17,  2) ^
               BDN32(t0_l, 21,  3) ^ BDN32(t0_l, 25,  4) ^ BDN32(t0_l, 29,  5) ^
               BUP32(t0_h,  1,  6) ^ BUP32(t0_h,  5,  7);
        x3_l = BCP32(t3_l,  0)     ^ BUP32(t2_l,  0, 10) ^ BUP32(t1_l,  0, 20) ^
               BUP32(t0_l,  0, 30) ^ BDN32(t3_l,  4,  1) ^ BUP32(t2_l,  4, 11) ^
               BUP32(t1_l,  4, 21) ^ BUP32(t0_l,  4, 31) ^ BDN32(t3_l,  8,  2) ^
               BUP32(t2_l,  8, 12) ^ BUP32(t1_l,  8, 22) ^ BDN32(t3_l, 12,  3) ^
               BUP32(t2_l, 12, 13) ^ BUP32(t1_l, 12, 23) ^ BDN32(t3_l, 16,  4) ^
               BDN32(t2_l, 16, 14) ^ BUP32(t1_l, 16, 24) ^ BDN32(t3_l, 20,  5) ^
               BDN32(t2_l, 20, 15) ^ BUP32(t1_l, 20, 25) ^ BDN32(t3_l, 24,  6) ^
               BDN32(t2_l, 24, 16) ^ BUP32(t1_l, 24, 26) ^ BDN32(t3_l, 28,  7) ^
               BDN32(t2_l, 28, 17) ^ BDN32(t1_l, 28, 27) ^ BUP32(t3_h,  0,  8) ^
               BUP32(t2_h,  0, 18) ^ BUP32(t1_h,  0, 28) ^ BUP32(t3_h,  4,  9) ^
               BUP32(t2_h,  4, 19) ^ BUP32(t1_h,  4, 29);
        x3_h = BDN32(t0_l,  8,  0) ^ BDN32(t0_l, 12,  1) ^ BDN32(t0_l, 16,  2) ^
               BDN32(t0_l, 20,  3) ^ BDN32(t0_l, 24,  4) ^ BDN32(t0_l, 28,  5) ^
               BUP32(t0_h,  0,  6) ^ BUP32(t0_h,  4,  7);
    }

    /* Rearrange the nibbles back into the original order */
    t0_l =  (x0_l & 0xFFU) | ((x1_l & 0xFFU) << 8) |
           ((x2_l & 0xFFU) << 16) | ((x3_l & 0xFFU) << 24);
    t1_l = ((x0_l & 0xFF00U) >> 8) | (x1_l & 0xFF00U) |
           ((x2_l & 0xFF00U) << 8) | ((x3_l & 0xFF00U) << 16);
    t2_l = ((x0_l & 0xFF0000U) >> 16) | ((x1_l & 0xFF0000U) >> 8) |
            (x2_l & 0xFF0000U) | ((x3_l & 0xFF0000U) << 8);
    t3_l = ((x0_l & 0xFF000000U) >> 24) | ((x1_l & 0xFF000000U) >> 16) |
           ((x2_l & 0xFF000000U) >> 8) | (x3_l & 0xFF000000U);
    t0_h = x0_h | (x1_h << 8) | (x2_h << 16) | (x3_h << 24);
    INV_PERM(t0_l);
    INV_PERM(t1_l);
    INV_PERM(t2_l);
    INV_PERM(t3_l);
    INV_PERM(t0_h);

    /* Store the local variables back to the state in little-endian order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = t0_l;
    state->W[1] = t1_l;
    state->W[2] = t2_l;
    state->W[3] = t3_l;
    state->W[4] = t0_h;
#else
    le_store_word32(state->B,      t0_l);
    le_store_word32(state->B +  4, t1_l);
    le_store_word32(state->B +  8, t2_l);
    le_store_word32(state->B + 12, t3_l);
    le_store_word32(state->B + 16, t0_h);
#endif
}

void spongent176_permute(spongent176_state_t *state)
{
    uint32_t x0_l, x1_l, x2_l, x3_l;
    uint32_t x0_h, x1_h, x2_h, x3_h;
    uint32_t t0_l, t1_l, t2_l, t3_l;
    uint32_t t0_h, t1_h, t2_h, t3_h;
    uint8_t round;
    const unsigned char *rc = RC_176;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    t0_l = state->W[0];
    t1_l = state->W[1];
    t2_l = state->W[2];
    t3_l = state->W[3];
    t0_h = state->W[4];
    t1_h = state->W[5];
#else
    t0_l = le_load_word32(state->B);
    t1_l = le_load_word32(state->B + 4);
    t2_l = le_load_word32(state->B + 8);
    t3_l = le_load_word32(state->B + 12);
    t0_h = le_load_word32(state->B + 16);
    t1_h = le_load_word16(state->B + 20); /* Last word is only 16 bits */
#endif

    /* Rerrange the nibbles so that bits 0..3 are scattered to x0..x3 */
    PERM(t0_l);
    PERM(t1_l);
    PERM(t2_l);
    PERM(t3_l);
    PERM(t0_h);
    PERM(t1_h);
    x0_l = (t0_l & 0xFFU) | ((t1_l & 0xFFU) << 8) |
           ((t2_l & 0xFFU) << 16) | ((t3_l & 0xFFU) << 24);
    x1_l = ((t0_l & 0xFF00U) >> 8) | (t1_l & 0xFF00U) |
           ((t2_l & 0xFF00U) << 8) | ((t3_l & 0xFF00U) << 16);
    x2_l = ((t0_l & 0xFF0000U) >> 16) | ((t1_l & 0xFF0000U) >> 8) |
           (t2_l & 0xFF0000U) | ((t3_l & 0xFF0000U) << 8);
    x3_l = ((t0_l & 0xFF000000U) >> 24) | ((t1_l & 0xFF000000U) >> 16) |
           ((t2_l & 0xFF000000U) >> 8) | (t3_l & 0xFF000000U);
    x0_h = (t0_h & 0xFFU) | ((t1_h << 8) & 0xFF00U);
    x1_h = ((t0_h >> 8) & 0xFFU) | (t1_h & 0xFF00U);
    x2_h = ((t0_h >> 16) & 0xFFU) | ((t1_h >> 8) & 0xFF00U);
    x3_h = (t0_h >> 24) | ((t1_h >> 16) & 0xFF00U);

    /* Perform the 90 rounds of Spongent-pi[176] */
    for (round = 0; round < 90; ++round, rc += 8) {
        /* Add the round constants to the front and back of the state */
        x0_l ^= rc[0];
        x1_l ^= rc[1];
        x2_l ^= rc[2];
        x3_l ^= rc[3];
        x0_h ^= ((uint32_t)(rc[4])) << 10;
        x1_h ^= ((uint32_t)(rc[5])) << 10;
        x2_h ^= ((uint32_t)(rc[6])) << 10;
        x3_h ^= ((uint32_t)(rc[7])) << 10;

        /* Apply the bit-sliced S-box to all 4-bit groups in the state */
        spongent_sbox(uint32_t, t0_l, t1_l, t2_l, t3_l, x0_l, x1_l, x2_l, x3_l);
        spongent_sbox(uint32_t, t0_h, t1_h, t2_h, t3_h, x0_h, x1_h, x2_h, x3_h);

        /* Permute the bits of the state.  Bit i is moved to (44 * i) % 175
         * for all bits except the last which is left where it is. */
        x0_l = BDN32(t3_l,  3,  0) ^ BUP32(t2_l,  3, 11) ^ BUP32(t1_l,  3, 22) ^
               BDN32(t3_l,  7,  1) ^ BUP32(t2_l,  7, 12) ^ BUP32(t1_l,  7, 23) ^
               BDN32(t3_l, 11,  2) ^ BUP32(t2_l, 11, 13) ^ BUP32(t1_l, 11, 24) ^
               BDN32(t3_l, 15,  3) ^ BDN32(t2_l, 15, 14) ^ BUP32(t1_l, 15, 25) ^
               BDN32(t3_l, 19,  4) ^ BDN32(t2_l, 19, 15) ^ BUP32(t1_l, 19, 26) ^
               BDN32(t3_l, 23,  5) ^ BDN32(t2_l, 23, 16) ^ BUP32(t1_l, 23, 27) ^
               BDN32(t3_l, 27,  6) ^ BDN32(t2_l, 27, 17) ^ BUP32(t1_l, 27, 28) ^
               BDN32(t3_l, 31,  7) ^ BDN32(t2_l, 31, 18) ^ BDN32(t1_l, 31, 29) ^
               BUP32(t3_h,  3,  8) ^ BUP32(t2_h,  3, 19) ^ BUP32(t1_h,  3, 30) ^
               BUP32(t3_h,  7,  9) ^ BUP32(t2_h,  7, 20) ^ BUP32(t1_h,  7, 31) ^
               BDN32(t3_h, 11, 10) ^ BUP32(t2_h, 11, 21);
        x0_h = BDN32(t0_l,  3,  1) ^ BDN32(t0_l,  7,  2) ^ BDN32(t0_l, 11,  3) ^
               BDN32(t0_l, 15,  4) ^ BDN32(t0_l, 19,  5) ^ BDN32(t0_l, 23,  6) ^
               BDN32(t0_l, 27,  7) ^ BDN32(t0_l, 31,  8) ^ BUP32(t0_h,  3,  9) ^
               BUP32(t0_h,  7, 10) ^ BDN32(t1_h, 11,  0) ^ BCP32(t0_h, 11);
        x1_l = BDN32(t3_l,  2,  0) ^ BUP32(t2_l,  2, 11) ^ BUP32(t1_l,  2, 22) ^
               BDN32(t3_l,  6,  1) ^ BUP32(t2_l,  6, 12) ^ BUP32(t1_l,  6, 23) ^
               BDN32(t3_l, 10,  2) ^ BUP32(t2_l, 10, 13) ^ BUP32(t1_l, 10, 24) ^
               BDN32(t3_l, 14,  3) ^ BCP32(t2_l, 14)     ^ BUP32(t1_l, 14, 25) ^
               BDN32(t3_l, 18,  4) ^ BDN32(t2_l, 18, 15) ^ BUP32(t1_l, 18, 26) ^
               BDN32(t3_l, 22,  5) ^ BDN32(t2_l, 22, 16) ^ BUP32(t1_l, 22, 27) ^
               BDN32(t3_l, 26,  6) ^ BDN32(t2_l, 26, 17) ^ BUP32(t1_l, 26, 28) ^
               BDN32(t3_l, 30,  7) ^ BDN32(t2_l, 30, 18) ^ BDN32(t1_l, 30, 29) ^
               BUP32(t3_h,  2,  8) ^ BUP32(t2_h,  2, 19) ^ BUP32(t1_h,  2, 30) ^
               BUP32(t3_h,  6,  9) ^ BUP32(t2_h,  6, 20) ^ BUP32(t1_h,  6, 31) ^
               BCP32(t3_h, 10)     ^ BUP32(t2_h, 10, 21);
        x1_h = BDN32(t0_l,  2,  1) ^ BDN32(t0_l,  6,  2) ^ BDN32(t0_l, 10,  3) ^
               BDN32(t0_l, 14,  4) ^ BDN32(t0_l, 18,  5) ^ BDN32(t0_l, 22,  6) ^
               BDN32(t0_l, 26,  7) ^ BDN32(t0_l, 30,  8) ^ BUP32(t0_h,  2,  9) ^
               BUP32(t0_h,  6, 10) ^ BDN32(t1_h, 10,  0) ^ BUP32(t0_h, 10, 11);
        x2_l = BDN32(t3_l,  1,  0) ^ BUP32(t2_l,  1, 11) ^ BUP32(t1_l,  1, 22) ^
               BDN32(t3_l,  5,  1) ^ BUP32(t2_l,  5, 12) ^ BUP32(t1_l,  5, 23) ^
               BDN32(t3_l,  9,  2) ^ BUP32(t2_l,  9, 13) ^ BUP32(t1_l,  9, 24) ^
               BDN32(t3_l, 13,  3) ^ BUP32(t2_l, 13, 14) ^ BUP32(t1_l, 13, 25) ^
               BDN32(t3_l, 17,  4) ^ BDN32(t2_l, 17, 15) ^ BUP32(t1_l, 17, 26) ^
               BDN32(t3_l, 21,  5) ^ BDN32(t2_l, 21, 16) ^ BUP32(t1_l, 21, 27) ^
               BDN32(t3_l, 25,  6) ^ BDN32(t2_l, 25, 17) ^ BUP32(t1_l, 25, 28) ^
               BDN32(t3_l, 29,  7) ^ BDN32(t2_l, 29, 18) ^ BCP32(t1_l, 29)     ^
               BUP32(t3_h,  1,  8) ^ BUP32(t2_h,  1, 19) ^ BUP32(t1_h,  1, 30) ^
               BUP32(t3_h,  5,  9) ^ BUP32(t2_h,  5, 20) ^ BUP32(t1_h,  5, 31) ^
               BUP32(t3_h,  9, 10) ^ BUP32(t2_h,  9, 21);
        x2_h = BCP32(t0_l,  1)     ^ BDN32(t0_l,  5,  2) ^ BDN32(t0_l,  9,  3) ^
               BDN32(t0_l, 13,  4) ^ BDN32(t0_l, 17,  5) ^ BDN32(t0_l, 21,  6) ^
               BDN32(t0_l, 25,  7) ^ BDN32(t0_l, 29,  8) ^ BUP32(t0_h,  1,  9) ^
               BUP32(t0_h,  5, 10) ^ BDN32(t1_h,  9,  0) ^ BUP32(t0_h,  9, 11);
        x3_l = BCP32(t3_l,  0)     ^ BUP32(t2_l,  0, 11) ^ BUP32(t1_l,  0, 22) ^
               BDN32(t3_l,  4,  1) ^ BUP32(t2_l,  4, 12) ^ BUP32(t1_l,  4, 23) ^
               BDN32(t3_l,  8,  2) ^ BUP32(t2_l,  8, 13) ^ BUP32(t1_l,  8, 24) ^
               BDN32(t3_l, 12,  3) ^ BUP32(t2_l, 12, 14) ^ BUP32(t1_l, 12, 25) ^
               BDN32(t3_l, 16,  4) ^ BDN32(t2_l, 16, 15) ^ BUP32(t1_l, 16, 26) ^
               BDN32(t3_l, 20,  5) ^ BDN32(t2_l, 20, 16) ^ BUP32(t1_l, 20, 27) ^
               BDN32(t3_l, 24,  6) ^ BDN32(t2_l, 24, 17) ^ BUP32(t1_l, 24, 28) ^
               BDN32(t3_l, 28,  7) ^ BDN32(t2_l, 28, 18) ^ BUP32(t1_l, 28, 29) ^
               BUP32(t3_h,  0,  8) ^ BUP32(t2_h,  0, 19) ^ BUP32(t1_h,  0, 30) ^
               BUP32(t3_h,  4,  9) ^ BUP32(t2_h,  4, 20) ^ BUP32(t1_h,  4, 31) ^
               BUP32(t3_h,  8, 10) ^ BUP32(t2_h,  8, 21);
        x3_h = BUP32(t0_l,  0,  1) ^ BDN32(t0_l,  4,  2) ^ BDN32(t0_l,  8,  3) ^
               BDN32(t0_l, 12,  4) ^ BDN32(t0_l, 16,  5) ^ BDN32(t0_l, 20,  6) ^
               BDN32(t0_l, 24,  7) ^ BDN32(t0_l, 28,  8) ^ BUP32(t0_h,  0,  9) ^
               BUP32(t0_h,  4, 10) ^ BDN32(t1_h,  8,  0) ^ BUP32(t0_h,  8, 11);
    }

    /* Rearrange the nibbles back into the original order */
    t0_l =  (x0_l & 0xFFU) | ((x1_l & 0xFFU) << 8) |
           ((x2_l & 0xFFU) << 16) | ((x3_l & 0xFFU) << 24);
    t1_l = ((x0_l & 0xFF00U) >> 8) | (x1_l & 0xFF00U) |
           ((x2_l & 0xFF00U) << 8) | ((x3_l & 0xFF00U) << 16);
    t2_l = ((x0_l & 0xFF0000U) >> 16) | ((x1_l & 0xFF0000U) >> 8) |
            (x2_l & 0xFF0000U) | ((x3_l & 0xFF0000U) << 8);
    t3_l = ((x0_l & 0xFF000000U) >> 24) | ((x1_l & 0xFF000000U) >> 16) |
           ((x2_l & 0xFF000000U) >> 8) | (x3_l & 0xFF000000U);
    t0_h = (x0_h & 0xFFU) | ((x1_h & 0xFFU) << 8) |
           ((x2_h & 0xFFU) << 16) | ((x3_h & 0xFFU) << 24);
    t1_h = ((x0_h >> 8) & 0xFFU) | (x1_h & 0xFF00U) |
           ((x2_h & 0xFF00U) << 8) | ((x3_h & 0xFF00U) << 16);
    INV_PERM(t0_l);
    INV_PERM(t1_l);
    INV_PERM(t2_l);
    INV_PERM(t3_l);
    INV_PERM(t0_h);
    INV_PERM(t1_h);

    /* Store the local variables back to the state in little-endian order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = t0_l;
    state->W[1] = t1_l;
    state->W[2] = t2_l;
    state->W[3] = t3_l;
    state->W[4] = t0_h;
    state->W[5] = t1_h;
#else
    le_store_word32(state->B,      t0_l);
    le_store_word32(state->B +  4, t1_l);
    le_store_word32(state->B +  8, t2_l);
    le_store_word32(state->B + 12, t3_l);
    le_store_word32(state->B + 16, t0_h);
    le_store_word16(state->B + 20, t1_h); /* Last word is only 16 bits */
#endif
}

#endif /* !SPONGENT_SLICED64 */

#endif /* !SPONGENT_ASM */
