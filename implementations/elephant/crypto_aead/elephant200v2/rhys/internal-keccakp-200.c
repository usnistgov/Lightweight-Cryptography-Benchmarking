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

#include "internal-keccakp-200.h"

/* Determine if Keccak-p[200] should be accelerated with assembly code */
#if defined(__AVR__)
#define KECCAKP_200_ASM 1
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define KECCAKP_200_ASM 1
#else
#define KECCAKP_200_ASM 0
#endif

#if !KECCAKP_200_ASM

#if !defined(LW_UTIL_CPU_IS_64BIT)
/* Define to 1 to select the optimised 32-bit version of Keccak-p[200] */
#define KECCAKP_200_OPT32 1

/* Define to 1 to select the optimised 64-bit version of Keccak-p[200] */
#define KECCAKP_200_OPT64 0
#else
#define KECCAKP_200_OPT32 0
#define KECCAKP_200_OPT64 1
#endif

#if KECCAKP_200_OPT32

/*
 * Optimized version for 32-bit platforms, inspired by the ARMv7 code at:
 *
 * https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-200/ARM/KeccakP-200-armv7m-le-gcc.s
 *
 * Multiple 8-bit lanes are loaded up into 32-bit registers and processed
 * in parallel.
 */

void keccakp_200_permute(keccakp_200_state_t *state)
{
    static uint8_t const RC[18] = {
        0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01, 0x81, 0x09,
        0x8A, 0x88, 0x09, 0x0A, 0x8B, 0x8B, 0x89, 0x03,
        0x02, 0x80
    };
    uint32_t r0_l, r0_r;        /* Left and right halves of row 0 */
    uint32_t r1_l, r1_r;        /* Left and right halves of row 1 */
    uint32_t r2_l, r2_r;        /* Left and right halves of row 2 */
    uint32_t r3_l, r3_r;        /* Left and right halves of row 3 */
    uint32_t r4_l, r4_r;        /* Left and right halves of row 4 */
    uint32_t C_l, C_r;
    unsigned round;

    /* Load the state into the row vectors */
    r0_l = le_load_word32(&(state->A[0][0]));
    r1_l = le_load_word32(&(state->A[1][0]));
    r2_l = le_load_word32(&(state->A[2][0]));
    r3_l = le_load_word32(&(state->A[3][0]));
    r4_l = le_load_word32(&(state->A[4][0]));
    r0_r = state->A[0][4];
    r1_r = state->A[1][4];
    r2_r = state->A[2][4];
    r3_r = state->A[3][4];
    r4_r = state->A[4][4];

    /* Perform all rounds */
    for (round = 0; round < 18; ++round) {
        /* Step mapping theta */
        /*
         * C[index] = state->A[0][index] ^ state->A[1][index] ^
         *            state->A[2][index] ^ state->A[3][index] ^
         *            state->A[4][index];
         */
        C_l = r0_l ^ r1_l ^ r2_l ^ r3_l ^ r4_l;
        C_r = r0_r ^ r1_r ^ r2_r ^ r3_r ^ r4_r;
        /*
         * D = C[(index + 4) % 5] ^ leftRotate1_8(C[(index + 1) % 5])
         */
        C_r = (((C_l & 0x7F7F7F7FUL) >> 7) | ((C_l & 0x80808080UL) >> 15) |
               ((C_r & 0x7FUL) << 25) | ((C_r & 0x80UL) << 17)) ^
              ((C_l << 8) | C_r);
        C_l = (((C_l & 0x7FL) << 1) | ((C_l & 0x80UL) >> 7)) ^ (C_l >> 24);
        /*
         * Apply D to all rows.  The left word of D is in the right word of C.
         */
        r0_l ^= C_r;
        r1_l ^= C_r;
        r2_l ^= C_r;
        r3_l ^= C_r;
        r4_l ^= C_r;
        r0_r ^= C_l;
        r1_r ^= C_l;
        r2_r ^= C_l;
        r3_r ^= C_l;
        r4_r ^= C_l;

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        #define MASK_OFF(col) (~(0xFFUL << (((col) & 3) * 8)))
        #define RHO_PI(dest, destcol, src, srccol, rot) \
            do { \
                C_l = ((src) >> (((srccol) & 3) * 8)) & 0xFFUL; \
                C_l = ((C_l << (rot)) | (C_l >> (8 - (rot)))) & 0xFFUL; \
                (dest) = ((dest) & MASK_OFF((destcol))) | \
                         (C_l << (((destcol) & 3) * 8)); \
            } while (0)
        #define RHO_PI_COPY(dest, destcol, src, srccol) \
            do { \
                C_l = ((src) >> (((srccol) & 3) * 8)) & 0xFFUL; \
                (dest) = ((dest) & MASK_OFF((destcol))) | \
                         (C_l << (((destcol) & 3) * 8)); \
            } while (0)
        /* D = state->A[0][1]; */
        C_r = (r0_l >> 8) & 0xFFUL;
        /* state->A[0][1] = leftRotate4_8(state->A[1][1]); */
        RHO_PI(r0_l, 1, r1_l, 1, 4);
        /* state->A[1][1] = leftRotate4_8(state->A[1][4]); */
        RHO_PI(r1_l, 1, r1_r, 4, 4);
        /* state->A[1][4] = leftRotate5_8(state->A[4][2]); */
        RHO_PI(r1_r, 4, r4_l, 2, 5);
        /* state->A[4][2] = leftRotate7_8(state->A[2][4]); */
        RHO_PI(r4_l, 2, r2_r, 4, 7);
        /* state->A[2][4] = leftRotate2_8(state->A[4][0]); */
        RHO_PI(r2_r, 4, r4_l, 0, 2);
        /* state->A[4][0] = leftRotate6_8(state->A[0][2]); */
        RHO_PI(r4_l, 0, r0_l, 2, 6);
        /* state->A[0][2] = leftRotate3_8(state->A[2][2]); */
        RHO_PI(r0_l, 2, r2_l, 2, 3);
        /* state->A[2][2] = leftRotate1_8(state->A[2][3]); */
        RHO_PI(r2_l, 2, r2_l, 3, 1);
        /* state->A[2][3] = state->A[3][4]; */
        RHO_PI_COPY(r2_l, 3, r3_r, 4);
        /* state->A[3][4] = state->A[4][3]; */
        RHO_PI_COPY(r3_r, 4, r4_l, 3);
        /* state->A[4][3] = leftRotate1_8(state->A[3][0]); */
        RHO_PI(r4_l, 3, r3_l, 0, 1);
        /* state->A[3][0] = leftRotate3_8(state->A[0][4]); */
        RHO_PI(r3_l, 0, r0_r, 4, 3);
        /* state->A[0][4] = leftRotate6_8(state->A[4][4]); */
        RHO_PI(r0_r, 4, r4_r, 4, 6);
        /* state->A[4][4] = leftRotate2_8(state->A[4][1]); */
        RHO_PI(r4_r, 4, r4_l, 1, 2);
        /* state->A[4][1] = leftRotate7_8(state->A[1][3]); */
        RHO_PI(r4_l, 1, r1_l, 3, 7);
        /* state->A[1][3] = leftRotate5_8(state->A[3][1]); */
        RHO_PI(r1_l, 3, r3_l, 1, 5);
        /* state->A[3][1] = leftRotate4_8(state->A[1][0]); */
        RHO_PI(r3_l, 1, r1_l, 0, 4);
        /* state->A[1][0] = leftRotate4_8(state->A[0][3]); */
        RHO_PI(r1_l, 0, r0_l, 3, 4);
        /* state->A[0][3] = leftRotate5_8(state->A[3][3]); */
        RHO_PI(r0_l, 3, r3_l, 3, 5);
        /* state->A[3][3] = leftRotate7_8(state->A[3][2]); */
        RHO_PI(r3_l, 3, r3_l, 2, 7);
        /* state->A[3][2] = leftRotate2_8(state->A[2][1]); */
        RHO_PI(r3_l, 2, r2_l, 1, 2);
        /* state->A[2][1] = leftRotate6_8(state->A[1][2]); */
        RHO_PI(r2_l, 1, r1_l, 2, 6);
        /* state->A[1][2] = leftRotate3_8(state->A[2][0]); */
        RHO_PI(r1_l, 2, r2_l, 0, 3);
        /* state->A[2][0] = leftRotate1_8(D); */
        r2_l = (r2_l & 0xFFFFFF00UL) | (((C_r << 1) | (C_r >> 7)) & 0xFFUL);

        /* Step mapping chi.  Combine each lane with two others in its row */
        /*
         * for (index = 0; index < 5; ++index) {
         *     C[0] = state->A[index][0];
         *     C[1] = state->A[index][1];
         *     C[2] = state->A[index][2];
         *     C[3] = state->A[index][3];
         *     C[4] = state->A[index][4];
         *     for (index2 = 0; index2 < 5; ++index2) {
         *         state->A[index][index2] =
         *             C[index2] ^
         *             ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
         *     }
         * }
         */
        #define CHI(rl, rr) \
            do { \
                C_l = (~(((rl) >> 8) | ((rr) << 24))) & \
                      (((rl) >> 16) | ((rl) << 24) | ((rr) << 16)); \
                C_r = ((~(rl)) & ((rl) >> 8)) & 0xFFUL; \
                (rl) ^= C_l; \
                (rr) ^= C_r; \
            } while (0)
        CHI(r0_l, r0_r);
        CHI(r1_l, r1_r);
        CHI(r2_l, r2_r);
        CHI(r3_l, r3_r);
        CHI(r4_l, r4_r);

        /* Step mapping iota.  XOR A[0][0] with the round constant */
        r0_l ^= RC[round];
    }

    /* Write the row vectors back to the state */
    le_store_word32(&(state->A[0][0]), r0_l);
    le_store_word32(&(state->A[1][0]), r1_l);
    le_store_word32(&(state->A[2][0]), r2_l);
    le_store_word32(&(state->A[3][0]), r3_l);
    le_store_word32(&(state->A[4][0]), r4_l);
    state->A[0][4] = (unsigned char)r0_r;
    state->A[1][4] = (unsigned char)r1_r;
    state->A[2][4] = (unsigned char)r2_r;
    state->A[3][4] = (unsigned char)r3_r;
    state->A[4][4] = (unsigned char)r4_r;
}

#elif KECCAKP_200_OPT64

/*
 * Optimized version for 64-bit platforms, inspired by the ARMv7 code at:
 *
 * https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-200/ARM/KeccakP-200-armv7m-le-gcc.s
 *
 * Multiple 8-bit lanes are loaded up into 64-bit registers and processed
 * in parallel.
 */

/* Load a little-endian 40-bit word from a byte buffer */
#define le_load_word40(ptr) \
    ((((uint64_t)((ptr)[4])) << 32) | \
     (((uint64_t)((ptr)[3])) << 24) | \
     (((uint64_t)((ptr)[2])) << 16) | \
     (((uint64_t)((ptr)[1])) << 8) | \
      ((uint64_t)((ptr)[0])))

/* Store a little-endian 40-bit word into a byte buffer */
#define le_store_word40(ptr, x) \
    do { \
        (ptr)[0] = (uint8_t)(x); \
        (ptr)[1] = (uint8_t)((x) >> 8); \
        (ptr)[2] = (uint8_t)((x) >> 16); \
        (ptr)[3] = (uint8_t)((x) >> 24); \
        (ptr)[4] = (uint8_t)((x) >> 32); \
    } while (0)

void keccakp_200_permute(keccakp_200_state_t *state)
{
    static uint8_t const RC[18] = {
        0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01, 0x81, 0x09,
        0x8A, 0x88, 0x09, 0x0A, 0x8B, 0x8B, 0x89, 0x03,
        0x02, 0x80
    };
    uint64_t r0, r1, r2, r3, r4;
    uint64_t C, D;
    unsigned round;

    /* Load the state into the row vectors */
    r0 = le_load_word40(&(state->A[0][0]));
    r1 = le_load_word40(&(state->A[1][0]));
    r2 = le_load_word40(&(state->A[2][0]));
    r3 = le_load_word40(&(state->A[3][0]));
    r4 = le_load_word40(&(state->A[4][0]));

    /* Perform all rounds */
    for (round = 0; round < 18; ++round) {
        /* Step mapping theta */
        /*
         * C[index] = state->A[0][index] ^ state->A[1][index] ^
         *            state->A[2][index] ^ state->A[3][index] ^
         *            state->A[4][index];
         */
        C = r0 ^ r1 ^ r2 ^ r3 ^ r4;
        /*
         * D = C[(index + 4) % 5] ^ leftRotate1_8(C[(index + 1) % 5])
         */
        D = ((C & 0x7F7F7F7F7FULL) << 1) | ((C & 0x8080808080ULL) >> 7);
        D = (D >> 8) | (D << 32);
        D ^= (C << 8) ^ (C >> 32);
        D &= 0xFFFFFFFFFFULL;
        /*
         * Apply D to all rows.
         */
        r0 ^= D;
        r1 ^= D;
        r2 ^= D;
        r3 ^= D;
        r4 ^= D;

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        #define MASK_OFF(col) (~(0xFFULL << ((col) * 8)))
        #define RHO_PI(dest, destcol, src, srccol, rot) \
            do { \
                C = ((src) >> ((srccol) * 8)) & 0xFFULL; \
                C = ((C << (rot)) | (C >> (8 - (rot)))) & 0xFFULL; \
                (dest) = ((dest) & MASK_OFF((destcol))) | \
                         (C << ((destcol) * 8)); \
            } while (0)
        #define RHO_PI_COPY(dest, destcol, src, srccol) \
            do { \
                C = ((src) >> ((srccol) * 8)) & 0xFFULL; \
                (dest) = ((dest) & MASK_OFF((destcol))) | \
                         (C << ((destcol) * 8)); \
            } while (0)
        /* D = state->A[0][1]; */
        D = (r0 >> 8) & 0xFFULL;
        /* state->A[0][1] = leftRotate4_8(state->A[1][1]); */
        RHO_PI(r0, 1, r1, 1, 4);
        /* state->A[1][1] = leftRotate4_8(state->A[1][4]); */
        RHO_PI(r1, 1, r1, 4, 4);
        /* state->A[1][4] = leftRotate5_8(state->A[4][2]); */
        RHO_PI(r1, 4, r4, 2, 5);
        /* state->A[4][2] = leftRotate7_8(state->A[2][4]); */
        RHO_PI(r4, 2, r2, 4, 7);
        /* state->A[2][4] = leftRotate2_8(state->A[4][0]); */
        RHO_PI(r2, 4, r4, 0, 2);
        /* state->A[4][0] = leftRotate6_8(state->A[0][2]); */
        RHO_PI(r4, 0, r0, 2, 6);
        /* state->A[0][2] = leftRotate3_8(state->A[2][2]); */
        RHO_PI(r0, 2, r2, 2, 3);
        /* state->A[2][2] = leftRotate1_8(state->A[2][3]); */
        RHO_PI(r2, 2, r2, 3, 1);
        /* state->A[2][3] = state->A[3][4]; */
        RHO_PI_COPY(r2, 3, r3, 4);
        /* state->A[3][4] = state->A[4][3]; */
        RHO_PI_COPY(r3, 4, r4, 3);
        /* state->A[4][3] = leftRotate1_8(state->A[3][0]); */
        RHO_PI(r4, 3, r3, 0, 1);
        /* state->A[3][0] = leftRotate3_8(state->A[0][4]); */
        RHO_PI(r3, 0, r0, 4, 3);
        /* state->A[0][4] = leftRotate6_8(state->A[4][4]); */
        RHO_PI(r0, 4, r4, 4, 6);
        /* state->A[4][4] = leftRotate2_8(state->A[4][1]); */
        RHO_PI(r4, 4, r4, 1, 2);
        /* state->A[4][1] = leftRotate7_8(state->A[1][3]); */
        RHO_PI(r4, 1, r1, 3, 7);
        /* state->A[1][3] = leftRotate5_8(state->A[3][1]); */
        RHO_PI(r1, 3, r3, 1, 5);
        /* state->A[3][1] = leftRotate4_8(state->A[1][0]); */
        RHO_PI(r3, 1, r1, 0, 4);
        /* state->A[1][0] = leftRotate4_8(state->A[0][3]); */
        RHO_PI(r1, 0, r0, 3, 4);
        /* state->A[0][3] = leftRotate5_8(state->A[3][3]); */
        RHO_PI(r0, 3, r3, 3, 5);
        /* state->A[3][3] = leftRotate7_8(state->A[3][2]); */
        RHO_PI(r3, 3, r3, 2, 7);
        /* state->A[3][2] = leftRotate2_8(state->A[2][1]); */
        RHO_PI(r3, 2, r2, 1, 2);
        /* state->A[2][1] = leftRotate6_8(state->A[1][2]); */
        RHO_PI(r2, 1, r1, 2, 6);
        /* state->A[1][2] = leftRotate3_8(state->A[2][0]); */
        RHO_PI(r1, 2, r2, 0, 3);
        /* state->A[2][0] = leftRotate1_8(D); */
        r2 = (r2 & MASK_OFF(0)) | (((D << 1) | (D >> 7)) & 0xFFULL);

        /* Step mapping chi.  Combine each lane with two others in its row */
        /*
         * for (index = 0; index < 5; ++index) {
         *     C[0] = state->A[index][0];
         *     C[1] = state->A[index][1];
         *     C[2] = state->A[index][2];
         *     C[3] = state->A[index][3];
         *     C[4] = state->A[index][4];
         *     for (index2 = 0; index2 < 5; ++index2) {
         *         state->A[index][index2] =
         *             C[index2] ^
         *             ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
         *     }
         * }
         */
        r0 = r0 ^ ((~((r0 >> 8) | (r0 << 32))) & ((r0 >> 16) | (r0 << 24)));
        r1 = r1 ^ ((~((r1 >> 8) | (r1 << 32))) & ((r1 >> 16) | (r1 << 24)));
        r2 = r2 ^ ((~((r2 >> 8) | (r2 << 32))) & ((r2 >> 16) | (r2 << 24)));
        r3 = r3 ^ ((~((r3 >> 8) | (r3 << 32))) & ((r3 >> 16) | (r3 << 24)));
        r4 = r4 ^ ((~((r4 >> 8) | (r4 << 32))) & ((r4 >> 16) | (r4 << 24)));

        /* Step mapping iota.  XOR A[0][0] with the round constant
         * and restrict the 64-bit registers back to 40-bit values */
        r0 = (r0 & 0xFFFFFFFFFFULL) ^ RC[round];
        r1 &= 0xFFFFFFFFFFULL;
        r2 &= 0xFFFFFFFFFFULL;
        r3 &= 0xFFFFFFFFFFULL;
        r4 &= 0xFFFFFFFFFFULL;
    }

    /* Write the row vectors back to the state */
    le_store_word40(&(state->A[0][0]), r0);
    le_store_word40(&(state->A[1][0]), r1);
    le_store_word40(&(state->A[2][0]), r2);
    le_store_word40(&(state->A[3][0]), r3);
    le_store_word40(&(state->A[4][0]), r4);
}

#else /* !KECCAKP_200_OPT32 && !KECCAKP_200_OPT64 */

/* Faster method to compute ((x + y) % 5) that avoids the division */
static unsigned char const addMod5Table[9] = {
    0, 1, 2, 3, 4, 0, 1, 2, 3
};
#define addMod5(x, y) (addMod5Table[(x) + (y)])

void keccakp_200_permute(keccakp_200_state_t *state)
{
    static uint8_t const RC[18] = {
        0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01, 0x81, 0x09,
        0x8A, 0x88, 0x09, 0x0A, 0x8B, 0x8B, 0x89, 0x03,
        0x02, 0x80
    };
    uint8_t C[5];
    uint8_t D;
    unsigned round;
    unsigned index, index2;
    for (round = 0; round < 18; ++round) {
        /* Step mapping theta.  The specification mentions two temporary
         * arrays of size 5 called C and D.  Compute D on the fly */
        for (index = 0; index < 5; ++index) {
            C[index] = state->A[0][index] ^ state->A[1][index] ^
                       state->A[2][index] ^ state->A[3][index] ^
                       state->A[4][index];
        }
        for (index = 0; index < 5; ++index) {
            D = C[addMod5(index, 4)] ^
                leftRotate1_8(C[addMod5(index, 1)]);
            for (index2 = 0; index2 < 5; ++index2)
                state->A[index2][index] ^= D;
        }

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        D = state->A[0][1];
        state->A[0][1] = leftRotate4_8(state->A[1][1]);
        state->A[1][1] = leftRotate4_8(state->A[1][4]);
        state->A[1][4] = leftRotate5_8(state->A[4][2]);
        state->A[4][2] = leftRotate7_8(state->A[2][4]);
        state->A[2][4] = leftRotate2_8(state->A[4][0]);
        state->A[4][0] = leftRotate6_8(state->A[0][2]);
        state->A[0][2] = leftRotate3_8(state->A[2][2]);
        state->A[2][2] = leftRotate1_8(state->A[2][3]);
        state->A[2][3] = state->A[3][4];
        state->A[3][4] = state->A[4][3];
        state->A[4][3] = leftRotate1_8(state->A[3][0]);
        state->A[3][0] = leftRotate3_8(state->A[0][4]);
        state->A[0][4] = leftRotate6_8(state->A[4][4]);
        state->A[4][4] = leftRotate2_8(state->A[4][1]);
        state->A[4][1] = leftRotate7_8(state->A[1][3]);
        state->A[1][3] = leftRotate5_8(state->A[3][1]);
        state->A[3][1] = leftRotate4_8(state->A[1][0]);
        state->A[1][0] = leftRotate4_8(state->A[0][3]);
        state->A[0][3] = leftRotate5_8(state->A[3][3]);
        state->A[3][3] = leftRotate7_8(state->A[3][2]);
        state->A[3][2] = leftRotate2_8(state->A[2][1]);
        state->A[2][1] = leftRotate6_8(state->A[1][2]);
        state->A[1][2] = leftRotate3_8(state->A[2][0]);
        state->A[2][0] = leftRotate1_8(D);

        /* Step mapping chi.  Combine each lane with two others in its row */
        for (index = 0; index < 5; ++index) {
            C[0] = state->A[index][0];
            C[1] = state->A[index][1];
            C[2] = state->A[index][2];
            C[3] = state->A[index][3];
            C[4] = state->A[index][4];
            for (index2 = 0; index2 < 5; ++index2) {
                state->A[index][index2] =
                    C[index2] ^
                    ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
            }
        }

        /* Step mapping iota.  XOR A[0][0] with the round constant */
        state->A[0][0] ^= RC[round];
    }
}

#endif /* !KECCAKP_200_OPT32 && !KECCAKP_200_OPT64 */

#endif /* !KECCAKP_200_ASM */
