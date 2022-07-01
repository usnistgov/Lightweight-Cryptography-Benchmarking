/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * ART(TK1) -> store
 * load AC(c0 c1) ^ TK3 ^ TK2
 * load TK1
 * calc AC(c0 c1) ^ TK3 ^ TK2 ^ TK1 -> use at (AC->ART)
 * SC->SR->(AC->ART)->MC
 *
 * number of rounds : 40
 */

#include "skinny.h"

/*
 * S-BOX
 */
unsigned char SBOX[512]
= {
    // Original
    0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
    0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
    0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
    0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
    0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
    0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
    0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
    0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
    0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
    0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
    0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
    0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
    0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
    0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
    0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
    0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff,

    // Original ^ c2(0x02)
    0x67, 0x4e, 0x68, 0x40, 0x49, 0x61, 0x41, 0x69, 0x57, 0x77, 0x58, 0x78, 0x51, 0x71, 0x59, 0x79,
    0x37, 0x8e, 0x38, 0x83, 0x8b, 0x31, 0x82, 0x39, 0x97, 0x27, 0x9a, 0x28, 0x92, 0x21, 0x9b, 0x29,
    0xe7, 0xce, 0xea, 0xc3, 0xcb, 0xe2, 0xc2, 0xeb, 0xd7, 0xf7, 0xda, 0xfa, 0xd2, 0xf2, 0xdb, 0xfb,
    0xa7, 0x1e, 0xaa, 0x10, 0x19, 0xa2, 0x11, 0xab, 0x07, 0xb7, 0x08, 0xba, 0x01, 0xb2, 0x09, 0xbb,
    0x30, 0x8a, 0x3e, 0x87, 0x8f, 0x36, 0x86, 0x3f, 0x93, 0x20, 0x9e, 0x2e, 0x96, 0x26, 0x9f, 0x2f,
    0x60, 0x48, 0x6e, 0x47, 0x4f, 0x66, 0x46, 0x6f, 0x50, 0x70, 0x5e, 0x7e, 0x56, 0x76, 0x5f, 0x7f,
    0xa3, 0x18, 0xae, 0x17, 0x1f, 0xa6, 0x16, 0xaf, 0x00, 0xb3, 0x0e, 0xbe, 0x06, 0xb6, 0x0f, 0xbf,
    0xe3, 0xca, 0xee, 0xc7, 0xcf, 0xe6, 0xc6, 0xef, 0xd3, 0xf3, 0xde, 0xfe, 0xd6, 0xf6, 0xdf, 0xff,
    0x34, 0x8c, 0x3a, 0x80, 0x89, 0x32, 0x81, 0x3b, 0x94, 0x24, 0x98, 0x2a, 0x91, 0x22, 0x99, 0x2b,
    0x64, 0x4c, 0x6a, 0x43, 0x4b, 0x62, 0x42, 0x6b, 0x54, 0x74, 0x5a, 0x7a, 0x52, 0x72, 0x5b, 0x7b,
    0xa4, 0x1c, 0xa8, 0x13, 0x1b, 0xa1, 0x12, 0xa9, 0x04, 0xb4, 0x0a, 0xb8, 0x02, 0xb1, 0x0b, 0xb9,
    0xe4, 0xcc, 0xe8, 0xc0, 0xc9, 0xe1, 0xc1, 0xe9, 0xd4, 0xf4, 0xd8, 0xf8, 0xd1, 0xf1, 0xd9, 0xf9,
    0x33, 0x88, 0x3c, 0x84, 0x8d, 0x35, 0x85, 0x3d, 0x90, 0x23, 0x9c, 0x2c, 0x95, 0x25, 0x9d, 0x2d,
    0x63, 0x4a, 0x6c, 0x44, 0x4d, 0x65, 0x45, 0x6d, 0x53, 0x73, 0x5c, 0x7c, 0x55, 0x75, 0x5d, 0x7d,
    0xa0, 0x1a, 0xac, 0x14, 0x1d, 0xa5, 0x15, 0xad, 0x03, 0xb0, 0x0c, 0xbc, 0x05, 0xb5, 0x0d, 0xbd,
    0xe0, 0xc8, 0xec, 0xc4, 0xcd, 0xe5, 0xc5, 0xed, 0xd0, 0xf0, 0xdc, 0xfc, 0xd5, 0xf5, 0xdd, 0xfd,
};

/*
 * Round Constants
 */
unsigned char RC[56]
= {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
    0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04,
    0x09, 0x13, 0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a,};

extern void Encrypt(unsigned char *block, unsigned char *roundKeys, unsigned char *pSBOX) __attribute__((noinline));
extern void RunEncryptionKeyScheduleTK2(unsigned char *roundKeys) __attribute__((noinline));
extern void RunEncryptionKeyScheduleTK3(unsigned char *roundKeys, unsigned char *pRC) __attribute__((noinline));

void skinny_128_384_enc123_12 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
    *((unsigned int *)&pskinny_ctrl->roundKeys[0] ) = *((unsigned int *)&CNT[0]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[4] ) = *((unsigned int *)&CNT[4]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[16]) = *((unsigned int *)&T[0]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[20]) = *((unsigned int *)&T[4]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[24]) = *((unsigned int *)&T[8]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[28]) = *((unsigned int *)&T[12]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[32]) = *((unsigned int *)&K[0]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[36]) = *((unsigned int *)&K[4]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[40]) = *((unsigned int *)&K[8]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[44]) = *((unsigned int *)&K[12]);

    RunEncryptionKeyScheduleTK3(pskinny_ctrl->roundKeys, RC);
    RunEncryptionKeyScheduleTK2(pskinny_ctrl->roundKeys);
    Encrypt(input, pskinny_ctrl->roundKeys, SBOX);

    pskinny_ctrl->func_skinny_128_384_enc = skinny_128_384_enc12_12;
}

void skinny_128_384_enc12_12 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
    (void)K;

    *((unsigned int *)&pskinny_ctrl->roundKeys[0] ) = *((unsigned int *)&CNT[0]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[4] ) = *((unsigned int *)&CNT[4]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[16]) = *((unsigned int *)&T[0]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[20]) = *((unsigned int *)&T[4]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[24]) = *((unsigned int *)&T[8]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[28]) = *((unsigned int *)&T[12]);

    RunEncryptionKeyScheduleTK2(pskinny_ctrl->roundKeys);
    Encrypt(input, pskinny_ctrl->roundKeys, SBOX);
}

extern void skinny_128_384_enc1_1 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
    (void)T;
    (void)K;

    *((unsigned int *)&pskinny_ctrl->roundKeys[0] ) = *((unsigned int *)&CNT[0]);
    *((unsigned int *)&pskinny_ctrl->roundKeys[4] ) = *((unsigned int *)&CNT[4]);

    Encrypt(input, pskinny_ctrl->roundKeys, SBOX);
}

__attribute__((aligned(4)))
void Encrypt(unsigned char *block, unsigned char *roundKeys, unsigned char *pSBOX)
{
    // r0    : ponits to plaintext
    // r1    : points to roundKeys(& masterKey)
    // r2    : points to SBOX
    // r3-r6 : cipher state
    // r7-r12: temp use
    // r14   : temp use
    asm volatile(
        "stmdb    sp!,       {r4-r12,r14}      \n\t"
        "stmdb.w  sp!,       {r0}              \n\t" // push store pointer

// ART(TK1)

        "ldm.w    r1,        {r3-r4}          \n\t" // load master key

    // round 1-2

//        // round key store(do not need)
//        "str.w    r3,        [r1,#0]          \n\t"
//        "str.w    r4,        [r1,#4]          \n\t"

        // premutation

        // r3 ( k3  k2  k1  k0)          --- --- --- ---
        // r4 ( k7  k6  k5  k4)          --- --- --- ---
        // r5 (--- --- --- ---) ----->   k5  k0  k7  k1
        // r6 (--- --- --- ---)          k3  k4  k6  k2
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r5,r4,     #16              \n\t" // r5( k5  k4  k7  k6)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7  k6)
        "pkhtb.w  r6,r3,     r3, asr #16      \n\t" // r6( k3  k2  k3  k2)
        "ror.w    r3,        #8               \n\t" // r3( k0  k3  k2  k1)
        "bfi.w    r5,r3,     #0,#8            \n\t" // r5( k5  k4  k2  k6)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k3  k2)
        "ror.w    r4,#16                      \n\t" // r4( k5  k4  k7  k6)
        "bfi.w    r6,r4,     #8,#8            \n\t" // r6( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r5,        r4               \n\t" // r5( k4  k5  k6  k7)
        "lsl.w    r5,        r5, #8           \n\t" // r5( k5  k6  k7 ---)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7 ---)
        "lsr.w    r3,        r3, #8           \n\t" // r3(---  k3  k2  k1)
        "bfi.w    r5,r3,     #0, #8           \n\t" // r5( k5  k0  k7  k1)
        "rev16.w  r6,        r3               \n\t" // r6( k3 ---  k1  k2)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k1  k2)
        "lsr.w    r4,        r4, #16          \n\t" // r4(--  ---  k7  k6)
        "bfi.w    r6,r4,     #8, #8           \n\t" // r6( k3  k4  k6  k2)
#endif
    // round 3-4

        // round key store
        "str.w    r5,        [r1,#8]          \n\t"
        "str.w    r6,        [r1,#12]         \n\t"

        // premutation

        // r3 (--- --- --- ---)          k5  k0  k7  k1
        // r4 (--- --- --- ---)          k3  k4  k6  k2
        // r5 ( k3  k2  k1  k0) ----->   --- --- --- ---
        // r6 ( k7  k6  k5  k4)          --- --- --- ---
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r3,r6,     #16              \n\t" // r3( k5  k4  k7  k6)
        "bfi.w    r3,r5,     #16,#8           \n\t" // r3( k5  k0  k7  k6)
        "pkhtb.w  r4,r5,     r5, asr #16      \n\t" // r4( k3  k2  k3  k2)
        "ror.w    r5,        #8               \n\t" // r5( k0  k3  k2  k1)
        "bfi.w    r3,r5,     #0,#8            \n\t" // r3( k5  k4  k2  k6)
        "bfi.w    r4,r6,     #16,#8           \n\t" // r4( k3  k4  k3  k2)
        "ror.w    r6,#16                      \n\t" // r6( k5  k4  k7  k6)
        "bfi.w    r4,r6,     #8,#8            \n\t" // r4( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r3,        r6               \n\t" // r3( k4  k5  k6  k7)
        "lsl.w    r3,        r3, #8           \n\t" // r3( k5  k6  k7 ---)
        "bfi.w    r3,r5,     #16,#8           \n\t" // r3( k5  k0  k7 ---)
        "lsr.w    r5,        r5, #8           \n\t" // r5(---  k3  k2  k1)
        "bfi.w    r3,r5,     #0, #8           \n\t" // r3( k5  k0  k7  k1)
        "rev16.w  r4,        r5               \n\t" // r4( k3 ---  k1  k2)
        "bfi.w    r4,r6,     #16,#8           \n\t" // r4( k3  k4  k1  k2)
        "lsr.w    r6,        r6, #16          \n\t" // r6(--  ---  k7  k6)
        "bfi.w    r4,r6,     #8, #8           \n\t" // r4( k3  k4  k6  k2)
#endif

    // round 5-6

        // round key store
        "str.w    r3,        [r1,#16]         \n\t"
        "str.w    r4,        [r1,#20]         \n\t"

        // premutation

        // r3 ( k3  k2  k1  k0)          --- --- --- ---
        // r4 ( k7  k6  k5  k4)          --- --- --- ---
        // r5 (--- --- --- ---) ----->   k5  k0  k7  k1
        // r6 (--- --- --- ---)          k3  k4  k6  k2
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r5,r4,     #16              \n\t" // r5( k5  k4  k7  k6)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7  k6)
        "pkhtb.w  r6,r3,     r3, asr #16      \n\t" // r6( k3  k2  k3  k2)
        "ror.w    r3,        #8               \n\t" // r3( k0  k3  k2  k1)
        "bfi.w    r5,r3,     #0,#8            \n\t" // r5( k5  k4  k2  k6)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k3  k2)
        "ror.w    r4,#16                      \n\t" // r4( k5  k4  k7  k6)
        "bfi.w    r6,r4,     #8,#8            \n\t" // r6( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r5,        r4               \n\t" // r5( k4  k5  k6  k7)
        "lsl.w    r5,        r5, #8           \n\t" // r5( k5  k6  k7 ---)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7 ---)
        "lsr.w    r3,        r3, #8           \n\t" // r3(---  k3  k2  k1)
        "bfi.w    r5,r3,     #0, #8           \n\t" // r5( k5  k0  k7  k1)
        "rev16.w  r6,        r3               \n\t" // r6( k3 ---  k1  k2)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k1  k2)
        "lsr.w    r4,        r4, #16          \n\t" // r4(--  ---  k7  k6)
        "bfi.w    r6,r4,     #8, #8           \n\t" // r6( k3  k4  k6  k2)
#endif
    // round 7-8

        // round key store
        "str.w    r5,        [r1,#24]         \n\t"
        "str.w    r6,        [r1,#28]         \n\t"

        // premutation

        // r3 (--- --- --- ---)          k5  k0  k7  k1
        // r4 (--- --- --- ---)          k3  k4  k6  k2
        // r5 ( k3  k2  k1  k0) ----->   --- --- --- ---
        // r6 ( k7  k6  k5  k4)          --- --- --- ---
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r3,r6,     #16              \n\t" // r3( k5  k4  k7  k6)
        "bfi.w    r3,r5,     #16,#8           \n\t" // r3( k5  k0  k7  k6)
        "pkhtb.w  r4,r5,     r5, asr #16      \n\t" // r4( k3  k2  k3  k2)
        "ror.w    r5,        #8               \n\t" // r5( k0  k3  k2  k1)
        "bfi.w    r3,r5,     #0,#8            \n\t" // r3( k5  k4  k2  k6)
        "bfi.w    r4,r6,     #16,#8           \n\t" // r4( k3  k4  k3  k2)
        "ror.w    r6,#16                      \n\t" // r6( k5  k4  k7  k6)
        "bfi.w    r4,r6,     #8,#8            \n\t" // r4( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r3,        r6               \n\t" // r3( k4  k5  k6  k7)
        "lsl.w    r3,        r3, #8           \n\t" // r3( k5  k6  k7 ---)
        "bfi.w    r3,r5,     #16,#8           \n\t" // r3( k5  k0  k7 ---)
        "lsr.w    r5,        r5, #8           \n\t" // r5(---  k3  k2  k1)
        "bfi.w    r3,r5,     #0, #8           \n\t" // r3( k5  k0  k7  k1)
        "rev16.w  r4,        r5               \n\t" // r4( k3 ---  k1  k2)
        "bfi.w    r4,r6,     #16,#8           \n\t" // r4( k3  k4  k1  k2)
        "lsr.w    r6,        r6, #16          \n\t" // r6(--  ---  k7  k6)
        "bfi.w    r4,r6,     #8, #8           \n\t" // r4( k3  k4  k6  k2)
#endif

    // round 9-10

        // round key store
        "str.w    r3,        [r1,#32]         \n\t"
        "str.w    r4,        [r1,#36]         \n\t"

        // premutation

        // r3 ( k3  k2  k1  k0)          --- --- --- ---
        // r4 ( k7  k6  k5  k4)          --- --- --- ---
        // r5 (--- --- --- ---) ----->   k5  k0  k7  k1
        // r6 (--- --- --- ---)          k3  k4  k6  k2
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r5,r4,     #16              \n\t" // r5( k5  k4  k7  k6)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7  k6)
        "pkhtb.w  r6,r3,     r3, asr #16      \n\t" // r6( k3  k2  k3  k2)
        "ror.w    r3,        #8               \n\t" // r3( k0  k3  k2  k1)
        "bfi.w    r5,r3,     #0,#8            \n\t" // r5( k5  k4  k2  k6)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k3  k2)
        "ror.w    r4,#16                      \n\t" // r4( k5  k4  k7  k6)
        "bfi.w    r6,r4,     #8,#8            \n\t" // r6( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r5,        r4               \n\t" // r5( k4  k5  k6  k7)
        "lsl.w    r5,        r5, #8           \n\t" // r5( k5  k6  k7 ---)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7 ---)
        "lsr.w    r3,        r3, #8           \n\t" // r3(---  k3  k2  k1)
        "bfi.w    r5,r3,     #0, #8           \n\t" // r5( k5  k0  k7  k1)
        "rev16.w  r6,        r3               \n\t" // r6( k3 ---  k1  k2)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k1  k2)
        "lsr.w    r4,        r4, #16          \n\t" // r4(--  ---  k7  k6)
        "bfi.w    r6,r4,     #8, #8           \n\t" // r6( k3  k4  k6  k2)
#endif
    // round 11-12

        // round key store
        "str.w    r5,        [r1,#40]         \n\t"
        "str.w    r6,        [r1,#44]         \n\t"

        // premutation

        // r3 (--- --- --- ---)          k5  k0  k7  k1
        // r4 (--- --- --- ---)          k3  k4  k6  k2
        // r5 ( k3  k2  k1  k0) ----->   --- --- --- ---
        // r6 ( k7  k6  k5  k4)          --- --- --- ---
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r3,r6,     #16              \n\t" // r3( k5  k4  k7  k6)
        "bfi.w    r3,r5,     #16,#8           \n\t" // r3( k5  k0  k7  k6)
        "pkhtb.w  r4,r5,     r5, asr #16      \n\t" // r4( k3  k2  k3  k2)
        "ror.w    r5,        #8               \n\t" // r5( k0  k3  k2  k1)
        "bfi.w    r3,r5,     #0,#8            \n\t" // r3( k5  k4  k2  k6)
        "bfi.w    r4,r6,     #16,#8           \n\t" // r4( k3  k4  k3  k2)
        "ror.w    r6,#16                      \n\t" // r6( k5  k4  k7  k6)
        "bfi.w    r4,r6,     #8,#8            \n\t" // r4( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r3,        r6               \n\t" // r3( k4  k5  k6  k7)
        "lsl.w    r3,        r3, #8           \n\t" // r3( k5  k6  k7 ---)
        "bfi.w    r3,r5,     #16,#8           \n\t" // r3( k5  k0  k7 ---)
        "lsr.w    r5,        r5, #8           \n\t" // r5(---  k3  k2  k1)
        "bfi.w    r3,r5,     #0, #8           \n\t" // r3( k5  k0  k7  k1)
        "rev16.w  r4,        r5               \n\t" // r4( k3 ---  k1  k2)
        "bfi.w    r4,r6,     #16,#8           \n\t" // r4( k3  k4  k1  k2)
        "lsr.w    r6,        r6, #16          \n\t" // r6(--  ---  k7  k6)
        "bfi.w    r4,r6,     #8, #8           \n\t" // r4( k3  k4  k6  k2)
#endif

    // round 13-14

        // round key store
        "str.w    r3,        [r1,#48]         \n\t"
        "str.w    r4,        [r1,#52]         \n\t"

        // premutation

        // r3 ( k3  k2  k1  k0)          --- --- --- ---
        // r4 ( k7  k6  k5  k4)          --- --- --- ---
        // r5 (--- --- --- ---) ----->   k5  k0  k7  k1
        // r6 (--- --- --- ---)          k3  k4  k6  k2
#ifdef STM32F4 // for Cortex-M4
        "ror.w    r5,r4,     #16              \n\t" // r5( k5  k4  k7  k6)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7  k6)
        "pkhtb.w  r6,r3,     r3, asr #16      \n\t" // r6( k3  k2  k3  k2)
        "ror.w    r3,        #8               \n\t" // r3( k0  k3  k2  k1)
        "bfi.w    r5,r3,     #0,#8            \n\t" // r5( k5  k4  k2  k6)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k3  k2)
        "ror.w    r4,#16                      \n\t" // r4( k5  k4  k7  k6)
        "bfi.w    r6,r4,     #8,#8            \n\t" // r6( k3  k4  k6  k2)
#else // for Cortex-M3
        "rev.w    r5,        r4               \n\t" // r5( k4  k5  k6  k7)
        "lsl.w    r5,        r5, #8           \n\t" // r5( k5  k6  k7 ---)
        "bfi.w    r5,r3,     #16,#8           \n\t" // r5( k5  k0  k7 ---)
        "lsr.w    r3,        r3, #8           \n\t" // r3(---  k3  k2  k1)
        "bfi.w    r5,r3,     #0, #8           \n\t" // r5( k5  k0  k7  k1)
        "rev16.w  r6,        r3               \n\t" // r6( k3 ---  k1  k2)
        "bfi.w    r6,r4,     #16,#8           \n\t" // r6( k3  k4  k1  k2)
        "lsr.w    r4,        r4, #16          \n\t" // r4(--  ---  k7  k6)
        "bfi.w    r6,r4,     #8, #8           \n\t" // r6( k3  k4  k6  k2)
#endif
    // round 15-16

        // round key store
        "str.w    r5,        [r1,#56]         \n\t"
        "str.w    r6,        [r1,#60]         \n\t"

        // premutation

        // not need to calculate (not used)

// SC->(AC->ART)->SR->MC

        "add.w    r14,       r2, #256         \n\t" // point to SBOX ^ c2(0x02)

        "ldm.w    r0,        {r3-r6}          \n\t" // load plaintext
                                                    // r0 now free to overwrite

    // round 1

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#0]          \n\t"  // load TK1
        "ldr.w    r10,       [r1,#4]          \n\t"  // load TK1
        "ldr.w    r11,       [r1,#64]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#68]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 2

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#72]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#76]          \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24   \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 3

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#8]          \n\t"  // load TK1
        "ldr.w    r10,       [r1,#12]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#80]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#84]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 4

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#88]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#92]          \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 5

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#16]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#20]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#96]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#100]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 6

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#104]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#108]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 7

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#24]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#28]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#112]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#116]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 8

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#120]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#124]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 9

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#32]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#36]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#128]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#132]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 10

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#136]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#140]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 11

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#40]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#44]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#144]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#148]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 12

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#152]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#156]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 13

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#48]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#52]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#160]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#164]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 14

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#168]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#172]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 15

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#56]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#60]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#176]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#180]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 16

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#184]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#188]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 17

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#0]          \n\t"  // load TK1
        "ldr.w    r10,       [r1,#4]          \n\t"  // load TK1
        "ldr.w    r11,       [r1,#192]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#196]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 18

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#200]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#204]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 19

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#8]          \n\t"  // load TK1
        "ldr.w    r10,       [r1,#12]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#208]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#212]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 20

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#216]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#220]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 21

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#16]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#20]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#224]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#228]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 22

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#232]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#236]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 23

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#24]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#28]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#240]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#244]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 24

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#248]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#252]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 25

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#32]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#36]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#256]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#260]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 26

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#264]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#268]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 27

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#40]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#44]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#272]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#276]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 28

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#280]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#284]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 29

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#48]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#52]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#288]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#292]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 30

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#296]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#300]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 31

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#56]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#60]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#304]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#308]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 32

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#312]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#316]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 33

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#0]          \n\t"  // load TK1
        "ldr.w    r10,       [r1,#4]          \n\t"  // load TK1
        "ldr.w    r11,       [r1,#320]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#324]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 34

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#328]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#332]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 35

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#8]          \n\t"  // load TK1
        "ldr.w    r10,       [r1,#12]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#336]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#340]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 36

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#344]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#348]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 37

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#16]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#20]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#352]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#356]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 38

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#360]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#364]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4
    // round 39

        // SubCell+ShiftRow+AC(c2)
        // r3 (s3  s2  s1  s0)
        // r4 (s7  s6  s5  s4)
        // r5 (s11 s10 s9  s8)
        // r6 (s15 s14 s13 s12)

        // 1st-2nd line
        // r3(s3 s2 s1 s0)
        "uxtb.w   r9,        r3, ror #24      \n\t" // s3
        "uxtb.w   r8,        r3, ror #16      \n\t" // s2
        "uxtb.w   r7,        r3, ror #8       \n\t" // s1
        "uxtb.w   r3,        r3               \n\t" // s0
        // r4(s6 s5 s4 s7)
        "uxtb.w   r12,       r4, ror #16      \n\t" // s6
        "uxtb.w   r11,       r4, ror #8       \n\t" // s5
        "uxtb.w   r10,       r4               \n\t" // s4
        "uxtb.w   r4,        r4, ror #24      \n\t" // s7
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "eor.w    r3,        r3, r7, lsl #8   \n\t"
        "eor.w    r3,        r3, r8, lsl #16  \n\t"
        "eor.w    r3,        r3, r9, lsl #24  \n\t"
        "eor.w    r4,        r4, r10, lsl #8  \n\t"
        "eor.w    r4,        r4, r11, lsl #16 \n\t"
        "eor.w    r4,        r4, r12, lsl #24 \n\t"

        // 3rd-4th line
        // r5(s9 s8 s11 s10)
        "uxtb.w   r9,        r5, ror #8       \n\t" // s9
        "uxtb.w   r8,        r5               \n\t" // s8
        "uxtb.w   r7,        r5, ror #24      \n\t" // s11
        "uxtb.w   r5,        r5, ror #16      \n\t" // s10
        // r6(s12 s15 s14 s13)
        "uxtb.w   r12,       r6               \n\t" // s12
        "uxtb.w   r11,       r6, ror #24      \n\t" // s15
        "uxtb.w   r10,       r6, ror #16      \n\t" // s14
        "uxtb.w   r6,        r6, ror #8       \n\t" // s13
        "ldrb.w   r9,        [r2,r9]          \n\t"
        "ldrb.w   r8,        [r14,r8]         \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r10,       [r2,r10]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "eor.w    r5,        r5, r7, lsl #8   \n\t"
        "eor.w    r5,        r5, r8, lsl #16  \n\t"
        "eor.w    r5,        r5, r9, lsl #24  \n\t"
        "eor.w    r6,        r6, r10, lsl #8  \n\t"
        "eor.w    r6,        r6, r11, lsl #16 \n\t"
        "eor.w    r6,        r6, r12, lsl #24 \n\t"

        // AddRoundKey and AddRoundConst(from roundKeys)
        "ldr.w    r9,        [r1,#24]         \n\t"  // load TK1
        "ldr.w    r10,       [r1,#28]         \n\t"  // load TK1
        "ldr.w    r11,       [r1,#368]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "ldr.w    r12,       [r1,#372]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r11,       r9               \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r12,       r10              \n\t"  // TK1 ^ TK2 ^ TK3 ^ AC(c0 c1)

        "eor.w    r8,        r3, r11          \n\t"  // r3 eor r11 ----------------->  r8( s3  s2  s1  s0)
        "eor.w    r7,        r4, r12, ror 24  \n\t"  // r4 eor (r12 ror 24) -------->  r7( s6  s5  s4  s7)
                                                     //                                r8( s9  s8 s11 s10)
                                                     //                                r6(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r10,       r8, r5           \n\t"  // r8 eor r5 ---------> r10
        "eor.w    r9,        r7, r5           \n\t"  // r7 eor r5 ---------> r9
        "eor.w    r7,        r6, r10          \n\t"  // r6 eor r10 --------> r7
                                                     // r8 ----------------> r8

    // round 40

        // SubCell+ShiftRow+AC(c2)
        // r7 (s3  s2  s1  s0)
        // r8 (s7  s6  s5  s4)
        // r9 (s11 s10 s9  s8)
        // r10(s15 s14 s13 s12)

        // 1st-2nd line
        // r7(s3 s2 s1 s0)
        "uxtb.w   r5,        r7, ror #24      \n\t" // s3
        "uxtb.w   r4,        r7, ror #16      \n\t" // s2
        "uxtb.w   r3,        r7, ror #8       \n\t" // s1
        "uxtb.w   r7,        r7               \n\t" // s0
        // r8(s6 s5 s4 s7)
        "uxtb.w   r12,       r8, ror #16      \n\t" // s6
        "uxtb.w   r11,       r8, ror #8       \n\t" // s5
        "uxtb.w   r6,        r8               \n\t" // s4
        "uxtb.w   r8,        r8, ror #24      \n\t" // s7
        "ldrb.w   r5,        [r2,r5]          \n\t"
        "ldrb.w   r4,        [r2,r4]          \n\t"
        "ldrb.w   r3,        [r2,r3]          \n\t"
        "ldrb.w   r7,        [r2,r7]          \n\t"
        "ldrb.w   r12,       [r2,r12]         \n\t"
        "ldrb.w   r11,       [r2,r11]         \n\t"
        "ldrb.w   r6,        [r2,r6]          \n\t"
        "ldrb.w   r8,        [r2,r8]          \n\t"
        "ldr.w    r0,        [r1,#376]        \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r7,        r7, r3, lsl #8   \n\t"
        "eor.w    r7,        r7, r4, lsl #16  \n\t"
        "eor.w    r7,        r7, r5, lsl #24  \n\t"
        "eor.w    r8,        r8, r6, lsl #8   \n\t"
        "eor.w    r8,        r8, r11, lsl #16 \n\t"
        "eor.w    r8,        r8, r12, lsl #24 \n\t"
        "eor.w    r4,        r7, r0           \n\t"  // r7 eor r0 ----------------->  r4( s3  s2  s1  s0)

        // 3rd-4th line
        // r9(s9 s8 s11 s10)
        "uxtb.w   r5,        r9, ror #8        \n\t" // s9
        "uxtb.w   r7,        r9                \n\t" // s8
        "uxtb.w   r3,        r9, ror #24       \n\t" // s11
        "uxtb.w   r9,        r9, ror #16       \n\t" // s10
        // r10(s12 s15 s14 s13)
        "uxtb.w   r12,       r10               \n\t" // s12
        "uxtb.w   r11,       r10, ror #24      \n\t" // s15
        "uxtb.w   r6,        r10, ror #16      \n\t" // s14
        "uxtb.w   r10,       r10, ror #8       \n\t" // s13
        "ldrb.w   r5,        [r2,r5]           \n\t"
        "ldrb.w   r7,        [r14,r7]          \n\t" // load from SBOX ^ c2(0x02)
        "ldrb.w   r3,        [r2,r3]           \n\t"
        "ldrb.w   r9,        [r2,r9]           \n\t"
        "ldrb.w   r12,       [r2,r12]          \n\t"
        "ldrb.w   r11,       [r2,r11]          \n\t"
        "ldrb.w   r6,        [r2,r6]           \n\t"
        "ldrb.w   r10,       [r2,r10]          \n\t"
        "ldr.w    r0,        [r1,#380]         \n\t"  // load TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w    r9,        r9, r3, lsl #8    \n\t"
        "eor.w    r9,        r9, r7, lsl #16   \n\t"
        "eor.w    r9,        r9, r5, lsl #24   \n\t"
        "eor.w    r10,       r10, r6, lsl #8   \n\t"
        "eor.w    r10,       r10, r11, lsl #16 \n\t"
        "eor.w    r10,       r10, r12, lsl #24 \n\t"
        "eor.w    r3,        r8, r0, ror 24    \n\t"  // r8 eor (r0 ror 24) -------->  r3( s6  s5  s4  s7)

        // AddRoundKey and AddRoundConst(from roundKeys)

                                                     //                                r9( s9  s8 s11 s10)
                                                     //                               r10(s12 s14 s14 s13)

        // MixColumn
        "eor.w    r6,       r4, r9            \n\t"  // r4 eor r9 --------> r6
        "eor.w    r5,       r3, r9            \n\t"  // r3 eor r9 --------> r5
        "eor.w    r3,       r10, r6           \n\t"  // r10 eor r6 --------> r3
                                                     // r4 ----------------> r4

        "ldmia.w  sp!,      {r0}              \n\t" // pop store pointer
                                                    // r0 reload

        "str.w    r3,       [r0,#0]           \n\t" // store ciphertext
        "str.w    r4,       [r0,#4]           \n\t" // store ciphertext
        "str.w    r5,       [r0,#8]           \n\t" // store ciphertext
        "str.w    r6,       [r0,#12]          \n\t" // store ciphertext

        "ldmia.w  sp!,      {r4-r12,r14}      \n\t"
    :
    : [block] "r" (block), [roundKeys] "r" (roundKeys), [pSBOX] "" (pSBOX)
    : "cc");
}

