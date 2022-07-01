/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * load * AC(c0 c1) ^ TK3
 * calc AC(c0 c1) ^ TK2 -> store
 * ART(TK2)
 *
 * number of rounds : 40
 */

__attribute__((aligned(4)))
void RunEncryptionKeyScheduleTK2(unsigned char *roundKeys)
{
    // r0    : points to roundKeys(& masterKey)
    // r1-r4 : key state
    // r5-r6 : temp use
    // r7    : constant(0xfefefefe)
    // r8    : constant(0x01010101)
    // r9    : temp use
    // r10   : temp use
    asm volatile(
        "stmdb      sp!,      {r4-r10}        \n\t"
        "ldr.w      r1,       [r0,#16]        \n\t" // load master key
        "ldr.w      r2,       [r0,#20]        \n\t" // load master key
        "ldr.w      r3,       [r0,#24]        \n\t" // load master key
        "ldr.w      r4,       [r0,#28]        \n\t" // load master key
        "mov.w      r7,       #0xfefefefe     \n\t"
        "mov.w      r8,       #0x01010101     \n\t"

   // round 1

        "ldr.w      r9,       [r0,#384]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#388]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#64]        \n\t"
        "str.w      r10,      [r0,#68]        \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 2

        "ldr.w      r9,       [r0,#392]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#396]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#72]        \n\t"
        "str.w      r10,      [r0,#76]        \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 3

        "ldr.w      r9,       [r0,#400]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#404]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#80]        \n\t"
        "str.w      r10,      [r0,#84]        \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 4

        "ldr.w      r9,       [r0,#408]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#412]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#88]        \n\t"
        "str.w      r10,      [r0,#92]        \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 5

        "ldr.w      r9,       [r0,#416]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#420]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#96]        \n\t"
        "str.w      r10,      [r0,#100]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 6

        "ldr.w      r9,       [r0,#424]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#428]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#104]       \n\t"
        "str.w      r10,      [r0,#108]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 7

        "ldr.w      r9,       [r0,#432]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#436]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#112]       \n\t"
        "str.w      r10,      [r0,#116]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 8

        "ldr.w      r9,       [r0,#440]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#444]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#120]       \n\t"
        "str.w      r10,      [r0,#124]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 9

        "ldr.w      r9,       [r0,#448]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#452]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#128]       \n\t"
        "str.w      r10,      [r0,#132]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 10

        "ldr.w      r9,       [r0,#456]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#460]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#136]       \n\t"
        "str.w      r10,      [r0,#140]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 11

        "ldr.w      r9,       [r0,#464]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#468]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#144]       \n\t"
        "str.w      r10,      [r0,#148]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 12

        "ldr.w      r9,       [r0,#472]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#476]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#152]       \n\t"
        "str.w      r10,      [r0,#156]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 13

        "ldr.w      r9,       [r0,#480]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#484]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#160]       \n\t"
        "str.w      r10,      [r0,#164]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 14

        "ldr.w      r9,       [r0,#488]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#492]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#168]       \n\t"
        "str.w      r10,      [r0,#172]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 15

        "ldr.w      r9,       [r0,#496]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#500]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#176]       \n\t"
        "str.w      r10,      [r0,#180]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 16

        "ldr.w      r9,       [r0,#504]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#508]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#184]       \n\t"
        "str.w      r10,      [r0,#188]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 17

        "ldr.w      r9,       [r0,#512]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#516]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#192]       \n\t"
        "str.w      r10,      [r0,#196]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 18

        "ldr.w      r9,       [r0,#520]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#524]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#200]       \n\t"
        "str.w      r10,      [r0,#204]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 19

        "ldr.w      r9,       [r0,#528]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#532]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#208]       \n\t"
        "str.w      r10,      [r0,#212]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 20

        "ldr.w      r9,       [r0,#536]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#540]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#216]       \n\t"
        "str.w      r10,      [r0,#220]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 21

        "ldr.w      r9,       [r0,#544]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#548]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#224]       \n\t"
        "str.w      r10,      [r0,#228]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 22

        "ldr.w      r9,       [r0,#552]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#556]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#232]       \n\t"
        "str.w      r10,      [r0,#236]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 23

        "ldr.w      r9,       [r0,#560]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#564]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#240]       \n\t"
        "str.w      r10,      [r0,#244]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 24

        "ldr.w      r9,       [r0,#568]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#572]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#248]       \n\t"
        "str.w      r10,      [r0,#252]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 25

        "ldr.w      r9,       [r0,#576]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#580]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#256]       \n\t"
        "str.w      r10,      [r0,#260]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 26

        "ldr.w      r9,       [r0,#584]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#588]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#264]       \n\t"
        "str.w      r10,      [r0,#268]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 27

        "ldr.w      r9,       [r0,#592]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#596]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#272]       \n\t"
        "str.w      r10,      [r0,#276]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 28

        "ldr.w      r9,       [r0,#600]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#604]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#280]       \n\t"
        "str.w      r10,      [r0,#284]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 29

        "ldr.w      r9,       [r0,#608]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#612]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#288]       \n\t"
        "str.w      r10,      [r0,#292]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 30

        "ldr.w      r9,       [r0,#616]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#620]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#296]       \n\t"
        "str.w      r10,      [r0,#300]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 31

        "ldr.w      r9,       [r0,#624]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#628]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#304]       \n\t"
        "str.w      r10,      [r0,#308]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 32

        "ldr.w      r9,       [r0,#632]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#636]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#312]       \n\t"
        "str.w      r10,      [r0,#316]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 33

        "ldr.w      r9,       [r0,#640]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#644]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#320]       \n\t"
        "str.w      r10,      [r0,#324]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 34

        "ldr.w      r9,       [r0,#648]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#652]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#328]       \n\t"
        "str.w      r10,      [r0,#332]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 35

        "ldr.w      r9,       [r0,#656]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#660]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#336]       \n\t"
        "str.w      r10,      [r0,#340]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 36

        "ldr.w      r9,       [r0,#664]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#668]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#344]       \n\t"
        "str.w      r10,      [r0,#348]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 37

        "ldr.w      r9,       [r0,#672]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#676]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#352]       \n\t"
        "str.w      r10,      [r0,#356]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 38

        "ldr.w      r9,       [r0,#680]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#684]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#360]       \n\t"
        "str.w      r10,      [r0,#364]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 39

        "ldr.w      r9,       [r0,#688]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#692]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#368]       \n\t"
        "str.w      r10,      [r0,#372]       \n\t"

        // permutation
        // r1 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r2 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r3 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r4 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r5,       r3              \n\t" // r5(k11 k10 k9  k8 )
        "mov        r6,       r4              \n\t" // r6(k15 k14 k13 k12)
        "mov        r3,       r1              \n\t" // r3(k3  k2  k1  k0)
        "mov        r4,       r2              \n\t" // r4(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r1,r6,    #16             \n\t" // r1(k13 k12 k15 k14)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13  k8 k15 k14)
        "pkhtb.w    r2,r5,    r5, asr #16     \n\t" // r2(k11 k10 k11 k10)
        "ror.w      r5,       #8              \n\t" // r5( k8 k11 k10  k8)
        "bfi.w      r1,r5,    #0,#8           \n\t" // r1(k13  k8 k15  k9)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k11 k10)
        "ror.w      r6,#16                    \n\t" // r6(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #8,#8           \n\t" // r2(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r1,       r6              \n\t" // r1(k12 k13 k14 k15)
        "lsl.w      r1,       r1, #8          \n\t" // r1(k13 k14 k15 --)
        "bfi.w      r1,r5,    #16,#8          \n\t" // r1(k13 k8  k15 --)
        "lsr.w      r5,       r5, #8          \n\t" // r5( -- k11 k10 k9)
        "bfi.w      r1,r5,    #0, #8          \n\t" // r1(k13 k8  k15 k9)
        "rev16.w    r2,       r5              \n\t" // r2(k11 --  k9  k10)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k11 k12 k9  k10)
        "lsr.w      r6,       r6, #16         \n\t" // r6(--  --  k15 k14)
        "bfi.w      r2,r6,    #8, #8          \n\t" // r2(k11 k12 k14 k10)
#endif
        // LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x6)
        "and.w      r5, r7, r1, lsl #1        \n\t"
        "and.w      r6, r8, r1, lsr #7        \n\t"
        "and.w      r1, r8, r1, lsr #5        \n\t"
        "eor.w      r1, r6                    \n\t"
        "eor.w      r1, r5                    \n\t"

        "and.w      r5, r7, r2, lsl #1        \n\t"
        "and.w      r6, r8, r2, lsr #7        \n\t"
        "and.w      r2, r8, r2, lsr #5        \n\t"
        "eor.w      r2, r6                    \n\t"
        "eor.w      r2, r5                    \n\t"

    // round 40

        "ldr.w      r9,       [r0,#696]       \n\t"  // load TK3 ^ AC(c0 c1)
        "ldr.w      r10,      [r0,#700]       \n\t"  // load TK3 ^ AC(c0 c1)

        "eor.w      r9,       r1              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)
        "eor.w      r10,      r2              \n\t"  // TK2 ^ TK3 ^ AC(c0 c1)

        // round key store((TK2 ^ TK3 ^ AC(c0 c1))
        "str.w      r9,       [r0,#376]       \n\t"
        "str.w      r10,      [r0,#380]       \n\t"

        // permutation

        // not need to calculate (not used)

        "ldmia.w    sp!,      {r4-r10}        \n\t"
    :
    : [roundKeys] "r" (roundKeys)
    : "cc");
}
