/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * AC(c0 c1) ^ TK3 -> store
 * ART(TK3)
 *
 * number of rounds : 40
 */

__attribute__((aligned(4)))
void RunEncryptionKeyScheduleTK3(unsigned char *roundKeys, unsigned char *pRC)
{
    // r0    : points to roundKeys(& masterKey)
    // r1    : points to RC
    // r2-r5 : key state
    // r6-r7 : temp use
    // r8    : constant(0x7f7f7f7f)
    // r9    : constant(0x80808080)
    asm volatile(
        "stmdb      sp!,      {r4-r9}         \n\t"
        "ldr.w      r2,       [r0,#32]        \n\t" // load master key
        "ldr.w      r3,       [r0,#36]        \n\t" // load master key
        "ldr.w      r4,       [r0,#40]        \n\t" // load master key
        "ldr.w      r5,       [r0,#44]        \n\t" // load master key
        "mov.w      r8,       #0x7f7f7f7f     \n\t"
        "mov.w      r9,       #0x80808080     \n\t"

    // round 1

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#0]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#384]       \n\t"
        "str.w      r7,       [r0,#388]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 2

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#1]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#392]       \n\t"
        "str.w      r7,       [r0,#396]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 3

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#2]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#400]       \n\t"
        "str.w      r7,       [r0,#404]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 4

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#3]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#408]       \n\t"
        "str.w      r7,       [r0,#412]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 5

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#4]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#416]       \n\t"
        "str.w      r7,       [r0,#420]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 6

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#5]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#424]       \n\t"
        "str.w      r7,       [r0,#428]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 7

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#6]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#432]       \n\t"
        "str.w      r7,       [r0,#436]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 8

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#7]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#440]       \n\t"
        "str.w      r7,       [r0,#444]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 9

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#8]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#448]       \n\t"
        "str.w      r7,       [r0,#452]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 10

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#9]         \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#456]       \n\t"
        "str.w      r7,       [r0,#460]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 11

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#10]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#464]       \n\t"
        "str.w      r7,       [r0,#468]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 12

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#11]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#472]       \n\t"
        "str.w      r7,       [r0,#476]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 13

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#12]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#480]       \n\t"
        "str.w      r7,       [r0,#484]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 14

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#13]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#488]       \n\t"
        "str.w      r7,       [r0,#492]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 15

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#14]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#496]       \n\t"
        "str.w      r7,       [r0,#500]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 16

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#15]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#504]       \n\t"
        "str.w      r7,       [r0,#508]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 17

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#16]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#512]       \n\t"
        "str.w      r7,       [r0,#516]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 18

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#17]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#520]       \n\t"
        "str.w      r7,       [r0,#524]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 19

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#18]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#528]       \n\t"
        "str.w      r7,       [r0,#532]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 20

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#19]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#536]       \n\t"
        "str.w      r7,       [r0,#540]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 21

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#20]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#544]       \n\t"
        "str.w      r7,       [r0,#548]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 22

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#21]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#552]       \n\t"
        "str.w      r7,       [r0,#556]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 23

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#22]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#560]       \n\t"
        "str.w      r7,       [r0,#564]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 24

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#23]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#568]       \n\t"
        "str.w      r7,       [r0,#572]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 25

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#24]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#576]       \n\t"
        "str.w      r7,       [r0,#580]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 26

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#25]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#584]       \n\t"
        "str.w      r7,       [r0,#588]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 27

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#26]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#592]       \n\t"
        "str.w      r7,       [r0,#596]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 28

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#27]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#600]       \n\t"
        "str.w      r7,       [r0,#604]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 29

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#28]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#608]       \n\t"
        "str.w      r7,       [r0,#612]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 30

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#29]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#616]       \n\t"
        "str.w      r7,       [r0,#620]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 31

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#30]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#624]       \n\t"
        "str.w      r7,       [r0,#628]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 32

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#31]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#632]       \n\t"
        "str.w      r7,       [r0,#636]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 33

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#32]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#640]       \n\t"
        "str.w      r7,       [r0,#644]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 34

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#33]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#648]       \n\t"
        "str.w      r7,       [r0,#652]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 35

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#34]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#656]       \n\t"
        "str.w      r7,       [r0,#660]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 36

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#35]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#664]       \n\t"
        "str.w      r7,       [r0,#668]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 37

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#36]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#672]       \n\t"
        "str.w      r7,       [r0,#676]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 38

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#37]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#680]       \n\t"
        "str.w      r7,       [r0,#684]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 39

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#38]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#688]       \n\t"
        "str.w      r7,       [r0,#692]       \n\t"

        // permutation
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6(k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7(k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4(k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5(k7  k6  k5  k4)
#ifdef STM32F4 // for Cortex-M4
        "ror.w      r2,r7,    #16             \n\t" // r2(k13 k12 k15 k14)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13  k8 k15 k14)
        "pkhtb.w    r3,r6,    r6, asr #16     \n\t" // r3(k11 k10 k11 k10)
        "ror.w      r6,       #8              \n\t" // r6( k8 k11 k10  k8)
        "bfi.w      r2,r6,    #0,#8           \n\t" // r2(k13  k8 k15  k9)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k11 k10)
        "ror.w      r7,#16                    \n\t" // r7(k13 k12 k15 k14)
        "bfi.w      r3,r7,    #8,#8           \n\t" // r3(k11 k12 k14 k10)
#else // for Cortex-M3
        "rev.w      r2,       r7              \n\t" // r2(k12 k13 k14 k15)
        "lsl.w      r2,       r2, #8          \n\t" // r2(k13 k14 k15 --)
        "bfi.w      r2,r6,    #16,#8          \n\t" // r2(k13 k8  k15 --)
        "lsr.w      r6,       r6, #8          \n\t" // r6( -- k11 k10 k9)
        "bfi.w      r2,r6,    #0, #8          \n\t" // r2(k13 k8  k15 k9)
        "rev16.w    r3,       r6              \n\t" // r3(k11 --  k9  k10)
        "bfi.w      r3,r7,    #16,#8          \n\t" // r3(k11 k12 k9  k10)
        "lsr.w      r7,       r7, #16         \n\t" // r7 (--  --  k15 k14)
        "bfi.w      r3,r7,    #8, #8          \n\t" // r3(k11 k12 k14 k10)
#endif
        // LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x2 x2 x1)
        "and.w      r6, r8, r2, lsr #1        \n\t"
        "and.w      r7, r9, r2, lsl #7        \n\t"
        "and.w      r2, r9, r2, lsl #1        \n\t"
        "eor.w      r2, r7                    \n\t"
        "eor.w      r2, r6                    \n\t"

        "and.w      r6, r8, r3, lsr #1        \n\t"
        "and.w      r7, r9, r3, lsl #7        \n\t"
        "and.w      r3, r9, r3, lsl #1        \n\t"
        "eor.w      r3, r7                    \n\t"
        "eor.w      r3, r6                    \n\t"

    // round 40

        // AC(c0 c1)
        "ldrb.w     r6,       [r1,#39]        \n\t" // load RC

        "eor.w      r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "and.w      r6,       r6, #0xf        \n\t"
        "eor.w      r6,       r6, r2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#696]       \n\t"
        "str.w      r7,       [r0,#700]       \n\t"

        // permutation

        // not need to calculate (not used)

        "ldmia.w    sp!,      {r4-r9}         \n\t"
    :
    : [roundKeys] "r" (roundKeys), [pRC] "r" (pRC)
    : "cc");
}
