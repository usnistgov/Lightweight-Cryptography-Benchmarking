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
 * number of rounds : 56
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
        "eor.w      r6,       r2, #0x1          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#512]       \n\t"
        "str.w      r3,       [r0,#516]       \n\t"

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
        "eor.w      r6,       r2, #0x3          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#520]       \n\t"
        "str.w      r3,       [r0,#524]       \n\t"

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
        "eor.w      r6,       r2, #0x7          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#528]       \n\t"
        "str.w      r3,       [r0,#532]       \n\t"

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
        "eor.w      r6,       r2, #0xf          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#536]       \n\t"
        "str.w      r3,       [r0,#540]       \n\t"

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
        "eor.w      r6,       r2, #0xf          \n\t" // k0^rc
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc

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

    // round 6

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xe          \n\t" // k0^rc

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

    // round 7

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xd          \n\t" // k0^rc


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

    // round 8

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xb          \n\t" // k0^rc

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

    // round 9

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x7          \n\t" // k0^rc

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

    // round 10

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xf          \n\t" // k0^rc

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

    // round 11

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xe          \n\t" // k0^rc

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

    // round 12

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xc          \n\t" // k0^rc

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

    // round 13

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x9          \n\t" // k0^rc

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

    // round 14

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x3          \n\t" // k0^rc

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

    // round 15

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x7          \n\t" // k0^rc

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

    // round 16

        // AC(c0 c1)
        "eor.w      r6,       r2, #0xe          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#632]       \n\t"
        "str.w      r3,       [r0,#636]       \n\t"

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
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xd          \n\t" // k0^rc

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

    // round 18

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xa          \n\t" // k0^rc

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

    // round 19

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x5          \n\t" // k0^rc

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

    // round 20

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xb          \n\t" // k0^rc

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

    // round 21

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x6          \n\t" // k0^rc

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

    // round 22

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xc          \n\t" // k0^rc

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

    // round 23

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x8          \n\t" // k0^rc

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

    // round 24

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x0          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#696]       \n\t"
        "str.w      r7,       [r0,#700]       \n\t"

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
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x1          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#704]       \n\t"
        "str.w      r7,       [r0,#708]       \n\t"

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
        "eor.w      r6,       r2, #0x2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#712]       \n\t"
        "str.w      r3,       [r0,#716]       \n\t"

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
        "eor.w      r6,       r2, #0x5          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#720]       \n\t"
        "str.w      r3,       [r0,#724]       \n\t"

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
        "eor.w      r6,       r2, #0xb          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#728]       \n\t"
        "str.w      r3,       [r0,#732]       \n\t"

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
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x7          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#736]       \n\t"
        "str.w      r7,       [r0,#740]       \n\t"

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
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xe          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#744]       \n\t"
        "str.w      r7,       [r0,#748]       \n\t"

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
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xc          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#752]       \n\t"
        "str.w      r7,       [r0,#756]       \n\t"

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
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x8          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#760]       \n\t"
        "str.w      r7,       [r0,#764]       \n\t"

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
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x1          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#768]       \n\t"
        "str.w      r7,       [r0,#772]       \n\t"

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
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x3          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#776]       \n\t"
        "str.w      r7,       [r0,#780]       \n\t"

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
        "eor.w      r6,       r2, #0x6          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#784]       \n\t"
        "str.w      r3,       [r0,#788]       \n\t"

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
        "eor.w      r6,       r2, #0xd          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#792]       \n\t"
        "str.w      r3,       [r0,#796]       \n\t"

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
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xb          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#800]       \n\t"
        "str.w      r7,       [r0,#804]       \n\t"

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
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x6          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#808]       \n\t"
        "str.w      r7,       [r0,#812]       \n\t"

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
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xd          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#816]       \n\t"
        "str.w      r7,       [r0,#820]       \n\t"

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
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0xa          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#824]       \n\t"
        "str.w      r7,       [r0,#828]       \n\t"

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

    // round 41

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x4          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#832]       \n\t"
        "str.w      r7,       [r0,#836]       \n\t"

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

    // round 42

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x9          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#840]       \n\t"
        "str.w      r7,       [r0,#844]       \n\t"

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

    // round 43

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#848]       \n\t"
        "str.w      r7,       [r0,#852]       \n\t"

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

    // round 44

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x4          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#856]       \n\t"
        "str.w      r7,       [r0,#860]       \n\t"

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

    // round 45

        // AC(c0 c1)
        "eor.w      r6,       r2, #0x8          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#864]       \n\t"
        "str.w      r3,       [r0,#868]       \n\t"

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

    // round 46

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x1          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#872]       \n\t"
        "str.w      r7,       [r0,#876]       \n\t"

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

    // round 47

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#880]       \n\t"
        "str.w      r7,       [r0,#884]       \n\t"

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

    // round 48

        // AC(c0 c1)
        "eor.w      r6,       r2, #0x4          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#888]       \n\t"
        "str.w      r3,       [r0,#892]       \n\t"

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

    // round 49

        // AC(c0 c1)
        "eor.w      r6,       r2, #0x9          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#896]       \n\t"
        "str.w      r3,       [r0,#900]       \n\t"

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

    // round 50

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x3          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#904]       \n\t"
        "str.w      r7,       [r0,#908]       \n\t"

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

    // round 51

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x6          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#912]       \n\t"
        "str.w      r7,       [r0,#916]       \n\t"

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

    // round 52

        // AC(c0 c1)
        "eor.w      r6,       r2, #0xc          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#920]       \n\t"
        "str.w      r3,       [r0,#924]       \n\t"

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

    // round 53

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x1          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x9          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#928]       \n\t"
        "str.w      r7,       [r0,#932]       \n\t"

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

    // round 54

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x3          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x2          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#936]       \n\t"
        "str.w      r7,       [r0,#940]       \n\t"

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

    // round 55

        // AC(c0 c1)
        "eor.w      r7,       r3, #0x2          \n\t" // k0^rc
        "eor.w      r6,       r2, #0x5          \n\t" // k0^rc
        // round key store
        "str.w      r6,       [r0,#944]       \n\t"
        "str.w      r7,       [r0,#948]       \n\t"

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

    // round 56

        // AC(c0 c1)
        "eor.w      r6,       r2, #0xa          \n\t" // k0^rc

        // round key store
        "str.w      r6,       [r0,#952]       \n\t"
        "str.w      r3,       [r0,#956]       \n\t"

        // permutation

        // not need to calculate (not used)

        "ldmia.w    sp!,      {r4-r9}         \n\t"
    :
    : [roundKeys] "r" (roundKeys), [pRC] "r" (pRC)
    : "cc");
}
