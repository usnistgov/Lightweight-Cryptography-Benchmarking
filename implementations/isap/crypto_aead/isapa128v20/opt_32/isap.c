#include "api.h"
#include "isap.h"
#include "asconp.h"

const u8 ISAP_IV_A[] = {0x01, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
const u8 ISAP_IV_KA[] = {0x02, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
const u8 ISAP_IV_KE[] = {0x03, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};

#define P_sB PX(12,&x0,&x1,&x2,&x3,&x4)
#define P_sE PX(12,&x0,&x1,&x2,&x3,&x4)
#define P_sH PX(12,&x0,&x1,&x2,&x3,&x4)
#define P_sK PX(12,&x0,&x1,&x2,&x3,&x4)

/******************************************************************************/
/*                                 ISAP_RK                                    */
/******************************************************************************/

void isap_rk(
    const u8 *k,
    const u8 *iv,
    const u8 *y,
    u8 *out,
    const u8 outlen)
{
    // State variables
    u32_2 x0, x1, x2, x3, x4;

    // Initialize
    to_bit_interleaving(&x0, U64BIG(*(u64 *)(k + 0)));
    to_bit_interleaving(&x1, U64BIG(*(u64 *)(k + 8)));
    to_bit_interleaving(&x2, U64BIG(*(u64 *)(iv + 0)));
    x3.o = 0;
    x3.e = 0;
    x4.o = 0;
    x4.e = 0;
    P_sK;

    // Absorb Y, bit by bit
    for (u8 i = 0; i < 127; i++) {
        u8 cur_byte_pos = i / 8;
        u8 cur_bit_pos = 7 - (i % 8);
        u32 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
        x0.o ^= ((u32)cur_bit) << 24;
        P_sB;
    }
    u8 cur_bit = ((y[15]) & 0x01) << 7;
    x0.o ^= ((u32)cur_bit) << (24);

    // Squeeze - Derive K*
    P_sK;
    *(u32 *)(out + 0) = x0.o;
    *(u32 *)(out + 4) = x0.e;
    *(u32 *)(out + 8) = x1.o;
    *(u32 *)(out + 12) = x1.e;
    if (outlen > 16) {
        *(u32 *)(out + 16) = x2.o;
        *(u32 *)(out + 20) = x2.e;
    }
}

/******************************************************************************/
/*                                 ISAP_MAC                                   */
/******************************************************************************/

void isap_mac(
    const u8 *k,
    const u8 *npub,
    const u8 *ad, u64 adlen,
    const u8 *c, u64 clen,
    u8 *tag)
{
    // State and temporary variables
    u32_2 x0, x1, x2, x3, x4;
    u32_2 t0;
    u64 tmp0;

    // Initialize
    to_bit_interleaving(&x0, U64BIG(*(u64 *)npub + 0));
    to_bit_interleaving(&x1, U64BIG(*(u64 *)(npub + 8)));
    to_bit_interleaving(&x2, U64BIG(*(u64 *)(ISAP_IV_A)));
    x3.o = 0;
    x3.e = 0;
    x4.o = 0;
    x4.e = 0;
    P_sH;

    // Absorb full lanes of AD
    while (adlen >= 8)
    {
        to_bit_interleaving(&t0, U64BIG(*(u64 *)ad));
        x0.e ^= t0.e;
        x0.o ^= t0.o;
        adlen -= ISAP_rH / 8;
        ad += ISAP_rH / 8;
        P_sH;
    }

    // Absorb partial lane of AD and add padding
    if (adlen > 0)
    {
        tmp0 = 0;
        u8 *tmp0_bytes = (u8 *)&tmp0;
        u8 i;
        for (i = 0; i < adlen; i++)
        {
            tmp0_bytes[i] = *ad;
            ad += 1;
        }
        tmp0_bytes[i] = 0x80;
        to_bit_interleaving(&t0, U64BIG(tmp0));
        x0.e ^= t0.e;
        x0.o ^= t0.o;
        P_sH;
    }

    // Absorb AD padding if not already done before
    if (adlen == 0)
    {
        x0.o ^= 0x80000000;
        P_sH;
    }

    // Domain Seperation
    x4.e ^= ((u32)0x01);

    // Absorb full lanes of C
    while (clen >= 8)
    {
        to_bit_interleaving(&t0, U64BIG(*(u64 *)c));
        x0.e ^= t0.e;
        x0.o ^= t0.o;
        P_sH;
        clen -= ISAP_rH / 8;
        c += ISAP_rH / 8;
    }

    // Absorb partial lane of C and add padding
    if (clen > 0)
    {
        tmp0 = 0;
        u8 *tmp0_bytes = (u8 *)&tmp0;
        u8 i;
        for (i = 0; i < clen; i++)
        {
            tmp0_bytes[i] = *c;
            c += 1;
        }
        tmp0_bytes[i] = 0x80;
        to_bit_interleaving(&t0, U64BIG(tmp0));
        x0.e ^= t0.e;
        x0.o ^= t0.o;
        P_sH;
    }

    // Absorb C padding if not already done before
    if (clen == 0)
    {
        x0.o ^= 0x80000000;
        P_sH;
    }

    // Finalize - Derive Ka*
    u64 y64[CRYPTO_KEYBYTES / 8];
    from_bit_interleaving(&tmp0, x0);
    y64[0] = U64BIG(tmp0);
    from_bit_interleaving(&tmp0, x1);
    y64[1] = U64BIG(tmp0);
    u32 ka_star32[CRYPTO_KEYBYTES / 4];
    isap_rk(k, ISAP_IV_KA, (u8 *)y64, (u8 *)ka_star32, CRYPTO_KEYBYTES);

    // Finalize - Squeeze T
    x0.o = ka_star32[0];
    x0.e = ka_star32[1];
    x1.o = ka_star32[2];
    x1.e = ka_star32[3];
    P_sH;
    from_bit_interleaving(&tmp0, x0);
    *(u64 *)(tag + 0) = U64BIG(tmp0);
    from_bit_interleaving(&tmp0, x1);
    *(u64 *)(tag + 8) = U64BIG(tmp0);
}

/******************************************************************************/
/*                                 ISAP_ENC                                   */
/******************************************************************************/

void isap_enc(
    const u8 *k,
    const u8 *npub,
    const u8 *m, u64 mlen,
    u8 *c)
{
    // Derive Ke
    u8 ke[ISAP_STATE_SZ - CRYPTO_NPUBBYTES];
    isap_rk(k, ISAP_IV_KE, npub, ke, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);

    // State and temporary variables
    u32_2 x0, x1, x2, x3, x4;
    u64 tmp0;

    // Init State
    x0.o = *(u32 *)(ke + 0);
    x0.e = *(u32 *)(ke + 4);
    x1.o = *(u32 *)(ke + 8);
    x1.e = *(u32 *)(ke + 12);
    x2.o = *(u32 *)(ke + 16);
    x2.e = *(u32 *)(ke + 20);
    to_bit_interleaving(&x3, U64BIG(*(u64 *)npub));
    to_bit_interleaving(&x4, U64BIG(*(u64 *)(npub + 8)));

    // Squeeze full lanes
    while (mlen >= 8)
    {
        P_sE;
        from_bit_interleaving(&tmp0, x0);
        *(u64 *)c = *(u64 *)m ^ U64BIG(tmp0);
        mlen -= 8;
        m += ISAP_rH / 8;
        c += ISAP_rH / 8;
    }

    // Squeeze partial lane
    if (mlen > 0)
    {
        P_sE;
        from_bit_interleaving(&tmp0, x0);
        tmp0 = U64BIG(tmp0);
        u8 *tmp0_bytes = (u8 *)&tmp0;
        for (u8 i = 0; i < mlen; i++)
        {
            *c = *m ^ tmp0_bytes[i];
            m += 1;
            c += 1;
        }
    }
}
