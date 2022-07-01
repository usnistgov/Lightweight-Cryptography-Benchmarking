#include <string.h>
#include <inttypes.h>
#include "api.h"
#include "isap.h"
#include "asconp.h"
#include "config.h"

forceinline void ABSORB_LANES(state_t *s, const uint8_t *src, uint64_t len)
{
    while (len >= 8)
    {
        // Absorb full lanes
        lane_t t0 = U64TOWORD(*(lane_t *)(src + 0));
        s->x[0] ^= t0.x;
        len -= ISAP_rH / 8;
        src += ISAP_rH / 8;
        P_sH;
    }

    if (len > 0)
    {
        // Absorb partial lane and padding
        size_t i;
        lane_t t0 = {0};
        for (i = 0; i < len; i++)
        {
            t0.b[7 - i] ^= *src;
            src++;
        }
        t0.b[7 - i] ^= 0x80;
        t0 = TOBI(t0);
        s->x[0] ^= t0.x;
        P_sH;
    }
    else
    {
        // Absorb padded empty lane
        s->b[0][7] ^= 0x80;
        P_sH;
    }
}

/******************************************************************************/
/*                                 ISAP_RK                                    */
/******************************************************************************/

void isap_rk(
    const uint8_t *k,
    const uint8_t *iv,
    const uint8_t *y,
    state_t *out,
    const size_t outlen)
{
    state_t state;
    state_t *s = &state;

    // Initialize
    s->l[0] = U64TOWORD(*(lane_t *)(k + 0));
    s->l[1] = U64TOWORD(*(lane_t *)(k + 8));
    s->l[2] = U64TOWORD(*(lane_t *)(iv + 0));
    s->x[3] = 0;
    s->x[4] = 0;
    P_sK;

    // Absorb Y, bit by bit
    for (size_t i = 0; i < 16; i++)
    {
        uint8_t y_byte = *y;
        s->b[0][7] ^= (y_byte & 0x80) << 0;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x40) << 1;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x20) << 2;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x10) << 3;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x08) << 4;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x04) << 5;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x02) << 6;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x01) << 7;
        if (i != 15)
        {
            P_sB;
            y += 1;
        }
    }

    // Squeeze K*
    P_sK;
    out->x[0] = s->x[0];
    out->x[1] = s->x[1];
    if (outlen > 16)
    {
        out->x[2] = s->x[2];
    }
}

/******************************************************************************/
/*                                 ISAP_MAC                                   */
/******************************************************************************/

void isap_mac(
    const uint8_t *k,
    const uint8_t *npub,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *c, uint64_t clen,
    uint8_t *tag)
{
    state_t state;
    state_t *s = &state;

    // Initialize
    s->l[0] = U64TOWORD(*(lane_t *)(npub + 0));
    s->l[1] = U64TOWORD(*(lane_t *)(npub + 8));
    s->l[2] = U64TOWORD(*(lane_t *)(ISAP_IV_A + 0));
    s->x[3] = 0;
    s->x[4] = 0;
    P_sH;

    // Absorb associated data
    ABSORB_LANES(s, ad, adlen);

    // Domain seperation
    s->w[4][0] ^= 0x1UL;

    // Absorb ciphertext
    ABSORB_LANES(s, c, clen);

    // Derive KA*
    s->l[0] = WORDTOU64(s->l[0]);
    s->l[1] = WORDTOU64(s->l[1]);
    isap_rk(k, ISAP_IV_KA, (const uint8_t *)(s->b), s, CRYPTO_KEYBYTES);

    // Squeeze tag
    P_sH;
    lane_t t0 = WORDTOU64(s->l[0]);
    memcpy(tag + 0, t0.b, 8);
    t0 = WORDTOU64(s->l[1]);
    memcpy(tag + 8, t0.b, 8);
}

/******************************************************************************/
/*                                 ISAP_ENC                                   */
/******************************************************************************/

void isap_enc(
    const uint8_t *k,
    const uint8_t *npub,
    const uint8_t *m, uint64_t mlen,
    uint8_t *c)

{
    state_t state;
    state_t *s = &state;

    // Init state
    isap_rk(k, ISAP_IV_KE, npub, s, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
    s->l[3] = U64TOWORD(*(lane_t *)(npub + 0));
    s->l[4] = U64TOWORD(*(lane_t *)(npub + 8));

    while (mlen >= ISAP_rH / 8)
    {
        // Encrypt full lanes
        P_sE;
        lane_t t0 = WORDTOU64(s->l[0]);
        *(uint64_t *)c = *(uint64_t *)m ^ t0.x;
        mlen -= ISAP_rH / 8;
        m += ISAP_rH / 8;
        c += ISAP_rH / 8;
    }

    if (mlen > 0)
    {
        // Encrypt partial lanes
        P_sE;
        lane_t t0 = WORDTOU64(s->l[0]);
        for (uint8_t i = 0; i < mlen; i++)
        {
            *c = *m ^ t0.b[i];
            m += 1;
            c += 1;
        }
    }
}

/******************************************************************************/
/*                                Ascon-Hash                                  */
/******************************************************************************/

#if ENABLE_HASH == 1

int crypto_hash(uint8_t *out, const uint8_t *in, unsigned long long inlen)
{

    state_t state;
    state_t *s = &state;

    // Initialize
    s->l[0] = U64TOWORD(*(lane_t *)(ASCON_HASH_IV + 0));
    s->x[1] = 0;
    s->x[2] = 0;
    s->x[3] = 0;
    s->x[4] = 0;
    P_sH;

    // Absorb input
    ABSORB_LANES(s, in, inlen);

    for (size_t i = 0; i < 4; i++)
    {
        // Squeeze full lanes
        lane_t t0 = WORDTOU64(s->l[0]);
        *(uint64_t *)(out + 8 * i) = t0.x;
        if (i < 3)
        {
            P_sH;
        }
    }

    return 0;
}

#endif
