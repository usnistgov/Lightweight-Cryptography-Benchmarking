#ifndef ASCONP_H
#define ASCONP_H

#include <inttypes.h>
#include "forceinline.h"

typedef union
{
    uint64_t x;
    uint32_t w[2];
    uint8_t b[8];
} lane_t;

typedef union
{
    lane_t l[5];
    uint64_t x[5];
    uint32_t w[5][2];
    uint8_t b[5][8];
} state_t;

/* ---------------------------------------------------------------- */

#define P_sH PROUNDS(s, 12)
#define P_sB PROUNDS(s, 1)
#define P_sE PROUNDS(s, 6)
#define P_sK PROUNDS(s, 12)

/* ---------------------------------------------------------------- */

#define U64TOWORD(x) interleave8(U64BIG(x))
#define WORDTOU64(x) U64BIG(interleave8(x))

/* ---------------------------------------------------------------- */

#define TOBI(x) interleave8(x)
#define FROMBI(x) interleave8(x)

/* ---------------------------------------------------------------- */

lane_t U64BIG(lane_t x)
{
    x.x = ((((x.x) & 0x00000000000000FFULL) << 56) | (((x.x) & 0x000000000000FF00ULL) << 40) |
           (((x.x) & 0x0000000000FF0000ULL) << 24) | (((x.x) & 0x00000000FF000000ULL) << 8) |
           (((x.x) & 0x000000FF00000000ULL) >> 8) | (((x.x) & 0x0000FF0000000000ULL) >> 24) |
           (((x.x) & 0x00FF000000000000ULL) >> 40) | (((x.x) & 0xFF00000000000000ULL) >> 56));
    return x;
}

/* ---------------------------------------------------------------- */

forceinline uint8_t ROR8(uint8_t a, int n) { return a >> n | a << (8 - n); }

/* ---------------------------------------------------------------- */

forceinline uint64_t ROR(uint64_t x, int n)
{
    lane_t b, a = {.x = x};
    b.b[0] = ROR8(a.b[(n + 0) & 0x7], (n + 0) >> 3);
    b.b[1] = ROR8(a.b[(n + 1) & 0x7], (n + 1) >> 3);
    b.b[2] = ROR8(a.b[(n + 2) & 0x7], (n + 2) >> 3);
    b.b[3] = ROR8(a.b[(n + 3) & 0x7], (n + 3) >> 3);
    b.b[4] = ROR8(a.b[(n + 4) & 0x7], (n + 4) >> 3);
    b.b[5] = ROR8(a.b[(n + 5) & 0x7], (n + 5) >> 3);
    b.b[6] = ROR8(a.b[(n + 6) & 0x7], (n + 6) >> 3);
    b.b[7] = ROR8(a.b[(n + 7) & 0x7], (n + 7) >> 3);
    return b.x;
}

/* ---------------------------------------------------------------- */

/* credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
forceinline lane_t interleave8(lane_t x)
{
    x.x = (x.x & 0xaa55aa55aa55aa55ull) | ((x.x & 0x00aa00aa00aa00aaull) << 7) |
          ((x.x >> 7) & 0x00aa00aa00aa00aaull);
    x.x = (x.x & 0xcccc3333cccc3333ull) | ((x.x & 0x0000cccc0000ccccull) << 14) |
          ((x.x >> 14) & 0x0000cccc0000ccccull);
    x.x = (x.x & 0xf0f0f0f00f0f0f0full) | ((x.x & 0x00000000f0f0f0f0ull) << 28) |
          ((x.x >> 28) & 0x00000000f0f0f0f0ull);
    return x;
}

/* ---------------------------------------------------------------- */

forceinline void ROUND(state_t *s, uint64_t C)
{
    uint64_t xtemp;
    /* round constant */
    s->x[2] ^= C;
    /* s-box layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    xtemp = s->x[0] & ~s->x[4];
    s->x[0] ^= s->x[2] & ~s->x[1];
    s->x[2] ^= s->x[4] & ~s->x[3];
    s->x[4] ^= s->x[1] & ~s->x[0];
    s->x[1] ^= s->x[3] & ~s->x[2];
    s->x[3] ^= xtemp;
    s->x[1] ^= s->x[0];
    s->x[3] ^= s->x[2];
    s->x[0] ^= s->x[4];
    /* linear layer */
    xtemp = s->x[0] ^ ROR(s->x[0], 28 - 19);
    s->x[0] ^= ROR(xtemp, 19);
    xtemp = s->x[1] ^ ROR(s->x[1], 61 - 39);
    s->x[1] ^= ROR(xtemp, 39);
    xtemp = s->x[2] ^ ROR(s->x[2], 6 - 1);
    s->x[2] ^= ROR(xtemp, 1);
    xtemp = s->x[3] ^ ROR(s->x[3], 17 - 10);
    s->x[3] ^= ROR(xtemp, 10);
    xtemp = s->x[4] ^ ROR(s->x[4], 41 - 7);
    s->x[4] ^= ROR(xtemp, 7);
    s->x[2] = ~s->x[2];
}

/* ---------------------------------------------------------------- */

void PROUNDS(state_t *s, uint8_t nr)
{
    switch (nr)
    {
    case 12:
        ROUND(s, 0x0101010100000000ull);
        ROUND(s, 0x0101010000000001ull);
        ROUND(s, 0x0101000100000100ull);
        ROUND(s, 0x0101000000000101ull);
        ROUND(s, 0x0100010100010000ull);
        ROUND(s, 0x0100010000010001ull);
    case 6:
        ROUND(s, 0x0100000100010100ull);
        ROUND(s, 0x0100000000010101ull);
        ROUND(s, 0x0001010101000000ull);
        ROUND(s, 0x0001010001000001ull);
        ROUND(s, 0x0001000101000100ull);
    default:
        ROUND(s, 0x0001000001000101ull);
    }
}

/* ---------------------------------------------------------------- */

#endif // ASCONP_H
