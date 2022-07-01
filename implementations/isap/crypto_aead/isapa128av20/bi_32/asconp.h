#ifndef ASCONP_H_
#define ASCONP_H_

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

#define P_sH P12ROUNDS(s)
#define P_sB P1ROUNDS(s)
#define P_sE P6ROUNDS(s)
#define P_sK P12ROUNDS(s)

/* ---------------------------------------------------------------- */

#define U64TOWORD(x) to_bit_interleaving(U64BIG(x))
#define WORDTOU64(x) U64BIG(from_bit_interleaving(x))

/* ---------------------------------------------------------------- */

#define TOBI(x) to_bit_interleaving(x)
#define FROMBI(x) from_bit_interleaving(x)

/* ---------------------------------------------------------------- */

forceinline lane_t U64BIG(lane_t x)
{
    x.x = ((((x.x) & 0x00000000000000FFULL) << 56) | (((x.x) & 0x000000000000FF00ULL) << 40) |
           (((x.x) & 0x0000000000FF0000ULL) << 24) | (((x.x) & 0x00000000FF000000ULL) << 8) |
           (((x.x) & 0x000000FF00000000ULL) >> 8) | (((x.x) & 0x0000FF0000000000ULL) >> 24) |
           (((x.x) & 0x00FF000000000000ULL) >> 40) | (((x.x) & 0xFF00000000000000ULL) >> 56));
    return x;
}

/* ---------------------------------------------------------------- */

// Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
forceinline lane_t to_bit_interleaving(lane_t in)
{
    uint32_t lo = in.w[0];
    uint32_t hi = in.w[1];
    uint32_t r0, r1;
    r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
    r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
    r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
    r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
    r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
    r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
    r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
    r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
    lane_t out;
    out.w[0] = (lo & 0x0000FFFF) | (hi << 16);
    out.w[1] = (lo >> 16) | (hi & 0xFFFF0000);
    return out;
}

/* ---------------------------------------------------------------- */

// Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
forceinline lane_t from_bit_interleaving(lane_t in)
{
    uint32_t lo = ((in).w[0] & 0x0000FFFF) | ((in).w[1] << 16);
    uint32_t hi = ((in).w[0] >> 16) | ((in).w[1] & 0xFFFF0000);
    uint32_t r0, r1;
    r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
    r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
    r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
    r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
    r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
    r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
    r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
    r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
    lane_t out;
    out.x = (uint64_t)hi << 32 | lo;
    return out;
}

/* ---------------------------------------------------------------- */

forceinline uint32_t ROR32(uint32_t x, int n)
{
    return x >> n | x << (-n & 31);
}

/* ---------------------------------------------------------------- */

forceinline uint64_t ROR(uint64_t x, int n)
{
    lane_t b, a = {.x = x};
    b.w[0] = (n % 2) ? ROR32(a.w[1], (n - 1) / 2) : ROR32(a.w[0], n / 2);
    b.w[1] = (n % 2) ? ROR32(a.w[0], (n + 1) / 2) : ROR32(a.w[1], n / 2);
    return b.x;
}

/* ---------------------------------------------------------------- */

forceinline void ROUND(state_t *s, uint64_t C)
{
    state_t t;
    /* round constant */
    s->x[2] ^= C;
    /* s-box layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[1] ^= t.x[0];
    t.x[3] ^= t.x[2];
    t.x[0] ^= t.x[4];
    /* linear layer */
    s->x[2] = t.x[2] ^ ROR(t.x[2], 6 - 1);
    s->x[3] = t.x[3] ^ ROR(t.x[3], 17 - 10);
    s->x[4] = t.x[4] ^ ROR(t.x[4], 41 - 7);
    s->x[0] = t.x[0] ^ ROR(t.x[0], 28 - 19);
    s->x[1] = t.x[1] ^ ROR(t.x[1], 61 - 39);
    s->x[2] = t.x[2] ^ ROR(s->x[2], 1);
    s->x[3] = t.x[3] ^ ROR(s->x[3], 10);
    s->x[4] = t.x[4] ^ ROR(s->x[4], 7);
    s->x[0] = t.x[0] ^ ROR(s->x[0], 19);
    s->x[1] = t.x[1] ^ ROR(s->x[1], 39);
    s->x[2] = ~s->x[2];
}

/* ---------------------------------------------------------------- */

forceinline void P12ROUNDS(state_t *s)
{
    ROUND(s, 0xc0000000c);
    ROUND(s, 0xc00000009);
    ROUND(s, 0x90000000c);
    ROUND(s, 0x900000009);
    ROUND(s, 0xc00000006);
    ROUND(s, 0xc00000003);
    ROUND(s, 0x900000006);
    ROUND(s, 0x900000003);
    ROUND(s, 0x60000000c);
    ROUND(s, 0x600000009);
    ROUND(s, 0x30000000c);
    ROUND(s, 0x300000009);
}

/* ---------------------------------------------------------------- */

forceinline void P6ROUNDS(state_t *s)
{
    ROUND(s, 0x900000006);
    ROUND(s, 0x900000003);
    ROUND(s, 0x60000000c);
    ROUND(s, 0x600000009);
    ROUND(s, 0x30000000c);
    ROUND(s, 0x300000009);
}

/* ---------------------------------------------------------------- */

forceinline void P1ROUNDS(state_t *s)
{
    ROUND(s, 0x300000009);
}

/* ---------------------------------------------------------------- */

#endif // ASCONP_H
