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

#define U64TOWORD(x) U64BIG(x)
#define WORDTOU64(x) U64BIG(x)

/* ---------------------------------------------------------------- */

#define TOBI(x) (x)
#define FROMBI(x) (x)

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

#define XMUL(i, x)                                   \
    do                                               \
    {                                                \
        tmp = (uint16_t)a.b[i] * (1 << (x));         \
        b.b[(byte_rol + (i)) & 0x7] ^= (uint8_t)tmp; \
        b.b[(byte_rol + (i) + 1) & 0x7] ^= tmp >> 8; \
    } while (0)

forceinline uint64_t ROR(uint64_t x, int n)
{
    lane_t a = {.x = x}, b = {.x = 0ull};
    int bit_rol = (64 - n) & 0x7;
    int byte_rol = (64 - n) >> 3;
    uint16_t tmp;
    XMUL(0, bit_rol);
    XMUL(1, bit_rol);
    XMUL(2, bit_rol);
    XMUL(3, bit_rol);
    XMUL(4, bit_rol);
    XMUL(5, bit_rol);
    XMUL(6, bit_rol);
    XMUL(7, bit_rol);
    return b.x;
}

/* ---------------------------------------------------------------- */

forceinline uint8_t NOT8(uint8_t a) { return ~a; }

forceinline uint8_t XOR8(uint8_t a, uint8_t b) { return a ^ b; }

forceinline uint8_t AND8(uint8_t a, uint8_t b) { return a & b; }

forceinline uint8_t OR8(uint8_t a, uint8_t b) { return a | b; }

/* ---------------------------------------------------------------- */

forceinline void LINEAR_LAYER(state_t *s, uint64_t xtemp)
{
    uint64_t temp;
    temp = s->x[2] ^ ROR(s->x[2], 28 - 19);
    s->x[0] = s->x[2] ^ ROR(temp, 19);
    temp = s->x[4] ^ ROR(s->x[4], 6 - 1);
    s->x[2] = s->x[4] ^ ROR(temp, 1);
    temp = s->x[1] ^ ROR(s->x[1], 41 - 7);
    s->x[4] = s->x[1] ^ ROR(temp, 7);
    temp = s->x[3] ^ ROR(s->x[3], 61 - 39);
    s->x[1] = s->x[3] ^ ROR(temp, 39);
    temp = xtemp ^ ROR(xtemp, 17 - 10);
    s->x[3] = xtemp ^ ROR(temp, 10);
}

/* ---------------------------------------------------------------- */

forceinline void NONLINEAR_LAYER(state_t *s, lane_t *xtemp, uint8_t pos)
{
    uint8_t t0;
    uint8_t t1;
    uint8_t t2;
    // Based on the round description of Ascon given in the Bachelor's thesis:
    //"Optimizing Ascon on RISC-V" of Lars Jellema
    // see https://github.com/Lucus16/ascon-riscv/
    t0 = XOR8(s->b[1][pos], s->b[2][pos]);
    t1 = XOR8(s->b[0][pos], s->b[4][pos]);
    t2 = XOR8(s->b[3][pos], s->b[4][pos]);
    s->b[4][pos] = OR8(s->b[3][pos], NOT8(s->b[4][pos]));
    s->b[4][pos] = XOR8(s->b[4][pos], t0);
    s->b[3][pos] = XOR8(s->b[3][pos], s->b[1][pos]);
    s->b[3][pos] = OR8(s->b[3][pos], t0);
    s->b[3][pos] = XOR8(s->b[3][pos], t1);
    s->b[2][pos] = XOR8(s->b[2][pos], t1);
    s->b[2][pos] = OR8(s->b[2][pos], s->b[1][pos]);
    s->b[2][pos] = XOR8(s->b[2][pos], t2);
    s->b[1][pos] = AND8(s->b[1][pos], NOT8(t1));
    s->b[1][pos] = XOR8(s->b[1][pos], t2);
    s->b[0][pos] = OR8(s->b[0][pos], t2);
    (*xtemp).b[pos] = XOR8(s->b[0][pos], t0);
}

/* ---------------------------------------------------------------- */

forceinline void ROUND(state_t *s, uint8_t C)
{
    lane_t xtemp;
    /* round constant */
    s->b[2][0] = XOR8(s->b[2][0], C);
    /* s-box layer */
    for (uint8_t i = 0; i < 8; i++)
        NONLINEAR_LAYER(s, &xtemp, i);
    /* linear layer */
    LINEAR_LAYER(s, xtemp.x);
}

/* ---------------------------------------------------------------- */

void PROUNDS(state_t *s, uint8_t nr)
{
    switch (nr)
    {
    case 12:
        ROUND(s, 0xf0);
        ROUND(s, 0xe1);
        ROUND(s, 0xd2);
        ROUND(s, 0xc3);
        ROUND(s, 0xb4);
        ROUND(s, 0xa5);
    case 6:
        ROUND(s, 0x96);
        ROUND(s, 0x87);
        ROUND(s, 0x78);
        ROUND(s, 0x69);
        ROUND(s, 0x5a);
    default:
        ROUND(s, 0x4b);
    }
}

/* ---------------------------------------------------------------- */

#endif // ASCONP_H
