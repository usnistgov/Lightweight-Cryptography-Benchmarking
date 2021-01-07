#ifndef ASCONP_H_
#define ASCONP_H_

#include <inttypes.h>

typedef unsigned char u8;
typedef uint32_t u32;
typedef unsigned long long u64;

typedef struct
{
    u32 e;
    u32 o;
} u32_2;

// Round constants, bit-interleaved
u32 rc_o[12] = {0xc, 0xc, 0x9, 0x9, 0xc, 0xc, 0x9, 0x9, 0x6, 0x6, 0x3, 0x3};
u32 rc_e[12] = {0xc, 0x9, 0xc, 0x9, 0x6, 0x3, 0x6, 0x3, 0xc, 0x9, 0xc, 0x9};

/* ---------------------------------------------------------------- */

u64 U64BIG(u64 x)
{
    return ((((x)&0x00000000000000FFULL) << 56) | (((x)&0x000000000000FF00ULL) << 40) |
            (((x)&0x0000000000FF0000ULL) << 24) | (((x)&0x00000000FF000000ULL) << 8) |
            (((x)&0x000000FF00000000ULL) >> 8) | (((x)&0x0000FF0000000000ULL) >> 24) |
            (((x)&0x00FF000000000000ULL) >> 40) | (((x)&0xFF00000000000000ULL) >> 56));
}

/* ---------------------------------------------------------------- */

// Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
void to_bit_interleaving(u32_2 *out, u64 in)
{
    u32 hi = (in) >> 32;
    u32 lo = (u32)(in);
    u32 r0, r1;
    r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
    r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
    r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
    r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
    r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
    r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
    r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
    r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
    (*out).e = (lo & 0x0000FFFF) | (hi << 16);
    (*out).o = (lo >> 16) | (hi & 0xFFFF0000);
}

/* ---------------------------------------------------------------- */

// Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
void from_bit_interleaving(u64 *out, u32_2 in)
{
    u32 lo = ((in).e & 0x0000FFFF) | ((in).o << 16);
    u32 hi = ((in).e >> 16) | ((in).o & 0xFFFF0000);
    u32 r0, r1;
    r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
    r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
    r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
    r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
    r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
    r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
    r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
    r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
    *out = (u64)hi << 32 | lo;
}

/* ---------------------------------------------------------------- */

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* ---------------------------------------------------------------- */

void static inline PX(u32 rounds, u32_2* x0, u32_2* x1, u32_2* x2, u32_2* x3, u32_2* x4) {
    u32_2 t0, t1, t2, t3, t4;
    for (u32 r = 12 - rounds; r < 12; r++){
        /* rcon */             
        (*x2).e ^= rc_e[r];
        (*x2).o ^= rc_o[r];
        /* non-linear layer */             
        (*x0).e ^= (*x4).e;
        (*x0).o ^= (*x4).o;
        (*x4).e ^= (*x3).e;
        (*x4).o ^= (*x3).o;
        (*x2).e ^= (*x1).e;
        (*x2).o ^= (*x1).o;
        (t0).e = (*x0).e;
        (t0).o = (*x0).o;
        (t4).e = (*x4).e;
        (t4).o = (*x4).o;
        (t3).e = (*x3).e;
        (t3).o = (*x3).o;
        (t1).e = (*x1).e;
        (t1).o = (*x1).o;
        (t2).e = (*x2).e;
        (t2).o = (*x2).o;
        (*x0).e = t0.e ^ (~t1.e & t2.e);
        (*x0).o = t0.o ^ (~t1.o & t2.o);
        (*x2).e = t2.e ^ (~t3.e & t4.e);
        (*x2).o = t2.o ^ (~t3.o & t4.o);
        (*x4).e = t4.e ^ (~t0.e & t1.e);
        (*x4).o = t4.o ^ (~t0.o & t1.o);
        (*x1).e = t1.e ^ (~t2.e & t3.e);
        (*x1).o = t1.o ^ (~t2.o & t3.o);
        (*x3).e = t3.e ^ (~t4.e & t0.e);
        (*x3).o = t3.o ^ (~t4.o & t0.o);
        (*x1).e ^= (*x0).e;
        (*x1).o ^= (*x0).o;
        (*x3).e ^= (*x2).e;
        (*x3).o ^= (*x2).o;
        (*x0).e ^= (*x4).e;
        (*x0).o ^= (*x4).o;
        /* linear layer */             
        t0.e = (*x0).e ^ ROTR32((*x0).o, 4);
        t0.o = (*x0).o ^ ROTR32((*x0).e, 5);
        t1.e = (*x1).e ^ ROTR32((*x1).e, 11);
        t1.o = (*x1).o ^ ROTR32((*x1).o, 11);
        t2.e = (*x2).e ^ ROTR32((*x2).o, 2);
        t2.o = (*x2).o ^ ROTR32((*x2).e, 3);
        t3.e = (*x3).e ^ ROTR32((*x3).o, 3);
        t3.o = (*x3).o ^ ROTR32((*x3).e, 4);
        t4.e = (*x4).e ^ ROTR32((*x4).e, 17);
        t4.o = (*x4).o ^ ROTR32((*x4).o, 17);
        (*x0).e ^= ROTR32(t0.o, 9);
        (*x0).o ^= ROTR32(t0.e, 10);
        (*x1).e ^= ROTR32(t1.o, 19);
        (*x1).o ^= ROTR32(t1.e, 20);
        (*x2).e ^= t2.o;
        (*x2).o ^= ROTR32(t2.e, 1);
        (*x3).e ^= ROTR32(t3.e, 5);
        (*x3).o ^= ROTR32(t3.o, 5);
        (*x4).e ^= ROTR32(t4.o, 3);
        (*x4).o ^= ROTR32(t4.e, 4);
        (*x2).e = ~(*x2).e;
        (*x2).o = ~(*x2).o;
    }
}

#endif // ASCONP_H_
