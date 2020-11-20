#ifndef SKINNYAEADM1_H_
#define SKINNYAEADM1_H_

#include "skinny128.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define TAGBYTES    16
#define KEYBYTES    16
#define BLOCKBYTES  16

#define SET_DOMAIN(ptr, domain) ((ptr)[15] = (domain))

#define UPDATE_LFSR(lfsr) ({                            \
    feedback = ((lfsr) & (1ULL << 63)) ? 0x1B : 0x00;   \
    (lfsr) = ((lfsr) << 1) ^ feedback;                  \
})

#define LE_STR_64(ptr, x)  ({       \
    (ptr)[0] = (u8)(x);             \
    (ptr)[1] = (u8)((x) >> 8);      \
    (ptr)[2] = (u8)((x) >> 16);     \
    (ptr)[3] = (u8)((x) >> 24);     \
    (ptr)[4] = (u8)((x) >> 32);     \
    (ptr)[5] = (u8)((x) >> 40);     \
    (ptr)[6] = (u8)((x) >> 48);     \
    (ptr)[7] = (u8)((x) >> 56);     \
})
//x ^= y with x, y 128-bit blocks
#define XOR_BLOCK(x,y) ({               \
    ((u32*)(x))[0] ^= ((u32*)(y))[0];   \
    ((u32*)(x))[1] ^= ((u32*)(y))[1];   \
    ((u32*)(x))[2] ^= ((u32*)(y))[2];   \
    ((u32*)(x))[3] ^= ((u32*)(y))[3];   \
})

#endif  // SKINNYAEADM1_H_