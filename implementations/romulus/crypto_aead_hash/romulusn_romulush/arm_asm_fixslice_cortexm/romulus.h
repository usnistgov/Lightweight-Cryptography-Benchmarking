#ifndef ROMULUSN1_H_
#define ROMULUSN1_H_

#include "skinny128.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef struct {
    u8 tk1[16];                     //to manipulate tk1 in a byte-wise manner
    u32 rtk1[32];                   //to avoid recomputation of the tk schedule
    u32 rtk[4*SKINNY128_384_ROUNDS];//all round tweakeys
} skinny_128_384_tks;

#define TAGBYTES    16
#define KEYBYTES    16
#define BLOCKBYTES  16

#define SET_DOMAIN(tk1, domain) ((tk1)[7] = (domain))

//G as defined in the Romulus specification in a 32-bit word-wise manner
#define G(x,y) ({                                                                   \
    tmp = ((u32*)(y))[0];                                                           \
    ((u32*)(x))[0] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);   \
    tmp = ((u32*)(y))[1];                                                           \
    ((u32*)(x))[1] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);   \
    tmp = ((u32*)(y))[2];                                                           \
    ((u32*)(x))[2] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);   \
    tmp = ((u32*)(y))[3];                                                           \
    ((u32*)(x))[3] = (tmp >> 1 & 0x7f7f7f7f) ^ ((tmp ^ (tmp << 7)) & 0x80808080);   \
})

//update the counter in tk1 in a 32-bit word-wise manner
#define UPDATE_CTR(tk1) ({                              \
    tmp = ((u32*)(tk1))[1];                             \
    ((u32*)(tk1))[1] = (tmp << 1) & 0x00ffffff;         \
    ((u32*)(tk1))[1] |= (((u32*)(tk1))[0] >> 31);       \
    ((u32*)(tk1))[1] |= tmp & 0xff000000;               \
    ((u32*)(tk1))[0] <<= 1;                             \
    if ((tmp >> 23) & 0x01)                             \
        ((u32*)(tk1))[0] ^= 0x95;                       \
})

//x <- y ^ z for 128-bit blocks
#define XOR_BLOCK(x,y,z) ({                             \
    ((u32*)(x))[0] = ((u32*)(y))[0] ^ ((u32*)(z))[0];   \
    ((u32*)(x))[1] = ((u32*)(y))[1] ^ ((u32*)(z))[1];   \
    ((u32*)(x))[2] = ((u32*)(y))[2] ^ ((u32*)(z))[2];   \
    ((u32*)(x))[3] = ((u32*)(y))[3] ^ ((u32*)(z))[3];   \
})


//Rho as defined in the Romulus specification
//use pad as a tmp variable in case y = z
#define RHO(x,y,z) ({       \
    G(pad,x);               \
    XOR_BLOCK(y, pad, z);   \
    XOR_BLOCK(x, x, z);     \
})

//Rho inverse as defined in the Romulus specification
//use pad as a tmp variable in case y = z
#define RHO_INV(x, y, z) ({ \
    G(pad, x);              \
    XOR_BLOCK(z, pad, y);   \
    XOR_BLOCK(x, x, z);     \
})

#endif  // ROMULUSN1_H_