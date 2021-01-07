
#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#include <stdio.h>
#include <stdlib.h>
#define U32BIG(x) (x)

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define aead_RATE (192 / 8)
#define PR0_ROUNDS 76
#define PR_ROUNDS 28
#define PRF_ROUNDS 32
/*

#define PR0_ROUNDS 76
#define PR_ROUNDS 40
#define PRF_ROUNDS 44


 * */
#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define U96_BIT_LOTR32_8(t0,t1,t2,t3,t4,t5){\
t3= LOTR32(t2, 2);\
t4 =LOTR32(t0, 3);\
t5 = LOTR32(t1, 3); \
}
//55=3*18+1
#define U96_BIT_LOTR32_55(t0,t1,t2,t3,t4,t5){\
t3= LOTR32(t1, 18); \
t4 = LOTR32(t2, 18);\
t5 = LOTR32(t0, 19); \
}

void packU96FormatToThreePacket(u32 * out, u8 * in);
void unpackU96FormatToThreePacket(u8 * out, u32 * in);

unsigned char  constant7Format[80];
#define puckU32ToThree_1(x){\
x &= 0x49249249;\
x = (x | (x >>  2)) & 0xc30c30c3;\
x = (x | (x >>4)) & 0x0f00f00f;\
x = (x | (x >> 8)) & 0xff0000ff;\
x = (x | (x >> 16)) & 0xfff;\
}
#define unpuckU32ToThree_1(x){\
x &= 0xfff;\
x = (x | (x << 16)) & 0xff0000ff;\
x = (x | (x << 8)) & 0x0f00f00f;\
x = (x | (x << 4)) & 0xc30c30c3;\
x = (x | (x << 2)) & 0x49249249;\
}

