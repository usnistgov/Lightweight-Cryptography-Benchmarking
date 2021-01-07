#include<malloc.h>
#include<stdio.h>
#include"crypto_hash.h"
#include"api.h"
#include  <string.h>
#define U32BIG(x) (x)


typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define puckU32ToFour(lo){\
u32 r0;\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
r0 = (lo ^ (lo << 1)) & 0x44444444, lo ^= r0 ^ (r0 >> 1);\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
r0 = (lo ^ (lo << 8)) & 0x00ff0000, lo ^= r0 ^ (r0 >> 8);\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
}
#define unpuckU32ToFour(lo){\
u32 r0;\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
r0 = (lo ^ (lo << 8)) & 0x00ff0000, lo ^= r0 ^ (r0 >> 8);\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
r0 = (lo ^ (lo << 1)) & 0x44444444, lo ^= r0 ^ (r0 >> 1);\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
}
#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}
#define BIT_LOTR32_16(t0,t1,t2,t3,t4,t5,t6,t7){\
t4= LOTR32(t0, 4);\
t5 = LOTR32(t1, 4);\
t6 = LOTR32(t2, 4); \
t7 = LOTR32(t3, 4); \
}
#define BIT_LOTR32_25(t0,t1,t2,t3,t4,t5,t6,t7){\
t4= LOTR32(t3, 7);\
t5 = LOTR32(t0, 6);\
t6 = LOTR32(t1, 6); \
t7 = LOTR32(t2, 6); \
}

unsigned char  constant8Format_hash[140];
