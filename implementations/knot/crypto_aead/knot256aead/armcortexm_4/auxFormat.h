#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#define U32BIG(x) (x)

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
void printU8(char name[], u8 var[], long len, int offset);

//new
void puckU8FormatToFourPacket(u8 in, u8 *out);

#define puck32(in)\
{\
temp1 = (in ^ (in >> 1)) & 0x22222222; in ^= temp1 ^ (temp1 << 1);\
temp1 = (in ^ (in >> 2)) & 0x0C0C0C0C; in ^= temp1 ^ (temp1 << 2);\
temp1 = (in ^ (in >> 4)) & 0x00F000F0; in ^= temp1 ^ (temp1 << 4);\
temp1 = (in ^ (in >> 8)) & 0x0000FF00; in ^= temp1 ^ (temp1 << 8);\
}
#define unpuck32(t0){\
	r0 = (t0 ^ (t0 >> 8)) & 0x0000FF00, t0 ^= r0 ^ (r0 << 8); \
	r0 = (t0 ^ (t0 >> 4)) & 0x00F000F0, t0 ^= r0 ^ (r0 << 4); \
	r0 = (t0 ^ (t0 >> 2)) & 0x0C0C0C0C, t0 ^= r0 ^ (r0 << 2); \
	r0 = (t0 ^ (t0 >> 1)) & 0x22222222, t0 ^= r0 ^ (r0 << 1); \
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

unsigned char constant7Format_aead[100];
