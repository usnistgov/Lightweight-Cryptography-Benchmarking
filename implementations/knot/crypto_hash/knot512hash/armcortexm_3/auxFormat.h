
#include"api.h"
#include  <string.h>
#define U32BIG(x) (x)


#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))
unsigned char  constant8Format_hash[140];

#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}


typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
void printU8(char name[], u8 var[], long len, int offset);

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
//u32 u32 t1, t2, t3,t8, 
#define unpackU128FormatToFourPacket( out,  dataFormat) {\
t3 = (dataFormat[3] & 0xff000000) | ((dataFormat[2] >> 8) & 0x00ff0000) | ((dataFormat[1] >> 16) & 0x0000ff00) | (dataFormat[0] >> 24);	\
t2 = ((dataFormat[3] << 8) & 0xff000000) | (dataFormat[2] & 0x00ff0000) | ((dataFormat[1] >> 8) & 0x0000ff00) | ((dataFormat[0] >> 16) & 0x000000ff);	\
t1 = ((dataFormat[3] << 16) & 0xff000000) | ((dataFormat[2] << 8) & 0x00ff0000) | (dataFormat[1] & 0x0000ff00) | ((dataFormat[0] >> 8) & 0x000000ff);	\
t8 = ((dataFormat[3] << 24) & 0xff000000) | ((dataFormat[2] << 16) & 0x00ff0000) | ((dataFormat[1] << 8) & 0x0000ff00) | (dataFormat[0] & 0x000000ff);	\
unpuckU32ToFour(t8);\
unpuckU32ToFour(t1); 	\
unpuckU32ToFour(t2); 	\
unpuckU32ToFour(t3); \
((u32*)out)[0] = U32BIG(t8);	\
((u32*)out)[1] = U32BIG(t1);	\
((u32*)out)[2] = U32BIG(t2);	\
((u32*)out)[3] = U32BIG(t3);	\
}
#define packU64FormatToFourPacket(  out,   in) {\
t1 = U32BIG(((u32*)in)[0]);	\
t2 = U32BIG(((u32*)in)[1]);	\
puckU32ToFour(t1);	\
puckU32ToFour(t2);	\
out[3] = ((t2 >> 16) & 0x0000ff00) | ((t1 >> 24));	\
out[2] = ((t2 >> 8) & 0x0000ff00) | ((t1 >> 16) & 0x000000ff);	\
out[1] = (t2 & 0x0000ff00) | ((t1 >> 8) & 0x000000ff);	\
out[0] = ((t2 << 8) & 0x0000ff00) | (t1 & 0x000000ff);	\
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

#define ROUND512( lunNum) {\
s[3] ^= (constant8Format_hash[lunNum] >> 6) & 0x3;\
s[2] ^= (constant8Format_hash[lunNum] >> 4) & 0x3;\
s[1] ^= (constant8Format_hash[lunNum] >> 2) & 0x3;\
s[0] ^= constant8Format_hash[lunNum] & 0x3;\
sbox(s[3], s[7], s[11], s[15],  s_temp[7], s_temp[11], s_temp[15]);\
sbox(s[2], s[6], s[10], s[14],  s[7]     , s_temp[10], s_temp[14]);\
sbox(s[1], s[5], s[9],  s[13],  s[6]     , s_temp[9], s_temp[13]);\
sbox(s[0], s[4], s[8],  s[12],  s[5]     , s_temp[8], s_temp[12]);\
s[4]= LOTR32(s_temp[7], 1);\
BIT_LOTR32_16(s_temp[8], s_temp[9], s_temp[10], s_temp[11], s[8], s[9], s[10], s[11]);\
BIT_LOTR32_25(s_temp[12], s_temp[13], s_temp[14], s_temp[15], s[12], s[13], s[14], s[15]);\
}

