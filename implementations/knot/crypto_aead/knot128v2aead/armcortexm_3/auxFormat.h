
#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#include <stdio.h>
#include <stdlib.h>
#define U32BIG(x) (x)

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define puckU32ToThree(x){\
x &= 0x92492492;\
x = (x | (x << 2)) & 0xc30c30c3;\
x = (x | (x << 4)) & 0xf00f00f0;\
x = (x | (x << 8)) & 0xff0000ff;\
x = (x | (x << 16)) & 0xfff00000;\
}
#define unpuckU32ToThree(x){\
x &= 0xfff00000;\
x = (x | (x >> 16)) & 0xff0000ff;\
x = (x | (x >> 8)) & 0xf00f00f0;\
x = (x | (x >> 4)) & 0xc30c30c3;\
x = (x | (x >> 2)) & 0x92492492;\
} 
#define packU32FormatToThreePacket( out,  in) {\
t2 = U32BIG(((u32*)in)[0]);	\
t2_64 = (in[3] & 0x80) >> 7, t2_65 = (in[3] & 0x40) >> 6;	\
t2 = t2 << 2;	\
temp2[0] = t2; temp2[1] = t2 << 1; temp2[2] = t2 << 2;	\
puckU32ToThree(temp2[0]);	\
puckU32ToThree(temp2[1]);	\
puckU32ToThree(temp2[2]);	\
out[0] = (temp2[0] >> 22);	\
out[1] = (((u32)t2_64) << 10) | (temp2[1] >> 22);	\
out[2] =(((u32)t2_65) << 10) | (temp2[2] >> 22);	\
} 
#define packU96FormatToThreePacket(out, in) {\
t9 = U32BIG(((u32*)in)[2]);	\
t1 = U32BIG(((u32*)in)[1]);	\
t2 = U32BIG(((u32*)in)[0]);	\
t1_32 = (in[7] & 0x80) >> 7, t2_64 = (in[3] & 0x80) >> 7, t2_65 = (in[3] & 0x40) >> 6;	\
t1 = t1 << 1;	\
t2 = t2 << 2;	\
temp0[0] = t9; temp0[1] = t9 << 1; temp0[2] = t9 << 2;	\
puckU32ToThree(temp0[0]);	\
puckU32ToThree(temp0[1]);	\
puckU32ToThree(temp0[2]);	\
temp1[0] = t1; temp1[1] = t1 << 1; temp1[2] = t1 << 2;	\
puckU32ToThree(temp1[0]);	\
puckU32ToThree(temp1[1]);	\
puckU32ToThree(temp1[2]);	\
temp2[0] = t2; temp2[1] = t2 << 1; temp2[2] = t2 << 2;	\
puckU32ToThree(temp2[0]);	\
puckU32ToThree(temp2[1]);	\
puckU32ToThree(temp2[2]);	\
out[0] = (temp0[0]) | (temp1[0] >> 11) | (temp2[0] >> 22);	\
out[1] = (temp0[1]) | (temp1[1] >> 11) | (((u32)t2_64) << 10) | (temp2[1] >> 22);	\
out[2] = (temp0[2]) | (((u32)t1_32) << 21) | (temp1[2] >> 11) | (((u32)t2_65) << 10) | (temp2[2] >> 22);	\
} 
#define unpackU32FormatToThreePacket(out, in) {\
temp2[0] = (in[0] & 0x000003ff) << 22;	\
t2_64 = ((in[1] & 0x00000400) << 21);	\
temp2[1] = (in[1] & 0x000003ff) << 22;	\
t2_65 = ((in[2] & 0x00000400) << 20);	\
temp2[2] = (in[2] & 0x000003ff) << 22;	\
unpuckU32ToThree(temp2[0]);	\
unpuckU32ToThree(temp2[1]);	\
unpuckU32ToThree(temp2[2]);	\
t2 = t2_65 | t2_64 | ((temp2[0] | temp2[1] >> 1 | temp2[2] >> 2) >> 2);	\
*(u32*)(out) = U32BIG(t2);	\
} 
#define unpackU96FormatToThreePacket( out, in) {\
temp0[0] = in[0] & 0xffe00000;	\
temp1[0] = (in[0] & 0x001ffc00) << 11;	\
temp2[0] = (in[0] & 0x000003ff) << 22;	\
temp0[1] = in[1] & 0xffe00000;	\
temp1[1] = (in[1] & 0x001ff800) << 11;	\
t2_64 = ((in[1] & 0x00000400) << 21);	\
temp2[1] = (in[1] & 0x000003ff) << 22;	\
temp0[2] = in[2] & 0xffc00000;	\
t1_32 = ((in[2] & 0x00200000) << 10);	\
temp1[2] = (in[2] & 0x001ff800) << 11;	\
t2_65 = ((in[2] & 0x00000400) << 20);	\
temp2[2] = (in[2] & 0x000003ff) << 22;	\
unpuckU32ToThree(temp0[0]);	\
unpuckU32ToThree(temp0[1]);	\
unpuckU32ToThree(temp0[2]);	\
t9 = temp0[0] | temp0[1] >> 1 | temp0[2] >> 2;	\
unpuckU32ToThree(temp1[0]);	\
unpuckU32ToThree(temp1[1]);	\
unpuckU32ToThree(temp1[2]);	\
t1 = t1_32 | ((temp1[0] | temp1[1] >> 1 | temp1[2] >> 2) >> 1);	\
unpuckU32ToThree(temp2[0]);	\
unpuckU32ToThree(temp2[1]);	\
unpuckU32ToThree(temp2[2]);	\
t2 = t2_65 | t2_64 | ((temp2[0] | temp2[1] >> 1 | temp2[2] >> 2) >> 2);	\
*(u32*)(out) = U32BIG(t2);	\
*(u32*)(out + 4) = U32BIG(t1);	\
*(u32*)(out + 8) = U32BIG(t9);	\
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define U96_BIT_LOTR32_8(t0,t1,t2,t3,t4,t5){\
t3= LOTR32(t2, 2);\
t4 =LOTR32(t0, 3);\
t5 = LOTR32(t1, 3); \
}
#define U96_BIT_LOTR32_55(t0,t1,t2,t3,t4,t5){\
t3= LOTR32(t1, 18); \
t4 = LOTR32(t2, 18);\
t5 = LOTR32(t0, 19); \
}
/*
s0  s1  s2
s3  s4  s5
s6  s7  s8
s9 s10 s11
*/


