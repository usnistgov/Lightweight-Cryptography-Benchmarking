
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

#define ROUND384(lunNum) {\
s[0] ^= (constant7Format[lunNum] >> 6) & 0x3;\
s[1] ^= (constant7Format[lunNum] >> 3) & 0x7;\
s[2] ^= constant7Format[lunNum] & 0x7;\
sbox(s[0], s[3], s[6], s[9] , s_temp[3], s_temp[6], s_temp[9]);\
sbox(s[1], s[4], s[7], s[10], s[3]     , s_temp[7], s_temp[10]);\
sbox(s[2], s[5], s[8], s[11], s[4]     , s_temp[8], s_temp[11]);\
s[5] = LOTR32(s_temp[3], 1); \
U96_BIT_LOTR32_8(s_temp[6], s_temp [7], s_temp[ 8], s[6],  s[7], s[8]);\
U96_BIT_LOTR32_55(s_temp[9], s_temp[10], s_temp[11], s[9], s[10], s[11]);\
}

//Processing_Data:
#define Processing_Data(data) \
do { \
			packU96FormatToThreePacket(dataFormat, data);          \
			s[0] ^= dataFormat[0];          \
			s[1] ^= dataFormat[1];          \
			s[2] ^= dataFormat[2];          \
			packU96FormatToThreePacket((dataFormat + 3), (data + 12));          \
			s[3] ^= dataFormat[3];          \
			s[4] ^= dataFormat[4];          \
			s[5] ^= dataFormat[5];          \
} while (0)

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

#define packU96FormatToThreePacket( out,  in) {               \
	temp0[0] = U32BIG(((u32*)in)[0]); temp0[1] = U32BIG(((u32*)in)[0]) >> 1; temp0[2] = U32BIG(((u32*)in)[0]) >> 2;               \
	puckU32ToThree_1(temp0[0]);               \
	puckU32ToThree_1(temp0[1]);               \
	puckU32ToThree_1(temp0[2]);               \
	temp1[0] = U32BIG(((u32*)in)[1]); temp1[1] = U32BIG(((u32*)in)[1]) >>1; temp1[2] = U32BIG(((u32*)in)[1]) >> 2;               \
	puckU32ToThree_1(temp1[0]);               \
	puckU32ToThree_1(temp1[1]);               \
	puckU32ToThree_1(temp1[2]);               \
	temp2[0] = U32BIG(((u32*)in)[2]); temp2[1] = U32BIG(((u32*)in)[2]) >> 1; temp2[2] = U32BIG(((u32*)in)[2]) >> 2;               \
	puckU32ToThree_1(temp2[0]);               \
	puckU32ToThree_1(temp2[1]);               \
	puckU32ToThree_1(temp2[2]);               \
	out[0] = (temp2[1]<<21)	|(temp1[0]<<10)	|temp0[2];               \
	out[1] = (temp2[0] << 21) | (temp1[2] << 11) | temp0[1];               \
	out[2] = (temp2[2] << 22) | (temp1[1] << 11) | temp0[0];               \
}

#define unpackU96FormatToThreePacket( out, in) {\
	temp0[0] = in[2] & 0x7ff;               \
	temp0[1] = in[1] & 0x7ff;                             \
	temp0[2] = in[0] & 0x3ff;               \
	temp1[0] = (in[0]>>10) & 0x7ff;               \
	temp1[1] = (in[2] >>11 ) & 0x7ff;               \
	temp1[2] = (in[1] >> 11) & 0x3ff;               \
	temp2[0] = in[1] >> 21;               \
	temp2[1] = in[0] >> 21;               \
	temp2[2] = in[2] >> 22;               \
	unpuckU32ToThree_1(temp0[0]);               \
	unpuckU32ToThree_1(temp0[1]);               \
	unpuckU32ToThree_1(temp0[2]);               \
	t[0] = temp0[0] | temp0[1] << 1 | temp0[2] << 2;               \
	unpuckU32ToThree_1(temp1[0]);               \
	unpuckU32ToThree_1(temp1[1]);               \
	unpuckU32ToThree_1(temp1[2]);               \
	t[1] = temp1[0] | temp1[1] << 1 | temp1[2] << 2;               \
	unpuckU32ToThree_1(temp2[0]);               \
	unpuckU32ToThree_1(temp2[1]);               \
	unpuckU32ToThree_1(temp2[2]);               \
	t[2] = temp2[0] | temp2[1] << 1 | temp2[2] << 2;           \
	memcpy(out, t, 12 * sizeof(unsigned char));                \
}




