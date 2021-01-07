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

// t9
#define puck32(in)\
{\
t9 = (in ^ (in >> 1)) & 0x22222222; in ^= t9 ^ (t9 << 1);\
t9 = (in ^ (in >> 2)) & 0x0C0C0C0C; in ^= t9 ^ (t9 << 2);\
t9 = (in ^ (in >> 4)) & 0x00F000F0; in ^= t9 ^ (t9 << 4);\
t9 = (in ^ (in >> 8)) & 0x0000FF00; in ^= t9 ^ (t9 << 8);\
}
// t9
#define unpuck32(t0){\
	t9 = (t0 ^ (t0 >> 8)) & 0x0000FF00, t0 ^= t9 ^ (t9 << 8); \
	t9 = (t0 ^ (t0 >> 4)) & 0x00F000F0, t0 ^= t9 ^ (t9 << 4); \
	t9 = (t0 ^ (t0 >> 2)) & 0x0C0C0C0C, t0 ^= t9 ^ (t9 << 2); \
	t9 = (t0 ^ (t0 >> 1)) & 0x22222222, t0 ^= t9 ^ (t9 << 1); \
}
//u32 t1, t2, t3,t8, 
#define packU128FormatToFourPacket(out,in) {\
	     t8 = U32BIG(((u32*)in)[0]);	\
		 t1 = U32BIG(((u32*)in)[1]);	\
		 t2 = U32BIG(((u32*)in)[2]);	\
		 t3 = U32BIG(((u32*)in)[3]);	\
		puck32(t8); puck32(t8);	\
		puck32(t1); puck32(t1);	\
		puck32(t2); puck32(t2);	\
		puck32(t3); puck32(t3);	\
		out[3] = (t3 & 0xff000000) | ((t2 >> 8) & 0x00ff0000) | ((t1 >> 16) & 0x0000ff00) | (t8 >> 24);	\
		out[2] = ((t3 << 8) & 0xff000000) | (t2 & 0x00ff0000) | ((t1 >> 8) & 0x0000ff00) | ((t8 >> 16) & 0x000000ff);	\
		out[1] = ((t3 << 16) & 0xff000000) | ((t2 << 8) & 0x00ff0000) | (t1 & 0x0000ff00) | ((t8 >> 8) & 0x000000ff);	\
		out[0] = ((t3 << 24) & 0xff000000) | ((t2 << 16) & 0x00ff0000) | ((t1 << 8) & 0x0000ff00) | (t8 & 0x000000ff);	\
}
//u32 u32 t1, t2, t3,t8, 
#define unpackU128FormatToFourPacket( out,  in) {\
t[3] = (in[3] & 0xff000000 )| ((in[2] >> 8) & 0x00ff0000)		| ((in[1] >> 16) & 0x0000ff00) | (in[0] >> 24);	\
t[2] = ((in[3] << 8) & 0xff000000) | (in[2] & 0x00ff0000)		| ((in[1] >> 8) & 0x0000ff00) | ((in[0] >> 16) & 0x000000ff);	\
t[1] = ((in[3] << 16) & 0xff000000) | ((in[2] << 8) & 0x00ff0000)		| (in[1] & 0x0000ff00) | ((in[0] >> 8) & 0x000000ff);	\
t[0] = ((in[3] << 24) & 0xff000000) | ((in[2] << 16) & 0x00ff0000)		| ((in[1] << 8) & 0x0000ff00) | (in[0] & 0x000000ff);	\
unpuck32(t[0]);	\
unpuck32(t[0]);	\
unpuck32(t[1]);	\
unpuck32(t[1]);	\
unpuck32(t[2]);	\
unpuck32(t[2]);	\
unpuck32(t[3]);\
unpuck32(t[3]);	\
memcpy(out, t, 16 * sizeof(unsigned char));\
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
s[3] ^= (constant7Format_aead[lunNum] >> 6) & 0x3;\
s[2] ^= (constant7Format_aead[lunNum] >> 4) & 0x3;\
s[1] ^= (constant7Format_aead[lunNum] >> 2) & 0x3;\
s[0] ^= constant7Format_aead[lunNum] & 0x3;\
sbox(s[3], s[7], s[11], s[15],  s_temp[7], s_temp[11], s_temp[15]);\
sbox(s[2], s[6], s[10], s[14],  s[7]     , s_temp[10], s_temp[14]);\
sbox(s[1], s[5], s[9],  s[13],  s[6]     , s_temp[9], s_temp[13]);\
sbox(s[0], s[4], s[8],  s[12],  s[5]     , s_temp[8], s_temp[12]);\
s[4]= LOTR32(s_temp[7], 1);\
BIT_LOTR32_16(s_temp[8], s_temp[9], s_temp[10], s_temp[11], s[8], s[9], s[10], s[11]);\
BIT_LOTR32_25(s_temp[12], s_temp[13], s_temp[14], s_temp[15], s[12], s[13], s[14], s[15]);\
}

