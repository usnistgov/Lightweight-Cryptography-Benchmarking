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
#define packFormat(out,in) {\
t1 = U32BIG(((u32*)in)[0]);	\
t2 = U32BIG(((u32*)in)[1]);	\
t3 = (t1 ^ (t1 >> 1)) & 0x22222222, t1 ^= t3 ^ (t3 << 1);	\
t3 = (t1 ^ (t1 >> 2)) & 0x0C0C0C0C, t1 ^= t3 ^ (t3 << 2);	\
t3 = (t1 ^ (t1 >> 4)) & 0x00F000F0, t1 ^= t3 ^ (t3 << 4);	\
t3 = (t1 ^ (t1 >> 8)) & 0x0000FF00, t1 ^= t3 ^ (t3 << 8);  	\
t5 = (t2 ^ (t2 >> 1)) & 0x22222222, t2 ^= t5 ^ (t5 << 1);	\
t5 = (t2 ^ (t2 >> 2)) & 0x0C0C0C0C, t2 ^= t5 ^ (t5 << 2);	\
t5 = (t2 ^ (t2 >> 4)) & 0x00F000F0, t2 ^= t5 ^ (t5 << 4);	\
t5 = (t2 ^ (t2 >> 8)) & 0x0000FF00, t2 ^= t5 ^ (t5 << 8);  	\
out[0] = (t2 & 0xFFFF0000) | (t1 >> 16);                  	\
out[1] = (t2 << 16) | (t1 & 0x0000FFFF);                	\
}
#define unpackFormat(out, in) {\
		t2 = (in[0] & 0xFFFF0000) | (in[1] >> 16); \
		t1 = (in[1] & 0x0000FFFF) | (in[0] << 16); \
		t3 = (t1 ^ (t1 >> 8)) & 0x0000FF00, t1 ^= t3 ^ (t3 << 8); \
		t3 = (t1 ^ (t1 >> 4)) & 0x00F000F0, t1 ^= t3 ^ (t3 << 4); \
		t3 = (t1 ^ (t1 >> 2)) & 0x0C0C0C0C, t1 ^= t3 ^ (t3 << 2); \
		t3 = (t1 ^ (t1 >> 1)) & 0x22222222, t1 ^= t3 ^ (t3 << 1); \
		t5 = (t2 ^ (t2 >> 8)) & 0x0000FF00, t2 ^= t5 ^ (t5 << 8); \
		t5 = (t2 ^ (t2 >> 4)) & 0x00F000F0, t2 ^= t5 ^ (t5 << 4); \
		t5 = (t2 ^ (t2 >> 2)) & 0x0C0C0C0C, t2 ^= t5 ^ (t5 << 2); \
		t5 = (t2 ^ (t2 >> 1)) & 0x22222222, t2 ^= t5 ^ (t5 << 1); \
		*((u64*)out) = ((u64)t2 << 32 | t1); \
}
#define getU32Format(out,  in) {\
	  t1, t2 = U32BIG(((u32*)in)[0]);	\
		t1 = (t2 ^ (t2 >> 1)) & 0x22222222, t2 ^= t1 ^ (t1 << 1);	\
		t1 = (t2 ^ (t2 >> 2)) & 0x0C0C0C0C, t2 ^= t1 ^ (t1 << 2);	\
		t1 = (t2 ^ (t2 >> 4)) & 0x00F000F0, t2 ^= t1 ^ (t1 << 4);	\
		t1 = (t2 ^ (t2 >> 8)) & 0x0000FF00, t2 ^= t1 ^ (t1 << 8);	\
		*out = t2;	\
}
#define ROUND256( constant6Format,lunNum) {\
	s[0] ^= constant6Format[lunNum]>> 4;\
	s[1] ^= constant6Format[lunNum]& 0x0f;\
	sbox(s[0], s[2], s[4], s[6], s_temp[2], s_temp[4], s_temp[6]);\
	sbox(s[1], s[3], s[5], s[7], s[2], s_temp[5], s_temp[7]);\
	s[3] = LOTR32(s_temp[2], 1);\
	s[4] = LOTR32(s_temp[4], 4);\
	s[5] = LOTR32(s_temp[5], 4);\
	s[6] = LOTR32(s_temp[7], 12);\
	s[7] = LOTR32(s_temp[6], 13);\
}


