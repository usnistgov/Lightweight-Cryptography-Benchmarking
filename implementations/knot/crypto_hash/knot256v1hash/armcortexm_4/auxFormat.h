#include"crypto_hash.h"
#include"api.h"
#define U32BIG(x) (x)


#include<stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}


#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))
void getU32Format(u32 *out, const u8* in);
void unpackFormat(u8 * out, u32 * in) ;
void P256(unsigned int *s, unsigned char *rc,  unsigned char rounds);


