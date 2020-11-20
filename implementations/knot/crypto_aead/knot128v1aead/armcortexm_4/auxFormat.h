#include<malloc.h>
#include"crypto_aead.h"
#include"api.h"
#include"stdio.h"
#include  <string.h>
#define U32BIG(x) (x)

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
unsigned char constant6Format[52];
unsigned char constant7Format[68];

#define RATE (64 / 8)

#define PR0_ROUNDS 52
#define PR_ROUNDS 28
#define PRF_ROUNDS 32

#define sbox(a, b, c, d,  f, g, h) \
{  \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

void packFormat(u32 * out, const u8 * in);
void unpackFormat(u8 * out, u32 * in);

