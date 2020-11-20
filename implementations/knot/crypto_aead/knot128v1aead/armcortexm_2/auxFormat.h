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

void packFormat(u32 * out, const u8 * in);
void unpackFormat(u8 * out, u32 * in);
void printU8(char name[], u8 var[], long len, int offset);

