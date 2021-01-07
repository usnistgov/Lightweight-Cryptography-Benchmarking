#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#define U32BIG(x) (x)

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

void P256(unsigned int *s, unsigned char *rc, unsigned char rounds);
void packFormat(u32 * out, const u8 * in);
void unpackFormat(u8 * out, u32 * in);
