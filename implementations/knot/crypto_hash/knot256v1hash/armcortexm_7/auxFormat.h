#include"api.h"
#define U32BIG(x) (x)
#include<string.h>


typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

void getU32Format(u32 *out, const u8* in);
void unpackFormat(u8 * out, u32 * in) ;
void P256(unsigned int *s, unsigned char *rc,  unsigned char rounds);


