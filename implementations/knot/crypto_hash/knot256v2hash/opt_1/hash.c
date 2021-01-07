#include "api.h"
#include <string.h>
#define PRH_ROUNDS 80
typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;
#define RATE 16
#define sbox(a, b, c, d, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}
#define ROTR96MORE321(a,b,n) ((b<<(n-32))>>32)
#define ROTR96MORE322(a,b,n) (b<<n|(u64)a<<(n-32)|b>>(96-n))
#define ROTR961(a,b,n) (((a)<<(n))|((b)>>(64-n)))
#define ROTR962(a,b,n) (((b)<<(n))|((a)>>(32-n)))
#define U32BIG(x) (x)
#define U64BIG(x) (x)
u8 constant7[80] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06,
		0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47,
		0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16,
		0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53,
		0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07,
		0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26,
		0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37};
#define ROUND384(i) {\
x00 ^= constant7[i];\
sbox(x00, x10, x20, x30, x50, x60, x70);\
sbox(x01, x11, x21, x31, x51, x61, x71);\
x11 = ROTR961(x51, x50, 1);\
x10 = ROTR962(x51, x50, 1);\
x21 = ROTR961(x61, x60, 8);\
x20 = ROTR962(x61, x60, 8);\
x31 = ROTR96MORE321(x71, x70, 55);\
x30 = ROTR96MORE322(x71, x70, 55);\
}
int crypto_hash(unsigned char *out, const unsigned char *in,
	unsigned long long inlen) {
	u64  i; 
	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u64 x30 = 0, x20 = 0, x10 = 0, x00 = 0;
	u32 x31 = 0x80000000, x21 = 0, x11 = 0, x01 = 0;
	u64  x50, x60, x70;
	u32  x51, x61, x71;
	u8 tempData1[16] = { 0 };
	// initialization
	//absorb
	while (inlen >= RATE) {
		x00 ^= U64BIG(*(u64*)in);
		x01 ^= U32BIG(*(u32*)(in + 8));
		x10 ^= U32BIG(*(u32*)(in + 12));
		for (i = 0; i < PRH_ROUNDS; i++) {
			ROUND384(i);
		}
		inlen -= RATE;
		in += RATE;
	}

	memset(tempData1, 0, RATE);
	memcpy(tempData1, in, inlen );
	tempData1[inlen] = 0x01;
	x00 ^= U64BIG(*(u64*)tempData1);
	x01 ^= U32BIG(*(u32*)(tempData1 + 8));
	x10 ^= U32BIG(*(u32*)(tempData1 + 12));
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND384(i);
	}
	//sequeez
	*(u64*)(out) = U64BIG(x00);
	*(u32*)(out + 8) = U32BIG(x01);
	*(u32*)(out + 12) = U64BIG(x10);
	out += CRYPTO_BYTES / 2;
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND384(i);
	}
	*(u64*)(out) = U64BIG(x00);
	*(u32*)(out + 8) = U32BIG(x01);
	*(u32*)(out + 12) = U64BIG(x10);
	return 0;
}



