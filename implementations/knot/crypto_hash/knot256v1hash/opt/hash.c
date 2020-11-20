#include"api.h"
typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef long long i64;

#define RATE (32 / 8)
#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define PRH_ROUNDS 68
#define ROUND256(i) ({\
		x0^=constant7[i];\
		sbox(x0, x1, x2, x3,x4, x5, x6, x7);\
		x0=x4;\
		x1=LOTR64(x5,1);\
		x2=LOTR64(x6,8);\
		x3=LOTR64(x7,25);\
})

#define EXT_BYTE32(x,n) ((u8)((u32)(x)>>(8*(n))))
#define INS_BYTE32(x,n) ((u32)(x)<<(8*(n)))
#define U32BIG(x) (x)
#define EXT_BYTE64(x,n) ((u8)((u64)(x)>>(8*(n))))
#define INS_BYTE64(x,n) ((u64)(x)<<(8*(n)))
#define U64BIG(x) (x)

u8 constant7[127] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06,
		0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47,
		0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16,
		0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53,
		0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07,
		0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26,
		0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37, 0x6f,
		0x5e, 0x3d, 0x7b, 0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d, 0x1a, 0x34,
		0x69, 0x52, 0x25, 0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e, 0x5c, 0x39,
		0x73, 0x66, 0x4c, 0x19, 0x32, 0x65, 0x4a, 0x15, 0x2a, 0x55, 0x2b, 0x57,
		0x2f, 0x5f, 0x3f, 0x7f, 0x7e, 0x7c, 0x78, 0x70, 0x60, 0x40 };
int crypto_hash(unsigned char *out, const unsigned char *in,
	unsigned long long inlen) {

	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u64 x3 = 0, x2 = 0, x1 = 0, x0 = 0, x7, x6, x5, x4;
	u64 rlen, i;

	// initialization
	//absorb
	rlen = inlen;
	//RATE=4
	while (rlen >= RATE) {
		x0 ^= (u64)U32BIG(*(u32*)in);
		for (i = 0; i < PRH_ROUNDS; i++) {

			ROUND256(i);
		}
		rlen -= RATE;
		in += RATE;
	}

	for (i = 0; i < rlen; ++i, ++in)
		x0 ^= (u64)INS_BYTE32(*in, i);
	x0 ^= (u64)INS_BYTE32(0x01, rlen);

	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND256(i);
	}

	//sequeez

	((u64*)out)[0] = U64BIG(x0);
	((u64*)out)[1] = U64BIG(x1);
	out += CRYPTO_BYTES / 2;
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND256(i);
	}
	((u64*)out)[0] = U64BIG(x0);
	((u64*)out)[1] = U64BIG(x1);
	return 0;
}




