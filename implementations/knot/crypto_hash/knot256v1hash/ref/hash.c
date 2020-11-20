#include"api.h"
typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef long long i64;
#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))

void load64(u64* x, u8* S) {
	int i;
	*x = 0;
	for (i = 0; i < 8; ++i)
		*x |= ((u64)S[i]) << i * 8;
}

void store64(u8* S, u64 x) {
	int i;
	for (i = 0; i < 8; ++i)
		S[i] = (u8)(x >> i * 8);
}

void permutation256(u8* S, int rounds, u8 *c) {

	int i;
	u64 x0, x1, x2, x3, x4, x5, x6, x7;
	u64 t1, t2, t3, t5, t6, t8, t9, t11;

	load64(&x0, S + 0);
	load64(&x1, S + 8);
	load64(&x2, S + 16);
	load64(&x3, S + 24);
	for (i = 0; i < rounds; ++i) {
		// addition of round constant
		x0 ^= c[i];
		// substitution layer
		sbox(x0, x1, x2, x3, x4, x5, x6, x7);
		// linear diffusion layer
		x0 = x4;
		x1 = LOTR64(x5, 1);
		x2 = LOTR64(x6, 8);
		x3 = LOTR64(x7, 25);
	}
	store64(S + 0, x0);
	store64(S + 8, x1);
	store64(S + 16, x2);
	store64(S + 24, x3);
}
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
	int nrh = 68;
	u32 i, j;
	int b = 256,
		r1 = 32, r2 = 128;
	u32 size = b / 8; //32    256=4*64=4*u64
	u32 rate1 = r1 / 8; //4
	u32 rate2 = r2 / 8; //128/8=16
	u64 v = inlen / rate1 + 1;
	u32 u = CRYPTO_BYTES / rate2; //32/16=2

	u8 M[v * rate1];
	u8 S[size];
	// pad in
	for (i = 0; i < inlen; ++i)
		M[i] = in[i];
	M[inlen] = 0x01;
	for (i = inlen + 1; i < v * rate1; ++i)
		M[i] = 0;
	// initialization
	for (i = 0; i < size; ++i)
		S[i] = 0;

	//absorb
	for (i = 0; i < v; ++i) {

		for (j = 0; j < rate1; ++j)
			S[j] ^= M[i * rate1 + j];

		permutation256(S, nrh, constant7);
	}

	//sequeez
	for (i = 0; i < u - 1; ++i) {
		for (j = 0; j < rate2; ++j) {
			out[j + i * rate2] = S[j];
		}
		permutation256(S, nrh, constant7);
	}
	for (j = 0; j < rate2; ++j) {
		out[j + i * rate2] = S[j];
	}
	return 0;
}

