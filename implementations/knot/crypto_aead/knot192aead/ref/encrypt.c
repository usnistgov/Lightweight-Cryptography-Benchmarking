#include"api.h"

typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;
typedef long long i64;
typedef unsigned int u32;

#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define ROTR961(a,b,n) (((a)<<(n))|((b)>>(64-n)))
#define ROTR962(a,b,n) (((b)<<(n))|((a)>>(32-n)))

#define ROTR96MORE321(a,b,n) ((b<<(n-32))>>32)
#define ROTR96MORE322(a,b,n) (b<<n|(u64)a<<(n-32)|b>>(96-n))

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

void load32(u32* x, u8* S) {
	int i;
	*x = 0;
	for (i = 0; i < 4; ++i)
		*x |= ((u32)S[i]) << i * 8;
}

void store32(u8* S, u32 x) {
	int i;
	for (i = 0; i < 4; ++i)
		S[i] = (u8)(x >> i * 8);
}

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
void permutation384(u8* S, int rounds, u8 *c) {
	int i;
	u64 x00, x10, x20, x30;
	u32 x01, x11, x21, x31;
	u64 x40, x50, x60, x70;
	u32 x41, x51, x61, x71;

	load64(&x00, S + 0);
	load32(&x01, S + 8);
	load64(&x10, S + 12);
	load32(&x11, S + 20);

	load64(&x20, S + 24);
	load32(&x21, S + 32);

	load64(&x30, S + 36);
	load32(&x31, S + 44);

	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	for (i = 0; i < rounds; ++i) {
		// addition of round constant
		x00 ^= c[i];
		//substitution layer 
		sbox(x00, x10, x20, x30, x40, x50, x60, x70);
		sbox(x01, x11, x21, x31, x41, x51, x61, x71);
		// linear diffusion layer

		x00 = x40;
		x01 = x41;
		x11 = ROTR961(x51, x50, 1);
		x10 = ROTR962(x51, x50, 1);
		x21 = ROTR961(x61, x60, 8);
		x20 = ROTR962(x61, x60, 8);
		x31 = ROTR96MORE321(x71, x70, 55);
		x30 = ROTR96MORE322(x71, x70, 55);
	}
	store64(S, x00);
	store32(S + 8, x01);
	store64(S + 12, x10);
	store32(S + 20, x11);
	store64(S + 24, x20);
	store32(S + 32, x21);
	store64(S + 36, x30);
	store32(S + 44, x31);
}
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {

	int nr0 = 76;
	int nr = 40;
	int nrf = 44;
	u32 klen = CRYPTO_KEYBYTES;
	u32 nlen = CRYPTO_NPUBBYTES;
	u32 taglen = CRYPTO_ABYTES;
	u32 size = 384 / 8; //48  4*12
	u32 rate = 96 / 8; //12
	u64 u = adlen / rate + 1;
	u64 v = mlen / rate + 1;
	u64 l = mlen % rate;

	u8 S[size];
	u8 A[u * rate];
	u8 M[v * rate];
	u64 i, j;
	// pad associated data
	for (i = 0; i < adlen; ++i)
		A[i] = ad[i];
	A[adlen] = 0x01;
	for (i = adlen + 1; i < u * rate; ++i)
		A[i] = 0;
	// pad plaintext
	for (i = 0; i < mlen; ++i)
		M[i] = m[i];
	M[mlen] = 0x01;
	for (i = mlen + 1; i < v * rate; ++i)
		M[i] = 0;
	// initialization
	for (i = 0; i < nlen; ++i)
		S[i] = npub[i];
	for (i = 0; i < klen; ++i)
		S[klen + i] = k[i];
	permutation384(S, nr0, constant7);
	// process associated data
	if (adlen != 0) {
		for (i = 0; i < u; ++i) {
			for (j = 0; j < rate; ++j) {
				S[j] ^= A[i * rate + j];
			}
			permutation384(S, nr, constant7);
		}
	}
	S[size - 1] ^= 0x80;
	// process plaintext
	if (mlen) {
		for (i = 0; i < v - 1; ++i) {
			for (j = 0; j < rate; ++j) {
				S[j] ^= M[i * rate + j];
				c[i * rate + j] = S[j];
			}
			permutation384(S, nr, constant7);
		}
		//不进行Ｐ
		for (j = 0; j <= l; ++j) {
			S[j] ^= M[i * rate + j];
			c[i * rate + j] = S[j];
		}
	}
	// finalization
	permutation384(S, nrf, constant7);
	// return tag
	for (i = 0; i < taglen; ++i) {
		c[mlen + i] = S[i];
	}
	*clen = mlen + taglen;
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	int nr0 = 76;
	int nr = 40;
	int nrf = 44;

	*mlen = 0;
	if (clen < CRYPTO_KEYBYTES)
		return -1;
	u32 klen = CRYPTO_KEYBYTES;
	u32 nlen = CRYPTO_NPUBBYTES;
	u32 taglen = CRYPTO_ABYTES;
	u32 size = 384 / 8; //48  4*12
	u32 rate = 96 / 8; //24

	u64 u = adlen / rate + 1;
	u64 v = (clen - taglen) / rate + 1;
	u64 l = (clen - taglen) % rate;
	u8 S[size];
	u8 A[u * rate];
	u8 M[v * rate];
	u64 i, j;
	// pad associated data
	for (i = 0; i < adlen; ++i)
		A[i] = ad[i];
	A[adlen] = 0x01;
	for (i = adlen + 1; i < u * rate; ++i)
		A[i] = 0;
	// initialization
	for (i = 0; i < nlen; ++i)
		S[i] = npub[i];
	;
	for (i = 0; i < klen; ++i)
		S[klen + i] = k[i];
	permutation384(S, nr0, constant7);
	// process associated data
	if (adlen != 0) {
		for (i = 0; i < u; ++i) {
			for (j = 0; j < rate; ++j) {
				S[j] ^= A[i * rate + j];
			}
			permutation384(S, nr, constant7);
		}
	}
	S[size - 1] ^= 0x80;
	// process c
	if (clen - taglen > 0) {
		for (i = 0; i < v - 1; ++i) {
			for (j = 0; j < rate; ++j) {
				M[j + rate * i] = S[j] ^ c[j + rate * i];
				S[j] = c[i * rate + j];
			}
			permutation384(S, nr, constant7);
		}

		for (j = 0; j < l; ++j) {
			M[j + rate * i] = S[j] ^ c[j + rate * i];
			S[j] = c[i * rate + j];
		}
		S[j] ^= 0x01;
	}
	// finalization
	permutation384(S, nrf, constant7);
	// return -1 if verification fails
	for (i = 0; i < klen; ++i)
		if (c[clen - klen + i] != S[i])
			return -1;
	// return plaintext
	*mlen = clen - taglen;
	for (i = 0; i < *mlen; ++i)
		m[i] = M[i];
	return 0;
}



