#include"crypto_aead.h"
#include"api.h"
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))
u8 constant6[63] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06, 0x0c, 0x18,
		0x31, 0x22, 0x05, 0x0a, 0x14, 0x29, 0x13, 0x27, 0x0f, 0x1e, 0x3d, 0x3a,
		0x34, 0x28, 0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32, 0x24, 0x09, 0x12,
		0x25, 0x0b, 0x16, 0x2d, 0x1b, 0x37, 0x2e, 0x1d, 0x3b, 0x36, 0x2c, 0x19,
		0x33, 0x26, 0x0d, 0x1a, 0x35, 0x2a, 0x15, 0x2b, 0x17, 0x2f, 0x1f, 0x3f,
		0x3e, 0x3c, 0x38, 0x30, 0x20 };

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

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {
	int nr0 = 52;
	int nr = 28;
	int nrf = 32;
	int b = 256, r = 64;
	u32 size = b / 8; //32
	u32 rate = r / 8; //8
	u32 klen = CRYPTO_KEYBYTES;
	u32 nlen = CRYPTO_NPUBBYTES;
	u32 taglen = CRYPTO_ABYTES;
	u32 u = adlen / rate + 1;
	u32 v = mlen / rate + 1;
	u32 vl = mlen % rate;
	u32 i, j;
	u8 A[u * rate];
	u8 M[v * rate];
	u8 S[size];
	//pad associated data
	for (i = 0; i < adlen; i++) {
		A[i] = ad[i];
	}
	A[adlen] = 0x01;
	for (i = adlen + 1; i < u * rate; i++) {
		A[i] = 0;
	}
	//pad plaintext data
	for (i = 0; i < mlen; i++) {
		M[i] = m[i];
	}
	M[mlen] = 0x01;
	for (i = mlen + 1; i < v * rate; i++) {
		M[i] = 0;
	}

	//initalization
	for (i = 0; i < nlen; i++) {
		S[i] = npub[i];
	}
	for (i = 0; i < klen; i++) {
		S[i + nlen] = k[i];
	}
	permutation256(S, nr0, constant6);
	//processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			for (j = 0; j < rate; j++) {
				S[j] ^= A[i * rate + j];
			}
			permutation256(S, nr, constant6);
		}
	}
	S[size - 1] ^= 0x80;
	// Encryption processiong plaintext data
	if (mlen != 0) {
		for (i = 0; i < v - 1; i++) {
			for (j = 0; j < rate; j++) {
				S[j] ^= M[i * rate + j];
				c[i * rate + j] = S[j];
			}
			permutation256(S, nr, constant6);
		}
		for (j = 0; j <= vl; j++) {
			S[j] ^= M[(v - 1) * rate + j];
			c[(v - 1) * rate + j] = S[j];
		}
	}
	//finalization
	permutation256(S, nrf, constant6);
	//return tag
	for (i = 0; i < taglen; i++) {
		c[mlen + i] = S[i];
	}
	*clen = mlen + taglen;
	return 0;
}
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	*mlen = 0;
	if (clen < CRYPTO_KEYBYTES)
		return -1;
	int nr0 = 52;
	int nr = 28;
	int nrf = 32;
	int b = 256, r = 64;
	u32 size = b / 8; //32
	u32 rate = r / 8; //8
	u32 klen = CRYPTO_KEYBYTES;
	u32 nlen = CRYPTO_NPUBBYTES;
	u32 taglen = CRYPTO_ABYTES;
	u32 u = adlen / rate + 1;
	u32 v = (clen - taglen) / rate + 1;
	u32 vl = (clen - taglen) % rate;
	u32 i, j;
	u8 A[u * rate];
	u8 M[v * rate];
	u8 S[size];
	//pad associated data
	for (i = 0; i < adlen; i++) {
		A[i] = ad[i];
	}
	A[adlen] = 0x01;
	for (i = adlen + 1; i < u * rate; i++) {
		A[i] = 0;
	}
	//initalization
	for (i = 0; i < nlen; i++) {
		S[i] = npub[i];
	}
	for (i = 0; i < klen; i++) {
		S[i + nlen] = k[i];
	}
	permutation256(S, nr0, constant6);
	//processiong associated data
	if (adlen != 0) {
		for (i = 0; i < u; i++) {
			for (j = 0; j < rate; j++) {
				S[j] ^= A[i * rate + j];
			}
			permutation256(S, nr, constant6);
		}
	}
	S[size - 1] ^= 0x80;
	// Encryption processiong 	ciphertext data

	if (clen != CRYPTO_KEYBYTES) {
		for (i = 0; i < v - 1; i++) {
			for (j = 0; j < rate; j++) {
				M[i * rate + j] = S[j] ^ c[i * rate + j];
				S[j] = c[i * rate + j];
			}
			permutation256(S, nr, constant6);
		}
		for (j = 0; j < vl; j++) {
			M[i * rate + j] = S[j] ^ c[i * rate + j];
			S[j] = c[i * rate + j];
		}
		S[j] ^= 0x01;
	}
	//finalization
	permutation256(S, nrf, constant6);
	// return -1 if verification fails
	for (i = 0; i < taglen; i++) {
		if (c[clen - taglen + i] != S[i]) {
			return -1;
		}
	}
	*mlen = clen - taglen;
	for (i = 0; i < clen - taglen; i++) {
		m[i] = M[i];
	}
	return 0;
}
