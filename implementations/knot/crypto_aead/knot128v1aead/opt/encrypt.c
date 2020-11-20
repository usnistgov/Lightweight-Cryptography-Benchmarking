#include "api.h"

typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;
#define RATE (64 / 8)

#define PR0_ROUNDS 52
#define PR_ROUNDS 28
#define PRF_ROUNDS 32

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))

#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(n))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(n)))
#define U64BIG(x) (x)
static const u8 constant6[63] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03,
		0x06, 0x0c, 0x18, 0x31, 0x22, 0x05, 0x0a, 0x14, 0x29, 0x13, 0x27, 0x0f,
		0x1e, 0x3d, 0x3a, 0x34, 0x28, 0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32,
		0x24, 0x09, 0x12, 0x25, 0x0b, 0x16, 0x2d, 0x1b, 0x37, 0x2e, 0x1d, 0x3b,
		0x36, 0x2c, 0x19, 0x33, 0x26, 0x0d, 0x1a, 0x35, 0x2a, 0x15, 0x2b, 0x17,
		0x2f, 0x1f, 0x3f, 0x3e, 0x3c, 0x38, 0x30, 0x20 };

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}
#define ROUND256(i) ({\
x0^=constant6[i];\
sbox(x0, x1, x2, x3,x4, x5, x6, x7);\
x0=x4;\
x1=LOTR64(x5,1);\
x2=LOTR64(x6,8);\
x3=LOTR64(x7,25);\
})

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {

	u64 K0 = U64BIG(((u64*)k)[0]);
	u64 K1 = U64BIG(((u64*)k)[1]);
	u64 N0 = U64BIG(((u64*)npub)[0]);
	u64 N1 = U64BIG(((u64*)npub)[1]);

	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u64 x3, x2, x1, x0, x7, x6, x5, x4;
	u64 rlen, i;

	// initialization
	x0 = N0;
	x1 = N1;
	x2 = K0;
	x3 = K1;

	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND256(i);
	}
	// process associated data
	if (adlen) {
		rlen = adlen;
		while (rlen >= RATE) {
			x0 ^= U64BIG(*(u64*)ad);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			rlen -= RATE;
			ad += RATE;
		}
		for (i = 0; i < rlen; ++i, ++ad)
			x0 ^= INS_BYTE(*ad, i);
		x0 ^= INS_BYTE(0x01, rlen);

		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND256(i);
		}
	}
	x3 ^= 0x8000000000000000;
	// process plaintext

	if (mlen) {
		rlen = mlen;
		while (rlen >= RATE) {
			x0 ^= U64BIG(*(u64*)m);
			*(u64*)c = U64BIG(x0);

			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			rlen -= RATE;
			m += RATE;
			c += RATE;
		}
		for (i = 0; i < rlen; ++i, ++m, ++c) {
			x0 ^= INS_BYTE(*m, i);
			*c = EXT_BYTE(x0, i);
		}
		x0 ^= INS_BYTE(0x01, rlen);
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND256(i);
	}
	// return tag

	for (i = 0; i < 8; ++i) {
		*c = EXT_BYTE(U64BIG(x0), i);
		c++;
	}
	for (i = 0; i < 8; ++i) {
		*c = EXT_BYTE(U64BIG(x1), i);
		c++;
	}
	*clen = mlen + CRYPTO_KEYBYTES;
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	*mlen = 0;
	if (clen < CRYPTO_KEYBYTES)
		return -1;
	u64 K0 = U64BIG(((u64*)k)[0]);
	u64 K1 = U64BIG(((u64*)k)[1]);
	u64 N0 = U64BIG(((u64*)npub)[0]);
	u64 N1 = U64BIG(((u64*)npub)[1]);

	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u64 x3, x2, x1, x0, x7, x6, x5, x4;
	u64 rlen, i;

	// initialization
	x0 = N0;
	x1 = N1;
	x2 = K0;
	x3 = K1;

	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND256(i);
	}
	// process associated data
	if (adlen) {
		rlen = adlen;
		while (rlen >= RATE) {
			x0 ^= U64BIG(*(u64*)ad);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			rlen -= RATE;
			ad += RATE;
		}
		for (i = 0; i < rlen; ++i, ++ad)
			x0 ^= INS_BYTE(*ad, i);
		x0 ^= INS_BYTE(0x01, rlen);

		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND256(i);
		}
	}
	x3 ^= 0x8000000000000000;
	// process plaintext

	rlen = clen - CRYPTO_KEYBYTES;

	if (rlen) {
		while (rlen >= RATE) {
			*(u64*)m = U64BIG(x0) ^ *(u64*)c;
			x0 = U64BIG(*((u64*)c));

			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			rlen -= RATE;
			m += RATE;
			c += RATE;
		}
		for (i = 0; i < rlen; ++i, ++m, ++c) {
			*m = EXT_BYTE(x0, i) ^ *c;
			x0 &= ~INS_BYTE(0xff, i);
			x0 |= INS_BYTE(*c, i);
		}
		x0 ^= INS_BYTE(0x01, rlen);
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND256(i);
	}
	// return -1 if verification fails
	t1 = *((u64*)c);
	c += RATE;
	t2 = *((u64*)c);

	if (t1 != U64BIG(x0) || t2 != U64BIG(x1)) {
		return -1;
	}
	*mlen = clen - CRYPTO_KEYBYTES;
	return 0;
}


