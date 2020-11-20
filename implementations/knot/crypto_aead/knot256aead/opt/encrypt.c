#include "api.h"

typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;

static const u8 constant7[127] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41,
		0x03, 0x06, 0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51,
		0x23, 0x47, 0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45,
		0x0b, 0x16, 0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54,
		0x29, 0x53, 0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21,
		0x43, 0x07, 0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49,
		0x13, 0x26, 0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b,
		0x37, 0x6f, 0x5e, 0x3d, 0x7b, 0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d,
		0x1a, 0x34, 0x69, 0x52, 0x25, 0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e,
		0x5c, 0x39, 0x73, 0x66, 0x4c, 0x19, 0x32, 0x65, 0x4a, 0x15, 0x2a, 0x55,
		0x2b, 0x57, 0x2f, 0x5f, 0x3f, 0x7f, 0x7e, 0x7c, 0x78, 0x70, 0x60, 0x40 };
#define sbox(a, b, c, d, e, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; e = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR1281(a,b,n) (((a)<<(n))|((b)>>(64-n)))
#define LOTR1282(a,b,n) (((b)<<(n))|((a)>>(64-n)))

#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(n))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(n)))
#define U64BIG(x) (x)

#define RATE (128 / 8)
#define PR0_ROUNDS 100
#define PR_ROUNDS 52
#define PRF_ROUNDS 56

#define ROUND512(i) ({\
		x00^=constant7[i];\
		sbox(x00, x10, x20, x30, b00, b10, b20, b30);\
		sbox(x01, x11, x21, x31, b01, b11, b21, b31);\
		x00=b00;\
		x10=LOTR1281(b10,b11,1);\
		x20=LOTR1281(b20,b21,16);\
		x30=LOTR1281(b30,b31,25);\
		x01=b01;\
		x11=LOTR1282(b10,b11,1);\
		x21=LOTR1282(b20,b21,16);\
		x31=LOTR1282(b30,b31,25);\
})
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {

	u64 b01, b11, b21, b31, b00, b10, b20, b30;
	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u64 x30, x20, x10, x00, x31, x21, x11, x01;

	u64 rlen, i;

	// initialization
	x00 = U64BIG(((u64*)npub)[0]);
	x01 = U64BIG(((u64*)npub)[1]);
	x10 = U64BIG(((u64*)npub)[2]);
	x11 = U64BIG(((u64*)npub)[3]);
	x20 = U64BIG(((u64*)k)[0]);
	x21 = U64BIG(((u64*)k)[1]);
	x30 = U64BIG(((u64*)k)[2]);
	x31 = U64BIG(((u64*)k)[3]);

	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND512(i);
	}
	// process associated data
	if (adlen) {
		rlen = adlen;
		while (rlen >= RATE) {
			x00 ^= U64BIG(((u64*)ad)[0]);
			x01 ^= U64BIG(((u64*)ad)[1]);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			rlen -= RATE;
			ad += RATE;
		}
		for (i = 0; i < rlen; ++i, ++ad)
			if (i < 8)
				x00 ^= INS_BYTE(*ad, i);
			else
				x01 ^= INS_BYTE(*ad, i - 8);
		if (rlen < 8)
			x00 ^= INS_BYTE(0x01, rlen);
		else
			x01 ^= INS_BYTE(0x01, (rlen - 8));

		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND512(i);
		}
	}
	x31 ^= 0x8000000000000000;

	// process plaintext
	rlen = mlen;
	if (rlen) {
		while (rlen >= RATE) {
			x00 ^= U64BIG(((u64*)m)[0]);
			x01 ^= U64BIG(((u64*)m)[1]);
			((u64*)c)[0] = U64BIG(x00);
			((u64*)c)[1] = U64BIG(x01);

			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			rlen -= RATE;
			m += RATE;
			c += RATE;
		}

		for (i = 0; i < rlen; ++i, ++m, ++c) {
			if (i < 8) {
				x00 ^= INS_BYTE(*m, i);
				*c = EXT_BYTE(x00, i);

			}
			else {
				x01 ^= INS_BYTE(*m, i - 8);
				*c = EXT_BYTE(x01, i - 8);

			}
		}
		if (rlen < 8)
			x00 ^= INS_BYTE(0x01, rlen);
		else
			x01 ^= INS_BYTE(0x01, (rlen - 8));

	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND512(i);
	}
	// return tag
	((u64*)c)[0] = U64BIG(x00);
	((u64*)c)[1] = U64BIG(x01);
	((u64*)c)[2] = U64BIG(x10);
	((u64*)c)[3] = U64BIG(x11);
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
	u64 rlen, i;

	u64 b01, b11, b21, b31, b00, b10, b20, b30;
	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u64 x30, x20, x10, x00, x31, x21, x11, x01;
	// initialization
	x00 = U64BIG(((u64*)npub)[0]);
	x01 = U64BIG(((u64*)npub)[1]);
	x10 = U64BIG(((u64*)npub)[2]);
	x11 = U64BIG(((u64*)npub)[3]);
	x20 = U64BIG(((u64*)k)[0]);
	x21 = U64BIG(((u64*)k)[1]);
	x30 = U64BIG(((u64*)k)[2]);
	x31 = U64BIG(((u64*)k)[3]);

	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND512(i);
	}
	// process associated data
	if (adlen) {
		rlen = adlen;
		while (rlen >= RATE) {
			x00 ^= U64BIG(((u64*)ad)[0]);
			x01 ^= U64BIG(((u64*)ad)[1]);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			rlen -= RATE;
			ad += RATE;
		}
		for (i = 0; i < rlen; ++i, ++ad)
			if (i < 8)
				x00 ^= INS_BYTE(*ad, i);
			else
				x01 ^= INS_BYTE(*ad, i - 8);
		if (rlen < 8)
			x00 ^= INS_BYTE(0x01, rlen);
		else
			x01 ^= INS_BYTE(0x01, (rlen - 8));

		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND512(i);
		}
	}
	x31 ^= 0x8000000000000000;
	// process plaintext
	rlen = clen - CRYPTO_KEYBYTES;
	if (rlen) {
		while (rlen >= RATE) {
			((u64*)m)[0] = U64BIG(x00) ^ ((u64*)c)[0];
			((u64*)m)[1] = U64BIG(x01) ^ ((u64*)c)[1];
			x00 = U64BIG(((u64*)c)[0]);
			x01 = U64BIG(((u64*)c)[1]);

			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			rlen -= RATE;
			m += RATE;
			c += RATE;
		}

		for (i = 0; i < rlen; ++i, ++m, ++c) {
			if (i < 8) {

				*m = EXT_BYTE(x00, i) ^ *c;
				x00 &= ~INS_BYTE(0xff, i);
				x00 |= INS_BYTE(*c, i);

			}
			else {
				*m = EXT_BYTE(x01, i - 8) ^ *c;
				x01 &= ~INS_BYTE(0xff, i - 8);
				x01 |= INS_BYTE(*c, i - 8);

			}
		}
		if (rlen < 8)
			x00 ^= INS_BYTE(0x01, rlen);
		else
			x01 ^= INS_BYTE(0x01, (rlen - 8));

	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND512(i);
	}
	// return -1 if verification fails

	if (((u64*)c)[0] != U64BIG(x00) || ((u64*)c)[1] != U64BIG(x01)
		|| ((u64*)c)[2] != U64BIG(x10) || ((u64*)c)[3] != U64BIG(x11))
		return -1;
	// return plaintext
	*mlen = clen - CRYPTO_KEYBYTES;
	return 0;
}

