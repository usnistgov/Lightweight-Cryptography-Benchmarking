#include <stdio.h>
#include "api.h"

typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const u8 constant7[100] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41,
		0x03, 0x06, 0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51,
		0x23, 0x47, 0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45,
		0x0b, 0x16, 0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54,
		0x29, 0x53, 0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21,
		0x43, 0x07, 0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49,
		0x13, 0x26, 0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b,
		0x37, 0x6f, 0x5e, 0x3d, 0x7b, 0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d,
		0x1a, 0x34, 0x69, 0x52, 0x25, 0x4b, 0x17, 0x2e, 0x5d };
#define sbox(a, b, c, d, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}

#define LOTR1281(a,b,n) (((a)<<(n))|((b)>>(64-n)))
#define LOTR1282(a,b,n) (((b)<<(n))|((a)>>(64-n)))

#define U64BIG(x) (x)

#define RATE 16
#define PR0_ROUNDS 100
#define PR_ROUNDS 52
#define PRF_ROUNDS 56

#define ROUND512(i) {\
		s[0]^=constant7[i];\
		sbox(s[0], s[2], s[4], s[6],  b10, b20, b30);\
		sbox(s[1], s[3], s[5], s[7],  b11, b21, b31);\
		s[2]=LOTR1281(b10,b11,1);\
		s[4]=LOTR1281(b20,b21,16);\
		s[6]=LOTR1281(b30,b31,25);\
		s[3]=LOTR1282(b10,b11,1);\
		s[5]=LOTR1282(b20,b21,16);\
		s[7]=LOTR1282(b30,b31,25);\
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {

	*clen = mlen + CRYPTO_ABYTES;
	u64   b11, b21, b31, b10, b20, b30;
	u64  t1, t2, t3, t5, t6, t8, t9, t11;
	u64 s[8] = { 0 };
	u64  i;
	u8 tempData[32] = { 0 };
	// initialization
	memcpy(s, npub, CRYPTO_NPUBBYTES);
	memcpy(s + 4, k, CRYPTO_KEYBYTES);
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND512(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			s[0] ^= U64BIG(((u64*)ad)[0]);
			s[1] ^= U64BIG(((u64*)ad)[1]);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			adlen -= RATE;
			ad += RATE;
		}

		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		s[1] ^= U64BIG(((u64*)tempData)[1]);
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND512(i);
		}
	}
	s[7] ^= 0x8000000000000000;
	// process plaintext
	if (mlen) {
		while (mlen >= RATE) {
			s[0] ^= U64BIG(((u64*)m)[0]);
			s[1] ^= U64BIG(((u64*)m)[1]);
			memcpy(c, s, RATE);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, m, mlen);
		tempData[mlen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		s[1] ^= U64BIG(((u64*)tempData)[1]);
		memcpy(c, s, mlen);
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND512(i);
	}
	// return tag
	memcpy(c, s, CRYPTO_ABYTES);
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	u64   b11, b21, b31, b10, b20, b30;
	u64  t1, t2, t3, t5, t6, t8, t9, t11;
	u64 s[8] = { 0 };
	u64  i;
	u8 tempData[32] = { 0 };
	// initialization
	memcpy(s, npub, CRYPTO_NPUBBYTES);
	memcpy(s + 4, k, CRYPTO_KEYBYTES);
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND512(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			s[0] ^= U64BIG(((u64*)ad)[0]);
			s[1] ^= U64BIG(((u64*)ad)[1]);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			adlen -= RATE;
			ad += RATE;
		}

		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		s[1] ^= U64BIG(((u64*)tempData)[1]);
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND512(i);
		}
	}
	s[7] ^= 0x8000000000000000;
	clen -= CRYPTO_ABYTES;
	if (clen) {
		while (clen >= RATE) {

			U64BIG(((u64*)m)[0]) = s[0] ^ U64BIG(((u64*)c)[0]);
			U64BIG(((u64*)m)[1]) = s[1] ^ U64BIG(((u64*)c)[1]);
			memcpy(s, c, RATE);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(i);
			}
			clen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, c, clen);
		tempData[clen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		s[1] ^= U64BIG(((u64*)tempData)[1]);
		memcpy(m, s, clen);
		memcpy(s, c, clen);
		c += clen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND512(i);
	}
	if (memcmp((void*)s, (void*)c, CRYPTO_ABYTES)) {
		memset(m, 0, (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}


