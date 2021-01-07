#include <stdio.h>
#include "api.h"

#include <string.h>
typedef unsigned long long u64;
typedef unsigned char u8;
typedef long long i64;

#define RATE 8

#define PR0_ROUNDS 52
#define PR_ROUNDS 28
#define PRF_ROUNDS 32

#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define U64BIG(x) (x)
static const u8 constant6[52] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03,
		0x06, 0x0c, 0x18, 0x31, 0x22, 0x05, 0x0a, 0x14, 0x29, 0x13, 0x27, 0x0f,
		0x1e, 0x3d, 0x3a, 0x34, 0x28, 0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32,
		0x24, 0x09, 0x12, 0x25, 0x0b, 0x16, 0x2d, 0x1b, 0x37, 0x2e, 0x1d, 0x3b,
		0x36, 0x2c, 0x19, 0x33, 0x26, 0x0d, 0x1a, 0x35, 0x2a };

#define sbox(a, b, c, d, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}
#define ROUND256(i) {\
s[0]^=constant6[i];\
sbox(s[0], s[1], s[2], s[3], x5, x6, x7);\
s[1]=LOTR64(x5,1);\
s[2]=LOTR64(x6,8);\
s[3]=LOTR64(x7,25);\
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {
	*clen = mlen + CRYPTO_ABYTES;
	u64 x7, x6, x5,i;
	u64  t1, t2, t3, t5, t6, t8, t9, t11;
	u8 tempData[8] = { 0 };
	u64 s[4] = { 0 };
	// initialization
	memcpy(s, npub,  CRYPTO_NPUBBYTES);
	memcpy(s + 2, k,  CRYPTO_KEYBYTES);
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND256(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			s[0] ^= U64BIG(((u64*)ad)[0]);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			adlen -= RATE;
			ad += RATE;
		}

		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen );
		tempData[adlen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND256(i);
		}
	}
	s[3] ^= 0x8000000000000000;
	// process plaintext
	if (mlen) {
		while (mlen >= RATE) {
			s[0] ^= U64BIG(*(u64* )m);
			memcpy(c, s, RATE );
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, m, mlen);
		tempData[mlen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		memcpy(c, s, mlen );
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND256(i);
	}
	// return tag
	memcpy(c, s, CRYPTO_ABYTES);
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
		unsigned char *nsec, const unsigned char *c, unsigned long long clen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *npub, const unsigned char *k) {
	if (clen < CRYPTO_KEYBYTES)
		return -1;
	*mlen = clen - CRYPTO_KEYBYTES;
	u64 x7, x6, x5, i;
	u64  t1, t2, t3, t5, t6, t8, t9, t11;
	u8 tempData[8] = { 0 };
	u64 s[4] = { 0 };
	// initialization
	memcpy(s, npub, CRYPTO_NPUBBYTES);
	memcpy(s + 2, k,  CRYPTO_KEYBYTES);
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND256(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			s[0] ^= U64BIG(((u64*)ad)[0]);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			adlen -= RATE;
			ad += RATE;
		}

		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen );
		tempData[adlen] = 0x01;
		s[0] ^= U64BIG(((u64*)tempData)[0]);
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND256(i);
		}
	}
	s[3] ^= 0x8000000000000000;
	clen -= CRYPTO_ABYTES;
	if (clen) {
		while (clen >= RATE) {
			U64BIG(*(u64*)(m)) = s[0] ^ U64BIG(*(u64*)(c));
			memcpy(s, c, RATE );
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(i);
			}
			clen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, c, clen );
		tempData[clen] = 0x01;
		s[0] ^= U64BIG(*(u64*)(tempData));
		memcpy(m, s, clen );
		memcpy(s, c, clen );
		c += clen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND256(i);
	}
	if (memcmp((void*)s, (void*)c, CRYPTO_ABYTES)) {
		memset(m, 0, (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
