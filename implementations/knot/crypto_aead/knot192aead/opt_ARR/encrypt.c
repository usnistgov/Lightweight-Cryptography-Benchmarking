#include"api.h"
#include <string.h>
#define PR0_ROUNDS 76
#define PR_ROUNDS 40
#define PRF_ROUNDS 44

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

#define RATE 12
#define sbox(a, b, c, d, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t4 = b | c; t5 = d ^ t1; g = t4 ^ t5; t6 = b ^ d; t7 = t3 & t5; a = t6 ^ t7; t8 = g & t6; f = t3 ^ t8; \
}

#define ROTR961(a,b,n) (((a)<<(n))|((b)>>(64-n)))
#define ROTR962(a,b,n) (((b)<<(n))|((a)>>(32-n)))

#define ROTR96MORE321(a,b,n) ((b<<(n-32))>>32)
#define ROTR96MORE322(a,b,n) (b<<n|(u64)a<<(n-32)|b>>(96-n))

#define U32BIG(x) (x)
#define U64BIG(x) (x)

u8 constant7[76] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06,
		0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47,
		0x0f, 0x1e, 0x3c, 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16,
		0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53,
		0x27, 0x4f, 0x1f, 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07,
		0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26,
		0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b};
#define ROUND384(i){\
		s[0] ^= constant7[i]; \
		sbox(U64BIG(((u64*)s)[0]), U64BIG(((u64*)(s+3))[0]), U64BIG(((u64*)(s+6))[0]), U64BIG(((u64*)(s+9))[0]), x50, x60, x70); \
		sbox(s[2], s[5], s[8], s[11], x51, x61, x71); \
		s[5] = ROTR961(x51, x50, 1); \
		U64BIG(((u64*)(s+3))[0]) = ROTR962(x51, x50, 1); \
		s[8] = ROTR961(x61, x60, 8); \
		U64BIG(((u64*)(s+6))[0]) = ROTR962(x61, x60, 8); \
		s[11] = ROTR96MORE321(x71, x70, 55); \
		U64BIG(((u64*)(s+9))[0]) = ROTR96MORE322(x71, x70, 55); \
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {
	*clen = mlen + CRYPTO_ABYTES;
	u32 s[12] = { 0 }, i;
	u64 t1, t2, t3, t5, t6, t8, t4, t7;
	u64   x50, x60, x70;
	u32   x51, x61, x71;
	u8 tempData[24] = { 0 };
	// initialization
	memcpy(s, npub, sizeof(unsigned char) * CRYPTO_NPUBBYTES);
	memcpy(s + CRYPTO_NPUBBYTES / 4, k, sizeof(unsigned char) * CRYPTO_KEYBYTES);



	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(ad));
			s[2] ^= U64BIG(*(u64*)(ad+8));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		s[2] ^= U32BIG(*(u32*)(tempData + 8));
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[11] ^= 0x80000000;
	// process plaintext
	if (mlen) {
		while (mlen >= RATE) {
			U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(m));
			s[2] ^= U32BIG(*(u32*)(m + 8));
			memcpy(c, s, RATE * sizeof(unsigned char));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		s[2] ^= U32BIG(*(u32*)(tempData + 8));
		memcpy(c, s, mlen * sizeof(unsigned char));
		c += mlen;
	}

	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	// return tag

	memcpy(c, s, sizeof(unsigned char) * CRYPTO_ABYTES);
	return 0;
}
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_KEYBYTES)
		return -1;

	u32 s[12] = { 0 }, i;
	u64 t1, t2, t3, t5, t6, t8, t4, t7;
	u64   x50, x60, x70;
	u32   x51, x61, x71;
	u8 tempData[24] = { 0 };
	// initialization
	memcpy(s, npub, sizeof(unsigned char) * CRYPTO_NPUBBYTES);
	memcpy(s + CRYPTO_NPUBBYTES / 4, k, sizeof(unsigned char) * CRYPTO_KEYBYTES);



	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(ad));
			s[2] ^= U32BIG(*(u32*)(ad + 8));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		s[2] ^= U32BIG(*(u32*)(tempData + 8));
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[11] ^= 0x80000000;
	// process c

	/////////
	clen -= CRYPTO_ABYTES;
	if (clen) {
		while (clen >= RATE) {
			U64BIG(*(u64*)(m)) = U64BIG(*(u64*)(s)) ^ U64BIG(*(u64*)(c));
			*(u32*)(m + 8) = s[2] ^ (*(u32*)(c + 8));
			memcpy(s, c, RATE * sizeof(unsigned char));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			clen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, c, clen * sizeof(unsigned char));
		tempData[clen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		s[2] ^= U32BIG(*(u32*)(tempData + 8));
		memcpy(m, s, clen * sizeof(unsigned char));
		memcpy(s, c, clen * sizeof(unsigned char));
		//	memcpy(m, tempData1, clen * sizeof(unsigned char));
		c += clen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	if (memcmp((void*)s, (void*)c, CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}

	return 0;
}

