#include"api.h"
#include <string.h>
typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

#define PR0_ROUNDS 76
#define PR_ROUNDS 28
#define PRF_ROUNDS 32
#define RATE 24
#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define LOTR64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define sbox64(a, b, c, d, f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t4 = b | c; t5 = d ^ t1; g = t4 ^ t5; t6 = b ^ d; t7 = t3 & t5; a = t6 ^ t7; t8 = g & t6; f = t3 ^ t8; \
}
#define sbox32(a, b, c, d, f, g, h)                                                                            \
{                                                                                                                             \
	t_1 = ~a; t_2 = b & t_1;t_3 = c ^ t_2; h = d ^ t_3; t_4 = b | c; t_5 = d ^ t_1; g = t_4 ^ t_5; t_6 = b ^ d; t_7 = t_3 & t_5; a = t_6 ^ t_7; t_8 = g & t_6; f = t_3 ^ t_8; \
}

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
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
		0x4d, 0x1b, 0x36, 0x6d, 0x5a, 0x35, 0x6b };

#define ROUND384(i){\
		s[0] ^= constant7[i]; \
		sbox64(U64BIG(*(u64*)(s)), U64BIG(*(u64*)(s+3)), U64BIG(*(u64*)(s+6)), U64BIG(*(u64*)(s+9)), x50, x60, x70); \
		sbox32(s[2], s[5], s[8], s[11], x51, x61, x71); \
		s[5] = ROTR961(x51, x50, 1); \
		U64BIG(*(u64*)(s + 3)) = ROTR962(x51, x50, 1); \
		s[8] = ROTR961(x61, x60, 8); \
		U64BIG(*(u64*)(s + 6)) = ROTR962(x61, x60, 8); \
		s[11] = ROTR96MORE321(x71, x70, 55); \
		U64BIG(*(u64*)(s + 9)) = ROTR96MORE322(x71, x70, 55); \
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {
	*clen = mlen + CRYPTO_ABYTES;
	u32 s[12] = { 0 }, i;
	u64 t1, t2, t3, t5, t6, t8, t4, t7;	
	u32 t_1, t_2, t_3, t_5, t_6, t_8, t_4, t_7;
	u64 x50, x60, x70;
	u32 x51, x61, x71;
	u8 tempData[24] = { 0 };
	memcpy(s, npub,  CRYPTO_NPUBBYTES);
	memcpy(s + CRYPTO_NPUBBYTES / 4, k, CRYPTO_KEYBYTES);
	s[11] = 0x80000000;
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(ad));
			U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(ad + 8));
			U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(ad + 16));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen  );
		tempData[adlen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(tempData + 8));
		U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(tempData + 16));
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[11] ^= 0x80000000;
	// process plaintext
	if (mlen) {
		while (mlen >= RATE) {
			U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(m));
			U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(m + 8));
			U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(m + 16));
			memcpy(c, s, RATE  );
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, m, mlen  );
		tempData[mlen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(tempData + 8));
		U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(tempData + 16));
		memcpy(c, s, mlen );
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	memcpy(c, s,  CRYPTO_ABYTES);
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {
	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	u32 s[12] = { 0 }, i;
	u64 t1, t2, t3, t5, t6, t8, t4, t7;
	u32 t_1, t_2, t_3, t_5, t_6, t_8, t_4, t_7;
	u64 x50, x60, x70;
	u32 x51, x61, x71;
	u8 tempData[24] = { 0 };
	memcpy(s, npub,   CRYPTO_NPUBBYTES);
	memcpy(s + CRYPTO_NPUBBYTES / 4, k,  CRYPTO_KEYBYTES);
	s[11] = 0x80000000;
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(ad));
			U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(ad + 8));
			U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(ad + 16));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen  );
		tempData[adlen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(tempData + 8));
		U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(tempData + 16));
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[11] ^= 0x80000000;
	/////////
	clen -= CRYPTO_ABYTES;
	if (clen) {
		while (clen >= RATE) {
			U64BIG(*(u64*)(m)) =
				U64BIG(*(u64*)(s)) ^ U64BIG(*(u64*)(c));
			U64BIG(*(u64*)(m + 8)) = U64BIG(
				*(u64*)(s + 2)) ^ U64BIG(*(u64*)(c + 8));
			U64BIG(*(u64*)(m + 16)) = U64BIG(
				*(u64*)(s + 4)) ^ U64BIG(*(u64*)(c + 16));
			memcpy(s, c, RATE  );
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			clen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, c, clen );
		tempData[clen] = 0x01;
		U64BIG(*(u64*)(s)) ^= U64BIG(*(u64*)(tempData));
		U64BIG(*(u64*)(s + 2)) ^= U64BIG(*(u64*)(tempData + 8));
		U64BIG(*(u64*)(s + 4)) ^= U64BIG(*(u64*)(tempData + 16));
		memcpy(m, s, clen  );
		memcpy(s, c, clen  );
		c += clen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	if (memcmp((void*)s, (void*)c, CRYPTO_ABYTES)) {
		memset(m, 0,   (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}


