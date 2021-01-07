#include"api.h"

#include <string.h>
typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

#define RATE (96 / 8)
#define PR0_ROUNDS 76
#define PR_ROUNDS 40
#define PRF_ROUNDS 44
#define sbox32(a, b, c, d,  f, g, h)                                                                            \
{                                                                                                                             \
	t_1 = ~a; t_2 = b & t_1;t_3 = c ^ t_2; h = d ^ t_3; t_5 = b | c; t_6 = d ^ t_1; g = t_5 ^ t_6; t_8 = b ^ d; t_9 = t_3 & t_6; a = t_8 ^ t_9; t_11 = g & t_8; f = t_3 ^ t_11; \
}

#define sbox64(a, b, c, d,  f, g, h)                                                                            \
{                                                                                                                             \
	t1 = ~a; t2 = b & t1;t3 = c ^ t2; h = d ^ t3; t5 = b | c; t6 = d ^ t1; g = t5 ^ t6; t8 = b ^ d; t9 = t3 & t6; a = t8 ^ t9; t11 = g & t8; f = t3 ^ t11; \
}


#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define ROTR961(a,b,n) (((a)<<(n))|((b)>>(64-n)))
#define ROTR962(a,b,n) (((b)<<(n))|((a)>>(32-n)))

#define ROTR96MORE321(a,b,n) ((b<<(n-32))>>32)
#define ROTR96MORE322(a,b,n) (b<<n|(u64)a<<(n-32)|b>>(96-n))

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

#define ROUND384(i) {\
x00 ^= constant7[i];\
sbox64(x00, x10, x20, x30,  x50, x60, x70);\
sbox32(x01, x11, x21, x31,  x51, x61, x71);\
x11 = ROTR961(x51, x50, 1);\
x10 = ROTR962(x51, x50, 1);\
x21 = ROTR961(x61, x60, 8);\
x20 = ROTR962(x61, x60, 8);\
x31 = ROTR96MORE321(x71, x70, 55);\
x30 = ROTR96MORE322(x71, x70, 55);\
}
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {
	*clen = mlen + CRYPTO_KEYBYTES;
	u64  i; //RATE=96/8=12
	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 t_1, t_2, t_3, t_5, t_6, t_8, t_9, t_11;
	u64 x30 = 0, x20 = 0, x10 = 0, x00 = 0;
	u32 x31 = 0, x21 = 0, x11 = 0, x01 = 0;

	u8 tempData[12] = { 0 };
	u8 tempData1[12] = { 0 };
	u8 tempData2[12] = { 0 };
	u64 x40, x50, x60, x70;
	u32 x41, x51, x61, x71;
	// initialization

	x00 = U64BIG(*(u64*)(npub));
	x01 = U32BIG(*(u32*)(npub + 8));
	x10 = U64BIG(*(u64*)(npub + 12));
	x11 = U32BIG(*(u32*)(npub + 20));
	x20 = U64BIG(*(u64*)(k));
	x21 = U32BIG(*(u32*)(k + 8));

		memcpy(&x30, k + 12, 8);
		memcpy(&x31, k + 20, 4);
	//x30 = U64BIG(*(u64*)(k + 12));
	//x31 = U32BIG(*(u32*)(k + 20));

	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}

	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			x00 ^= U64BIG(*(u64*)(ad));
			x01 ^= U32BIG(*(u32*)(ad + 8));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= RATE;
			ad += RATE;
		}

		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		x00 ^= U64BIG(*(u64*)(tempData));
		x01 ^= U32BIG(*(u32*)(tempData + 8));
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	x31 ^= 0x80000000;
	// process plaintext
	if (mlen) {
		while (mlen >= RATE) {
			x00 ^= U64BIG(*(u64*)(m));
			x01 ^= U32BIG(*(u32*)(m + 8));
			*(u64*)c = U64BIG(x00);
			*(u32*)(c + 8) = U32BIG(x01);

			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}

			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, m, mlen);
		tempData[mlen] = 0x01;
		x00 ^= U64BIG(*(u64*)(tempData));
		x01 ^= U32BIG(*(u32*)(tempData + 8));
		*(u64*)tempData1 = U64BIG(x00);
		*(u32*)(tempData1 + 8) = U32BIG(x01);
		memcpy(c, tempData1, mlen * sizeof(unsigned char));
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	// return tag
	*(u64*)c = U64BIG(x00);
	*(u32*)(c + 8) = U32BIG(x01);
	*(u64*)(c + 12) = U64BIG(x10);
	*(u32*)(c + 20) = U32BIG(x11);
	return 0;
}
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {

	*mlen = clen - CRYPTO_KEYBYTES;
	if (clen < CRYPTO_KEYBYTES)
		return -1;

	u8 tempData[12] = { 0 };
	u8 tempData1[12] = { 0 };
	u64 i; //RATE=96/8=12
	u64 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 t_1, t_2, t_3, t_5, t_6, t_8, t_9, t_11;
	u64 x30 = 0, x20 = 0, x10 = 0, x00 = 0;
	u32 x31 = 0, x21 = 0, x11 = 0, x01 = 0;

	u64 x40, x50, x60, x70;
	u32 x41, x51, x61, x71;

	// initialization

	x00 = U64BIG(*(u64*)(npub));
	x01 = U32BIG(*(u32*)(npub + 8));
	x10 = U64BIG(*(u64*)(npub + 12));
	x11 = U32BIG(*(u32*)(npub + 20));
	x20 = U64BIG(*(u64*)(k));
	x21 = U32BIG(*(u32*)(k + 8));
	x30 = U64BIG(*(u64*)(k + 12));
	x31 = U32BIG(*(u32*)(k + 20));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}

	// process associated data

	if (adlen) {
		while (adlen >= RATE) {
			x00 ^= U64BIG(*(u64*)(ad));
			x01 ^= U32BIG(*(u32*)(ad + 8));
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, RATE);
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		x00 ^= U64BIG(*(u64*)(tempData));
		x01 ^= U32BIG(*(u32*)(tempData + 8));
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	x31 ^= 0x80000000;
	// process c
	clen -= CRYPTO_KEYBYTES;
	if (clen > 0) {
		while (clen >= RATE) {
			*(u64*)(m) = U64BIG(x00) ^ (*(u64*)(c));
			*(u32*)(m + 8) = U32BIG(x01) ^ (*(u32*)(c + 8));

			x00 = U64BIG(*(u64*)(c));
			x01 = U32BIG(*(u32*)(c + 8));
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
		*(u64*)(tempData1) = U64BIG(x00) ^ (*(u64*)(tempData));
		*(u32*)(tempData1 + 8) = U32BIG(x01) ^ (*(u32*)(tempData + 8));
		memcpy(m, tempData1, clen * sizeof(unsigned char));
		memcpy(tempData1, c, clen * sizeof(unsigned char));
		x00 = U64BIG(*(u64*)(tempData1));
		x01 = U32BIG(*(u32*)(tempData1 + 8));
		c += clen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	memcpy(c+CRYPTO_KEYBYTES/2, tempData1, CRYPTO_KEYBYTES/2);
	// return -1 if verification fails
	if (*(u32*)(c + 8) != U32BIG(x01) || *(u64*)(c) != U64BIG(x00)
		|| *(u32*)(c + 20) != U32BIG(x11)
		|| *(u64*)(c + 12) != U64BIG(x10)){
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}

