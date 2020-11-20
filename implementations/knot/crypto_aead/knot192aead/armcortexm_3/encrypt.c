
#include"auxFormat.h"

#define aead_RATE (96 / 8)
#define PR0_ROUNDS 76
#define PR_ROUNDS 40
#define PRF_ROUNDS 44
unsigned char  constant7Format[127] = {
	/*constant7Format[127]:*/
0x01,0x08,0x40,0x02,0x10,0x80,0x05,0x09,0x48,0x42,0x12,0x90,
0x85,0x0c,0x41,0x0a,0x50,0x82,0x15,0x89,0x4d,0x4b,0x5a,0xd2,
0x97,0x9c,0xc4,0x06,0x11,0x88,0x45,0x0b,0x58,0xc2,0x17,0x99,
0xcd,0x4e,0x53,0x9a,0xd5,0x8e,0x54,0x83,0x1d,0xc9,0x4f,0x5b,
0xda,0xd7,0x9e,0xd4,0x86,0x14,0x81,0x0d,0x49,0x4a,0x52,0x92,
0x95,0x8c,0x44,0x03,0x18,0xc0,0x07,0x19,0xc8,0x47,0x1b,0xd8,
0xc7,0x1e,0xd1,0x8f,0x5c,0xc3,0x1f,0xd9,0xcf,0x5e,0xd3,0x9f,
0xdc,0xc6,0x16,0x91,0x8d,0x4c,0x43,0x1a,0xd0,0x87,0x1c,0xc1,
0x0f,0x59,0xca,0x57,0x9b,0xdd,0xce,0x56,0x93,0x9d,0xcc,0x46,
0x13,0x98,0xc5,0x0e,0x51,0x8a,0x55,0x8b,0x5d,0xcb,0x5f,0xdb,
0xdf,0xde,0xd6,0x96,0x94,0x84,0x04, };
#define ROUND384(lunNum) {\
s[0] ^= (constant7Format[lunNum] >> 6) & 0x3;\
s[1] ^= (constant7Format[lunNum] >> 3) & 0x7;\
s[2] ^= constant7Format[lunNum] & 0x7;\
sbox(s[0], s[3], s[6], s[9] , s_temp[3], s_temp[6], s_temp[9]);\
sbox(s[1], s[4], s[7], s[10], s[3]     , s_temp[7], s_temp[10]);\
sbox(s[2], s[5], s[8], s[11], s[4]     , s_temp[8], s_temp[11]);\
s[5] = LOTR32(s_temp[3], 1); \
U96_BIT_LOTR32_8(s_temp[6], s_temp [7], s_temp[ 8], s[6],  s[7], s[8]);\
U96_BIT_LOTR32_55(s_temp[9], s_temp[10], s_temp[11], s[9], s[10], s[11]);\
}
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {

	u8 i; 
	u32 s[12] = { 0 };
	u32 dataFormat[3] = { 0 };
	u8 tempData[12] = { 0 };
	u32 s_temp[12] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 t1_32, t2_64, t2_65;
	u32 temp0[3] = { 0 };
	u32 temp1[3] = { 0 };
	u32 temp2[3] = { 0 };
	*clen = mlen + CRYPTO_ABYTES;
	// initialization
	packU96FormatToThreePacket(s, npub);
	packU96FormatToThreePacket((s + 3), (npub + 12));
	packU96FormatToThreePacket((s + 6), k);
	packU96FormatToThreePacket((s + 9), (k + 12));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		packU96FormatToThreePacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[9] ^= 0x80000000;
	if (mlen) { 
		while (mlen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, m);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			unpackU96FormatToThreePacket(c, s);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen);
		tempData[mlen] = 0x01;
		packU96FormatToThreePacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		unpackU96FormatToThreePacket(tempData, s);
		memcpy(c, tempData, mlen);
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	// return tag
	unpackU96FormatToThreePacket(c, s);
	unpackU96FormatToThreePacket((c + 12), (s + 3));
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {
	u8 i, j;
	u32 s[12] = { 0 };
	u32 dataFormat[6] = { 0 };
	u32 dataFormat_1[3] = { 0 };
	u8 tempData[12] = { 0 };
	u8 tempU8[48] = { 0 };
	u32 s_temp[12] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 t1_32, t2_64, t2_65;
	u32 temp0[3] = { 0 };
	u32 temp1[3] = { 0 };
	u32 temp2[3] = { 0 };	
	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	// initialization
	packU96FormatToThreePacket(s, npub);
	packU96FormatToThreePacket((s + 3), (npub + 12));
	packU96FormatToThreePacket((s + 6), k);
	packU96FormatToThreePacket((s + 9), (k + 12));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND384(i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));

		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		packU96FormatToThreePacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[9] ^= 0x80000000;
	clen -= CRYPTO_ABYTES;
	if (clen) {
		while (clen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, c);
			dataFormat_1[0] = s[0] ^ dataFormat[0];
			dataFormat_1[1] = s[1] ^ dataFormat[1];
			dataFormat_1[2] = s[2] ^ dataFormat[2];
			unpackU96FormatToThreePacket(m, dataFormat_1);
			s[0] = dataFormat[0];
			s[1] = dataFormat[1];
			s[2] = dataFormat[2];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			clen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		unpackU96FormatToThreePacket(tempU8, s);
		for (i = 0; i < clen; ++i, ++m, ++c)
		{
			*m = tempU8[i] ^ *c;
			tempU8[i] = *c;
		}
		tempU8[i] ^= 0x01;
		packU96FormatToThreePacket(s, tempU8);
	}
	// finalization		
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);
	}
	// return tag	
	unpackU96FormatToThreePacket(tempU8, s);
	unpackU96FormatToThreePacket((tempU8 + 12), (s + 3));
	if (memcmp((void*)tempU8, (void*)c, CRYPTO_ABYTES)) {
		*mlen = 0;
		memset(m, 0, sizeof(unsigned char) * (clen - CRYPTO_ABYTES));
		return -1;
	}
	return 0;
}
