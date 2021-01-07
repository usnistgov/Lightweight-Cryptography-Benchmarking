#include"auxFormat.h"

#define aead_RATE 12
//#define aead_RATE (96 / 8)
#define PR0_ROUNDS 76
#define PR_ROUNDS 40
#define PRF_ROUNDS 44

unsigned char constant7Format[76] = {
/*constant7Format[127]:*/
0x01, 0x08, 0x40, 0x02, 0x10, 0x80, 0x05, 0x09, 0x48, 0x42, 0x12, 0x90, 0x85,
		0x0c, 0x41, 0x0a, 0x50, 0x82, 0x15, 0x89, 0x4d, 0x4b, 0x5a, 0xd2, 0x97,
		0x9c, 0xc4, 0x06, 0x11, 0x88, 0x45, 0x0b, 0x58, 0xc2, 0x17, 0x99, 0xcd,
		0x4e, 0x53, 0x9a, 0xd5, 0x8e, 0x54, 0x83, 0x1d, 0xc9, 0x4f, 0x5b, 0xda,
		0xd7, 0x9e, 0xd4, 0x86, 0x14, 0x81, 0x0d, 0x49, 0x4a, 0x52, 0x92, 0x95,
		0x8c, 0x44, 0x03, 0x18, 0xc0, 0x07, 0x19, 0xc8, 0x47, 0x1b, 0xd8, 0xc7,
		0x1e, 0xd1, 0x8f, };

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {

	u8 i;
	u32 s[12] = { 0 };
	u32 dataFormat[3] = { 0 };
	u8 tempData[12] = { 0 };
	u8 tempU8[48] = { 0 };
	u32 s_temp[12] = { 0 };

	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 temp0[3] = { 0 };
	u32 temp1[3] = { 0 };
	u32 temp2[3] = { 0 };
	u32 t[3] = { 0 };
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
			Processing_Data(ad);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		Processing_Data(tempData);
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND384(i);
		}
	}
	s[9] ^= 0x80000000;
	if (mlen) {
		while (mlen >= aead_RATE) {
			Processing_Data(m);
			unpackU96FormatToThreePacket(c, s);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, m, mlen);
		tempData[mlen] = 0x01;
		Processing_Data(tempData);
		unpackU96FormatToThreePacket(tempData, s);
		memcpy(c, tempData, mlen);
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {

		ROUND384(i);

	}

	unpackU96FormatToThreePacket(tempU8, s);

	unpackU96FormatToThreePacket((tempU8 + 12), (s + 3));

	memcpy(c, tempU8, CRYPTO_ABYTES * sizeof(unsigned char));
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
		unsigned char *nsec, const unsigned char *c, unsigned long long clen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *npub, const unsigned char *k) {
	u8 i;
	u32 s[12] = { 0 };
	u32 dataFormat[6] = { 0 };
	u32 dataFormat_1[3] = { 0 };
	u8 tempData[12] = { 0 };
	u8 tempU8[48] = { 0 };
	u32 s_temp[12] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 temp0[3] = { 0 };
	u32 temp1[3] = { 0 };
	u32 temp2[3] = { 0 };
	u32 t[3] = { 0 };
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
			Processing_Data(ad);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND384(i);
			}
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, ad, adlen);
		tempData[adlen] = 0x01;
		Processing_Data(tempData);
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
			unpackU96FormatToThreePacket(m, dataFormat_1);\

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
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, c, clen * sizeof(unsigned char));
		tempData[clen] = 0x01;
		U32BIG(((u32*)tempU8)[0]) ^= U32BIG(
				((u32* )tempData)[0]);
		U32BIG(((u32*)tempU8)[1]) ^= U32BIG(
				((u32* )tempData)[1]);
		U32BIG(((u32*)tempU8)[2]) ^= U32BIG(
				((u32* )tempData)[2]);
		memcpy(m, tempU8, clen * sizeof(unsigned char));
		memcpy(tempU8, tempData, clen * sizeof(unsigned char));
		c += clen;
		packU96FormatToThreePacket(s, tempU8);
	}
	// finalization		
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND384(i);

	}
	unpackU96FormatToThreePacket(tempU8, s);
	unpackU96FormatToThreePacket((tempU8 + 12), (s + 3));

	if (memcmp((void*) tempU8, (void*) c, CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
