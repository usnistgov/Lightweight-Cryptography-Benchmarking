#include"auxFormat.h"

#define aead_RATE (192 / 8)
/*
 #define PR0_ROUNDS 76  /3=25+1
 #define PR_ROUNDS 28   /3=9+1
 #define PRF_ROUNDS 32  /3=10+2


#define PR0_ROUNDS 25
#define PR_ROUNDS 13
#define PRF_ROUNDS 14
 */

#define PR0_ROUNDS 25
#define PR_ROUNDS 9
#define PRF_ROUNDS 10
unsigned char constant7Format[76] = { 0x01, 0x08, 0x40, 0x02, 0x10, 0x80, 0x05,
		0x09, 0x48, 0x42, 0x12, 0x90, 0x85, 0x0c, 0x41, 0x0a, 0x50, 0x82, 0x15,
		0x89, 0x4d, 0x4b, 0x5a, 0xd2, 0x97, 0x9c, 0xc4, 0x06, 0x11, 0x88, 0x45,
		0x0b, 0x58, 0xc2, 0x17, 0x99, 0xcd, 0x4e, 0x53, 0x9a, 0xd5, 0x8e, 0x54,
		0x83, 0x1d, 0xc9, 0x4f, 0x5b, 0xda, 0xd7, 0x9e, 0xd4, 0x86, 0x14, 0x81,
		0x0d, 0x49, 0x4a, 0x52, 0x92, 0x95, 0x8c, 0x44, 0x03, 0x18, 0xc0, 0x07,
		0x19, 0xc8, 0x47, 0x1b, 0xd8, 0xc7, 0x1e, 0xd1, 0x8f, };

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {
	u32 s[12] = { 0 };
	u8 tempData[24] = { 0 };
	u32 dataFormat[6] = { 0 };
	u8 tempU8[24] = { 0 };
	u32  t2;
	*clen = mlen + CRYPTO_ABYTES;
	// initialization
	packU96FormatToThreePacket(s, npub);
	memcpy(tempData, npub + 12, sizeof(unsigned char) * 4);
	memcpy(tempData + 4, k, sizeof(unsigned char) * 16);
	packU96FormatToThreePacket((s + 3), tempData);
	packU96FormatToThreePacket((s + 6), (tempData + 12));
	s[9] = 0x80000000;
	P384_1(s, constant7Format, PR0_ROUNDS);
	// process associated data
	if (adlen) {
		while (adlen >= aead_RATE) {
			Processing_Data(ad);
			P384_1(s, constant7Format, PR_ROUNDS);
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		Processing_Data(tempData);
		P384_1(s, constant7Format, PR_ROUNDS);
	}
	s[9] ^= 0x80000000;
	// process p data
	if (mlen) {
		while (mlen >= aead_RATE) {
			Processing_Data(m);
			unpackU96FormatToThreePacket(c, s);
			unpackU96FormatToThreePacket((c + 12), (s + 3));
			P384_1(s, constant7Format, PR_ROUNDS);
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen] = 0x01;
		Processing_Data(tempData);
		unpackU96FormatToThreePacket(tempData, s);
		unpackU96FormatToThreePacket((tempData + 12), (s + 3));
		memcpy(c, tempData, mlen * sizeof(unsigned char));
		c += mlen;
	}
	// finalization
	P384_2(s, constant7Format, PRF_ROUNDS);
	unpackU96FormatToThreePacket(tempU8, s);
	unpackU96FormatToThreePacket((tempU8 + 12), (s + 3));
	memcpy(c, tempU8, sizeof(unsigned char) * 12);
	memcpy(c + 12, tempU8 + 12, sizeof(unsigned char) * 4);
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
		unsigned char *nsec, const unsigned char *c, unsigned long long clen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *npub, const unsigned char *k) {
	u32 s[12] = { 0 };
	u32 dataFormat[12] = { 0 };
	u32 dataFormat_1[12] = { 0 };
	u8 tempData[24] = { 0 };
	u8 tempU8[24] = { 0 };
	u32 t2;
	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	// initialization
	packU96FormatToThreePacket(s, npub);
	memcpy(tempData, npub + 12, sizeof(unsigned char) * 4);
	memcpy(tempData + 4, k, sizeof(unsigned char) * 16);
	packU96FormatToThreePacket((s + 3), tempData);
	packU96FormatToThreePacket((s + 6), (tempData + 12));
	s[9] = 0x80000000;
	P384_1(s, constant7Format, PR0_ROUNDS);
	// process associated data
	if (adlen) {
		while (adlen >= aead_RATE) {
			Processing_Data(ad);
			P384_1(s, constant7Format, PR_ROUNDS);
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		Processing_Data(tempData);
		P384_1(s, constant7Format, PR_ROUNDS);
	}
	s[9] ^= 0x80000000;
	clen -= CRYPTO_ABYTES;
	if (clen) {
		while (clen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, c);
			dataFormat_1[0] = s[0] ^ dataFormat[0];
			dataFormat_1[1] = s[1] ^ dataFormat[1];
			dataFormat_1[2] = s[2] ^ dataFormat[2];
			packU96FormatToThreePacket((dataFormat + 3), (c + 12));
			dataFormat_1[3] = s[3] ^ dataFormat[3];
			dataFormat_1[4] = s[4] ^ dataFormat[4];
			dataFormat_1[5] = s[5] ^ dataFormat[5];
			unpackU96FormatToThreePacket(m, dataFormat_1);
			unpackU96FormatToThreePacket((m + 12), (dataFormat_1 + 3));
			s[0] = dataFormat[0];
			s[1] = dataFormat[1];
			s[2] = dataFormat[2];
			s[3] = dataFormat[3];
			s[4] = dataFormat[4];
			s[5] = dataFormat[5];
			P384_1(s, constant7Format, PR_ROUNDS);
			clen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		unpackU96FormatToThreePacket(tempU8, s);
		unpackU96FormatToThreePacket((tempU8 + 12), (s + 3));

		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, c, clen * sizeof(unsigned char));
		tempData[clen] = 0x01;
		U32BIG(((u32*)tempU8)[0]) ^= U32BIG(((u32* )tempData)[0]);
		U32BIG(((u32*)tempU8)[1]) ^= U32BIG(((u32* )tempData)[1]);
		U32BIG(((u32*)tempU8)[2]) ^= U32BIG(((u32* )tempData)[2]);
		U32BIG(((u32*)tempU8)[3]) ^= U32BIG(((u32* )tempData)[3]);
		U32BIG(((u32*)tempU8)[4]) ^= U32BIG(((u32* )tempData)[4]);
		U32BIG(((u32*)tempU8)[5]) ^= U32BIG(((u32* )tempData)[5]);
		memcpy(m, tempU8, clen * sizeof(unsigned char));
		memcpy(tempU8, tempData, clen * sizeof(unsigned char));
		c +=clen;
		packU96FormatToThreePacket(s, tempU8);
		packU96FormatToThreePacket((s + 3), (tempU8 + 12));
	}
	// finalization
	P384_2(s, constant7Format, PRF_ROUNDS);
	unpackU96FormatToThreePacket(tempU8, s);
	unpackU96FormatToThreePacket((tempU8 + 12), (s + 3));
	if (memcmp((void*) tempU8, (void*) (c ), CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
