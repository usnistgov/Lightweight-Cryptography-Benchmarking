#include"auxFormat.h"

void Initialize(u32 *s, const unsigned char *npub, const unsigned char *k) {
	u8 tempData[24] = { 0 };
	packU96FormatToThreePacket(s, npub);
	memcpy(tempData, npub + 12, sizeof(unsigned char) * 4);
	memcpy(tempData + 4, k, sizeof(unsigned char) * 16);
	packU96FormatToThreePacket(s + 3, tempData);
	packU96FormatToThreePacket(s + 6, tempData + 12);
	s[9] = 0x80000000;
	P384(s, constant7Format, PR0_ROUNDS);
}
void ProcessAssocData(u32 *s, const u8 *ad, unsigned long long adlen) {
	u32 dataFormat[6] = { 0 };
	u8 tempData[24] = { 0 };
	if (adlen) {
		while (adlen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			packU96FormatToThreePacket(dataFormat + 3, ad + 12);
			s[3] ^= dataFormat[3];
			s[4] ^= dataFormat[4];
			s[5] ^= dataFormat[5];
			P384(s, constant7Format, PR_ROUNDS);
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		packU96FormatToThreePacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		packU96FormatToThreePacket(dataFormat + 3, tempData + 12);
		s[3] ^= dataFormat[3];
		s[4] ^= dataFormat[4];
		s[5] ^= dataFormat[5];

		P384(s, constant7Format, PR_ROUNDS);
	}
	s[9] ^= 0x80000000;
}

void ProcessPlaintext(u32 *s, const u8 *m, unsigned long long mlen,
		unsigned char *c) {
	u32 dataFormat[6] = { 0 };
	u8 tempData[24] = { 0 };
	if (mlen) {
		while (mlen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, m);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			packU96FormatToThreePacket(dataFormat + 3, m + 12);
			s[3] ^= dataFormat[3];
			s[4] ^= dataFormat[4];
			s[5] ^= dataFormat[5];
			unpackU96FormatToThreePacket(c, s);
			unpackU96FormatToThreePacket(c + 12, s + 3);

			P384(s, constant7Format, PR_ROUNDS);
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen] = 0x01;
		packU96FormatToThreePacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		packU96FormatToThreePacket(dataFormat + 3, tempData + 12);
		s[3] ^= dataFormat[3];
		s[4] ^= dataFormat[4];
		s[5] ^= dataFormat[5];
		unpackU96FormatToThreePacket(tempData, s);
		unpackU96FormatToThreePacket(tempData + 12, s + 3);
		memcpy(c, tempData, mlen * sizeof(unsigned char));
	}
}
void Finalize_GenerateTag(u32 *s, unsigned char *c) {
	u8 tempData[12] = { 0 };
	P384(s, constant7Format, PRF_ROUNDS);
	// return tag
	unpackU96FormatToThreePacket(c, s);
	unpackU96FormatToThreePacket(tempData, s + 3);
	memcpy(c + 12, tempData, sizeof(unsigned char) * 4);
}
void ProcessCiphertext(u32 *s, unsigned char *m, const unsigned char *c,
		unsigned long long clen) {
	u32 dataFormat[12] = { 0 };
	u32 dataFormat_1[12] = { 0 };
	u8 tempU8[24] = { 0 }, tempData[24] = { 0 };
	if (clen) {
		while (clen >= aead_RATE) {
			packU96FormatToThreePacket(dataFormat, c);
			dataFormat_1[0] = s[0] ^ dataFormat[0];
			dataFormat_1[1] = s[1] ^ dataFormat[1];
			dataFormat_1[2] = s[2] ^ dataFormat[2];
			packU96FormatToThreePacket(dataFormat + 3, c + 12);
			dataFormat_1[3] = s[3] ^ dataFormat[3];
			dataFormat_1[4] = s[4] ^ dataFormat[4];
			dataFormat_1[5] = s[5] ^ dataFormat[5];
			unpackU96FormatToThreePacket(m, dataFormat_1);
			unpackU96FormatToThreePacket(m + 12, dataFormat_1 + 3);
			s[0] = dataFormat[0];
			s[1] = dataFormat[1];
			s[2] = dataFormat[2];
			s[3] = dataFormat[3];
			s[4] = dataFormat[4];
			s[5] = dataFormat[5];

			P384(s, constant7Format, PR_ROUNDS);
			clen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		unpackU96FormatToThreePacket(tempU8, s);
		unpackU96FormatToThreePacket(tempU8 + 12, s + 3);
		memset(tempData, 0, aead_RATE);
		memcpy(tempData, c, clen * sizeof(unsigned char));
		tempData[clen] = 0x01;
		U32BIG(((u32*)tempU8)[0]) ^= U32BIG(
				((u32* )tempData)[0]);
		U32BIG(((u32*)tempU8)[1]) ^= U32BIG(
				((u32* )tempData)[1]);
		U32BIG(((u32*)tempU8)[2]) ^= U32BIG(
				((u32* )tempData)[2]);
		U32BIG(((u32*)tempU8)[3]) ^= U32BIG(
				((u32* )tempData)[3]);
		U32BIG(((u32*)tempU8)[4]) ^= U32BIG(
				((u32* )tempData)[4]);
		U32BIG(((u32*)tempU8)[5]) ^= U32BIG(
				((u32* )tempData)[5]);
		memcpy(m, tempU8, clen * sizeof(unsigned char));
		memcpy(tempU8, tempData, clen * sizeof(unsigned char));
		c += clen;
		packU96FormatToThreePacket(s, tempU8);
		packU96FormatToThreePacket(s + 3, tempU8 + 12);
	}
}
int Finalize_VerifyTag(u32 *s, const unsigned char *c, unsigned char *m,
		unsigned long long *mlen) {
	u8 tempU8[24] = { 0 };
	P384(s, constant7Format, PRF_ROUNDS);
	// return tag	
	unpackU96FormatToThreePacket(tempU8, s);
	unpackU96FormatToThreePacket(tempU8 + 12, s + 3);
	if (memcmp((void*) tempU8, (void*) (c), CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {
	u32 s[12] = { 0 };
	*clen = mlen + CRYPTO_ABYTES;
	// initialization
	Initialize(s, npub, k);
	// process associated data
	ProcessAssocData(s, ad, adlen);
	ProcessPlaintext(s, m, mlen, c);
	// finalization
	Finalize_GenerateTag(s, c + mlen);
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
		unsigned char *nsec, const unsigned char *c, unsigned long long clen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *npub, const unsigned char *k) {
	u32 s[12] = { 0 };
	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	// initialization
	Initialize(s, npub, k);
	// process associated data
	ProcessAssocData(s, ad, adlen);
	ProcessCiphertext(s, m, c, clen - CRYPTO_ABYTES);
	// finalization		
	return Finalize_VerifyTag(s, c + clen - CRYPTO_KEYBYTES, m, mlen);
}
