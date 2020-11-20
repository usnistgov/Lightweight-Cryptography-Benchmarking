#include"auxFormat.h"

#define aead_RATE (128 / 8)
#define PR0_ROUNDS 100
#define PR_ROUNDS 52
#define PRF_ROUNDS 56
void Initialize(u32 *s, const unsigned char *npub, const unsigned char *k) {
	packU128FormatToFourPacket(s, npub);
	packU128FormatToFourPacket(s + 4, npub + 16);
	packU128FormatToFourPacket(s + 8, k);
	packU128FormatToFourPacket(s + 12, k + 16);
	P512(s, constant7Format_aead, PR0_ROUNDS);
}
void ProcessAssocData(u32 *s, const u8* ad, unsigned long long adlen) {
	u32 dataFormat[4] = { 0 };
	u8 tempData[16] = { 0 };
	if (adlen) {
		while (adlen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			s[3] ^= dataFormat[3];
			P512(s, constant7Format_aead, PR_ROUNDS);
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		packU128FormatToFourPacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		s[3] ^= dataFormat[3];
		P512(s, constant7Format_aead, PR_ROUNDS);
	}
	s[15] ^= 0x80000000;
}
void ProcessPlaintext(u32 *s, const u8* m, unsigned long long mlen,
		unsigned char *c) {
	u32 dataFormat[4] = { 0 };
	u8 tempData[16] = { 0 };
	if (mlen) {
		while (mlen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat, m);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			s[3] ^= dataFormat[3];
			unpackU128FormatToFourPacket(c, s);
			P512(s, constant7Format_aead, PR_ROUNDS);
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen] = 0x01;
		packU128FormatToFourPacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		s[3] ^= dataFormat[3];
		unpackU128FormatToFourPacket(tempData, s);
		memcpy(c, tempData, mlen * sizeof(unsigned char));
		//c += mlen;
	}
}

void Finalize_GenerateTag(u32 *s, unsigned char *c) {
	P512(s, constant7Format_aead, PRF_ROUNDS);
	// return tag
	unpackU128FormatToFourPacket(c, s);
	unpackU128FormatToFourPacket(c + 16, s + 4);
}
int Finalize_VerifyTag(u32 *s, const unsigned char *c, unsigned char *m,
		unsigned long long *mlen) {
	u8 tempU8[32] = { 0 };
	P512(s, constant7Format_aead, PRF_ROUNDS);
	unpackU128FormatToFourPacket(tempU8, s);
	unpackU128FormatToFourPacket(tempU8 + 16, s + 4);
	if (memcmp((void*) tempU8, (void*) (c), CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
void ProcessCiphertext(u32 *s, unsigned char *m, const unsigned char *c,
		unsigned long long clen) {
	u32 dataFormat[8] = { 0 };
	u32 dataFormat_1[4] = { 0 };
	u8 i, tempU8[64] = { 0 };
	if (clen) {
		while (clen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat, c);
			dataFormat_1[0] = s[0] ^ dataFormat[0];
			dataFormat_1[1] = s[1] ^ dataFormat[1];
			dataFormat_1[2] = s[2] ^ dataFormat[2];
			dataFormat_1[3] = s[3] ^ dataFormat[3];
			unpackU128FormatToFourPacket(m, dataFormat_1);
			s[0] = dataFormat[0];
			s[1] = dataFormat[1];
			s[2] = dataFormat[2];
			s[3] = dataFormat[3];
			P512(s, constant7Format_aead, PR_ROUNDS);
			clen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		unpackU128FormatToFourPacket(tempU8, s);
		for (i = 0; i < clen; ++i, ++m, ++c) {
			*m = tempU8[i] ^ *c;
			tempU8[i] = *c;
		}
		tempU8[i] ^= 0x01;
		packU128FormatToFourPacket(s, tempU8);
	}
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {
	u32 s[16] = { 0 };
	*clen = mlen + CRYPTO_ABYTES;
	//initialization
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
	u32 s[16] = { 0 };
	if (clen < CRYPTO_ABYTES)
		return -1;
	*mlen = clen - CRYPTO_ABYTES;
	//initialization
	Initialize(s, npub, k);
	ProcessAssocData(s, ad, adlen);
	ProcessCiphertext(s, m, c, clen - CRYPTO_ABYTES);
	// finalization		
	return Finalize_VerifyTag(s, c + clen - CRYPTO_KEYBYTES, m, mlen);
}
