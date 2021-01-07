#include"auxFormat.h"

#define aead_RATE 16
//#define aead_RATE (128 / 8)
#define PR0_ROUNDS 24
#define PR_ROUNDS 12
#define PRF_ROUNDS 13
unsigned char constant7Format_aead[100] = { 0x01, 0x04, 0x10, 0x40, 0x02, 0x08,
		0x21, 0x05, 0x14, 0x50, 0x42, 0x0a, 0x29, 0x24, 0x11, 0x44, 0x12, 0x48,
		0x23, 0x0d, 0x35, 0x55, 0x56, 0x5a, 0x6b, 0x2e, 0x38, 0x60, 0x03, 0x0c,
		0x31, 0x45, 0x16, 0x58, 0x63, 0x0f, 0x3d, 0x74, 0x53, 0x4e, 0x3b, 0x6c,
		0x32, 0x49, 0x27, 0x1d, 0x75, 0x57, 0x5e, 0x7b, 0x6e, 0x3a, 0x68, 0x22,
		0x09, 0x25, 0x15, 0x54, 0x52, 0x4a, 0x2b, 0x2c, 0x30, 0x41, 0x06, 0x18,
		0x61, 0x07, 0x1c, 0x71, 0x47, 0x1e, 0x79, 0x66, 0x1b, 0x6d, 0x36, 0x59,
		0x67, 0x1f, 0x7d, 0x76, 0x5b, 0x6f, 0x3e, 0x78, 0x62, 0x0b, 0x2d, 0x34,
		0x51, 0x46, 0x1a, 0x69, 0x26, 0x19, 0x65, 0x17, 0x5c, 0x73, };
//initialization

#define Processing_Data(data) \
do { \
	packU128FormatToFourPacket(dataFormat, data);   \
	s[0] ^= dataFormat[0];   \
	s[1] ^= dataFormat[1];   \
	s[2] ^= dataFormat[2];   \
	s[3] ^= dataFormat[3];   \
} while (0)

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {
	u32 s[16] = { 0 };
	u32 dataFormat[4] = { 0 };
	u8 tempData[16] = { 0 };
	u8 tempU8[32] = { 0 };
	*clen = mlen + CRYPTO_ABYTES;
	//initialization
	packU128FormatToFourPacket(s, npub);
	packU128FormatToFourPacket((s + 4), (npub + 16));
	packU128FormatToFourPacket((s + 8), k);
	packU128FormatToFourPacket((s + 12), (k + 16));
	P512(s, constant7Format_aead, PR0_ROUNDS);

	// process associated data
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
	// process p data
	if (mlen) {
		while (mlen >= aead_RATE) {
			Processing_Data(m);
			unpackU128FormatToFourPacket(c, s);

			P512(s, constant7Format_aead, PR_ROUNDS);
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen] = 0x01;
		Processing_Data(tempData);
		unpackU128FormatToFourPacket(tempData, s);
		memcpy(c, tempData, mlen * sizeof(unsigned char));
		c += mlen;
	}
	// finalization
	P512(s, constant7Format_aead, PRF_ROUNDS);
	unpackU128FormatToFourPacket(tempU8, s);
	unpackU128FormatToFourPacket((tempU8 + 16), (s + 4));
	memcpy(c, tempU8, CRYPTO_ABYTES * sizeof(unsigned char));
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
		unsigned char *nsec, const unsigned char *c, unsigned long long clen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *npub, const unsigned char *k) {
	// initialization
	u32 s[16] = { 0 };
	u32 dataFormat_1[4] = { 0 };
	u32 dataFormat[4] = { 0 };
	u8 tempData[32] = { 0 };
	u8 tempU8[64] = { 0 };
	if (clen < CRYPTO_ABYTES)
		return -1;
	*mlen = clen - CRYPTO_ABYTES;
	//initialization
	packU128FormatToFourPacket(s, npub);
	packU128FormatToFourPacket((s + 4), (npub + 16));
	packU128FormatToFourPacket((s + 8), k);
	packU128FormatToFourPacket((s + 12), (k + 16));
	P512(s, constant7Format_aead, PR0_ROUNDS);
	// process associated data
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
	// process c data
	clen = clen - CRYPTO_KEYBYTES;
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
		memset(tempData, 0, sizeof(tempData));
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
		memcpy(m, tempU8, clen * sizeof(unsigned char));
		memcpy(tempU8, tempData, clen * sizeof(unsigned char));
		packU128FormatToFourPacket(s, tempU8);
		c += clen;
	}
	// finalization
	P512(s, constant7Format_aead, PRF_ROUNDS);
	unpackU128FormatToFourPacket(tempU8, s);
	unpackU128FormatToFourPacket((tempU8 + 16), (s + 4));
	if (memcmp((void*) tempU8, (void*) c, CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
