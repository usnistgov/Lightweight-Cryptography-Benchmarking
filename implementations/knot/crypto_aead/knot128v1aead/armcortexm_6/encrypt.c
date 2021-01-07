#include"auxFormat.h"

//#define RATE (64 / 8)
#define RATE 8

#define PR0_ROUNDS 25
#define PR_ROUNDS 13
#define PRF_ROUNDS 15

unsigned char constant6Format[52] = { 0x01, 0x10, 0x02, 0x20, 0x04, 0x41, 0x11,
		0x12, 0x22, 0x24, 0x45, 0x50, 0x03, 0x30, 0x06, 0x61, 0x15, 0x53, 0x33,
		0x36, 0x67, 0x74, 0x46, 0x60, 0x05, 0x51, 0x13, 0x32, 0x26, 0x65, 0x54,
		0x42, 0x21, 0x14, 0x43, 0x31, 0x16, 0x63, 0x35, 0x57, 0x72, 0x27, 0x75,
		0x56, 0x62, 0x25, 0x55, 0x52, 0x23, 0x34, 0x47, 0x70, };

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *nsec, const unsigned char *npub,
		const unsigned char *k) {
	u32 s[8] = { 0 };
	u32 dataFormat[2] = { 0 };
	u8 tempData[16];
	//initialization
	*clen = mlen + CRYPTO_ABYTES;
	packFormat(s, npub);
	packFormat((s + 2), (npub + 8));
	packFormat((s + 4), k);
	packFormat((s + 6), (k + 8));
	P256(s, constant6Format, PR0_ROUNDS);
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			packFormat(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			P256(s, constant6Format, PR_ROUNDS);
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		packFormat(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		P256(s, constant6Format, PR_ROUNDS);
	}
	s[6] ^= 0x80000000;
	//Encryption:
	if (mlen) {
		while (mlen >= RATE) {
			packFormat(dataFormat, m);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			unpackFormat(c, s);

			P256(s, constant6Format, PR_ROUNDS);
			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen] = 0x01;
		packFormat(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		unpackFormat(tempData, s);
		memcpy(c, tempData, mlen * sizeof(unsigned char));
		c += mlen;
	}
	// finalization
	P256(s, constant6Format, PRF_ROUNDS);
	unpackFormat(tempData, s);
	unpackFormat((tempData + 8), (s + 2));
	memcpy(c, tempData, CRYPTO_ABYTES);
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
		unsigned char *nsec, const unsigned char *c, unsigned long long clen,
		const unsigned char *ad, unsigned long long adlen,
		const unsigned char *npub, const unsigned char *k) {
	u32 s[8] = { 0 };
	u32 dataFormat[4] = { 0 };
	u32 dataFormat_1[2] = { 0 };
	u8 tempU8[32] = { 0 };
	u8 tempData[16];
	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	//initialization
	packFormat(s, npub);
	packFormat((s + 2), (npub + 8));
	packFormat((s + 4), k);
	packFormat((s + 6), (k + 8));
	P256(s, constant6Format, PR0_ROUNDS);
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			packFormat(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			P256(s, constant6Format, PR_ROUNDS);
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		packFormat(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		P256(s, constant6Format, PR_ROUNDS);
	}

	s[6] ^= 0x80000000;
	// process c
	clen = clen - CRYPTO_KEYBYTES;
	if (clen) {
		while (clen >= RATE) {
			packFormat(dataFormat, c);
			dataFormat_1[0] = s[0] ^ dataFormat[0];
			dataFormat_1[1] = s[1] ^ dataFormat[1];
			unpackFormat(m, dataFormat_1);
			s[0] = dataFormat[0];
			s[1] = dataFormat[1];
			P256(s, constant6Format, PR_ROUNDS);
			clen -= RATE;
			m += RATE;
			c += RATE;
		}
		unpackFormat(tempU8, s);
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, c, clen * sizeof(unsigned char));
		tempData[clen] = 0x01;
		U32BIG(((u32*)tempU8)[0]) ^= U32BIG(
				((u32* )tempData)[0]);
		U32BIG(((u32*)tempU8)[1]) ^= U32BIG(
				((u32* )tempData)[1]);
		memcpy(m, tempU8, clen * sizeof(unsigned char));
		memcpy(tempU8, tempData, clen * sizeof(unsigned char));
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		c += clen;

		packFormat(s, tempU8);
	}
	// finalization
	P256(s, constant6Format, PRF_ROUNDS);
	unpackFormat(tempData, s);
	unpackFormat((tempData + 8), (s + 2));
	if (memcmp((void*) tempData, (void*) c, CRYPTO_ABYTES)) {
		memset(m, 0, sizeof(unsigned char) * (*mlen));
		*mlen = 0;
		return -1;
	}
	return 0;
}
