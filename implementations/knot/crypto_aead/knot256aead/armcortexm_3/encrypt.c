
#include"auxFormat.h"

#define aead_RATE (128 / 8)
#define PR0_ROUNDS 100
#define PR_ROUNDS 52
#define PRF_ROUNDS 56
unsigned char  constant7Format_aead[127] = { 
	/*constant7_aead_256*/
0x1,
0x4,
0x10,
0x40,
0x2,
0x8,
0x21,
0x5,
0x14,
0x50,
0x42,
0xa,
0x29,
0x24,
0x11,
0x44,
0x12,
0x48,
0x23,
0xd,
0x35,
0x55,
0x56,
0x5a,
0x6b,
0x2e,
0x38,
0x60,
0x3,
0xc,
0x31,
0x45,
0x16,
0x58,
0x63,
0xf,
0x3d,
0x74,
0x53,
0x4e,
0x3b,
0x6c,
0x32,
0x49,
0x27,
0x1d,
0x75,
0x57,
0x5e,
0x7b,
0x6e,
0x3a,
0x68,
0x22,
0x9,
0x25,
0x15,
0x54,
0x52,
0x4a,
0x2b,
0x2c,
0x30,
0x41,
0x6,
0x18,
0x61,
0x7,
0x1c,
0x71,
0x47,
0x1e,
0x79,
0x66,
0x1b,
0x6d,
0x36,
0x59,
0x67,
0x1f,
0x7d,
0x76,
0x5b,
0x6f,
0x3e,
0x78,
0x62,
0xb,
0x2d,
0x34,
0x51,
0x46,
0x1a,
0x69,
0x26,
0x19,
0x65,
0x17,
0x5c,
0x73,
0x4f,
0x3f,
0x7c,
0x72,
0x4b,
0x2f,
0x3c,
0x70,
0x43,
0xe,
0x39,
0x64,
0x13,
0x4c,
0x33,
0x4d,
0x37,
0x5d,
0x77,
0x5f,
0x7f,
0x7e,
0x7a,
0x6a,
0x2a,
0x28,
0x20, 
};



int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
) {
	u32 i ;
	u32 s_temp[16] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u32 s[16] = { 0 };
	u32 dataFormat[4] = { 0 };
	u8 tempData[16] = {0};
	*clen = mlen + CRYPTO_ABYTES;
	//initialization
	packU128FormatToFourPacket(s, npub);
	packU128FormatToFourPacket((s + 4), (npub + 16));
	packU128FormatToFourPacket((s + 8), k);
	packU128FormatToFourPacket((s + 12), (k + 16));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND512(constant7Format_aead,i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			s[3] ^= dataFormat[3];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(constant7Format_aead, i);
			}
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
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND512(constant7Format_aead, i);
		}
	}
	s[15] ^= 0x80000000;
	if (mlen) {
		while (mlen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat, m);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			s[2] ^= dataFormat[2];
			s[3] ^= dataFormat[3];
			unpackU128FormatToFourPacket(c, s);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(constant7Format_aead, i);
			}
			mlen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, m, mlen * sizeof(unsigned char));
		tempData[mlen]= 0x01;
		packU128FormatToFourPacket(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		s[3] ^= dataFormat[3];
		unpackU128FormatToFourPacket(tempData, s);
		memcpy(c, tempData, mlen * sizeof(unsigned char));
		c += mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND512(constant7Format_aead, i);
	}
	// return tag
	unpackU128FormatToFourPacket(c, s);
	unpackU128FormatToFourPacket((c+16), (s+4));
	return 0;
}

int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
){
	u32 s_temp[16] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u8 i ;
	// initialization
	u32 s[16] = { 0 };
	u32 dataFormat_1[4] = { 0 };
	u32 dataFormat_2[4] = { 0 };
	u8 tempData[16] = { 0 };
	u8 tempU8[64] = { 0 };
	
	if (clen < CRYPTO_ABYTES)
		return -1;
	*mlen = clen - CRYPTO_ABYTES;
	//initialization
	packU128FormatToFourPacket(s, npub);
	packU128FormatToFourPacket((s + 4), (npub + 16));
	packU128FormatToFourPacket((s + 8), k);
	packU128FormatToFourPacket((s + 12), (k + 16));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND512(constant7Format_aead, i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat_2, ad);
			s[0] ^= dataFormat_2[0];
			s[1] ^= dataFormat_2[1];
			s[2] ^= dataFormat_2[2];
			s[3] ^= dataFormat_2[3];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(constant7Format_aead, i);
			}
			adlen -= aead_RATE;
			ad += aead_RATE;
		}
		memset(tempData, 0, sizeof(tempData));

		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		packU128FormatToFourPacket(dataFormat_2, tempData);
		s[0] ^= dataFormat_2[0];
		s[1] ^= dataFormat_2[1];
		s[2] ^= dataFormat_2[2];
		s[3] ^= dataFormat_2[3];
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND512(constant7Format_aead, i);
		}
	}
	s[15] ^= 0x80000000;
	clen = clen - CRYPTO_KEYBYTES;

	if (clen) {
		while (clen >= aead_RATE) {
			packU128FormatToFourPacket(dataFormat_2, c);
			dataFormat_1[0] = s[0] ^ dataFormat_2[0];
			dataFormat_1[1] = s[1] ^ dataFormat_2[1];
			dataFormat_1[2] = s[2] ^ dataFormat_2[2];
			dataFormat_1[3] = s[3] ^ dataFormat_2[3];
			unpackU128FormatToFourPacket(m, dataFormat_1);
			s[0] = dataFormat_2[0];
			s[1] = dataFormat_2[1];
			s[2] = dataFormat_2[2];
			s[3] = dataFormat_2[3];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND512(constant7Format_aead, i);
			}
			clen -= aead_RATE;
			m += aead_RATE;
			c += aead_RATE;
		}
		unpackU128FormatToFourPacket(tempU8, s);
		for (i = 0; i < clen; ++i, ++m, ++c)
		{
			*m = tempU8[i] ^ *c;
			tempU8[i] = *c;
		}
		tempU8[i] ^= 0x01;
		packU128FormatToFourPacket(s, tempU8);
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND512(constant7Format_aead, i);
	}
	// return tag	
	unpackU128FormatToFourPacket(tempU8, s);
	unpackU128FormatToFourPacket((tempU8 + 16), (s + 4));
	if (memcmp((void*)tempU8, (void*)c, CRYPTO_ABYTES)) {
		*mlen = 0;
		memset(m, 0, sizeof(unsigned char) * (clen - CRYPTO_ABYTES));
		return -1;
	}
	return 0;
}