
#include"auxFormat.h"

#define RATE (64 / 8)

#define PR0_ROUNDS 52
#define PR_ROUNDS 28
#define PRF_ROUNDS 32
unsigned char  constant6Format[63] = {
	/*constant6_aead_128v1:*/
0x1,
0x10,
0x2,
0x20,
0x4,
0x41,
0x11,
0x12,
0x22,
0x24,
0x45,
0x50,
0x3,
0x30,
0x6,
0x61,
0x15,
0x53,
0x33,
0x36,
0x67,
0x74,
0x46,
0x60,
0x5,
0x51,
0x13,
0x32,
0x26,
0x65,
0x54,
0x42,
0x21,
0x14,
0x43,
0x31,
0x16,
0x63,
0x35,
0x57,
0x72,
0x27,
0x75,
0x56,
0x62,
0x25,
0x55,
0x52,
0x23,
0x34,
0x47,
0x70,
0x7,
0x71,
0x17,
0x73,
0x37,
0x77,
0x76,
0x66,
0x64,
0x44,
0x40,

};



int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec, const unsigned char *npub,
	const unsigned char *k) {
	unsigned int  i, j;
	u32 s[8] = { 0 };
	u32 dataFormat[2] = { 0 };
	u8 tempData[8];
	u32 s_temp[8] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	*clen = mlen + CRYPTO_ABYTES;
	//initialization
	packFormat(s, npub);
	packFormat((s + 2), (npub + 8));
	packFormat((s + 4), k);
	packFormat((s + 6), (k + 8));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND256(constant6Format,i);
	}
	// process associated data
	if (adlen) { 
		while (adlen >= RATE) {
			packFormat(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(constant6Format, i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
memcpy(tempData, ad, adlen * sizeof(unsigned char));	
tempData[adlen] = 0x01;
		packFormat(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND256(constant6Format, i);
		}
	}
	s[6] ^= 0x80000000;
	if (mlen) {
		while (mlen >= RATE) {
			packFormat(dataFormat, m);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			unpackFormat(c, s);
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(constant6Format, i);
			}
			mlen -= RATE;
			m += RATE;
			c += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
memcpy(tempData, m, mlen * sizeof(unsigned char));
  
tempData[mlen]= 0x01;
		packFormat(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		unpackFormat(tempData, s);
		memcpy(c, tempData, mlen * sizeof(unsigned char));
		c +=mlen;
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND256(constant6Format, i);
	}
	// return tag
	unpackFormat(tempData, s);
		memcpy(c, tempData, sizeof(tempData));
	unpackFormat(tempData,(s + 2));
		memcpy(c+8, tempData, sizeof(tempData));
	return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec, const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub, const unsigned char *k) {
	u8 i, j;
	// initialization
	//256/32=8
	u32 s[8] = { 0 };
	u32 dataFormat[4] = { 0 };
	u32 dataFormat_1[2] = { 0 };
	u8 tempU8[32] = { 0 };
	u8 tempData[8];
	u32 s_temp[8] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
		*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	//initialization
	packFormat(s, npub);
	packFormat((s + 2), (npub + 8));
	packFormat((s + 4), k);
	packFormat((s + 6), (k + 8));
	for (i = 0; i < PR0_ROUNDS; i++) {
		ROUND256(constant6Format, i);
	}
	// process associated data
	if (adlen) {
		while (adlen >= RATE) {
			packFormat(dataFormat, ad);
			s[0] ^= dataFormat[0];
			s[1] ^= dataFormat[1];
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(constant6Format, i);
			}
			adlen -= RATE;
			ad += RATE;
		}
		memset(tempData, 0, sizeof(tempData));
		memcpy(tempData, ad, adlen * sizeof(unsigned char));
		tempData[adlen] = 0x01;
		packFormat(dataFormat, tempData);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		for (i = 0; i < PR_ROUNDS; i++) {
			ROUND256(constant6Format, i);
		}
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
			for (i = 0; i < PR_ROUNDS; i++) {
				ROUND256(constant6Format, i);
			}
			clen -= RATE;
			m += RATE;
			c += RATE;
		}
		unpackFormat(tempU8, s);
		for (i = 0; i < clen; ++i, ++m, ++c)
		{
			*m = tempU8[i]^ *c;
			tempU8[i] = *c;
		}
		tempU8[i] ^= 0x01;
		packFormat(s, tempU8);	
	}
	// finalization
	for (i = 0; i < PRF_ROUNDS; i++) {
		ROUND256(constant6Format, i);
	}
	// return tag	
		unpackFormat(tempU8, s);
		unpackFormat((tempU8+8), (s+2));
	if (memcmp((void*)tempU8, (void*)c,CRYPTO_ABYTES)) {
		*mlen = 0;
		memset(m, 0, sizeof(unsigned char) * (clen - CRYPTO_ABYTES));
	   return -1;
	}
	return 0;
}
