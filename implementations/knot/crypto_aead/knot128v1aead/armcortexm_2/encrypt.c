#include"auxFormat.h"

void ProcessAssocData(unsigned int *s, const u8* ad, unsigned long long adlen) {
	u32 dataFormat[2] = { 0 };
	u8 tempData[8];
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
}
void ProcessPlaintext(unsigned int *s, const u8* m, unsigned long long mlen,
		unsigned char *c) {
	u32 dataFormat[2] = { 0 };
	u8 tempData[8] = { 0 };
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
		//c+=mlen;
	}
}
void Finalize_GenerateTag(unsigned int *s, unsigned char *c) {
	P256(s, constant6Format, PRF_ROUNDS);
	// return tag
	unpackFormat(c, s);
	unpackFormat((c + 8), (s + 2));
}
void Initialize(unsigned int *s, const unsigned char *npub, const unsigned char *k) {
	packFormat(s, npub);
	packFormat(s + 2, npub + 8);
	packFormat(s + 4, k);
	packFormat(s + 6, k + 8);
	P256(s, constant6Format, PR0_ROUNDS);
}
void ProcessCiphertext(unsigned int *s, unsigned char *m, const unsigned char *c,
		unsigned long long clen) {
	u8 tempU8[32] = { 0 }, i;
	u32 dataFormat[2] = { 0 };
	u32 dataFormat_1[2] = { 0 };
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
		for (i = 0; i < clen; ++i, ++m, ++c) {
			*m = tempU8[i] ^ *c;
			tempU8[i] = *c;
		}
		tempU8[i] ^= 0x01;
		packFormat(s, tempU8);
	}
}
int Finalize_VerifyTag(unsigned int *s, const unsigned char *c, unsigned char *m,
		unsigned long long *mlen) {
	u8 tempU8[16] = { 0 };
	P256(s, constant6Format, PRF_ROUNDS);
	// return tag	
	unpackFormat(tempU8, s);
	unpackFormat((tempU8 + 8), (s + 2));
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
	unsigned int  s[8] = { 0 };
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
	unsigned int s[8] = { 0 };
	*mlen = clen - CRYPTO_ABYTES;
	if (clen < CRYPTO_ABYTES)
		return -1;
	//initialization
	Initialize(s, npub, k);
	// process associated data
	ProcessAssocData(s, ad, adlen);
	// process cipher
	ProcessCiphertext(s, m, c, clen - CRYPTO_KEYBYTES);
	// finalization
	return Finalize_VerifyTag(s, c + clen - CRYPTO_KEYBYTES, m, mlen);
}
