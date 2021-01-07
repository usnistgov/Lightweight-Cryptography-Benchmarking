#include"auxFormat.h"

//#define hash_RATE (48 / 8)
#define hash_RATE 6

#define PRH_ROUNDS 104

int crypto_hash(unsigned char *out, const unsigned char *in,
		unsigned long long inlen) {
	u32 dataFormat[3] = { 0 };
	// initialization
	u32 s[12] = { 0 };
	u8 tempData[12];
	//absorb
	while (inlen >= hash_RATE) {
		packU48FormatToThreePacket(dataFormat, in);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		P384(s, constant7Format, PRH_ROUNDS);
		inlen -= hash_RATE;
		in += hash_RATE;
	}
	memset(tempData, 0, hash_RATE);
	memcpy(tempData, in, inlen * sizeof(unsigned char));
	tempData[inlen] = 0x01;
	packU48FormatToThreePacket(dataFormat, tempData);
	s[0] ^= dataFormat[0];
	s[1] ^= dataFormat[1];
	s[2] ^= dataFormat[2];

	P384(s, constant7Format, PRH_ROUNDS);
	//sequeez

	unpackU96FormatToThreePacket(out, s);
	unpackU96FormatToThreePacket(out + 12, s + 3);

	P384(s, constant7Format, PRH_ROUNDS);
	out += CRYPTO_BYTES / 2;
	unpackU96FormatToThreePacket(out, s);
	unpackU96FormatToThreePacket(out + 12, s + 3);
	return 0;
}

