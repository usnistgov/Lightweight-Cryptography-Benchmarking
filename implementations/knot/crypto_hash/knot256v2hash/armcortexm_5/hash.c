#include"auxFormat.h"



#define hash_RATE (128 / 8)
//#define PRH_ROUNDS 80
#define PRH_ROUNDS 26


int crypto_hash(unsigned char *out, const unsigned char *in,
	unsigned long long inlen) {

	u32 s[12] = { 0 };
	u32 dataFormat[6] = { 0 };
	u8  tempData[24] = { 0 };
	u32 t2;
	// initialization
	s[9] = 0x80000000;
	//absorb
	while (inlen >= hash_RATE) {
		packU96FormatToThreePacket(dataFormat, in);
		s[0] ^= dataFormat[0];
		s[1] ^= dataFormat[1];
		s[2] ^= dataFormat[2];
		packU32FormatToThreePacket(dataFormat + 3, in + 12);
		s[3] ^= dataFormat[3];
		s[4] ^= dataFormat[4];
		s[5] ^= dataFormat[5];
		P384_2(s, constant7Format, PRH_ROUNDS);
		inlen -= hash_RATE;
		in += hash_RATE;
	}
	memset(tempData, 0, sizeof(tempData));
	memcpy(tempData, in, inlen * sizeof(unsigned char));
	tempData[inlen] = 0x01;
	packU96FormatToThreePacket(dataFormat, tempData);
	s[0] ^= dataFormat[0];
	s[1] ^= dataFormat[1];
	s[2] ^= dataFormat[2];
	packU32FormatToThreePacket(dataFormat + 3, tempData + 12);
	s[3] ^= dataFormat[3];
	s[4] ^= dataFormat[4];
	s[5] ^= dataFormat[5];
	P384_2(s, constant7Format, PRH_ROUNDS);
	//sequeez

	unpackU96FormatToThreePacket(out, s);
	unpackU32FormatToThreePacket(out + 12, s + 3);
	P384_2(s, constant7Format, PRH_ROUNDS);
	out += CRYPTO_BYTES / 2;
	unpackU96FormatToThreePacket(out, s);
	unpackU32FormatToThreePacket(out + 12, s + 3);
	return 0;

}



