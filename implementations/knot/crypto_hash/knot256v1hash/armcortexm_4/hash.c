#include"auxFormat.h"


#define hash_RATE (32 / 8)
/*

#define PR0_ROUNDS 68  /3=22+2
 * */
#define PRH_ROUNDS 68

unsigned char  constant7Format[68] = {
/*constant7_hash_256v1:*/
		0x1,
			0x10,
			0x2,
			0x20,
			0x4,
			0x40,
			0x9,
			0x11,
			0x12,
			0x22,
			0x24,
			0x44,
			0x49,
			0x18,
			0x3,
			0x30,
			0x6,
			0x60,
			0xd,
			0x51,
			0x1b,
			0x33,
			0x36,
			0x66,
			0x6d,
			0x5c,
			0x4a,
			0x28,
			0x5,
			0x50,
			0xb,
			0x31,
			0x16,
			0x62,
			0x2d,
			0x55,
			0x5b,
			0x3a,
			0x27,
			0x74,
			0x4f,
			0x78,
			0xe,
			0x61,
			0x1d,
			0x53,
			0x3b,
			0x37,
			0x76,
			0x6f,
			0x7c,
			0x4e,
			0x68,
			0xc,
			0x41,
			0x19,
			0x13,
			0x32,
			0x26,
			0x64,
			0x4d,
			0x58,
			0xa,
			0x21,
			0x14,
			0x42,
			0x29,
			0x15,
};
int crypto_hash(unsigned char *out, const unsigned char *in,
	unsigned long long inlen) {
	u32 dataFormat[2] = { 0 };
	// initialization
	u32 s[8] = { 0 };
	u8 tempData[32];
	//absorb
	while (inlen >= hash_RATE) {
		getU32Format(dataFormat, in);
		s[0] ^= dataFormat[0] >>16;
		s[1] ^= dataFormat[0] &0xffff;
		P256(s, constant7Format, PRH_ROUNDS);
		inlen -= hash_RATE;
		in += hash_RATE;
	}
	memset(tempData, 0, sizeof(tempData));
	memcpy(tempData, in, inlen * sizeof(unsigned char));
	tempData[inlen] = 0x01;
	getU32Format(dataFormat, tempData);
	s[0] ^= dataFormat[0] >> 16;
	s[1] ^= dataFormat[0] & 0xffff;

	P256(s, constant7Format, PRH_ROUNDS);
	//sequeez
	unpackFormat(out, s);
	unpackFormat((out + 8), (s + 2));

	P256(s, constant7Format, PRH_ROUNDS);
	out += CRYPTO_BYTES / 2;
	unpackFormat(out, s);
	unpackFormat((out + 8), (s + 2));
	return 0;
}



