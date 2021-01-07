#include"auxFormat.h"

#define hash_RATE (32 / 8)

#define PRH_ROUNDS 68

unsigned char constant7Format[68] = { 0x01, 0x10, 0x02, 0x20, 0x04, 0x40, 0x09,
		0x11, 0x12, 0x22, 0x24, 0x44, 0x49, 0x18, 0x03, 0x30, 0x06, 0x60, 0x0d,
		0x51, 0x1b, 0x33, 0x36, 0x66, 0x6d, 0x5c, 0x4a, 0x28, 0x05, 0x50, 0x0b,
		0x31, 0x16, 0x62, 0x2d, 0x55, 0x5b, 0x3a, 0x27, 0x74, 0x4f, 0x78, 0x0e,
		0x61, 0x1d, 0x53, 0x3b, 0x37, 0x76, 0x6f, 0x7c, 0x4e, 0x68, 0x0c, 0x41,
		0x19, 0x13, 0x32, 0x26, 0x64, 0x4d, 0x58, 0x0a, 0x21, 0x14, 0x42, 0x29,
		0x15, };
#define Processing_Data(data) \
do { \
		getU32Format(dataFormat, data);\
		s[0] ^= dataFormat[0] >> 16;\
		s[1] ^= dataFormat[0] & 0xffff;\
} while (0)

int crypto_hash(unsigned char *out, const unsigned char *in,
		unsigned long long inlen) {
	u32 s_temp[8] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	u8 i;
	u32 dataFormat[2] = { 0 };
	// initialization
	u32 s[8] = { 0 };
	u8 tempData[32];
	//absorb
	while (inlen >= hash_RATE) {
		Processing_Data(in);
		for (i = 0; i < PRH_ROUNDS; i++) {
			ROUND256(constant7Format, i);
		}
		inlen -= hash_RATE;
		in += hash_RATE;
	}
	memset(tempData, 0, sizeof(tempData));
	memcpy(tempData, in, inlen * sizeof(unsigned char));
	tempData[inlen] = 0x01;
	Processing_Data(tempData);
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND256(constant7Format, i);
	}
	//sequeez
	unpackFormat(out, s);
	unpackFormat((out + 8), (s + 2));
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND256(constant7Format, i);
	}
	out += CRYPTO_BYTES / 2;
	unpackFormat(out, s);
	unpackFormat((out + 8), (s + 2));
	return 0;
}

