#include"auxFormat.h"

#define hash_RATE 16
//#define hash_RATE (128 / 8)
#define PRH_ROUNDS 80
//12*7=84
unsigned char constant7Format[80] = {
/*constant7Format[127]:*/
0x01, 0x08, 0x40, 0x02, 0x10, 0x80, 0x05, 0x09, 0x48, 0x42, 0x12, 0x90, 0x85,
		0x0c, 0x41, 0x0a, 0x50, 0x82, 0x15, 0x89, 0x4d, 0x4b, 0x5a, 0xd2, 0x97,
		0x9c, 0xc4, 0x06, 0x11, 0x88, 0x45, 0x0b, 0x58, 0xc2, 0x17, 0x99, 0xcd,
		0x4e, 0x53, 0x9a, 0xd5, 0x8e, 0x54, 0x83, 0x1d, 0xc9, 0x4f, 0x5b, 0xda,
		0xd7, 0x9e, 0xd4, 0x86, 0x14, 0x81, 0x0d, 0x49, 0x4a, 0x52, 0x92, 0x95,
		0x8c, 0x44, 0x03, 0x18, 0xc0, 0x07, 0x19, 0xc8, 0x47, 0x1b, 0xd8, 0xc7,
		0x1e, 0xd1, 0x8f, 0x5c, 0xc3, 0x1f, 0xd9, };
#define Processing_Data(data) \
do { \
packU96FormatToThreePacket(dataFormat, data);\
s[0] ^= dataFormat[0];\
s[1] ^= dataFormat[1];\
s[2] ^= dataFormat[2];\
packU32FormatToThreePacket((dataFormat + 3), (data + 12));\
s[3] ^= dataFormat[3];\
s[4] ^= dataFormat[4];\
s[5] ^= dataFormat[5];\
} while (0)

int crypto_hash(unsigned char *out, const unsigned char *in,
		unsigned long long inlen) {

	u32 s[12] = { 0 };
	u32 dataFormat[6] = { 0 };
	u8 i, tempData[24] = { 0 };
	u32 s_temp[12] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	// initialization
	s[9] = 0x80000000;
	//absorb
	while (inlen >= hash_RATE) {
		Processing_Data(in);
		for (i = 0; i < PRH_ROUNDS; i++) {
			ROUND384(i);
		}
		inlen -= hash_RATE;
		in += hash_RATE;
	}
	memset(tempData, 0, hash_RATE);
	memcpy(tempData, in, inlen * sizeof(unsigned char));
	tempData[inlen] = 0x01;
	Processing_Data(tempData);
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND384(i);
	}
	//sequeez
	unpackU96FormatToThreePacket(out, s);
	unpackU32FormatToThreePacket((out + 12), (s + 3));
	for (i = 0; i < PRH_ROUNDS; i++) {
		ROUND384(i);
	}
	out += CRYPTO_BYTES / 2;
	unpackU96FormatToThreePacket(out, s);
	unpackU32FormatToThreePacket((out + 12), (s + 3));
	return 0;
}

