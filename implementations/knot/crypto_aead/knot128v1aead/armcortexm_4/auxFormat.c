#include"auxFormat.h"

//#define PRINTFormatToU8
#define PRINTU8
unsigned char constant6Format[52] = {
/*constant6_aead_128v1:*/
0x01, 0x10, 0x02, 0x20, 0x04, 0x41, 0x11, 0x12, 0x22, 0x24, 0x45, 0x50, 0x03,
		0x30, 0x06, 0x61, 0x15, 0x53, 0x33, 0x36, 0x67, 0x74, 0x46, 0x60, 0x05,
		0x51, 0x13, 0x32, 0x26, 0x65, 0x54, 0x42, 0x21, 0x14, 0x43, 0x31, 0x16,
		0x63, 0x35, 0x57, 0x72, 0x27, 0x75, 0x56, 0x62, 0x25, 0x55, 0x52, 0x23,
		0x34, 0x47, 0x70, };

void P256(unsigned int *s, unsigned char *round, unsigned char lunNum) {

	u32 s_temp[8] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	unsigned char i;
	for (i = 0; i < lunNum; i++) {
		s[0] ^= round[i] >> 4;
		s[1] ^= round[i] & 0x0f;
		sbox(s[0], s[2], s[4], s[6], s_temp[2], s_temp[4], s_temp[6]);
		sbox(s[1], s[3], s[5], s[7], s[2], s_temp[5], s_temp[7]);
		s[3] = LOTR32(s_temp[2], 1);
		s[4] = LOTR32(s_temp[4], 4);
		s[5] = LOTR32(s_temp[5], 4);
		s[6] = LOTR32(s_temp[7], 12);
		s[7] = LOTR32(s_temp[6], 13);
	}
}
void packFormat(u32 * out, const u8 * in) {
	u32 t0 = U32BIG(((u32* )in)[0]);
	u32 t1 = U32BIG(((u32* )in)[1]);
	u32 r0, r1;
	r0 = (t0 ^ (t0 >> 1)) & 0x22222222, t0 ^= r0 ^ (r0 << 1);
	r0 = (t0 ^ (t0 >> 2)) & 0x0C0C0C0C, t0 ^= r0 ^ (r0 << 2);
	r0 = (t0 ^ (t0 >> 4)) & 0x00F000F0, t0 ^= r0 ^ (r0 << 4);
	r0 = (t0 ^ (t0 >> 8)) & 0x0000FF00, t0 ^= r0 ^ (r0 << 8);  //t0 odd  even 
	r1 = (t1 ^ (t1 >> 1)) & 0x22222222, t1 ^= r1 ^ (r1 << 1);
	r1 = (t1 ^ (t1 >> 2)) & 0x0C0C0C0C, t1 ^= r1 ^ (r1 << 2);
	r1 = (t1 ^ (t1 >> 4)) & 0x00F000F0, t1 ^= r1 ^ (r1 << 4);
	r1 = (t1 ^ (t1 >> 8)) & 0x0000FF00, t1 ^= r1 ^ (r1 << 8);  //t1 odd even 
	out[0] = (t1 & 0xFFFF0000) | (t0 >> 16);                 // t1.odd|t0.odd  
	out[1] = (t1 << 16) | (t0 & 0x0000FFFF);                 // t1.even|t0.even
}
void unpackFormat(u8 * out, u32 * in) {
	u32 t[2] = { 0 };
	t[1] = (in[0] & 0xFFFF0000) | (in[1] >> 16);
	t[0] = (in[1] & 0x0000FFFF) | (in[0] << 16);
	u32 r0, r1;
	r0 = (t[0] ^ (t[0] >> 8)) & 0x0000FF00, t[0] ^= r0 ^ (r0 << 8);
	r0 = (t[0] ^ (t[0] >> 4)) & 0x00F000F0, t[0] ^= r0 ^ (r0 << 4);
	r0 = (t[0] ^ (t[0] >> 2)) & 0x0C0C0C0C, t[0] ^= r0 ^ (r0 << 2);
	r0 = (t[0] ^ (t[0] >> 1)) & 0x22222222, t[0] ^= r0 ^ (r0 << 1);
	r1 = (t[1] ^ (t[1] >> 8)) & 0x0000FF00, t[1] ^= r1 ^ (r1 << 8);
	r1 = (t[1] ^ (t[1] >> 4)) & 0x00F000F0, t[1] ^= r1 ^ (r1 << 4);
	r1 = (t[1] ^ (t[1] >> 2)) & 0x0C0C0C0C, t[1] ^= r1 ^ (r1 << 2);
	r1 = (t[1] ^ (t[1] >> 1)) & 0x22222222, t[1] ^= r1 ^ (r1 << 1);
	memcpy(out, t, 8 * sizeof(unsigned char));
}



void getU32Format(u32 *out, const u8* in) {
	u32 r0, lo = U32BIG(((u32* )in)[0]);
	r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
	r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
	r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
	r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
	*out = lo;
}
