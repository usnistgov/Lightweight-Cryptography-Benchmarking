#include"auxFormat.h"

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
