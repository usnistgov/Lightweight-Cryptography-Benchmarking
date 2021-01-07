#include"auxFormat.h"

void P512(unsigned int *s, unsigned char *round, unsigned char lunNum) {
	u32 s_temp[16] = { 0 };
	u32 t1, t2, t3, t5, t6, t8, t9, t11;
	unsigned char i;
	for (i = 0; i < lunNum; i++) {
		s[3] ^= (round[i] >> 6) & 0x3;
		s[2] ^= (round[i] >> 4) & 0x3;
		s[1] ^= (round[i] >> 2) & 0x3;
		s[0] ^= round[i] & 0x3;
		sbox(s[3], s[7], s[11], s[15], s_temp[7], s_temp[11], s_temp[15]);
		sbox(s[2], s[6], s[10], s[14], s[7], s_temp[10], s_temp[14]);
		sbox(s[1], s[5], s[9], s[13], s[6], s_temp[9], s_temp[13]);
		sbox(s[0], s[4], s[8], s[12], s[5], s_temp[8], s_temp[12]);
		s[4] = LOTR32(s_temp[7], 1);
		BIT_LOTR32_16(s_temp[8], s_temp[9], s_temp[10], s_temp[11], s[8], s[9],
				s[10], s[11]);
		BIT_LOTR32_25(s_temp[12], s_temp[13], s_temp[14], s_temp[15], s[12],
				s[13], s[14], s[15]);

	}
}
void packU128FormatToFourPacket(u32 * out, u8 * in) {
	u32 t0 = U32BIG(((u32* )in)[0]);
	u32 t1 = U32BIG(((u32* )in)[1]);
	u32 t2 = U32BIG(((u32* )in)[2]);
	u32 t3 = U32BIG(((u32* )in)[3]);
	puckU32ToFour(t0);	\
	puckU32ToFour(t1);	\
	puckU32ToFour(t2);	\
	puckU32ToFour(t3);	\
	out[3] = (t3 & 0xff000000) | ((t2 >> 8) & 0x00ff0000)
			| ((t1 >> 16) & 0x0000ff00) | (t0 >> 24);
	out[2] = ((t3 << 8) & 0xff000000) | (t2 & 0x00ff0000)
			| ((t1 >> 8) & 0x0000ff00) | ((t0 >> 16) & 0x000000ff);
	out[1] = ((t3 << 16) & 0xff000000) | ((t2 << 8) & 0x00ff0000)
			| (t1 & 0x0000ff00) | ((t0 >> 8) & 0x000000ff);
	out[0] = ((t3 << 24) & 0xff000000) | ((t2 << 16) & 0x00ff0000)
			| ((t1 << 8) & 0x0000ff00) | (t0 & 0x000000ff);
}
void unpackU128FormatToFourPacket(u8 * out, u32 * in) {
	u32 t[4] = { 0 };
	t[3] = (in[3] & 0xff000000 )| ((in[2] >> 8) & 0x00ff0000)
			| ((in[1] >> 16) & 0x0000ff00) | (in[0] >> 24);
	t[2] = ((in[3] << 8) & 0xff000000) | (in[2] & 0x00ff0000)
			| ((in[1] >> 8) & 0x0000ff00) | ((in[0] >> 16) & 0x000000ff);
	t[1] = ((in[3] << 16) & 0xff000000) | ((in[2] << 8) & 0x00ff0000)
			| (in[1] & 0x0000ff00) | ((in[0] >> 8) & 0x000000ff);
	t[0] = ((in[3] << 24) & 0xff000000) | ((in[2] << 16) & 0x00ff0000)
			| ((in[1] << 8) & 0x0000ff00) | (in[0] & 0x000000ff);
	unpuckU32ToFour(t[0]);
	unpuckU32ToFour(t[1]);
	unpuckU32ToFour(t[2]);
	unpuckU32ToFour(t[3]);
	memcpy(out, t, 16 * sizeof(unsigned char));
}


unsigned char constant7Format_aead[100] = {
/*constant7_aead_256*/
0x1, 0x4, 0x10, 0x40, 0x2, 0x8, 0x21, 0x5, 0x14, 0x50, 0x42, 0xa, 0x29, 0x24,
		0x11, 0x44, 0x12, 0x48, 0x23, 0xd, 0x35, 0x55, 0x56, 0x5a, 0x6b, 0x2e,
		0x38, 0x60, 0x3, 0xc, 0x31, 0x45, 0x16, 0x58, 0x63, 0xf, 0x3d, 0x74,
		0x53, 0x4e, 0x3b, 0x6c, 0x32, 0x49, 0x27, 0x1d, 0x75, 0x57, 0x5e, 0x7b,
		0x6e, 0x3a, 0x68, 0x22, 0x9, 0x25, 0x15, 0x54, 0x52, 0x4a, 0x2b, 0x2c,
		0x30, 0x41, 0x6, 0x18, 0x61, 0x7, 0x1c, 0x71, 0x47, 0x1e, 0x79, 0x66,
		0x1b, 0x6d, 0x36, 0x59, 0x67, 0x1f, 0x7d, 0x76, 0x5b, 0x6f, 0x3e, 0x78,
		0x62, 0xb, 0x2d, 0x34, 0x51, 0x46, 0x1a, 0x69, 0x26, 0x19, 0x65, 0x17,
		0x5c, 0x73,

};
