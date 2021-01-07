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
void packU64FormatToFourPacket(u32 *out, u8 *in) {
	u32 t1, t2;
	t1 = U32BIG(((u32* )in)[0]);
	t2 = U32BIG(((u32* )in)[1]);
	puckU32ToFour(t2);
	puckU32ToFour(t1);
	out[3] = ((t2 >> 16) & 0x0000ff00) | ((t1 >> 24));
	out[2] = ((t2 >> 8) & 0x0000ff00) | ((t1 >> 16) & 0x000000ff);
	out[1] = (t2 & 0x0000ff00) | ((t1 >> 8) & 0x000000ff);
	out[0] = ((t2 << 8) & 0x0000ff00) | (t1 & 0x000000ff);
}

void unpackU128FormatToFourPacket(u8 *out, u32 *in) {
	u32 t[4] = { 0 };
	t[3] = (in[3] & 0xff000000) | ((in[2] >> 8) & 0x00ff0000)
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
