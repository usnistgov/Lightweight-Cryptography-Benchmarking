#include"auxFormat.h"
void P512(unsigned int *s, unsigned char *round, unsigned char rounds) {
	u32 rci, t1, t2, t3, t9;
	unsigned char rcNum = 0;
	rci = round[rcNum++];
	ARC(rci);
	SBOX1(s[0], s[4], s[8 ], s[12]);
	SBOX1(s[1], s[5], s[9 ], s[13]);
	SBOX1(s[2], s[6], s[10], s[14]);
	SBOX1(s[3], s[7], s[11], s[15]);
	while (rounds--) {
		rci = round[rcNum++];
		ARC(rci);
		SBOX2(s[0], s[7], s[8], s[15]);
		SBOX3(s[1], s[4], s[9 ], s[12]);
		SBOX3(s[2], s[5], s[10], s[13]);
		SBOX3(s[3], s[6], s[11], s[14]);
		rci = round[rcNum++];
		ARC(rci);
		SBOX2(s[0], s[6], s[8], s[14]);
		SBOX3(s[1], s[7], s[9 ], s[15]);
		SBOX3(s[2], s[4], s[10], s[12]);
		SBOX3(s[3], s[5], s[11], s[13]);
		rci = round[rcNum++];
		ARC(rci);
		SBOX2(s[0], s[5], s[8], s[13]);
		SBOX3(s[1], s[6], s[9 ], s[14]);
		SBOX3(s[2], s[7], s[10], s[15]);
		SBOX3(s[3], s[4], s[11], s[12]);
		rci = round[rcNum++];
		ARC(rci);
		SBOX2(s[0], s[4], s[8 ], s[12]);
		SBOX3(s[1], s[5], s[9 ], s[13]);
		SBOX3(s[2], s[6], s[10], s[14]);
		SBOX3(s[3], s[7], s[11], s[15]);
	}
	rci = round[rcNum++];
	ARC(rci);
	SBOX2(s[0], s[7], s[8], s[15]);
	SBOX3(s[1], s[4], s[9 ], s[12]);
	SBOX3(s[2], s[5], s[10], s[13]);
	SBOX3(s[3], s[6], s[11], s[14]);
	rci = round[rcNum++];
	ARC(rci);
	SBOX2(s[0], s[6], s[8], s[14]);
	SBOX3(s[1], s[7], s[9 ], s[15]);
	SBOX3(s[2], s[4], s[10], s[12]);
	SBOX3(s[3], s[5], s[11], s[13]);
	rci = round[rcNum++];
	ARC(rci);
	SBOX2(s[0], s[5], s[8], s[13]);
	SBOX3(s[1], s[6], s[9 ], s[14]);
	SBOX3(s[2], s[7], s[10], s[15]);
	SBOX3(s[3], s[4], s[11], s[12]);
	SR(s[4], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]);
}

void packU128FormatToFourPacket(u32 *out, u8 *in) {
	u32 t0 = U32BIG(((u32* )in)[0]);
	u32 t1 = U32BIG(((u32* )in)[1]);
	u32 t2 = U32BIG(((u32* )in)[2]);
	u32 t3 = U32BIG(((u32* )in)[3]);
	puckU32ToFour(t0);
	puckU32ToFour(t1);
	puckU32ToFour(t2);
	puckU32ToFour(t3);
	out[3] = (t3 & 0xff000000) | ((t2 >> 8) & 0x00ff0000)
			| ((t1 >> 16) & 0x0000ff00) | (t0 >> 24);
	out[2] = ((t3 << 8) & 0xff000000) | (t2 & 0x00ff0000)
			| ((t1 >> 8) & 0x0000ff00) | ((t0 >> 16) & 0x000000ff);
	out[1] = ((t3 << 16) & 0xff000000) | ((t2 << 8) & 0x00ff0000)
			| (t1 & 0x0000ff00) | ((t0 >> 8) & 0x000000ff);
	out[0] = ((t3 << 24) & 0xff000000) | ((t2 << 16) & 0x00ff0000)
			| ((t1 << 8) & 0x0000ff00) | (t0 & 0x000000ff);
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

