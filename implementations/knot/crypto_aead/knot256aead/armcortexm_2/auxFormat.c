#include"auxFormat.h"

void P512(unsigned int *s, unsigned char *round, unsigned char rounds) {
	u32 rci,t1,t2,t3,t9;
	unsigned char i;
	for (i = 0; i < rounds; i++) {
	    rci=round[0]; \
	    P512_ARC_1(rci);\
		for (i = 1;i < rounds;i++) {\
			  P512_2SC(s[0],s[4],s[8] ,s[12],s[1],s[5],s[9] ,s[13]);\
			  P512_2SC(s[2],s[6],s[10],s[14],s[3],s[7],s[11],s[15]);\
			  P512_SR_1();\
			  rci=round[i];\
			  P512_SR_ARC_2(rci);\
		}\
		P512_2SC(s[0],s[4],s[8] ,s[12],s[1],s[5],s[9] ,s[13]);\
		P512_2SC(s[2],s[6],s[10],s[14],s[3],s[7],s[11],s[15]);\
		P512_SR_1();\
		P512_SR_2();\

	}
}
void packU128FormatToFourPacket(u32 * out, u8 * in) {
	u32 t0 = U32BIG(((u32*)in)[0]);
	u32 t1 = U32BIG(((u32*)in)[1]);
	u32 t2 = U32BIG(((u32*)in)[2]);
	u32 t3 = U32BIG(((u32*)in)[3]);
	puckU32ToFour(t0);
	puckU32ToFour(t1);
	puckU32ToFour(t2);
	puckU32ToFour(t3);
	out[3] = (t3 & 0xff000000) | ((t2 >> 8) & 0x00ff0000) | ((t1 >> 16) & 0x0000ff00) | (t0 >> 24);
	out[2] = ((t3 << 8) & 0xff000000) | (t2 & 0x00ff0000) | ((t1 >> 8) & 0x0000ff00) | ((t0 >> 16) & 0x000000ff);
	out[1] = ((t3 << 16) & 0xff000000) | ((t2 << 8) & 0x00ff0000) | (t1 & 0x0000ff00) | ((t0 >> 8) & 0x000000ff);
	out[0] = ((t3 << 24) & 0xff000000) | ((t2 << 16) & 0x00ff0000) | ((t1 << 8) & 0x0000ff00) | (t0 & 0x000000ff);
}
void unpackU128FormatToFourPacket(u8 * out, u32 * in) {
	u32 temp[4] = { 0 };
	u32  t0, t1, t2, t3;
	memcpy(temp, in, sizeof(unsigned int) * 4);
	t3 = (temp[3] & 0xff000000 )| ((temp[2] >> 8) & 0x00ff0000) | ((temp[1] >> 16) & 0x0000ff00) | (temp[0] >> 24);
	t2 = ((temp[3] << 8) & 0xff000000) | (temp[2] & 0x00ff0000) | ((temp[1] >> 8) & 0x0000ff00) | ((temp[0] >> 16) & 0x000000ff);
	t1 = ((temp[3] << 16) & 0xff000000) | ((temp[2] << 8) & 0x00ff0000) | (temp[1] & 0x0000ff00) | ((temp[0] >> 8) & 0x000000ff);
	t0 = ((temp[3] << 24) & 0xff000000) | ((temp[2] << 16) & 0x00ff0000) | ((temp[1] << 8) & 0x0000ff00) | (temp[0] & 0x000000ff);
	unpuckU32ToFour(t0);
	unpuckU32ToFour(t1);
	unpuckU32ToFour(t2);
	unpuckU32ToFour(t3);
	((u32*)out)[0] = U32BIG(t0);
	((u32*)out)[1] = U32BIG(t1);
	((u32*)out)[2] = U32BIG(t2);
	((u32*)out)[3] = U32BIG(t3);
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
