#include"auxFormat.h"

void packU96FormatToThreePacket(u32 * out, u8 * in) {
	u32 temp0[3] = { 0 };
	u32 temp1[3] = { 0 };
	u32 temp2[3] = { 0 };
	u32 t1=U32BIG(((u32*)in)[0]);
	temp0[0] = t1; temp0[1] = t1 >> 1; temp0[2] = t1>> 2;
	puckU32ToThree_1(temp0[0]);
	puckU32ToThree_1(temp0[1]);
	puckU32ToThree_1(temp0[2]);
	t1=U32BIG(((u32*)in)[1]);
	temp1[0] = t1; temp1[1] = t1>>1; temp1[2] = t1 >> 2;
	puckU32ToThree_1(temp1[0]);
	puckU32ToThree_1(temp1[1]);
	puckU32ToThree_1(temp1[2]);
	t1=U32BIG(((u32*)in)[2]);
	temp2[0] = t1; temp2[1] =t1 >> 1; temp2[2] = t1>> 2;
	puckU32ToThree_1(temp2[0]);
	puckU32ToThree_1(temp2[1]);
	puckU32ToThree_1(temp2[2]);
	out[0] = (temp2[1]<<21)	|(temp1[0]<<10)	|temp0[2];
	out[1] = (temp2[0] << 21) | (temp1[2] << 11) | temp0[1];
	out[2] = (temp2[2] << 22) | (temp1[1] << 11) | temp0[0];
}
void unpackU96FormatToThreePacket(u8 * out, u32 * in) {
	u32 temp0[3] = { 0 };
	u32 temp1[3] = { 0 };
	u32 temp2[3] = { 0 };
	u32 t[3] = { 0 };
	u32 t0=in[0] ;
	u32 t1=in[1] ;
	u32 t2=in[2] ;
	temp0[0] = t2 & 0x7ff;
	temp0[1] = t1 & 0x7ff;
	temp0[2] = t0 & 0x3ff;
	temp1[0] = (t0>>10) & 0x7ff;
	temp1[1] = (t2 >>11 ) & 0x7ff;
	temp1[2] = (t1 >> 11) & 0x3ff;
	temp2[0] = t1 >> 21;
	temp2[1] = t0 >> 21;
	temp2[2] = t2 >> 22;
	unpuckU32ToThree_1(temp0[0]);
	unpuckU32ToThree_1(temp0[1]);
	unpuckU32ToThree_1(temp0[2]);
	t[0] = temp0[0] | temp0[1] << 1 | temp0[2] << 2;
	unpuckU32ToThree_1(temp1[0]);
	unpuckU32ToThree_1(temp1[1]);
	unpuckU32ToThree_1(temp1[2]);
	t[1] = temp1[0] | temp1[1] << 1 | temp1[2] << 2;
	unpuckU32ToThree_1(temp2[0]);
	unpuckU32ToThree_1(temp2[1]);
	unpuckU32ToThree_1(temp2[2]);
	t[2] = temp2[0] | temp2[1] << 1 | temp2[2] << 2;
	memcpy(out, t, 12 * sizeof(unsigned char));
}
void ROUND384_Three(unsigned int *s, unsigned char *c, int lunnum) {
	unsigned int t, t1, t2;
	u32 rci, temp;
	rci = c[0];
	ARC(rci);
	SBOX(s[0], s[3], s[6], s[9]);
	SBOX(s[1], s[4], s[7], s[10]);
	SBOX(s[2], s[5], s[8], s[11]);
	t = 1;
	while (lunnum--) {
		temp = ((u32*) (c + t))[0];
		rci = temp & 0xff;
		ARC(rci);
		SBOX1_ROR(s[0], s[4], s[8], s[10] );
		SBOX2_ROR(s[1], s[5], s[6], s[11]);
		SBOX3_ROR(s[2], s[3], s[7], s[9]);
		rci = (temp & 0xff00) >> 8;
		ARC(rci);
		SBOX1_ROR(s[0], s[5], s[7], s[11]);
		SBOX2_ROR(s[1], s[3], s[8], s[9]);
		SBOX3_ROR(s[2], s[4], s[6], s[10]);
		rci = (temp & 0xff0000) >> 16;
		ARC(rci);
		SBOX1_ROR(s[0], s[3], s[6], s[9]);
		SBOX2_ROR(s[1], s[4], s[7], s[10]);
		SBOX3_ROR(s[2], s[5], s[8], s[11]);
		t += 3;
	}
}
