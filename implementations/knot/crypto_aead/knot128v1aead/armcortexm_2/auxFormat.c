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
void P256(unsigned int *s, unsigned char *rc,  unsigned char rounds) {
	unsigned int reg1, reg2;
	asm volatile (
			"enc_loop:                         \n\t"
			"/*add round const*/           \n\t"
			"ldrb    %[reg1],     [%[rc]]          \n\t"
			"and    %[reg2],     %[reg1], 0xf        \n\t"
			"eors    %[S_0],  %[S_0], %[reg1],LSR #4 \n\t" /*s[0] ^= constant6Format[lunNum]>>4;*/\
			"eors    %[S_1],  %[S_1], %[reg2]       \n\t" /*s[1] ^= constant6Format[lunNum] & 0x0f;*/\
			"/*sbox first column*/         \n\t"
			"mvns    %[S_0],     %[S_0]            \n\t"
			"ands    %[reg1],    %[S_2], %[S_0]        \n\t"
			"eors    %[reg1],    %[S_4], %[reg1]        \n\t"
			"orrs    %[S_4],     %[S_2], %[S_4]        \n\t"
			"eors    %[S_0],     %[S_6], %[S_0]        \n\t"
			"eors    %[S_4],     %[S_4], %[S_0]        \n\t"
			"eors    %[reg2],    %[S_2], %[S_6]        \n\t"
			"eors    %[S_6],     %[S_6], %[reg1]        \n\t"
			"ands    %[S_0],     %[reg1],%[S_0]        \n\t"
			"eors    %[S_0],     %[reg2],%[S_0]        \n\t"
			"ands    %[S_2],     %[S_4], %[reg2]       \n\t"
			"eors    %[S_2],     %[reg1], %[S_2]        \n\t"
			"/*sbox first column*/         \n\t"
			"mvns    %[S_1],     %[S_1]            \n\t"
			"ands    %[reg1],    %[S_3], %[S_1]        \n\t"
			"eors    %[reg1],    %[S_5], %[reg1]        \n\t"
			"orrs    %[S_5],     %[S_3], %[S_5]        \n\t"
			"eors    %[S_1],     %[S_7], %[S_1]        \n\t"
			"eors    %[S_5],     %[S_5], %[S_1]        \n\t"
			"eors    %[reg2],    %[S_3], %[S_7]        \n\t"
			"eors    %[S_7],     %[S_7], %[reg1]        \n\t"
			"ands    %[S_1],     %[reg1],%[S_1]        \n\t"
			"eors    %[S_1],     %[reg2],%[S_1]        \n\t"
			"ands    %[S_3],     %[S_5], %[reg2]       \n\t"
			"eors    %[S_3],     %[reg1], %[S_3]        \n\t"
			"/*rotate shift left 1 bit*/   \n\t"
			"mov    %[reg1],    %[S_3]       \n\t"
			"mov    %[S_3],     %[S_2] , ROR #31 \n\t"
			"mov    %[S_2],     %[reg1]       \n\t"
			"/*rotate shift left 8 bits*/  \n\t"
			"mov    %[S_4],    %[S_4] , ROR #28 \n\t"
			"mov    %[S_5],    %[S_5] , ROR #28 \n\t"
			"/*rotate shift left 25 bits*/ \n\t"
			"mov    %[reg1],    %[S_6]       \n\t"
			"mov    %[S_6],     %[S_7] , ROR #20 \n\t"
			"mov    %[S_7],     %[reg1] , ROR #19      \n\t"
			"/*loop control*/              \n\t"
			"adds    %[rc],  %[rc], #1     \n\t"
			"subs    %[ro],  %[ro], #1     \n\t"
			"bne     enc_loop              \n\t"
			/* ----------------------------- */
			: /* output variables - including inputs that are changed */
			[ro] "+r" (rounds),[reg1] "=r" (reg1), [reg2] "=r" (reg2), [rc] "+r" (rc),
			[S_0] "+r" (s[0]), [S_2] "+r" (s[2]), [S_4] "+r" (s[4]), [S_6] "+r" (s[6]) ,
			[S_1] "+r" (s[1]), [S_3] "+r" (s[3]), [S_5] "+r" (s[5]), [S_7] "+r" (s[7])
			: /* input variables */
			: /* clobber registers for temporary values */
	);

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
