#include"auxFormat.h"

void P256(unsigned int *s, unsigned char *rc, unsigned char rounds) {
	unsigned int reg1, reg2;
	asm volatile (
			"/*add round const*/           \n\t"
			"ldrb    %[reg1],     [%[rc]]          \n\t"
			"and    %[reg2],     %[reg1], 0xf        \n\t"
			"eors    %[S_0],  %[S_0], %[reg1],LSR #4 \n\t" /*s[0] ^= constant6Format[lunNum]>>4;*/\
			"eors    %[S_1],  %[S_1], %[reg2]       \n\t" /*s[1] ^= constant6Format[lunNum] & 0x0f;*/\
			"adds    %[rc],  %[rc], #1     \n\t"
			"/*sbox first column  0,2,4,6                        sbox1(s[0], s[2], s[4], s[6]);    */   \n\t"
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
			"/*sbox first column 1,3,5,7                        sbox1(s[1], s[3], s[5], s[7])  */  \n\t"
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
			"enc_loop:                         \n\t"
			"/*add round const*/           \n\t"
			"ldrb    %[reg1],     [%[rc]]          \n\t"
			"and    %[reg2],     %[reg1], 0xf        \n\t"
			"eors    %[S_0],  %[S_0], %[reg1],LSR #4 \n\t" /*s[0] ^= constant6Format[lunNum]>>4;*/\
			"eors    %[S_1],  %[S_1], %[reg2]       \n\t" /*s[1] ^= constant6Format[lunNum] & 0x0f;*/\

			"adds    %[rc],  %[rc], #1     \n\t"

			"/*sbox first column  0,3,4,7           sbox1(s[0], s[3],ROR(s[4], 28),  ROR(s[7], 20)); */         \n\t"

   	        "ROR    %[S_4],      #28            \n\t"\
   	        "ROR    %[S_7],      #20            \n\t"\
			"mvns    %[S_0],     %[S_0]            \n\t"
			"ands    %[reg1],    %[S_3], %[S_0]        \n\t"
			"eors    %[reg1],    %[S_4], %[reg1]        \n\t"
			"orrs    %[S_4],     %[S_3], %[S_4]        \n\t"
			"eors    %[S_0],     %[S_7], %[S_0]        \n\t"
			"eors    %[S_4],     %[S_4], %[S_0]        \n\t"
			"eors    %[reg2],    %[S_3], %[S_7]        \n\t"
			"eors    %[S_7],     %[S_7], %[reg1]        \n\t"
			"ands    %[S_0],     %[reg1],%[S_0]        \n\t"
			"eors    %[S_0],     %[reg2],%[S_0]        \n\t"
			"ands    %[S_3],     %[S_4], %[reg2]       \n\t"
			"eors    %[S_3],     %[reg1], %[S_3]        \n\t"

			"/*sbox first column 1,2,5,6            sbox1(s[1], ROR(s[2], 31), ROR(s[5], 28),  ROR(s[6], 19));   */  \n\t"
   	        "ROR    %[S_2],      #31            \n\t"\
   	        "ROR    %[S_5],      #28            \n\t"\
   	        "ROR    %[S_6],      #19           \n\t"\
			"mvns    %[S_1],     %[S_1]            \n\t"
			"ands    %[reg1],    %[S_2], %[S_1]        \n\t"
			"eors    %[reg1],    %[S_5], %[reg1]        \n\t"
			"orrs    %[S_5],     %[S_2], %[S_5]        \n\t"
			"eors    %[S_1],     %[S_6], %[S_1]        \n\t"
			"eors    %[S_5],     %[S_5], %[S_1]        \n\t"
			"eors    %[reg2],    %[S_2], %[S_6]        \n\t"
			"eors    %[S_6],     %[S_6], %[reg1]        \n\t"
			"ands    %[S_1],     %[reg1],%[S_1]        \n\t"
			"eors    %[S_1],     %[reg2],%[S_1]        \n\t"
			"ands    %[S_2],     %[S_5], %[reg2]       \n\t"
			"eors    %[S_2],     %[reg1], %[S_2]        \n\t"

			"/*add round const*/           \n\t"
			"ldrb    %[reg1],     [%[rc]]          \n\t"
			"and    %[reg2],     %[reg1], 0xf        \n\t"
			"eors    %[S_0],  %[S_0], %[reg1],LSR #4 \n\t" /*s[0] ^= constant6Format[lunNum]>>4;*/\
			"eors    %[S_1],  %[S_1], %[reg2]       \n\t" /*s[1] ^= constant6Format[lunNum] & 0x0f;*/\

			"adds    %[rc],  %[rc], #1     \n\t"

			"/*sbox first column  0,2,4,6          sbox1(s[0], s[2], ROR(s[4], 28),  ROR(s[6], 20)); */         \n\t"
   	        "ROR    %[S_4],      #28            \n\t"\
   	        "ROR    %[S_6],      #20            \n\t"\
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

			"/*sbox first column 1,3,5,7            sbox1(s[1], ROR(s[3], 31), ROR(s[5], 28),  ROR(s[7], 19));   */  \n\t"
   	        "ROR    %[S_3],      #31            \n\t"\
   	        "ROR    %[S_5],      #28            \n\t"\
   	        "ROR    %[S_7],      #19           \n\t"\
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

			"/*loop control*/              \n\t"
			"subs    %[ro],  %[ro], #1     \n\t"
			"bne     enc_loop              \n\t"

			"/*add round const*/           \n\t"
			"ldrb    %[reg1],     [%[rc]]          \n\t"
			"and    %[reg2],     %[reg1], 0xf        \n\t"
			"eors    %[S_0],  %[S_0], %[reg1],LSR #4 \n\t" /*s[0] ^= constant6Format[lunNum]>>4;*/\
			"eors    %[S_1],  %[S_1], %[reg2]       \n\t" /*s[1] ^= constant6Format[lunNum] & 0x0f;*/\

			"/*sbox first column  0,3,4,7           sbox1(s[0], s[3],ROR(s[4], 28),  ROR(s[7], 20)); */         \n\t"

   	        "ROR    %[S_4],      #28            \n\t"\
   	        "ROR    %[S_7],      #20            \n\t"\
			"mvns    %[S_0],     %[S_0]            \n\t"
			"ands    %[reg1],    %[S_3], %[S_0]        \n\t"
			"eors    %[reg1],    %[S_4], %[reg1]        \n\t"
			"orrs    %[S_4],     %[S_3], %[S_4]        \n\t"
			"eors    %[S_0],     %[S_7], %[S_0]        \n\t"
			"eors    %[S_4],     %[S_4], %[S_0]        \n\t"
			"eors    %[reg2],    %[S_3], %[S_7]        \n\t"
			"eors    %[S_7],     %[S_7], %[reg1]        \n\t"
			"ands    %[S_0],     %[reg1],%[S_0]        \n\t"
			"eors    %[S_0],     %[reg2],%[S_0]        \n\t"
			"ands    %[S_3],     %[S_4], %[reg2]       \n\t"
			"eors    %[S_3],     %[reg1], %[S_3]        \n\t"

			"/*sbox first column 1,2,5,6            sbox1(s[1], ROR(s[2], 31), ROR(s[5], 28),  ROR(s[6], 19));   */  \n\t"
   	        "ROR    %[S_2],      #31            \n\t"\
   	        "ROR    %[S_5],      #28            \n\t"\
   	        "ROR    %[S_6],      #19           \n\t"\
			"mvns    %[S_1],     %[S_1]            \n\t"
			"ands    %[reg1],    %[S_2], %[S_1]        \n\t"
			"eors    %[reg1],    %[S_5], %[reg1]        \n\t"
			"orrs    %[S_5],     %[S_2], %[S_5]        \n\t"
			"eors    %[S_1],     %[S_6], %[S_1]        \n\t"
			"eors    %[S_5],     %[S_5], %[S_1]        \n\t"
			"eors    %[reg2],    %[S_2], %[S_6]        \n\t"
			"eors    %[S_6],     %[S_6], %[reg1]        \n\t"
			"ands    %[S_1],     %[reg1],%[S_1]        \n\t"
			"eors    %[S_1],     %[reg2],%[S_1]        \n\t"
			"ands    %[S_2],     %[S_5], %[reg2]       \n\t"
			"eors    %[S_2],     %[reg1], %[S_2]        \n\t"

			"ROR    %[S_3],    #31 \n\t"
			"ROR    %[S_4],    #28 \n\t"
			"ROR    %[S_5],    #28 \n\t"
			"ROR    %[S_6],    #20 \n\t"
			"ROR    %[S_7],    #19      \n\t"
			: /* output variables - including inputs that are changed */
			[ro] "+r" (rounds),[reg1] "=r" (reg1), [reg2] "=r" (reg2), [rc] "+r" (rc),
			[S_0] "+r" (s[0]), [S_2] "+r" (s[2]), [S_4] "+r" (s[4]), [S_6] "+r" (s[6]) ,
			[S_1] "+r" (s[1]), [S_3] "+r" (s[3]), [S_5] "+r" (s[5]), [S_7] "+r" (s[7])
			: /* input variables */
			: /* clobber registers for temporary values */
	);
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
