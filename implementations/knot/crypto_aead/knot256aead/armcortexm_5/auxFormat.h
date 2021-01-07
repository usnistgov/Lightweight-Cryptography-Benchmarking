#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#include <stdio.h>
#include <stdlib.h>
#define U32BIG(x) (x)

void P512(unsigned int *s, unsigned char *round, unsigned char rounds);

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
void printU8(char name[], u8 var[], long len, int offset);



#define puckU32ToFour(lo){\
u32 r0;\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
r0 = (lo ^ (lo << 1)) & 0x44444444, lo ^= r0 ^ (r0 >> 1);\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
r0 = (lo ^ (lo << 8)) & 0x00ff0000, lo ^= r0 ^ (r0 >> 8);\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
}
#define unpuckU32ToFour(lo){\
u32 r0;\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
r0 = (lo ^ (lo << 8)) & 0x00ff0000, lo ^= r0 ^ (r0 >> 8);\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
r0 = (lo ^ (lo << 4)) & 0x0f000f00, lo ^= r0 ^ (r0 >> 4);\
r0 = (lo ^ (lo << 1)) & 0x44444444, lo ^= r0 ^ (r0 >> 1);\
r0 = (lo ^ (lo << 2)) & 0x30303030, lo ^= r0 ^ (r0 >> 2);\
}
//t1
#define ARC(rci) \
  do { \
    __asm__ __volatile__ ( \
    		"/*add round const   s0 s1 s2 s3*/           \n\t"\
			"ands %[t1] ,  %[rci], #0xc0\n\t" \
			"eors %[S_3],  %[S_3], %[t1], LSR  #6 \n\t"   /*s[3] ^= (constant7Format_aead[lunNum] >> 6) & 0x3;*/\
			"ands %[t2] ,  %[rci], #0x30\n\t" \
			"eors %[S_2],  %[S_2], %[t2], LSR  #4 \n\t"   /*s[2] ^= (constant7Format_aead[lunNum] >> 4) & 0x3;*/\
			"ands %[t3] ,  %[rci], #0xc\n\t" \
			"eors %[S_1],  %[S_1], %[t3], LSR  #2 \n\t"   /*s[1] ^= (constant7Format_aead[lunNum] >> 2) & 0x3;*/\
			"ands %[t4] ,  %[rci], #0x3\n\t" \
			"eors %[S_0],  %[S_0], %[t4]       \n\t"      /*s[0] ^= constant7Format_aead[lunNum] & 0x3;*/\
			: /* output variables - including inputs that are changed */\
			  [t1] "=r" (t1),  [t2] "=r" (t2),  [t3] "=r" (t3),   [t4] "=r" (t9), [rci] "+r" (rci),\
			  [S_0] "+r" (s[0]), [S_1] "+r" (s[1]), [S_2] "+r" (s[2]),[S_3] "+r" (s[3])\
			  : : );\
}while (0)
#define SBOX2(S1,S2,S3,S4) \
  do { \
    __asm__ __volatile__ ( \
			"/*sbox   column*/         \n\t"\
			"ROR      %[S_2]  ,   #31     \n\t"\
			"ROR      %[S_4]  ,   #28     \n\t"\
			"ROR      %[S_6]  ,   #25     \n\t"\
			"mvns    %[S_0],     %[S_0]            \n\t"\
			"ands    %[t1],      %[S_2], %[S_0]        \n\t"\
			"eors    %[t1],      %[S_4], %[t1]        \n\t"\
			"orrs    %[S_4],     %[S_2], %[S_4]        \n\t"\
			"eors    %[S_0],     %[S_6], %[S_0]        \n\t"\
			"eors    %[S_4],     %[S_4], %[S_0]        \n\t"\
			"eors    %[t2],      %[S_2], %[S_6]        \n\t"\
			"eors    %[S_6],     %[S_6], %[t1]        \n\t"\
			"ands    %[S_0],     %[t1] , %[S_0]        \n\t"\
			"eors    %[S_0],     %[t2] , %[S_0]        \n\t"\
			"ands    %[S_2],     %[S_4], %[t2]       \n\t"\
			"eors    %[S_2],     %[t1] , %[S_2]        \n\t"\
	: /* output variables - including inputs that are changed */\
		[t1] "=r" (t1), [t2] "=r" (t2),\
		[S_0] "+r" (S1), [S_2] "+r" (S2), [S_4] "+r" (S3), [S_6] "+r" (S4) \
		: : );\
}while (0)
#define SBOX3(S1,S2,S3,S4) \
  do { \
	    __asm__ __volatile__ ( \
			"/*sbox   column*/         \n\t"\
			"ROR      %[S_4]  ,   #28     \n\t"\
			"ROR      %[S_6]  ,   #26     \n\t"\
			"mvns    %[S_0],     %[S_0]            \n\t"\
			"ands    %[t1],      %[S_2], %[S_0]        \n\t"\
			"eors    %[t1],      %[S_4], %[t1]        \n\t"\
			"orrs    %[S_4],     %[S_2], %[S_4]        \n\t"\
			"eors    %[S_0],     %[S_6], %[S_0]        \n\t"\
			"eors    %[S_4],     %[S_4], %[S_0]        \n\t"\
			"eors    %[t2],      %[S_2], %[S_6]        \n\t"\
			"eors    %[S_6],     %[S_6], %[t1]        \n\t"\
			"ands    %[S_0],     %[t1] , %[S_0]        \n\t"\
			"eors    %[S_0],     %[t2] , %[S_0]        \n\t"\
			"ands    %[S_2],     %[S_4], %[t2]       \n\t"\
			"eors    %[S_2],     %[t1] , %[S_2]        \n\t"\
	: /* output variables - including inputs that are changed */\
		[t1] "=r" (t1), [t2] "=r" (t2),\
		[S_0] "+r" (S1), [S_2] "+r" (S2), [S_4] "+r" (S3), [S_6] "+r" (S4) \
		: : );\
}while (0)

#define SBOX1(S1,S2,S3,S4) \
  do { \
    __asm__ __volatile__ ( \
            "/*sbox   column*/         \n\t"\
   	        "mvns    %[S_0],     %[S_0]            \n\t"\
   	        "ands    %[t1],      %[S_2], %[S_0]        \n\t"\
   	        "eors    %[t1],      %[S_4], %[t1]        \n\t"\
   	        "orrs    %[S_4],     %[S_2], %[S_4]        \n\t"\
   	        "eors    %[S_0],     %[S_6], %[S_0]        \n\t"\
   	        "eors    %[S_4],     %[S_4], %[S_0]        \n\t"\
   	        "eors    %[t2],      %[S_2], %[S_6]        \n\t"\
   	        "eors    %[S_6],     %[S_6], %[t1]        \n\t"\
   	        "ands    %[S_0],     %[t1] , %[S_0]        \n\t"\
   	        "eors    %[S_0],     %[t2] , %[S_0]        \n\t"\
   	        "ands    %[S_2],     %[S_4], %[t2]       \n\t"\
   	        "eors    %[S_2],     %[t1] , %[S_2]        \n\t"\
    : /* output variables - including inputs that are changed */\
		[t1] "=r" (t1), [t2] "=r" (t2),\
		[S_0] "+r" (S1), [S_2] "+r" (S2), [S_4] "+r" (S3), [S_6] "+r" (S4) \
		: : );\
}while (0)
#define SR(S4,S8,S9,S10,S11,S12,S13,S14,S15) \
  do { \
    __asm__ __volatile__ ( \
    	"ROR      %[S_4]  ,   #31     \n\t"\
		"ROR    %[S_11]  ,   #28      \n\t"\
		"ROR    %[S_10]  ,   #28      \n\t"\
		"ROR     %[S_9]   ,   #28      \n\t"\
		"ROR     %[S_8]   ,   #28        \n\t"\
    	"ROR     %[S_12] ,   #25        \n\t"\
    	"ROR     %[S_13] ,   #26      \n\t"\
    	"ROR     %[S_14] ,   #26      \n\t"\
    	"ROR     %[S_15] ,   #26        \n\t"\
    : /* output variables - including inputs that are changed */\
	  [S_4] "+r" (S4),\
	 [S_12] "+r" (S12), [S_8] "+r" (S8)  ,\
	 [S_13] "+r" (S13), [S_9] "+r" (S9)  ,\
	 [S_14] "+r" (S14), [S_10] "+r" (S10),\
	 [S_15] "+r" (S15), [S_11] "+r" (S11)\
	 : : );\
}while (0)
unsigned char constant7Format_aead[100];
