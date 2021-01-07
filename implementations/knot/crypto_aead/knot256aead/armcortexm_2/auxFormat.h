#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#define U32BIG(x) (x)

#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define LOTR32(x,n) (((x)<<(n))|((x)>>(32-(n))))

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

void unpackU128FormatToFourPacket(u8 * out, u32 * in) ;

void packU128FormatToFourPacket(u32 * out, u8 * in) ;

void P512(unsigned int *s, unsigned char *round, unsigned char rounds);

unsigned char constant7Format_aead[100];

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
#define P512_ARC_1(rci) \
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
//t1 t2
#define P512_2SC(S1,S2,S3,S4,S5,S6,S7,S8) \
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
            "/*sbox   column*/         \n\t"\
   	        "mvns    %[S_1],     %[S_1]            \n\t"\
   	        "ands    %[t3],      %[S_3], %[S_1]        \n\t"\
   	        "eors    %[t3],      %[S_5], %[t3]        \n\t"\
   	        "orrs    %[S_5],     %[S_3], %[S_5]        \n\t"\
   	        "eors    %[S_1],     %[S_7], %[S_1]        \n\t"\
   	        "eors    %[S_5],     %[S_5], %[S_1]        \n\t"\
   	        "eors    %[t2],      %[S_3], %[S_7]        \n\t"\
   	        "eors    %[S_7],     %[S_7], %[t3]        \n\t"\
   	        "ands    %[S_1],     %[t3] , %[S_1]        \n\t"\
   	        "eors    %[S_1],     %[t2] , %[S_1]        \n\t"\
   	        "ands    %[S_3],     %[S_5], %[t2]       \n\t"\
   	        "eors    %[S_3],     %[t3] , %[S_3]        \n\t"\
    : /* output variables - including inputs that are changed */\
		[t1] "=r" (t1), [t2] "=r" (t2), [t3] "=r" (t3),\
		[S_0] "+r" (S1), [S_2] "+r" (S2), [S_4] "+r" (S3), [S_6] "+r" (S4) ,\
		[S_1] "+r" (S5), [S_3] "+r" (S6), [S_5] "+r" (S7), [S_7] "+r" (S8)\
		: : );\
}while (0)
#define P512_SR_1() \
  do { \
    __asm__ __volatile__ ( \
    "/*rotate shift left 1 bit  [w9 w5 w1-> (w1,1) w9 w5] */   \n\t"\
    	"mov    %[t1],      %[S_7]       \n\t"\
    	"mov    %[S_7],     %[S_6]       \n\t"\
    	"mov    %[S_6],     %[S_5]       \n\t"\
    	"mov    %[S_5],     %[S_4]       \n\t"\
    	"ROR    %[S_4],     %[t1]    , #31        \n\t"\
    "/*rotate shift left 8 bits [w10 w6 w2-> （w6,3)  (w2,3)  ( w10,2)]*/  \n\t"\
		"ROR    %[S_11],    %[S_11]  , #28      \n\t"\
		"ROR    %[S_10],    %[S_10]  , #28      \n\t"\
		"ROR    %[S_9],     %[S_9]   , #28      \n\t"\
		"ROR    %[S_8],     %[S_8]   , #28        \n\t"\
    : /* output variables - including inputs that are changed */\
	 [t1] "=r" (t1),\
	 [S_4] "+r" (s[4]), [S_8] "+r" (s[8])  ,\
	 [S_5] "+r" (s[5]), [S_9] "+r" (s[9])  ,\
	 [S_6] "+r" (s[6]), [S_10] "+r" (s[10]),\
	 [S_7] "+r" (s[7]), [S_11] "+r" (s[11])\
	 : : );\
}while (0)
	//t1 t2
#define P512_SR_ARC_2(rci) \
  do { \
    __asm__ __volatile__ ( \
    "/*rotate shift left 25 bit  [w11 w7 w3-> （w3,13)  (w11,14)  ( w7,14)] */   \n\t"\
		"mov    %[t3],    	%[S_15]       \n\t"\
		"ROR    %[S_15],    %[S_14] , #26      \n\t"\
		"ROR    %[S_14],    %[S_13] , #26      \n\t"\
		"ROR    %[S_13],    %[S_12] , #26      \n\t"\
		"ROR    %[S_12],    %[t3]   , #25        \n\t"\
		"/*add round const   s0 s1 s2 s3*/           \n\t"\
		"ands   %[t1]  ,    %[rci]  , #0xc0\n\t" \
		"eors   %[S_3] ,    %[S_3]  , %[t1], LSR  #6 \n\t"   /*s[3] ^= (constant7Format_aead[lunNum] >> 6) & 0x3;*/\
		"ands   %[t2]  ,    %[rci]  , #0x30\n\t" \
		"eors   %[S_2] ,    %[S_2]  , %[t2], LSR  #4 \n\t"   /*s[2] ^= (constant7Format_aead[lunNum] >> 4) & 0x3;*/\
		"ands   %[t3]  ,    %[rci]  , #0xc\n\t" \
		"eors   %[S_1] ,    %[S_1]  , %[t3], LSR  #2 \n\t"   /*s[1] ^= (constant7Format_aead[lunNum] >> 2) & 0x3;*/\
		"ands   %[t1]  ,    %[rci]  , #0x3\n\t" \
		"eors   %[S_0] ,    %[S_0]  , %[t1]       \n\t"      /*s[0] ^= constant7Format_aead[lunNum] & 0x3;*/\
    : /* output variables - including inputs that are changed */\
	   	[t1] "=r" (t1),	[t2] "=r" (t2), [t3] "=r" (t3),   [rci] "+r" (rci),\
		[S_0] "+r" (s[0]),  [S_1] "+r" (s[1]),  [S_2] "+r" (s[2]),  [S_3] "+r" (s[3]),\
		[S_12] "+r" (s[12]),[S_13] "+r" (s[13]),[S_14] "+r" (s[14]),[S_15] "+r" (s[15])\
		: : );\
}while (0)
	//t1
#define P512_SR_2() \
  do { \
    __asm__ __volatile__ ( \
    "/*rotate shift left 25 bit  [w11 w7 w3-> （w3,13)  (w11,14)  ( w7,14)] */   \n\t"\
    	"mov    %[t1],    	%[S_15]       \n\t"\
    	"ROR    %[S_15],    %[S_14] , #26      \n\t"\
    	"ROR    %[S_14],    %[S_13] , #26      \n\t"\
    	"ROR    %[S_13],    %[S_12] , #26      \n\t"\
    	"ROR    %[S_12],    %[t1]   , #25        \n\t"\
    : /* output variables - including inputs that are changed */\
	[S_12] "+r" (s[12]),[S_13] "+r" (s[13]),[S_14] "+r" (s[14]),[S_15] "+r" (s[15]),\
	 [t1] "=r" (t1): : );\
}while (0)

