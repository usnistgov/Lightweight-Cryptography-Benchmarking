#include<malloc.h>
#include"crypto_hash.h"
#include"api.h"
#include  <string.h>
#include <stdio.h>
#include <stdlib.h>
#define U32BIG(x) (x)
#define U16BIG(x) (x)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;


void packU48FormatToThreePacket(u32 * out, u8 * in) ;

void P384(unsigned int *s, unsigned char *round, unsigned char lunNum) ;
void unpackU96FormatToThreePacket(u8 * out, u32 * in) ;
#define puckU32ToThree_1(x){\
x &= 0x49249249;\
x = (x | (x >>  2)) & 0xc30c30c3;\
x = (x | (x >>4)) & 0x0f00f00f;\
x = (x | (x >> 8)) & 0xff0000ff;\
x = (x | (x >> 16)) & 0xfff;\
}
#define unpuckU32ToThree_1(x){\
x &= 0xfff;\
x = (x | (x << 16)) & 0xff0000ff;\
x = (x | (x << 8)) & 0x0f00f00f;\
x = (x | (x << 4)) & 0xc30c30c3;\
x = (x | (x << 2)) & 0x49249249;\
}

#define P384_ARC_SC1(rci,S2,S3,S4) \
  do { \
    __asm__ __volatile__ ( \
    		"/*add round const   s0 s1 s2 */           \n\t"\
		"ands %[t1], %[rci], #0xc0\n\t" \
	    "eors %[S_0],  %[S_0], %[t1], LSR  #6 \n\t"   /*s[0] ^= (constant7Format[lunNum] >> 6) & 0x3;*/\
        "ands %[t1], %[rci], #0x38\n\t" \
	    "eors %[S_1],  %[S_1], %[t1], LSR  #3 \n\t"   /*s[0] ^= (constant7Format[lunNum] >> 6) & 0x3;*/\
	    "ands %[t1], %[rci], #0x7\n\t" \
	    "eors %[S_3],  %[S_3], %[t1]       \n\t"   /*s[2] ^= constant7Format[lunNum] & 0x7;*/\
        "/*sbox  column*/         \n\t"\
        "mvns    %[S_0],     %[S_0]            \n\t"\
        "ands    %[t1],    %[S_2], %[S_0]        \n\t"\
        "eors    %[t1],    %[S_4], %[t1]        \n\t"\
        "orrs    %[S_4],     %[S_2], %[S_4]        \n\t"\
        "eors    %[S_0],     %[S_6], %[S_0]        \n\t"\
        "eors    %[S_4],     %[S_4], %[S_0]        \n\t"\
        "eors    %[t2],    %[S_2], %[S_6]        \n\t"\
        "eors    %[S_6],     %[S_6], %[t1]        \n\t"\
        "ands    %[S_0],     %[t1],%[S_0]        \n\t"\
        "eors    %[S_0],     %[t2],%[S_0]        \n\t"\
        "ands    %[S_2],     %[S_4], %[t2]       \n\t"\
        "eors    %[S_2],     %[t1], %[S_2]        \n\t"\
    : /* output variables - including inputs that are changed */\
		[t1]  "=r" (t1),   [t2] "=r" (t2),    [rci] "+r" (rci), \
		[S_0] "+r" (s[0]), [S_1] "+r" (s[1]), [S_3] "+r" (s[2]),\
		[S_2] "+r" (S2),   [S_4] "+r" (S3),   [S_6] "+r" (S4) \
		: : );\
}while (0)
#define P384_2SC(S1,S2,S3,S4,S5,S6,S7,S8) \
  do { \
    __asm__ __volatile__ ( \
            "/*sbox   column*/         \n\t"\
   	        "mvns    %[S_0],     %[S_0]            \n\t"\
   	        "ands    %[t1],    %[S_2], %[S_0]        \n\t"\
   	        "eors    %[t1],    %[S_4], %[t1]        \n\t"\
   	        "orrs    %[S_4],     %[S_2], %[S_4]        \n\t"\
   	        "eors    %[S_0],     %[S_6], %[S_0]        \n\t"\
   	        "eors    %[S_4],     %[S_4], %[S_0]        \n\t"\
   	        "eors    %[t2],    %[S_2], %[S_6]        \n\t"\
   	        "eors    %[S_6],     %[S_6], %[t1]        \n\t"\
   	        "ands    %[S_0],     %[t1],%[S_0]        \n\t"\
   	        "eors    %[S_0],     %[t2],%[S_0]        \n\t"\
   	        "ands    %[S_2],     %[S_4], %[t2]       \n\t"\
   	        "eors    %[S_2],     %[t1], %[S_2]        \n\t"\
            "/*sbox   column*/         \n\t"\
   	        "mvns    %[S_1],     %[S_1]            \n\t"\
   	        "ands    %[t1],    %[S_3], %[S_1]        \n\t"\
   	        "eors    %[t1],    %[S_5], %[t1]        \n\t"\
   	        "orrs    %[S_5],     %[S_3], %[S_5]        \n\t"\
   	        "eors    %[S_1],     %[S_7], %[S_1]        \n\t"\
   	        "eors    %[S_5],     %[S_5], %[S_1]        \n\t"\
   	        "eors    %[t2],    %[S_3], %[S_7]        \n\t"\
   	        "eors    %[S_7],     %[S_7], %[t1]        \n\t"\
   	        "ands    %[S_1],     %[t1],%[S_1]        \n\t"\
   	        "eors    %[S_1],     %[t2],%[S_1]        \n\t"\
   	        "ands    %[S_3],     %[S_5], %[t2]       \n\t"\
   	        "eors    %[S_3],     %[t1], %[S_3]        \n\t"\
    : /* output variables - including inputs that are changed */\
		[t1] "=r" (t1), [t2] "=r" (t2),\
		[S_0] "+r" (S1), [S_2] "+r" (S2), [S_4] "+r" (S3), [S_6] "+r" (S4) ,\
		[S_1] "+r" (S5), [S_3] "+r" (S6), [S_5] "+r" (S7), [S_7] "+r" (S8)\
		: : );\
}while (0)
#define P384_SR() \
  do { \
    __asm__ __volatile__ ( \
    "/*rotate shift left 1 bit  [w9 w5 w1-> (w1,1) w9 w5] */   \n\t"\
		"mov    %[t1],      %[S_3]       \n\t"\
		"mov    %[S_3],     %[S_4]       \n\t"\
		"mov    %[S_4],     %[S_5]       \n\t"\
		"ROR    %[S_5],     %[t1]   , #31        \n\t"\
    "/*rotate shift left 8 bits [w10 w6 w2-> （w6,3)  (w2,3)  ( w10,2)]*/  \n\t"\
		"mov    %[t1],      %[S_8]       \n\t"\
		"ROR    %[S_8],     %[S_7]  , #29      \n\t"\
		"ROR    %[S_7],     %[S_6]  , #29      \n\t"\
		"ROR    %[S_6],     %[t1]   , #30        \n\t"\
    "/*rotate shift left 55 bit  [w11 w7 w3-> （w3,13)  (w11,14)  ( w7,14)] */   \n\t"\
		"mov    %[t1],      %[S_9]       \n\t"\
		"ROR    %[S_9],     %[S_10] , #14      \n\t"\
		"ROR    %[S_10],    %[S_11] , #14      \n\t"\
		"ROR    %[S_11],    %[t1]   , #13        \n\t"\
    : /* output variables - including inputs that are changed */\
	 [t1] "=r" (t1),\
	 [S_3] "+r" (s[3]), [S_6] "+r" (s[6]), [S_9] "+r" (s[9]) ,\
	 [S_4] "+r" (s[4]), [S_7] "+r" (s[7]), [S_10] "+r" (s[10]),\
	 [S_5] "+r" (s[5]), [S_8] "+r" (s[8]), [S_11] "+r" (s[11])\
	 : : );\
}while (0)


unsigned char  constant7Format[104];

