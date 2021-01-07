#include"crypto_aead.h"
#include"api.h"
#include  <string.h>
#include <stdio.h>
#include <stdlib.h>
#define U32BIG(x) (x)

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

void ROUND384_Three(unsigned int *s, unsigned char  *c,int lunnum);



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


#define ARR_SIZE(a) (sizeof((a))/sizeof((a[0])))
//Processing_Data:
#define Processing_Data(data) \
do { \
			packU96FormatToThreePacket(dataFormat, data);          \
			s[0] ^= dataFormat[0];          \
			s[1] ^= dataFormat[1];          \
			s[2] ^= dataFormat[2];          \
			packU96FormatToThreePacket((dataFormat + 3), (data + 12));          \
			s[3] ^= dataFormat[3];          \
			s[4] ^= dataFormat[4];          \
			s[5] ^= dataFormat[5];          \
} while (0)
/////////////////////////
#define ARC(rci) \
  do { \
    __asm__ __volatile__ ( \
    		"/*add round const   s0 s1 s2 */           \n\t"\
		"ands %[t1], %[rci], #0xc0\n\t" \
	    "eors %[S_0],  %[S_0], %[t1], LSR  #6 \n\t"   /*s[0] ^= (constant7Format[lunNum] >> 6) & 0x3;*/\
        "ands %[t1], %[rci], #0x38\n\t" \
	    "eors %[S_1],  %[S_1], %[t1], LSR  #3 \n\t"   /*s[0] ^= (constant7Format[lunNum] >> 6) & 0x3;*/\
	    "ands %[t1], %[rci], #0x7\n\t" \
	    "eors %[S_3],  %[S_3], %[t1]       \n\t"   /*s[2] ^= constant7Format[lunNum] & 0x7;*/\
    : /* output variables - including inputs that are changed */\
		[t1]  "=r" (t1),    [rci] "+r" (rci), \
		[S_0] "+r" (s[0]), [S_1] "+r" (s[1]), [S_3] "+r" (s[2])\
		: : );\
}while (0)
#define SBOX(S1,S2,S3,S4) \
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
#define SBOX1(S1,S2,S3,S4) \
  do { \
    __asm__ __volatile__ ( \
            "/*sbox   column*/         \n\t"\
"ROR      %[S_4]  ,   #30     \n\t"\
"ROR      %[S_6]  ,   #14     \n\t"\
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
#define SBOX2(S1,S2,S3,S4) \
  do { \
    __asm__ __volatile__ ( \
            "/*sbox   column*/         \n\t"\
"ROR      %[S_4]  ,   #29     \n\t"\
"ROR      %[S_6]  ,   #14     \n\t"\
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
"ROR      %[S_2]  ,   #31     \n\t"\
"ROR      %[S_4]  ,   #29     \n\t"\
"ROR      %[S_6]  ,   #13     \n\t"\
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
#define ROUND384_1(rci) {\
	ARC(rci);\
SBOX(s[0], s[3], s[6], s[9] );\
SBOX(s[1], s[4], s[7], s[10]);\
SBOX(s[2], s[5], s[8], s[11]);\
}
#define ROUND384_2(rci) {\
	ARC(rci);\
SBOX1(s[0], s[4], s[8], s[10] );\
SBOX2(s[1], s[5], s[6], s[11]);\
SBOX3(s[2], s[3], s[7], s[9]);\
}
#define ROUND384_3(rci) {\
	ARC(rci);\
SBOX1(s[0], s[5], s[7], s[11]);\
SBOX2(s[1], s[3], s[8], s[9]);\
SBOX3(s[2], s[4], s[6], s[10]);\
}
#define ROUND384_4(rci) {\
	ARC(rci);\
SBOX1(s[0], s[3], s[6], s[9]);\
SBOX2(s[1], s[4], s[7], s[10]);\
SBOX3(s[2], s[5], s[8], s[11]);\
}
#define  P384_1( s,  round,  lunNum) {\
		u32 t1;\
		ROUND384_Three(s,round,lunNum);\
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
}
#define  P384_2( s,  round,  lunNum) {\
		u32 t1,rci;\
		ROUND384_Three(s,round,lunNum);\
		rci=round[lunNum*3+1];\
		ROUND384_2(rci);\
	    __asm__ __volatile__ ( \
	    "/*rotate shift left 1 bit  [w9 w5 w1-> (w1,1) w9 w5] */   \n\t"\
			"mov    %[t1],      %[S_4]       \n\t"\
			"mov    %[S_4],     %[S_3]       \n\t"\
			"mov    %[S_3],     %[S_5]       \n\t"\
			"ROR    %[S_5],     %[t1]   , #31        \n\t"\
	    "/*rotate shift left 8 bits [w10 w6 w2-> （w6,3)  (w2,3)  ( w10,2)]*/  \n\t"\
			"mov    %[t1],      %[S_8]       \n\t"\
			"ROR    %[S_8],     %[S_6]  , #29      \n\t"\
			"ROR    %[S_6],     %[S_7]  , #30      \n\t"\
			"ROR    %[S_7],     %[t1]   , #29        \n\t"\
	    "/*rotate shift left 55 bit  [w11 w7 w3-> （w3,13)  (w11,14)  ( w7,14)] */   \n\t"\
			"mov    %[t1],      %[S_10]       \n\t"\
			"ROR    %[S_10],     %[S_9] , #14      \n\t"\
			"ROR    %[S_9],    %[S_11] , #14      \n\t"\
			"ROR    %[S_11],    %[t1]   , #13       \n\t"\
	    : /* output variables - including inputs that are changed */\
		 [t1] "=r" (t1),\
		 [S_3] "+r" (s[3]), [S_6] "+r" (s[6]), [S_9] "+r" (s[9]) ,\
		 [S_4] "+r" (s[4]), [S_7] "+r" (s[7]), [S_10] "+r" (s[10]),\
		 [S_5] "+r" (s[5]), [S_8] "+r" (s[8]), [S_11] "+r" (s[11])\
		 : : );\
}
//////////////////////
