#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "photon.h"

#define S 4
#define WORDFILTER 0xF

static inline byte lookup_RC(int di, int ri)
{
	static ROM_DATA_BYTE RC[12][D] = {
    {0x1, 0x0, 0x2, 0x6, 0xe, 0xf, 0xd, 0x9}, 
    {0x3, 0x2, 0x0, 0x4, 0xc, 0xd, 0xf, 0xb}, 
    {0x7, 0x6, 0x4, 0x0, 0x8, 0x9, 0xb, 0xf}, 
    {0xe, 0xf, 0xd, 0x9, 0x1, 0x0, 0x2, 0x6}, 
    {0xd, 0xc, 0xe, 0xa, 0x2, 0x3, 0x1, 0x5}, 
    {0xb, 0xa, 0x8, 0xc, 0x4, 0x5, 0x7, 0x3}, 
    {0x6, 0x7, 0x5, 0x1, 0x9, 0x8, 0xa, 0xe}, 
    {0xc, 0xd, 0xf, 0xb, 0x3, 0x2, 0x0, 0x4}, 
    {0x9, 0x8, 0xa, 0xe, 0x6, 0x7, 0x5, 0x1}, 
    {0x2, 0x3, 0x1, 0x5, 0xd, 0xc, 0xe, 0xa}, 
    {0x5, 0x4, 0x6, 0x2, 0xa, 0xb, 0x9, 0xd}, 
    {0xa, 0xb, 0x9, 0xd, 0x5, 0x4, 0x6, 0x2}
    };
	return READ_ROM_DATA_BYTE(RC[ri][di]);
}


#define CPY(x0, x1) (x0 = x1)
#define NOT(x0, x1) (x0 = ~x1)
#define XOR(x0, x1, x2) (x0 = x1 ^ x2)
#define AND(x0, x1, x2) (x0 = x1 & x2)
#define  OR(x0, x1, x2) (x0 = x1 | x2)

#define GET_BIT(bx, x, bi) ((bx) = ((x) >> (bi)) & 1)
#define ROT8L_1_INPLACE(x) ((x) = ((x) >> 1) | ((x) << 7))
#define ROT8L_2_INPLACE(x) ((x) = ((x) >> 2) | ((x) << 6))
#define ROT8L_3_INPLACE(x) ((x) = ((x) >> 3) | ((x) << 5))
#define ROT8L_4_INPLACE(x) ((x) = ((x) >> 4) | ((x) << 4))
#define ROT8L_5_INPLACE(x) ((x) = ((x) >> 5) | ((x) << 3))
#define ROT8L_6_INPLACE(x) ((x) = ((x) >> 6) | ((x) << 2))
#define ROT8L_7_INPLACE(x) ((x) = ((x) >> 7) | ((x) << 1))
//#endif


// SBox
#define SBox(x0, x1, x2, x3, t0, t1) \
do {\
	XOR(x1, x1, x2); \
	CPY(t0, x2    ); \
	AND(t0, t0, x1); \
	XOR(x3, x3, t0); \
	CPY(t0, x3    ); \
	AND(x3, x3, x1); \
	XOR(x3, x3, x2); \
	CPY(t1, x3    ); \
	XOR(x3, x3, x0); \
	NOT(x3, x3    ); \
	CPY(x2, x3    ); \
	OR (t1, t1, x0); \
	XOR(x0, x0, t0); \
	XOR(x1, x1, x0); \
	OR (x2, x2, x1); \
	XOR(x2, x2, t0); \
	XOR(x1, x1, t1); \
	XOR(x3, x3, x1); \
} while(0) ;

# define mul2_GF16_0x13_xor(x0, x1, x2, x3, sum0, sum1, sum2, sum3, t0, t1, t2, t3) \
do { \
XOR(t3, x3, x0); /* Output : ( MSB ) x1 ,x2 ,x3 , x0 ( LSB ) */ \
XOR(sum0, sum0, x0); \
XOR(sum1, sum1, t3); \
XOR(sum2, sum2, x2); \
XOR(sum3, sum3, x1); \
} while(0) ; 

# define mul4_GF16_0x13_xor(x0, x1, x2, x3, sum0, sum1, sum2, sum3, t0, t1, t2, t3) \
do { \
XOR(t3, x3, x0);  XOR(t0, x0, x1); /* Output : ( MSB ) x2 ,x3 ,x0 , x1 ( LSB ) */ \
XOR(sum0, sum0, x1); \
XOR(sum1, sum1, t0); \
XOR(sum2, sum2, t3); \
XOR(sum3, sum3, x2); \
} while(0) ; 

# define mul5_GF16_0x13_xor(x0, x1, x2, x3, sum0, sum1, sum2, sum3, t0, t1, t2, t3) \
do { \
XOR(t2, x2 ,x0); XOR(t3, x3 ,x1); \
XOR(t1, x1 ,t2); XOR(t0, x0 ,t3); /* Output : ( MSB ) x2 ,x0 ,x1 , x3 ( LSB ) */ \
XOR(sum0, sum0, t3); \
XOR(sum1, sum1, t1); \
XOR(sum2, sum2, t0); \
XOR(sum3, sum3, t2); \
} while(0) ; 

# define mul6_GF16_0x13_xor(x0, x1, x2, x3, sum0, sum1, sum2, sum3, t0, t1, t2, t3) \
do { \
XOR(t3, x3 ,x1);  XOR(t1, x1 ,x0); \
XOR(t2, x2 ,t1);  XOR(t0, x0 ,t2); \
XOR(t2, t2 ,t3); /* Output : ( MSB ) x0 ,x2 ,x3 , x1 ( LSB ) */ \
XOR(sum0, sum0, t1); \
XOR(sum1, sum1, t3); \
XOR(sum2, sum2, t2); \
XOR(sum3, sum3, t0); \
} while(0) ; 

# define mul8_GF16_0x13_xor(x0, x1, x2, x3, sum0, sum1, sum2, sum3, t0, t1, t2, t3) \
do { \
XOR(t3, x3 ,x0);  XOR(t0, x0 ,x1); \
XOR(t1, x1 ,x2); /* Output : ( MSB ) x3 ,x0 ,x1 , x2 ( LSB ) */ \
XOR(sum0, sum0, x2); \
XOR(sum1, sum1, t1); \
XOR(sum2, sum2, t0); \
XOR(sum3, sum3, t3); \
} while(0) ; 

# define mulb_GF16_0x13_xor(x0, x1, x2, x3, sum0, sum1, sum2, sum3, t0, t1, t2, t3) \
do { \
XOR(t2, x2 ,x0); XOR(t1, x1 ,x3); \
XOR(t0, x0 ,t1); XOR(t3, x3 ,t2); /* Output : ( MSB ) x1 ,x2 ,x0 , x3 ( LSB ) */ \
XOR(sum0, sum0, t3); \
XOR(sum1, sum1, t0); \
XOR(sum2, sum2, t2); \
XOR(sum3, sum3, t1); \
} while(0) ; 

#define A1(              \
    x00, x01, x02, x03,  \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    t0, t1, t2, t3) \
do { \
    sum0 = 0; \
    sum1 = 0; \
    sum2 = 0; \
    sum3 = 0; \
    mul2_GF16_0x13_xor(x03, x02, x01, x00, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mul4_GF16_0x13_xor(x13, x12, x11, x10, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mul2_GF16_0x13_xor(x23, x22, x21, x20, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mulb_GF16_0x13_xor(x33, x32, x31, x30, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mul2_GF16_0x13_xor(x43, x42, x41, x40, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mul8_GF16_0x13_xor(x53, x52, x51, x50, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mul5_GF16_0x13_xor(x63, x62, x61, x60, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
    mul6_GF16_0x13_xor(x73, x72, x71, x70, sum0, sum1, sum2, sum3, t0, t1, t2, t3); \
} while(0) ;

#define MixColumn(       \
    x00, x01, x02, x03,  \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    t0, t1, t2, t3) \
do { \
    A1(                  /* A1 */\
    x00, x01, x02, x03,  \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    t0, t1, t2, t3 \
    )\
    \
    A1(                  /* A2 */\
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    t0, t1, t2, t3 \
    )\
    A1(                  /* A3 */\
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    x10, x11, x12, x13,  \
    t0, t1, t2, t3 \
    )\
    A1(                  /* A4 */\
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    t0, t1, t2, t3 \
    )\
    A1(                  /* A5 */\
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    t0, t1, t2, t3 \
    )\
    A1(                  /* A6 */\
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    t0, t1, t2, t3 \
    )\
    A1(                  /* A7 */\
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    t0, t1, t2, t3 \
    )\
    A1(                  /* A8 */\
    x70, x71, x72, x73,  \
    sum0, sum1, sum2, sum3, \
    x00, x01, x02, x03, \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    t0, t1, t2, t3 \
    )\
    CPY(x70, x60);       \
    CPY(x71, x61);       \
    CPY(x72, x62);       \
    CPY(x73, x63);       \
    CPY(x60, x50);       \
    CPY(x61, x51);       \
    CPY(x62, x52);       \
    CPY(x63, x53);       \
    CPY(x50, x40);       \
    CPY(x51, x41);       \
    CPY(x52, x42);       \
    CPY(x53, x43);       \
    CPY(x40, x30);       \
    CPY(x41, x31);       \
    CPY(x42, x32);       \
    CPY(x43, x33);       \
    CPY(x30, x20);       \
    CPY(x31, x21);       \
    CPY(x32, x22);       \
    CPY(x33, x23);       \
    CPY(x20, x10);       \
    CPY(x21, x11);       \
    CPY(x22, x12);       \
    CPY(x23, x13);       \
    CPY(x10, x00);       \
    CPY(x11, x01);       \
    CPY(x12, x02);       \
    CPY(x13, x03);       \
    CPY(x00, sum0);      \
    CPY(x01, sum1);      \
    CPY(x02, sum2);      \
    CPY(x03, sum3);      \
} while(0) ;

#define AddKey_Row(x0, x1, x2, x3, row, round, t0, t1) \
do { \
	t0 = lookup_RC(row, round); \
	GET_BIT(t1, t0, 0);         \
	XOR(x0, x0, t1); \
	GET_BIT(t1, t0, 1);         \
	XOR(x1, x1, t1); \
	GET_BIT(t1, t0, 2);         \
	XOR(x2, x2, t1); \
	GET_BIT(t1, t0, 3);         \
	XOR(x3, x3, t1); \
} while(0) ;

#define ShiftRow_1(x0, x1, x2, x3) \
do { \
    ROT8L_1_INPLACE(x0); \
    ROT8L_1_INPLACE(x1); \
    ROT8L_1_INPLACE(x2); \
    ROT8L_1_INPLACE(x3); \
} while(0) ;
#define ShiftRow_2(x0, x1, x2, x3) \
do { \
    ROT8L_2_INPLACE(x0); \
    ROT8L_2_INPLACE(x1); \
    ROT8L_2_INPLACE(x2); \
    ROT8L_2_INPLACE(x3); \
} while(0) ;
#define ShiftRow_3(x0, x1, x2, x3) \
do { \
    ROT8L_3_INPLACE(x0); \
    ROT8L_3_INPLACE(x1); \
    ROT8L_3_INPLACE(x2); \
    ROT8L_3_INPLACE(x3); \
} while(0) ;
#define ShiftRow_4(x0, x1, x2, x3) \
do { \
    ROT8L_4_INPLACE(x0); \
    ROT8L_4_INPLACE(x1); \
    ROT8L_4_INPLACE(x2); \
    ROT8L_4_INPLACE(x3); \
} while(0) ;
#define ShiftRow_5(x0, x1, x2, x3) \
do { \
    ROT8L_5_INPLACE(x0); \
    ROT8L_5_INPLACE(x1); \
    ROT8L_5_INPLACE(x2); \
    ROT8L_5_INPLACE(x3); \
} while(0) ;
#define ShiftRow_6(x0, x1, x2, x3) \
do { \
    ROT8L_6_INPLACE(x0); \
    ROT8L_6_INPLACE(x1); \
    ROT8L_6_INPLACE(x2); \
    ROT8L_6_INPLACE(x3); \
} while(0) ;
#define ShiftRow_7(x0, x1, x2, x3) \
do { \
    ROT8L_7_INPLACE(x0); \
    ROT8L_7_INPLACE(x1); \
    ROT8L_7_INPLACE(x2); \
    ROT8L_7_INPLACE(x3); \
} while(0) ;


#if defined(PC)
#define ReorderWord(x, t) \
do { \
/*  S00 S01 S02 S03 S04 S05 S06 S07 S10 S11 S12 S13 S14 S15 S16 S17 S20 S21 S22 S23 S24 S25 S26 S27 S30 S31 S32 S33 S34 S35 S36 S37 */ \
/*  s37 s36 s35 s34 s33 s32 s31 s30 s27 s26 s25 s24 s23 s22 s21 s20 s17 s16 s15 s14 s13 s12 s11 s10 s07 s06 s05 s04 s03 s02 s01 s00 */ \
    t = (x ^ (x >> 2U)) & 0x0C0C0C0CU; x = x ^ t ^ (t << 2U); \
/*  S00 S01 S04 S05 S02 S03 S06 S07 S10 S11 S14 S15 S12 S13 S16 S17 S20 S21 S24 S25 S22 S23 S26 S27 S30 S31 S34 S35 S32 S33 S36 S37 */ \
/*  s37 s36 s33 s32 s35 s34 s31 s30 s27 s26 s23 s22 s25 s24 s21 s20 s17 s16 s13 s12 s15 s14 s11 s10 s07 s06 s03 s02 s05 s04 s01 s00 */ \
    t = (x ^ (x >> 4U)) & 0x00F000F0U; x = x ^ t ^ (t << 4U); \
/*  S00 S01 S04 S05 S10 S11 S14 S15 S02 S03 S06 S07 S12 S13 S16 S17 S20 S21 S24 S25 S30 S31 S34 S35 S22 S23 S26 S27 S32 S33 S36 S37 */ \
/*  s37 s36 s33 s32 s27 s26 s23 s22 s35 s34 s31 s30 s25 s24 s21 s20 s17 s16 s13 s12 s07 s06 s03 s02 s15 s14 s11 s10 s05 s04 s01 s00 */ \
    t = (x ^ (x >> 8U)) & 0x0000FF00U; x = x ^ t ^ (t << 8U); \
/*  S00 S01 S04 S05 S10 S11 S14 S15 S20 S21 S24 S25 S30 S31 S34 S35 S02 S03 S06 S07 S12 S13 S16 S17 S22 S23 S26 S27 S32 S33 S36 S37 */ \
/*  s37 s36 s33 s32 s27 s26 s23 s22 s17 s16 s13 s12 s07 s06 s03 s02 s35 s34 s31 s30 s25 s24 s21 s20 s15 s14 s11 s10 s05 s04 s01 s00 */ \
    t = (x ^ (x >> 1U)) & 0x22222222U; x = x ^ t ^ (t << 1U); \
/*  S00 S04 S01 S05 S10 S14 S11 S15 S20 S24 S21 S25 S30 S34 S31 S35 S02 S06 S03 S07 S12 S16 S13 S17 S22 S26 S23 S27 S32 S36 S33 S37 */ \
/*  s37 s33 s36 s32 s27 s23 s26 s22 s17 s13 s16 s12 s07 s03 s06 s02 s35 s31 s34 s30 s25 s21 s24 s20 s15 s11 s14 s10 s05 s01 s04 s00 */ \
    t = (x ^ (x >> 2U)) & 0x0C0C0C0CU; x = x ^ t ^ (t << 2U); \
/*  S00 S04 S10 S14 S01 S05 S11 S15 S20 S24 S30 S34 S21 S25 S31 S35 S02 S06 S12 S16 S03 S07 S13 S17 S22 S26 S32 S36 S23 S27 S33 S37 */ \
/*  s37 s33 s27 s23 s36 s32 s26 s22 s17 s13 s07 s03 s16 s12 s06 s02 s35 s31 s25 s21 s34 s30 s24 s20 s15 s11 s05 s01 s14 s10 s04 s00 */ \
    t = (x ^ (x >> 4U)) & 0x00F000F0U; x = x ^ t ^ (t << 4U); \
/*  S00 S04 S10 S14 S20 S24 S30 S34 S01 S05 S11 S15 S21 S25 S31 S35 S02 S06 S12 S16 S22 S26 S32 S36 S03 S07 S13 S17 S23 S27 S33 S37 */ \
/*  s37 s33 s27 s23 s17 s13 s07 s03 s36 s32 s26 s22 s16 s12 s06 s02 s35 s31 s25 s21 s15 s11 s05 s01 s34 s30 s24 s20 s14 s10 s04 s00 */ \
} while(0);
#else
#define ReorderByte(x, t) \
do { \
} while (0);
#define ReorderWord(x, t) \
do { \
} while (0);
#endif

#define ReorderRow(r) \
do { \
    row = ((uint32_t *)State_in)[r];  \
    ReorderWord(row, tmp);            \
    s##r##0 = (row >> (0 * 8)) & 0xFF; \
    s##r##1 = (row >> (1 * 8)) & 0xFF; \
    s##r##2 = (row >> (2 * 8)) & 0xFF; \
    s##r##3 = (row >> (3 * 8)) & 0xFF; \
} while (0);

#define ReorderState() \
do { \
    ReorderRow(0) \
    ReorderRow(1) \
    ReorderRow(2) \
    ReorderRow(3) \
    ReorderRow(4) \
    ReorderRow(5) \
    ReorderRow(6) \
    ReorderRow(7) \
} while (0);


#if defined(PC)
#define InvReorderWord(x, t) \
do { \
/*  S00 S04 S10 S14 S20 S24 S30 S34 S01 S05 S11 S15 S21 S25 S31 S35 S02 S06 S12 S16 S22 S26 S32 S36 S03 S07 S13 S17 S23 S27 S33 S37 */ \
    t = (x ^ (x >> 4U)) & 0x00F000F0U; x = x ^ t ^ (t << 4U); \
/*  S00 S04 S10 S14 S01 S05 S11 S15 S20 S24 S30 S34 S21 S25 S31 S35 S02 S06 S12 S16 S03 S07 S13 S17 S22 S26 S32 S36 S23 S27 S33 S37 */ \
    t = (x ^ (x >> 2U)) & 0x0C0C0C0CU; x = x ^ t ^ (t << 2U); \
/*  S00 S04 S01 S05 S10 S14 S11 S15 S20 S24 S21 S25 S30 S34 S31 S35 S02 S06 S03 S07 S12 S16 S13 S17 S22 S26 S23 S27 S32 S36 S33 S37 */ \
    t = (x ^ (x >> 1U)) & 0x22222222U; x = x ^ t ^ (t << 1U); \
/*  S00 S01 S04 S05 S10 S11 S14 S15 S20 S21 S24 S25 S30 S31 S34 S35 S02 S03 S06 S07 S12 S13 S16 S17 S22 S23 S26 S27 S32 S33 S36 S37 */ \
    t = (x ^ (x >> 8U)) & 0x0000FF00U; x = x ^ t ^ (t << 8U); \
/*  S00 S01 S04 S05 S10 S11 S14 S15 S02 S03 S06 S07 S12 S13 S16 S17 S20 S21 S24 S25 S30 S31 S34 S35 S22 S23 S26 S27 S32 S33 S36 S37 */ \
    t = (x ^ (x >> 4U)) & 0x00F000F0U; x = x ^ t ^ (t << 4U); \
/*  S00 S01 S04 S05 S02 S03 S06 S07 S10 S11 S14 S15 S12 S13 S16 S17 S20 S21 S24 S25 S22 S23 S26 S27 S30 S31 S34 S35 S32 S33 S36 S37 */ \
    t = (x ^ (x >> 2U)) & 0x0C0C0C0CU; x = x ^ t ^ (t << 2U); \
/*  S00 S01 S02 S03 S04 S05 S06 S07 S10 S11 S12 S13 S14 S15 S16 S17 S20 S21 S22 S23 S24 S25 S26 S27 S30 S31 S32 S33 S34 S35 S36 S37 */ \
} while(0);
#else
#define InvReorderByte(x, t) \
do { \
} while (0);
#define InvReorderWord(x, t) \
do { \
} while (0);
#endif


#define InvReorderRow(r) \
do { \
    row  = ((uint32_t)s##r##0 & 0xFFU) << (0 * 8) ; \
    row |= ((uint32_t)s##r##1 & 0xFFU) << (1 * 8) ; \
    row |= ((uint32_t)s##r##2 & 0xFFU) << (2 * 8) ; \
    row |= ((uint32_t)s##r##3 & 0xFFU) << (3 * 8) ; \
    InvReorderWord(row, tmp);            \
    ((uint32_t *)State_in)[r] = row;  \
} while (0);

#define InvReorderState() \
do { \
    InvReorderRow(0) \
    InvReorderRow(1) \
    InvReorderRow(2) \
    InvReorderRow(3) \
    InvReorderRow(4) \
    InvReorderRow(5) \
    InvReorderRow(6) \
    InvReorderRow(7) \
} while (0);


void PHOTON_Permutation(unsigned char *State_in)
{
    uint8_t s00, s01, s02, s03;
    uint8_t s10, s11, s12, s13;
    uint8_t s20, s21, s22, s23;
    uint8_t s30, s31, s32, s33;
    uint8_t s40, s41, s42, s43;
    uint8_t s50, s51, s52, s53;
    uint8_t s60, s61, s62, s63;
    uint8_t s70, s71, s72, s73;
    uint8_t tmp0, tmp1, tmp2, tmp3;
    uint8_t tmp4, tmp5, tmp6, tmp7;

    uint32_t row;
    uint32_t tmp;
    
    int i;

    ReorderState();


	for(i = 0; i < ROUND; i++)
	{
		AddKey_Row(s00, s01, s02, s03, 0, i, tmp0, tmp1);
		AddKey_Row(s10, s11, s12, s13, 1, i, tmp0, tmp1);
		AddKey_Row(s20, s21, s22, s23, 2, i, tmp0, tmp1);
		AddKey_Row(s30, s31, s32, s33, 3, i, tmp0, tmp1);
		AddKey_Row(s40, s41, s42, s43, 4, i, tmp0, tmp1);
		AddKey_Row(s50, s51, s52, s53, 5, i, tmp0, tmp1);
		AddKey_Row(s60, s61, s62, s63, 6, i, tmp0, tmp1);
		AddKey_Row(s70, s71, s72, s73, 7, i, tmp0, tmp1);

		SBox(s00, s01, s02, s03, tmp0, tmp1);
		SBox(s10, s11, s12, s13, tmp0, tmp1);
		SBox(s20, s21, s22, s23, tmp0, tmp1);
		SBox(s30, s31, s32, s33, tmp0, tmp1);
		SBox(s40, s41, s42, s43, tmp0, tmp1);
		SBox(s50, s51, s52, s53, tmp0, tmp1);
		SBox(s60, s61, s62, s63, tmp0, tmp1);
		SBox(s70, s71, s72, s73, tmp0, tmp1);

    	ShiftRow_1(s10, s11, s12, s13);
    	ShiftRow_2(s20, s21, s22, s23);
    	ShiftRow_3(s30, s31, s32, s33);
    	ShiftRow_4(s40, s41, s42, s43);
    	ShiftRow_5(s50, s51, s52, s53);
    	ShiftRow_6(s60, s61, s62, s63);
    	ShiftRow_7(s70, s71, s72, s73);    

		MixColumn(
    	s00, s01, s02, s03,
    	s10, s11, s12, s13,
    	s20, s21, s22, s23,
    	s30, s31, s32, s33,
    	s40, s41, s42, s43,
    	s50, s51, s52, s53,
    	s60, s61, s62, s63,
    	s70, s71, s72, s73,
    	tmp0, tmp1, tmp2, tmp3,
    	tmp4, tmp5, tmp6, tmp7);
	}

    InvReorderState();

}