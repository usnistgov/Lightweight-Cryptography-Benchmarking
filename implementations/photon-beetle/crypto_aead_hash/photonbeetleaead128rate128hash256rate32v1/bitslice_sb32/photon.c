#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "photon.h"

#define S 4
#define WORDFILTER 0xF

static const uint32_t RC[12][2 * 4] = {
{0x00000001U, 0x01010000U, 0x01000000U, 0x00000000U, 0x01010100U, 0x00000101U, 0x00010101U, 0x01010101U},
{0x00000001U, 0x00000101U, 0x01000000U, 0x00000000U, 0x01010100U, 0x01010000U, 0x00010101U, 0x01010101U},
{0x00000001U, 0x00000101U, 0x00010101U, 0x00000000U, 0x01010100U, 0x01010000U, 0x01000000U, 0x01010101U},
{0x01010100U, 0x00000101U, 0x00010101U, 0x01010101U, 0x00000001U, 0x01010000U, 0x01000000U, 0x00000000U},
{0x00000001U, 0x01010000U, 0x00010101U, 0x01010101U, 0x01010100U, 0x00000101U, 0x01000000U, 0x00000000U},
{0x00000001U, 0x00000101U, 0x01000000U, 0x01010101U, 0x01010100U, 0x01010000U, 0x00010101U, 0x00000000U},
{0x01010100U, 0x00000101U, 0x00010101U, 0x00000000U, 0x00000001U, 0x01010000U, 0x01000000U, 0x01010101U},
{0x01010100U, 0x01010000U, 0x00010101U, 0x01010101U, 0x00000001U, 0x00000101U, 0x01000000U, 0x00000000U},
{0x00000001U, 0x01010000U, 0x01000000U, 0x01010101U, 0x01010100U, 0x00000101U, 0x00010101U, 0x00000000U},
{0x01010100U, 0x00000101U, 0x01000000U, 0x00000000U, 0x00000001U, 0x01010000U, 0x00010101U, 0x01010101U},
{0x00000001U, 0x01010000U, 0x00010101U, 0x00000000U, 0x01010100U, 0x00000101U, 0x01000000U, 0x01010101U},
{0x01010100U, 0x00000101U, 0x01000000U, 0x01010101U, 0x00000001U, 0x01010000U, 0x00010101U, 0x00000000U}
};

#define CPY(x0, x1) (x0 = x1)
#define NOT(x0, x1) (x0 = ~x1)
#define XOR(x0, x1, x2) (x0 = x1 ^ x2)
#define AND(x0, x1, x2) (x0 = x1 & x2)
#define  OR(x0, x1, x2) (x0 = x1 | x2)

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

#define AddKey(row0123_bit0, row0123_bit1, row0123_bit2, row0123_bit3, row4567_bit0, row4567_bit1, row4567_bit2, row4567_bit3, round) \
do { \
	row0123_bit0 ^= RC[round][0]; \
	row0123_bit1 ^= RC[round][1]; \
	row0123_bit2 ^= RC[round][2]; \
	row0123_bit3 ^= RC[round][3]; \
	row4567_bit0 ^= RC[round][4]; \
	row4567_bit1 ^= RC[round][5]; \
	row4567_bit2 ^= RC[round][6]; \
	row4567_bit3 ^= RC[round][7]; \
} while(0) ;

#define ROT8L_1_INPLACE(x) ((x) = ((x) >> 1) | ((x) << 7))
#define ROT8L_2_INPLACE(x) ((x) = ((x) >> 2) | ((x) << 6))
#define ROT8L_3_INPLACE(x) ((x) = ((x) >> 3) | ((x) << 5))
#define ROT8L_4_INPLACE(x) ((x) = ((x) >> 4) | ((x) << 4))
#define ROT8L_5_INPLACE(x) ((x) = ((x) >> 5) | ((x) << 3))
#define ROT8L_6_INPLACE(x) ((x) = ((x) >> 6) | ((x) << 2))
#define ROT8L_7_INPLACE(x) ((x) = ((x) >> 7) | ((x) << 1))

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


#define InsertBytesWord(byte0, byte1, byte2, byte3, word0) \
do { \
    word0  =  (uint32_t)byte0; \
    word0 |= ((uint32_t)byte1 <<  8); \
    word0 |= ((uint32_t)byte2 << 16); \
    word0 |= ((uint32_t)byte3 << 24); \
} while(0);

#define InsertBytesWords_State(\
    x00, x01, x02, x03,  \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    row0123_nb0, row0123_nb1, row0123_nb2, row0123_nb3, \
    row4567_nb0, row4567_nb1, row4567_nb2, row4567_nb3) \
do { \
    InsertBytesWord(x00, x10, x20, x30, row0123_nb0) \
    InsertBytesWord(x01, x11, x21, x31, row0123_nb1) \
    InsertBytesWord(x02, x12, x22, x32, row0123_nb2) \
    InsertBytesWord(x03, x13, x23, x33, row0123_nb3) \
    InsertBytesWord(x40, x50, x60, x70, row4567_nb0) \
    InsertBytesWord(x41, x51, x61, x71, row4567_nb1) \
    InsertBytesWord(x42, x52, x62, x72, row4567_nb2) \
    InsertBytesWord(x43, x53, x63, x73, row4567_nb3) \
} while(0);

/**
x0 = row0_3 row0_2 row0_1 row0_0 => row1_1 row1_0 row0_1 row0_0 => row1_1 row0_1 row1_0 row0_0 => row3_0 row2_0 row1_0 row0_0
x1 = row1_3 row1_2 row1_1 row1_0 => row1_3 row1_2 row0_3 row0_2 => row1_3 row0_3 row1_2 row0_2 => row3_2 row2_2 row1_2 row0_2
x2 = row2_3 row2_2 row2_1 row2_0 => row3_1 row3_0 row2_1 row2_0 => row3_1 row2_1 row3_0 row2_0 => row3_1 row2_1 row1_1 row0_1
x3 = row3_3 row3_2 row3_1 row3_0 => row3_3 row3_2 row2_3 row2_2 => row3_3 row2_3 row3_2 row2_2 => row3_3 row2_3 row1_3 row0_3

x0 = row3_0 row2_0 row1_0 row0_0
x1 = row3_1 row2_1 row1_1 row0_1
x2 = row3_2 row2_2 row1_2 row0_2
x3 = row3_3 row2_3 row1_3 row0_3
**/
#define InterleaveByteWords(x0, x1, x2, x3, t) \
do { \
t = (x0 ^ (x1 << 16)) & 0xFFFF0000; x0 = x0 ^ t; x1 = x1 ^ (t >> 16);\
t = (x2 ^ (x3 << 16)) & 0xFFFF0000; x2 = x2 ^ t; x3 = x3 ^ (t >> 16);\
t = (x0 ^ (x0 >>  8)) & 0x0000FF00; x0 = x0 ^ t ^ (t << 8);\
t = (x1 ^ (x1 >>  8)) & 0x0000FF00; x1 = x1 ^ t ^ (t << 8);\
t = (x2 ^ (x2 >>  8)) & 0x0000FF00; x2 = x2 ^ t ^ (t << 8);\
t = (x3 ^ (x3 >>  8)) & 0x0000FF00; x3 = x3 ^ t ^ (t << 8);\
t = (x0 ^ (x2 << 16)) & 0xFFFF0000; x0 = x0 ^ t; x2 = x2 ^ (t >> 16);\
t = (x1 ^ (x3 << 16)) & 0xFFFF0000; x1 = x1 ^ t; x3 = x3 ^ (t >> 16);\
t = x1;\
x1 = x2;\
x2 = t;\
} while(0);

#define ExtractBytesWord(byte0, byte1, byte2, byte3, word0) \
do { \
    byte0 = (uint8_t)( word0 & 0xFF); \
    byte1 = (uint8_t)((word0 >>  8) & 0xFF); \
    byte2 = (uint8_t)((word0 >> 16) & 0xFF); \
    byte3 = (uint8_t)((word0 >> 24) & 0xFF); \
} while(0);

#define ExtractBytesWords_State(\
    x00, x01, x02, x03,  \
    x10, x11, x12, x13,  \
    x20, x21, x22, x23,  \
    x30, x31, x32, x33,  \
    x40, x41, x42, x43,  \
    x50, x51, x52, x53,  \
    x60, x61, x62, x63,  \
    x70, x71, x72, x73,  \
    row0123_nb0, row0123_nb1, row0123_nb2, row0123_nb3, \
    row4567_nb0, row4567_nb1, row4567_nb2, row4567_nb3) \
do { \
    ExtractBytesWord(x00, x10, x20, x30, row0123_nb0) \
    ExtractBytesWord(x01, x11, x21, x31, row0123_nb1) \
    ExtractBytesWord(x02, x12, x22, x32, row0123_nb2) \
    ExtractBytesWord(x03, x13, x23, x33, row0123_nb3) \
    ExtractBytesWord(x40, x50, x60, x70, row4567_nb0) \
    ExtractBytesWord(x41, x51, x61, x71, row4567_nb1) \
    ExtractBytesWord(x42, x52, x62, x72, row4567_nb2) \
    ExtractBytesWord(x43, x53, x63, x73, row4567_nb3) \
} while(0);

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

#define ReorderState(row0, row1, row2, row3, row4, row5, row6, row7, wtmp0, wtmp1) \
do { \
    row0 = ((uint32_t *)State_in)[0]; ReorderWord(row0, wtmp0); \
    row1 = ((uint32_t *)State_in)[1]; ReorderWord(row1, wtmp1); \
    row2 = ((uint32_t *)State_in)[2]; ReorderWord(row2, wtmp0); \
    row3 = ((uint32_t *)State_in)[3]; ReorderWord(row3, wtmp1); \
    row4 = ((uint32_t *)State_in)[4]; ReorderWord(row4, wtmp0); \
    row5 = ((uint32_t *)State_in)[5]; ReorderWord(row5, wtmp1); \
    row6 = ((uint32_t *)State_in)[6]; ReorderWord(row6, wtmp0); \
    row7 = ((uint32_t *)State_in)[7]; ReorderWord(row7, wtmp1); \
    InterleaveByteWords(row0, row1, row2, row3, wtmp0) \
    InterleaveByteWords(row4, row5, row6, row7, wtmp1) \
} while (0);

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

#define InvReorderState( \
    row0123_nb0, row0123_nb1, row0123_nb2, row0123_nb3,\
    row4567_nb0, row4567_nb1, row4567_nb2, row4567_nb3, wtmp0, wtmp1) \
do { \
    InterleaveByteWords(row0123_nb0, row0123_nb1, row0123_nb2, row0123_nb3, wtmp0) \
    InterleaveByteWords(row4567_nb0, row4567_nb1, row4567_nb2, row4567_nb3, wtmp1) \
    InvReorderWord(row0123_nb0, wtmp0); ((uint32_t *)State_in)[0] = row0123_nb0; \
    InvReorderWord(row0123_nb1, wtmp1); ((uint32_t *)State_in)[1] = row0123_nb1; \
    InvReorderWord(row0123_nb2, wtmp0); ((uint32_t *)State_in)[2] = row0123_nb2; \
    InvReorderWord(row0123_nb3, wtmp1); ((uint32_t *)State_in)[3] = row0123_nb3; \
    InvReorderWord(row4567_nb0, wtmp0); ((uint32_t *)State_in)[4] = row4567_nb0; \
    InvReorderWord(row4567_nb1, wtmp1); ((uint32_t *)State_in)[5] = row4567_nb1; \
    InvReorderWord(row4567_nb2, wtmp0); ((uint32_t *)State_in)[6] = row4567_nb2; \
    InvReorderWord(row4567_nb3, wtmp1); ((uint32_t *)State_in)[7] = row4567_nb3; \
} while (0);

void PHOTON_Permutation(unsigned char *State_in)
{
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
    uint32_t wtmp0, wtmp1;
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

    int i;

    ReorderState(w0, w1, w2, w3, w4, w5, w6, w7, wtmp0, wtmp1);

	for(i = 0; i < ROUND; i++)
	{
		AddKey(w0, w1, w2, w3, w4, w5, w6, w7, i)

		SBox(w0, w1, w2, w3, wtmp0, wtmp1);
        SBox(w4, w5, w6, w7, wtmp0, wtmp1);

        ExtractBytesWords_State(
        s00, s01, s02, s03,  
        s10, s11, s12, s13,  
        s20, s21, s22, s23,  
        s30, s31, s32, s33,  
        s40, s41, s42, s43,  
        s50, s51, s52, s53,  
        s60, s61, s62, s63,  
        s70, s71, s72, s73,  
        w0, w1, w2, w3, 
        w4, w5, w6, w7) 

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

        InsertBytesWords_State(
        s00, s01, s02, s03,
        s10, s11, s12, s13,
        s20, s21, s22, s23,
        s30, s31, s32, s33,
        s40, s41, s42, s43,
        s50, s51, s52, s53,
        s60, s61, s62, s63,
        s70, s71, s72, s73,
        w0, w1, w2, w3,
        w4, w5, w6, w7)
	}

    InvReorderState(w0, w1, w2, w3, w4, w5, w6, w7, wtmp0, wtmp1);
}