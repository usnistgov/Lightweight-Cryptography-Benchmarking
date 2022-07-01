/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * ART(TK1) -> store
 * load AC(c0 c1) ^ TK3 ^ TK2
 * load TK1
 * calc AC(c0 c1) ^ TK3 ^ TK2 ^ TK1 -> use at (AC->ART)
 * SC->SR->(AC->ART)->MC
 *
 * number of rounds : 40 or 56
 */

#include "skinny.h"

/*
 * S-BOX
 */
unsigned char SBOX[]
= {
    // Original
    0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
    0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
    0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
    0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
    0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
    0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
    0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
    0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
    0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
    0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
    0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
    0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
    0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
    0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
    0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
    0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff,
};

 /*
 * S-BOX ^ AC(c2)
 */
unsigned char SBOX2[]
= {   // Original ^ c2(0x02)
    0x67, 0x4e, 0x68, 0x40, 0x49, 0x61, 0x41, 0x69, 0x57, 0x77, 0x58, 0x78, 0x51, 0x71, 0x59, 0x79,
    0x37, 0x8e, 0x38, 0x83, 0x8b, 0x31, 0x82, 0x39, 0x97, 0x27, 0x9a, 0x28, 0x92, 0x21, 0x9b, 0x29,
    0xe7, 0xce, 0xea, 0xc3, 0xcb, 0xe2, 0xc2, 0xeb, 0xd7, 0xf7, 0xda, 0xfa, 0xd2, 0xf2, 0xdb, 0xfb,
    0xa7, 0x1e, 0xaa, 0x10, 0x19, 0xa2, 0x11, 0xab, 0x07, 0xb7, 0x08, 0xba, 0x01, 0xb2, 0x09, 0xbb,
    0x30, 0x8a, 0x3e, 0x87, 0x8f, 0x36, 0x86, 0x3f, 0x93, 0x20, 0x9e, 0x2e, 0x96, 0x26, 0x9f, 0x2f,
    0x60, 0x48, 0x6e, 0x47, 0x4f, 0x66, 0x46, 0x6f, 0x50, 0x70, 0x5e, 0x7e, 0x56, 0x76, 0x5f, 0x7f,
    0xa3, 0x18, 0xae, 0x17, 0x1f, 0xa6, 0x16, 0xaf, 0x00, 0xb3, 0x0e, 0xbe, 0x06, 0xb6, 0x0f, 0xbf,
    0xe3, 0xca, 0xee, 0xc7, 0xcf, 0xe6, 0xc6, 0xef, 0xd3, 0xf3, 0xde, 0xfe, 0xd6, 0xf6, 0xdf, 0xff,
    0x34, 0x8c, 0x3a, 0x80, 0x89, 0x32, 0x81, 0x3b, 0x94, 0x24, 0x98, 0x2a, 0x91, 0x22, 0x99, 0x2b,
    0x64, 0x4c, 0x6a, 0x43, 0x4b, 0x62, 0x42, 0x6b, 0x54, 0x74, 0x5a, 0x7a, 0x52, 0x72, 0x5b, 0x7b,
    0xa4, 0x1c, 0xa8, 0x13, 0x1b, 0xa1, 0x12, 0xa9, 0x04, 0xb4, 0x0a, 0xb8, 0x02, 0xb1, 0x0b, 0xb9,
    0xe4, 0xcc, 0xe8, 0xc0, 0xc9, 0xe1, 0xc1, 0xe9, 0xd4, 0xf4, 0xd8, 0xf8, 0xd1, 0xf1, 0xd9, 0xf9,
    0x33, 0x88, 0x3c, 0x84, 0x8d, 0x35, 0x85, 0x3d, 0x90, 0x23, 0x9c, 0x2c, 0x95, 0x25, 0x9d, 0x2d,
    0x63, 0x4a, 0x6c, 0x44, 0x4d, 0x65, 0x45, 0x6d, 0x53, 0x73, 0x5c, 0x7c, 0x55, 0x75, 0x5d, 0x7d,
    0xa0, 0x1a, 0xac, 0x14, 0x1d, 0xa5, 0x15, 0xad, 0x03, 0xb0, 0x0c, 0xbc, 0x05, 0xb5, 0x0d, 0xbd,
    0xe0, 0xc8, 0xec, 0xc4, 0xcd, 0xe5, 0xc5, 0xed, 0xd0, 0xf0, 0xdc, 0xfc, 0xd5, 0xf5, 0xdd, 0xfd,
};

#ifdef ___SKINNY_LOOP
/*
 * Round Constants
 */
unsigned char RC[]
= {
    0x01, 0x00, 0x03, 0x00, 0x07, 0x00, 0x0f, 0x00, 0x0f, 0x01, 0x0e, 0x03, 0x0d, 0x03, 0x0b, 0x03,
    0x07, 0x03, 0x0f, 0x02, 0x0e, 0x01, 0x0c, 0x03, 0x09, 0x03, 0x03, 0x03, 0x07, 0x02, 0x0e, 0x00,
    0x0d, 0x01, 0x0a, 0x03, 0x05, 0x03, 0x0b, 0x02, 0x06, 0x01, 0x0c, 0x02, 0x08, 0x01, 0x00, 0x03,
    0x01, 0x02, 0x02, 0x00, 0x05, 0x00, 0x0b, 0x00, 0x07, 0x01, 0x0e, 0x02, 0x0c, 0x01, 0x08, 0x03,
    0x01, 0x03, 0x03, 0x02, 0x06, 0x00, 0x0d, 0x00, 0x0b, 0x01, 0x06, 0x03, 0x0d, 0x02, 0x0a, 0x01,
#ifdef ___NUM_OF_ROUNDS_56
    0x04, 0x03, 0x09, 0x02, 0x02, 0x01, 0x04, 0x02, 0x08, 0x00, 0x01, 0x01, 0x02, 0x02, 0x04, 0x00,
    0x09, 0x00, 0x03, 0x01, 0x06, 0x02, 0x0c, 0x00, 0x09, 0x01, 0x02, 0x03, 0x05, 0x02, 0x0a, 0x00,
#endif
    };
#endif

extern void Encrypt(unsigned char *block, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2);
extern void RunEncryptionKeyScheduleTK2(uint32_t *roundKeys);
#ifdef ___SKINNY_LOOP
extern void RunEncryptionKeyScheduleTK3(uint32_t *roundKeys, unsigned char *pRC);
#else
extern void RunEncryptionKeyScheduleTK3(uint32_t *roundKeys);
#endif

void skinny_128_384_enc123_12 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
  uint32_t *pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
  pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
  pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

  pack_word(T[0],  T[1],  T[2],  T[3],  pt[4]);
  pack_word(T[7],  T[4],  T[5],  T[6],  pt[5]);
  pack_word(T[8],  T[9],  T[10], T[11], pt[6]);
  pack_word(T[15], T[12], T[13], T[14], pt[7]);

  pack_word(K[0],  K[1],  K[2],  K[3],  pt[8]);
  pack_word(K[7],  K[4],  K[5],  K[6],  pt[9]);
  pack_word(K[8],  K[9],  K[10], K[11], pt[10]);
  pack_word(K[15], K[12], K[13], K[14], pt[11]);
#else
  pt[0] = *(uint32_t*)(&CNT[0]);
  pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

  pt[4] = *(uint32_t*)(&T[0]);
  pack_word(T[7],  T[4],  T[5],  T[6],  pt[5]);
  pt[6] = *(uint32_t*)(&T[8]);
  pack_word(T[15], T[12], T[13], T[14], pt[7]);

  pt[8] = *(uint32_t*)(&K[0]);
  pack_word(K[7],  K[4],  K[5],  K[6],  pt[9]);
  pt[10] = *(uint32_t*)(&K[8]);
  pack_word(K[15], K[12], K[13], K[14], pt[11]);
#endif

#ifdef ___SKINNY_LOOP
  RunEncryptionKeyScheduleTK3(pskinny_ctrl->roundKeys, RC);
#else
  RunEncryptionKeyScheduleTK3(pskinny_ctrl->roundKeys);
#endif
  RunEncryptionKeyScheduleTK2(pskinny_ctrl->roundKeys);
  Encrypt(input, pskinny_ctrl->roundKeys, SBOX, SBOX2);

  pskinny_ctrl->func_skinny_128_384_enc = skinny_128_384_enc12_12;

}

void skinny_128_384_enc12_12 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
  (void)K;

  uint32_t *pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
  pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
  pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

  pack_word(T[0],  T[1],  T[2],  T[3],  pt[4]);
  pack_word(T[7],  T[4],  T[5],  T[6],  pt[5]);
  pack_word(T[8],  T[9],  T[10], T[11], pt[6]);
  pack_word(T[15], T[12], T[13], T[14], pt[7]);
#else
  pt[0] = *(uint32_t*)(&CNT[0]);
  pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

  pt[4] = *(uint32_t*)(&T[0]);
  pack_word(T[7],  T[4],  T[5],  T[6],  pt[5]);
  pt[6] = *(uint32_t*)(&T[8]);
  pack_word(T[15], T[12], T[13], T[14], pt[7]);
#endif

  RunEncryptionKeyScheduleTK2(pskinny_ctrl->roundKeys);
  Encrypt(input, pskinny_ctrl->roundKeys, SBOX, SBOX2);

}

extern void skinny_128_384_enc1_1 (unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
  (void)T;
  (void)K;

  uint32_t *pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
  pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
  pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);
#else
  pt[0] = *(uint32_t*)(&CNT[0]);
  pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);
#endif

  Encrypt(input, pskinny_ctrl->roundKeys, SBOX, SBOX2);

}

#define PERMUTATION_TK1()                                                         \
/* permutation */                                                                 \
                                                                                  \
  PERMUTATION();                                                                  \
                                                                                  \
  /* store */                                                                     \
                                                                                  \
  *tk1++ = w0;                                                                    \
  *tk1++ = w1;

#define SBOX_0(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox[t0];                                                                  \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0)       ^                                                                \
      (t1 << 8)  ^                                                                \
      (t2 << 16) ^                                                                \
      (t3 << 24);

#define SBOX_8(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox[t0];                                                                  \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0 << 8)  ^                                                                \
      (t1 << 16) ^                                                                \
      (t2 << 24) ^                                                                \
      (t3);

#define SBOX_16(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox2[t0];  /* AC(c2) */                                                   \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0 << 16) ^                                                                \
      (t1 << 24) ^                                                                \
      (t2)       ^                                                                \
      (t3 << 8);

#define SBOX_24(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox[t0];                                                                  \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0 << 24) ^                                                                \
      (t1)       ^                                                                \
      (t2 << 8)  ^                                                                \
      (t3 << 16);

#define SKINNY_MAIN()                                                             \
                                                                                  \
  /* odd */                                                                       \
                                                                                  \
  /*  LUT(with ShiftRows) */                                                      \
                                                                                  \
    SBOX_0(w0);                                                                   \
    SBOX_8(w1);                                                                   \
    SBOX_16(w2);                                                                  \
    SBOX_24(w3);                                                                  \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* Load TK1 */                                                                  \
                                                                                  \
    w0 ^= *tk1++;                                                                 \
    w1 ^= *tk1++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;                                                                      \
                                                                                  \
  /* even */                                                                      \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    SBOX_0(w0);                                                                   \
    SBOX_8(w1);                                                                   \
    SBOX_16(w2);                                                                  \
    SBOX_24(w3);                                                                  \
                                                                                  \
  /* Load TK2^TK3^AC(c0 c1) */                                                    \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;

#ifndef ___SKINNY_LOOP

void Encrypt(unsigned char *block, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2)
{
  uint32_t *tk1;
  uint32_t *tk2;
  uint32_t t0;          // used in MACRO
  uint32_t t1;          // used in MACRO
  uint32_t t2;          // used in MACRO
  uint32_t t3;          // used in MACRO
  uint32_t w0;
  uint32_t w1;
  uint32_t w2;
  uint32_t w3;

// TK1

  // load master key
  w0 = roundKeys[0];
  w1 = roundKeys[1];

  // 1st round
  // not need to store

  tk1 = &roundKeys[2];

  // 2nd, ... ,8th round
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();

// SB+AC+ShR+MC

#ifndef ___ENABLE_WORD_CAST
  pack_word(block[0],  block[1],  block[2],  block[3],  w0);
  pack_word(block[4],  block[5],  block[6],  block[7],  w1);
  pack_word(block[8],  block[9],  block[10], block[11], w2);
  pack_word(block[12], block[13], block[14], block[15], w3);
#else
  w0 = *(uint32_t*)(&block[0]);
  w1 = *(uint32_t*)(&block[4]);
  w2 = *(uint32_t*)(&block[8]);
  w3 = *(uint32_t*)(&block[12]);
#endif

  tk2 = &roundKeys[16];
  tk1 = &roundKeys[0];

  // 1st, ...,16th round
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

  tk1 = &roundKeys[0];

  // 17th, ...,32th round
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

  tk1 = &roundKeys[0];

  // 33th, ...,40th round
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

#ifdef ___NUM_OF_ROUNDS_56

  // 41th, ...,48th round
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

  tk1 = &roundKeys[0];

  // 49th, ... ,56th round
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

#endif

#ifndef ___ENABLE_WORD_CAST
  unpack_word(block[0],  block[1],  block[2],  block[3],  w0);
  unpack_word(block[4],  block[5],  block[6],  block[7],  w1);
  unpack_word(block[8],  block[9],  block[10], block[11], w2);
  unpack_word(block[12], block[13], block[14], block[15], w3);
#else
  *(uint32_t*)(&block[0])  = w0;
  *(uint32_t*)(&block[4])  = w1;
  *(uint32_t*)(&block[8])  = w2;
  *(uint32_t*)(&block[12]) = w3;
#endif

}

#else

void Encrypt(unsigned char *block, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2)
{
  uint32_t *tk1;
  uint32_t *tk2;
  uint32_t t0;          // used in MACRO
  uint32_t t1;          // used in MACRO
  uint32_t t2;          // used in MACRO
  uint32_t t3;          // used in MACRO
  uint32_t w0;
  uint32_t w1;
  uint32_t w2;
  uint32_t w3;

// TK1

  // load master key
  w0 = roundKeys[0];
  w1 = roundKeys[1];

  // 1st round
  // not need to store

  tk1 = &roundKeys[2];

  // 2nd, ... ,8th round
  for(int i=0;i<7;i++)
  {
     PERMUTATION_TK1();
  }

// SB+AC+ShR+MC

#ifndef ___ENABLE_WORD_CAST
  pack_word(block[0],  block[1],  block[2],  block[3],  w0);
  pack_word(block[4],  block[5],  block[6],  block[7],  w1);
  pack_word(block[8],  block[9],  block[10], block[11], w2);
  pack_word(block[12], block[13], block[14], block[15], w3);
#else
  w0 = *(uint32_t*)(&block[0]);
  w1 = *(uint32_t*)(&block[4]);
  w2 = *(uint32_t*)(&block[8]);
  w3 = *(uint32_t*)(&block[12]);
#endif

  tk2 = &roundKeys[16];

  // 1st, ... ,32th or 48th round
#ifndef ___NUM_OF_ROUNDS_56
  for(int j=0;j<2;j++)
#else
  for(int j=0;j<3;j++)
#endif
  {
    tk1 = &roundKeys[0];
    for(int i=0;i<8;i++)
    {
      SKINNY_MAIN();
    }
  }

  // 33th , ... ,40th or 49th, .... ,56th round
  {
    tk1 = &roundKeys[0];
    for(int i=0;i<4;i++)
    {
      SKINNY_MAIN();
    }
  }
#ifndef ___ENABLE_WORD_CAST
  unpack_word(block[0],  block[1],  block[2],  block[3],  w0);
  unpack_word(block[4],  block[5],  block[6],  block[7],  w1);
  unpack_word(block[8],  block[9],  block[10], block[11], w2);
  unpack_word(block[12], block[13], block[14], block[15], w3);
#else
  *(uint32_t*)(&block[0])  = w0;
  *(uint32_t*)(&block[4])  = w1;
  *(uint32_t*)(&block[8])  = w2;
  *(uint32_t*)(&block[12]) = w3;
#endif

}

#endif
