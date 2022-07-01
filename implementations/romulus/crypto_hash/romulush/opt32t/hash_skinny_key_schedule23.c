/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * TK2 ^ TK3 ^ AC(c0 c1) -> store
 * ART(TK2)
 * ART(TK3)
 *
 * number of rounds : 40 or 56
 */

#include "hash_skinny.h"

#define PERMUTATION_TK23(c0Val, c1Val)                                            \
                                                                                  \
  /* permutation (TK2) */                                                         \
                                                                                  \
    PERMUTATION(tk20, tk21)                                                       \
                                                                                  \
  /* LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x5) */   \
    tk20 = ((tk20 << 1) & 0xfefefefe) ^                                           \
           (((tk20 >> 7) ^ (tk20 >> 5)) & 0x01010101);                            \
    tk21 = ((tk21 << 1) & 0xfefefefe) ^                                           \
           (((tk21 >> 7) ^ (tk21 >> 5)) & 0x01010101);                            \
                                                                                  \
  /* permutation (TK3) */                                                         \
                                                                                  \
    PERMUTATION(tk30, tk31)                                                       \
                                                                                  \
  /* LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x3 x2 x1) */   \
    tk30 = ((tk30 >> 1) & 0x7f7f7f7f) ^                                           \
           (((tk30 << 7) ^ (tk30 << 1)) & 0x80808080);                            \
    tk31 = ((tk31 >> 1) & 0x7f7f7f7f) ^                                           \
           (((tk31 << 7) ^ (tk31 << 1)) & 0x80808080);                            \
                                                                                  \
  /* TK2 ^ TK3 ^ AC(c0 c1) */                                                     \
  /* store */                                                                     \
    *tk2++ = tk20 ^ tk30 ^ c0Val;                                                 \
    *tk2++ = tk21 ^ tk31 ^ ((uint32_t)c1Val << 8);                                \
    tk2 += 2;

#ifndef ___SKINNY_LOOP

void hash_RunEncryptionKeyScheduleTK23(uint32_t *roundKeys)
{
  uint32_t *tk2;
  uint32_t t0;         // used in MACRO
  uint32_t t1;         // used in MACRO
  uint32_t t2;         // used in MACRO
  uint32_t tk20;
  uint32_t tk21;
  uint32_t tk30;
  uint32_t tk31;

  // odd

  // load master key
  tk20 = roundKeys[4];
  tk21 = roundKeys[5];
  tk30 = roundKeys[8];
  tk31 = roundKeys[9];

  tk2 = &roundKeys[32];

  // 1st round
  *tk2++ = tk20 ^ tk30 ^ 0x01;
  *tk2++ = tk21 ^ tk31;
  tk2 += 2;

  // 3rd,5th, ... ,37th,39th round
  PERMUTATION_TK23(0x7, 0x0);
  PERMUTATION_TK23(0xf, 0x1);
  PERMUTATION_TK23(0xd, 0x3);
  PERMUTATION_TK23(0x7, 0x3);
  PERMUTATION_TK23(0xe, 0x1);
  PERMUTATION_TK23(0x9, 0x3);
  PERMUTATION_TK23(0x7, 0x2);
  PERMUTATION_TK23(0xd, 0x1);
  PERMUTATION_TK23(0x5, 0x3);

  PERMUTATION_TK23(0x6, 0x1);
  PERMUTATION_TK23(0x8, 0x1);
  PERMUTATION_TK23(0x1, 0x2);
  PERMUTATION_TK23(0x5, 0x0);
  PERMUTATION_TK23(0x7, 0x1);
  PERMUTATION_TK23(0xc, 0x1);
  PERMUTATION_TK23(0x1, 0x3);
  PERMUTATION_TK23(0x6, 0x0);
  PERMUTATION_TK23(0xb, 0x1);
  PERMUTATION_TK23(0xd, 0x2);

#ifdef ___NUM_OF_ROUNDS_56

  // 41td,43th, ... ,53th,55th round
  PERMUTATION_TK23(0x4, 0x3);
  PERMUTATION_TK23(0x2, 0x1);
  PERMUTATION_TK23(0x8, 0x0);
  PERMUTATION_TK23(0x2, 0x2);
  PERMUTATION_TK23(0x9, 0x0);
  PERMUTATION_TK23(0x6, 0x2);
  PERMUTATION_TK23(0x9, 0x1);
  PERMUTATION_TK23(0x5, 0x2);

#endif

  // even

  // load master key
  tk20 = roundKeys[6];
  tk21 = roundKeys[7];
  tk30 = roundKeys[10];
  tk31 = roundKeys[11];

  tk2 = &roundKeys[34];

  // 2nd,4th, ... ,38th,40th round
  PERMUTATION_TK23(0x3, 0x0);
  PERMUTATION_TK23(0xf, 0x0);
  PERMUTATION_TK23(0xe, 0x3);
  PERMUTATION_TK23(0xb, 0x3);
  PERMUTATION_TK23(0xf, 0x2);
  PERMUTATION_TK23(0xc, 0x3);
  PERMUTATION_TK23(0x3, 0x3);
  PERMUTATION_TK23(0xe, 0x0);
  PERMUTATION_TK23(0xa, 0x3);
  PERMUTATION_TK23(0xb, 0x2);

  PERMUTATION_TK23(0xc, 0x2);
  PERMUTATION_TK23(0x0, 0x3);
  PERMUTATION_TK23(0x2, 0x0);
  PERMUTATION_TK23(0xb, 0x0);
  PERMUTATION_TK23(0xe, 0x2);
  PERMUTATION_TK23(0x8, 0x3);
  PERMUTATION_TK23(0x3, 0x2);
  PERMUTATION_TK23(0xd, 0x0);
  PERMUTATION_TK23(0x6, 0x3);
  PERMUTATION_TK23(0xa, 0x1);

#ifdef ___NUM_OF_ROUNDS_56

  // 42nd,44th, ... ,54th,56th round
  PERMUTATION_TK23(0x9, 0x2);
  PERMUTATION_TK23(0x4, 0x2);
  PERMUTATION_TK23(0x1, 0x1);
  PERMUTATION_TK23(0x4, 0x0);
  PERMUTATION_TK23(0x3, 0x1);
  PERMUTATION_TK23(0xc, 0x0);
  PERMUTATION_TK23(0x2, 0x3);
  PERMUTATION_TK23(0xa, 0x0);

#endif

}

#else

void hash_RunEncryptionKeyScheduleTK23(uint32_t *roundKeys, unsigned char *pRC)
{

  uint32_t *tk2;
  uint32_t t0;         // used in MACRO
  uint32_t t1;         // used in MACRO
  uint32_t t2;         // used in MACRO
  uint32_t tk20;
  uint32_t tk21;
  uint32_t tk30;
  uint32_t tk31;
  uint16_t c0;
  uint16_t c1;

  // odd

  // load master key
  tk20 = roundKeys[4];
  tk21 = roundKeys[5];
  tk30 = roundKeys[8];
  tk31 = roundKeys[9];

  tk2 = &roundKeys[32];

  // 1st round
  *tk2++ = tk20 ^ tk30 ^ 0x01;
  *tk2++ = tk21 ^ tk31;
  tk2 += 2;

  pRC += 4;
  // 3rd,5th, ...
#ifndef ___NUM_OF_ROUNDS_56
  for(int i=0;i<19;i++)
#else
  for(int i=0;i<27;i++)
#endif
  {
    c0 = *pRC++;
    c1 = *pRC++;
    pRC += 2;
    PERMUTATION_TK23(c0, c1);
  }

  // even

  // load master key
  tk20 = roundKeys[6];
  tk21 = roundKeys[7];
  tk30 = roundKeys[10];
  tk31 = roundKeys[11];

  tk2 = &roundKeys[34];
#ifndef ___NUM_OF_ROUNDS_56
  pRC -= 78;
#else
  pRC -= 110;
#endif

  // 2nd,4th, ...
#ifndef ___NUM_OF_ROUNDS_56
  for(int i=0;i<20;i++)
#else
  for(int i=0;i<28;i++)
#endif
  {
    c0 = *pRC++;
    c1 = *pRC++;
    pRC += 2;
    PERMUTATION_TK23(c0, c1);
  }

}

#endif
