/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * AC(c0 c1) ^ TK3 -> store
 * ART(TK3)
 *
 * number of rounds : 40 or 56
 */

#include "skinny.h"

#define PERMUTATION_TK3(c0Val, c1Val)                                             \
                                                                                  \
  /* permutation */                                                               \
                                                                                  \
    PERMUTATION()                                                                 \
                                                                                  \
  /* LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x3 x2 x1) */   \
    w0 = ((w0 >> 1) & 0x7f7f7f7f) ^                                               \
         (((w0 << 7) ^ (w0 << 1)) & 0x80808080);                                  \
    w1 = ((w1 >> 1) & 0x7f7f7f7f) ^                                               \
         (((w1 << 7) ^ (w1 << 1)) & 0x80808080);                                  \
                                                                                  \
  /* K3^AC(c0 c1) */                                                              \
  /* store */                                                                     \
    *tk3++ = w0 ^ c0Val;                                                          \
    *tk3++ = w1 ^ c1Val;                                                          \
    tk3 += 2;

#ifndef ___SKINNY_LOOP

void RunEncryptionKeyScheduleTK3(uint32_t *roundKeys)
{
  uint32_t *tk3;
  uint32_t t0;         // used in MACRO
  uint32_t t1;         // used in MACRO
  uint32_t t2;         // used in MACRO
  uint32_t w0;
  uint32_t w1;

  // odd

  // load master key
  w0 = roundKeys[8];
  w1 = roundKeys[9];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[96];
#else
  tk3 = &roundKeys[128];
#endif

  // 1st round
  *tk3++ = w0 ^ 0x01;
  *tk3++ = w1;
  tk3 += 2;

  // 3rd,5th, ... ,37th,39th round
  PERMUTATION_TK3(0x7, 0x000);
  PERMUTATION_TK3(0xf, 0x100);
  PERMUTATION_TK3(0xd, 0x300);
  PERMUTATION_TK3(0x7, 0x300);
  PERMUTATION_TK3(0xe, 0x100);
  PERMUTATION_TK3(0x9, 0x300);
  PERMUTATION_TK3(0x7, 0x200);
  PERMUTATION_TK3(0xd, 0x100);
  PERMUTATION_TK3(0x5, 0x300);

  PERMUTATION_TK3(0x6, 0x100);
  PERMUTATION_TK3(0x8, 0x100);
  PERMUTATION_TK3(0x1, 0x200);
  PERMUTATION_TK3(0x5, 0x000);
  PERMUTATION_TK3(0x7, 0x100);
  PERMUTATION_TK3(0xc, 0x100);
  PERMUTATION_TK3(0x1, 0x300);
  PERMUTATION_TK3(0x6, 0x000);
  PERMUTATION_TK3(0xb, 0x100);
  PERMUTATION_TK3(0xd, 0x200);

#ifdef ___NUM_OF_ROUNDS_56

  // 41td,43th, ... ,53th,55th round
  PERMUTATION_TK3(0x4, 0x300);
  PERMUTATION_TK3(0x2, 0x100);
  PERMUTATION_TK3(0x8, 0x000);
  PERMUTATION_TK3(0x2, 0x200);
  PERMUTATION_TK3(0x9, 0x000);
  PERMUTATION_TK3(0x6, 0x200);
  PERMUTATION_TK3(0x9, 0x100);
  PERMUTATION_TK3(0x5, 0x200);

#endif

  // even

  // load master key
  w0 = roundKeys[10];
  w1 = roundKeys[11];


#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[98];
#else
  tk3 = &roundKeys[130];
#endif

  // 2nd,4th, ... ,38th,40th round
  PERMUTATION_TK3(0x3, 0x000);
  PERMUTATION_TK3(0xf, 0x000);
  PERMUTATION_TK3(0xe, 0x300);
  PERMUTATION_TK3(0xb, 0x300);
  PERMUTATION_TK3(0xf, 0x200);
  PERMUTATION_TK3(0xc, 0x300);
  PERMUTATION_TK3(0x3, 0x300);
  PERMUTATION_TK3(0xe, 0x000);
  PERMUTATION_TK3(0xa, 0x300);
  PERMUTATION_TK3(0xb, 0x200);

  PERMUTATION_TK3(0xc, 0x200);
  PERMUTATION_TK3(0x0, 0x300);
  PERMUTATION_TK3(0x2, 0x000);
  PERMUTATION_TK3(0xb, 0x000);
  PERMUTATION_TK3(0xe, 0x200);
  PERMUTATION_TK3(0x8, 0x300);
  PERMUTATION_TK3(0x3, 0x200);
  PERMUTATION_TK3(0xd, 0x000);
  PERMUTATION_TK3(0x6, 0x300);
  PERMUTATION_TK3(0xa, 0x100);

#ifdef ___NUM_OF_ROUNDS_56

  // 42nd,44th, ... ,54th,56th round
  PERMUTATION_TK3(0x9, 0x200);
  PERMUTATION_TK3(0x4, 0x200);
  PERMUTATION_TK3(0x1, 0x100);
  PERMUTATION_TK3(0x4, 0x000);
  PERMUTATION_TK3(0x3, 0x100);
  PERMUTATION_TK3(0xc, 0x000);
  PERMUTATION_TK3(0x2, 0x300);
  PERMUTATION_TK3(0xa, 0x000);

#endif

}

#else

void RunEncryptionKeyScheduleTK3(uint32_t *roundKeys, unsigned char *pRC)
{
  uint32_t *tk3;
  uint32_t t0;         // used in MACRO
  uint32_t t1;         // used in MACRO
  uint32_t t2;         // used in MACRO
  uint32_t w0;
  uint32_t w1;
  uint16_t c0;
  uint16_t c1;

  // odd
  
  // load master key
  w0 = roundKeys[8];
  w1 = roundKeys[9];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[96];
#else
  tk3 = &roundKeys[128];
#endif

  // 1st round
  *tk3++ = w0 ^ 0x01;
  *tk3++ = w1;
  tk3 += 2;

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
    c1 <<= 8;
    pRC += 2;
    PERMUTATION_TK3(c0, c1);
  }

  // even

  // load master key
  w0 = roundKeys[10];
  w1 = roundKeys[11];

#ifndef ___NUM_OF_ROUNDS_56
  pRC -= 78;
  tk3 = &roundKeys[98];
#else
  pRC -= 110;
  tk3 = &roundKeys[130];
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
    c1 <<= 8;
    pRC += 2;
    PERMUTATION_TK3(c0, c1);
  }

}

#endif
