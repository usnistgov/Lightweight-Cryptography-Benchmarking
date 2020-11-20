/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * load * AC(c0 c1) ^ TK3
 * calc AC(c0 c1) ^ TK2 -> store
 * ART(TK2)
 *
 * number of rounds : 40 or 56
 */

#include "skinny.h"

#define PERMUTATION_TK2()                                                         \
                                                                                  \
  /* permutation */                                                               \
                                                                                  \
    PERMUTATION()                                                                 \
                                                                                  \
  /* LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x5) */   \
    w0 = ((w0 << 1) & 0xfefefefe) ^                                               \
         (((w0 >> 7) ^ (w0 >> 5)) & 0x01010101);                                  \
    w1 = ((w1 << 1) & 0xfefefefe) ^                                               \
         (((w1 >> 7) ^ (w1 >> 5)) & 0x01010101);                                  \
                                                                                  \
  /* Load TK3 */                                                                  \
  /* TK2^TK3^AC(c0 c1) */                                                         \
  /* store */                                                                     \
    *tk2++ = w0 ^ *tk3++;                                                         \
    *tk2++ = w1 ^ *tk3++;                                                         \
    tk2 += 2;                                                                     \
    tk3 += 2;

#ifndef ___SKINNY_LOOP

void RunEncryptionKeyScheduleTK2(uint32_t *roundKeys)
{
  uint32_t* tk2;  // used in MACRO
  uint32_t* tk3;  // used in MACRO
  uint32_t t0;    // used in MACRO
  uint32_t t1;    // used in MACRO
  uint32_t t2;    // used in MACRO
  uint32_t w0;
  uint32_t w1;

  // odd
  
  // load master key
  w0 = roundKeys[4];
  w1 = roundKeys[5];

  tk2 = &roundKeys[16];
#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[96];
#else
  tk3 = &roundKeys[128];
#endif

  // 1st round
  *tk2++ = w0 ^ *tk3++;
  *tk2++ = w1 ^ *tk3++;

  tk2 += 2;
  tk3 += 2;

  // 3rd,5th, ... ,37th,39th round
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();

  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();

#ifdef ___NUM_OF_ROUNDS_56

  // 41th,43th, ... ,51th,53th round
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();

#endif

  // even

  // load master key
  w0 = roundKeys[6];
  w1 = roundKeys[7];

  tk2 = &roundKeys[18];
#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[98];
#else
  tk3 = &roundKeys[130];
#endif

  // 2nd,4th, ... ,54th,56th round
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();

  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();

#ifdef ___NUM_OF_ROUNDS_56

  // 42nd,44th, ... ,54th,56th round
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();
  PERMUTATION_TK2();

#endif

}

#else

void RunEncryptionKeyScheduleTK2(uint32_t *roundKeys)
{
  uint32_t* tk2;  // used in MACRO
  uint32_t* tk3;  // used in MACRO
  uint32_t t0;    // used in MACRO
  uint32_t t1;    // used in MACRO
  uint32_t t2;    // used in MACRO
  uint32_t w0;
  uint32_t w1;

  // odd

  // load master key
  w0 = roundKeys[4];
  w1 = roundKeys[5];

  tk2 = &roundKeys[16];
#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[96];
#else
  tk3 = &roundKeys[128];
#endif

  // 1st round
  *tk2++ = w0 ^ *tk3++;
  *tk2++ = w1 ^ *tk3++;

  tk2 += 2;
  tk3 += 2;

  // 3rd,5th, ...
#ifndef ___NUM_OF_ROUNDS_56
  for(int i=0;i<19;i++)
#else
  for(int i=0;i<27;i++)
#endif
  {
    PERMUTATION_TK2();
  }

  // even

  // load master key
  w0 = roundKeys[6];
  w1 = roundKeys[7];

  tk2 = &roundKeys[18];
#ifndef ___NUM_OF_ROUNDS_56
  tk3 = &roundKeys[98];
#else
  tk3 = &roundKeys[130];
#endif

  // 2nd,4th, ...
#ifndef ___NUM_OF_ROUNDS_56
  for(int i=0;i<20;i++)
#else
  for(int i=0;i<28;i++)
#endif
  {
    PERMUTATION_TK2();
  }

}

#endif
