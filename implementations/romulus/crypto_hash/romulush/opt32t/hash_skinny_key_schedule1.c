/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * T1 -> store
 * ART(TK1)
 *
 * number of rounds : 40 or 56
 */

#include "hash_skinny.h"

#define PERMUTATION_TK1()                                                         \
                                                                                  \
  /* permutation */                                                               \
                                                                                  \
    PERMUTATION(w0, w1)                                                           \
                                                                                  \
  /* store */                                                                     \
                                                                                  \
    *tk1++ = w0;                                                                  \
    *tk1++ = w1;                                                                  \
    tk1 += 2;

#ifndef ___SKINNY_LOOP

void hash_RunEncryptionKeyScheduleTK1(uint32_t *roundKeys)
{

  uint32_t *tk1;
  uint32_t t0;          // used in MACRO
  uint32_t t1;          // used in MACRO
  uint32_t t2;          // used in MACRO
  uint32_t w0;
  uint32_t w1;

  // odd

  // load master key
  w0 = roundKeys[0];
  w1 = roundKeys[1];

  // 1st round
  // not need to store

  tk1 = &roundKeys[4];

  // 3rd, ... ,15th round
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();

  // even

  tk1 = &roundKeys[2];

  // load master key
  w0 = roundKeys[2];
  w1 = roundKeys[3];

  // 2nd, ... ,16th round
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();
  PERMUTATION_TK1();

}

#else

void hash_RunEncryptionKeyScheduleTK1(uint32_t *roundKeys)
{

  uint32_t *tk1;
  uint32_t t0;          // used in MACRO
  uint32_t t1;          // used in MACRO
  uint32_t t2;          // used in MACRO
  uint32_t w0;
  uint32_t w1;

  // odd

  // load master key
  w0 = roundKeys[0];
  w1 = roundKeys[1];

  // 1st round
  // not need to store

  tk1 = &roundKeys[4];

  // 3rd, ... ,15th round
  for(int i=0;i<7;i++) {
    PERMUTATION_TK1();
  }

  // even

  tk1 = &roundKeys[2];

  // load master key
  w0 = roundKeys[2];
  w1 = roundKeys[3];

  // 2nd, ... ,16th round
  for(int i=0;i<8;i++) {
    PERMUTATION_TK1();
  }

}

#endif
