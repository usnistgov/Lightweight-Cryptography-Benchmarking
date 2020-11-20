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

#ifdef ___ENABLE_DWORD_CAST

#define PERMUTATION_TK3(c0Val, c1Val)                                             \
                                                                                  \
  /* permutation */                                                               \
                                                                                  \
    PERMUTATION()                                                                 \
                                                                                  \
  /* LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x3 x2 x1) */   \
    dw = ((dw >> 1) & 0x7f7f7f7f7f7f7f7f) ^                                       \
         (((dw << 7) ^ (dw << 1)) & 0x8080808080808080);                          \
                                                                                  \
  /* K3^AC(c0 c1) */                                                              \
  /* store */                                                                     \
    dt0 = dw ^ c0Val;                                                             \
    *tk3 = dt0 ^ ((uint64_t)c1Val << 40);                                         \
    tk3 += 2;

#ifndef ___SKINNY_LOOP

void RunEncryptionKeyScheduleTK3(unsigned char *roundKeys)
{
  uint64_t *tk3;
  uint64_t dt0;         // used in MACRO
  uint64_t dt1;         // used in MACRO
  uint64_t dw;

  // odd

  // load master key
  dw = *(uint64_t*)&roundKeys[32];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = (uint64_t*)&roundKeys[384];
#else
  tk3 = (uint64_t*)&roundKeys[512];
#endif

  // 1st round
  *tk3++ = dw ^ 0x01;
  tk3 += 1;

  // 3rd,5th, ... ,37th,39th round
  PERMUTATION_TK3(0x7, 0x0);
  PERMUTATION_TK3(0xf, 0x1);
  PERMUTATION_TK3(0xd, 0x3);
  PERMUTATION_TK3(0x7, 0x3);
  PERMUTATION_TK3(0xe, 0x1);
  PERMUTATION_TK3(0x9, 0x3);
  PERMUTATION_TK3(0x7, 0x2);
  PERMUTATION_TK3(0xd, 0x1);
  PERMUTATION_TK3(0x5, 0x3);

  PERMUTATION_TK3(0x6, 0x1);
  PERMUTATION_TK3(0x8, 0x1);
  PERMUTATION_TK3(0x1, 0x2);
  PERMUTATION_TK3(0x5, 0x0);
  PERMUTATION_TK3(0x7, 0x1);
  PERMUTATION_TK3(0xc, 0x1);
  PERMUTATION_TK3(0x1, 0x3);
  PERMUTATION_TK3(0x6, 0x0);
  PERMUTATION_TK3(0xb, 0x1);
  PERMUTATION_TK3(0xd, 0x2);

#ifdef ___NUM_OF_ROUNDS_56

  // 41td,43th, ... ,53th,55th round
  PERMUTATION_TK3(0x4, 0x3);
  PERMUTATION_TK3(0x2, 0x1);
  PERMUTATION_TK3(0x8, 0x0);
  PERMUTATION_TK3(0x2, 0x2);
  PERMUTATION_TK3(0x9, 0x0);
  PERMUTATION_TK3(0x6, 0x2);
  PERMUTATION_TK3(0x9, 0x1);
  PERMUTATION_TK3(0x5, 0x2);

#endif

  // even

  // load master key
  dw = *(uint64_t*)&roundKeys[40];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = (uint64_t*)&roundKeys[392];
#else
  tk3 = (uint64_t*)&roundKeys[520];
#endif

  // 2nd,4th, ... ,38th,40th round
  PERMUTATION_TK3(0x3, 0x0);
  PERMUTATION_TK3(0xf, 0x0);
  PERMUTATION_TK3(0xe, 0x3);
  PERMUTATION_TK3(0xb, 0x3);
  PERMUTATION_TK3(0xf, 0x2);
  PERMUTATION_TK3(0xc, 0x3);
  PERMUTATION_TK3(0x3, 0x3);
  PERMUTATION_TK3(0xe, 0x0);
  PERMUTATION_TK3(0xa, 0x3);
  PERMUTATION_TK3(0xb, 0x2);

  PERMUTATION_TK3(0xc, 0x2);
  PERMUTATION_TK3(0x0, 0x3);
  PERMUTATION_TK3(0x2, 0x0);
  PERMUTATION_TK3(0xb, 0x0);
  PERMUTATION_TK3(0xe, 0x2);
  PERMUTATION_TK3(0x8, 0x3);
  PERMUTATION_TK3(0x3, 0x2);
  PERMUTATION_TK3(0xd, 0x0);
  PERMUTATION_TK3(0x6, 0x3);
  PERMUTATION_TK3(0xa, 0x1);

#ifdef ___NUM_OF_ROUNDS_56

  // 42nd,44th, ... ,54th,56th round
  PERMUTATION_TK3(0x9, 0x2);
  PERMUTATION_TK3(0x4, 0x2);
  PERMUTATION_TK3(0x1, 0x1);
  PERMUTATION_TK3(0x4, 0x0);
  PERMUTATION_TK3(0x3, 0x1);
  PERMUTATION_TK3(0xc, 0x0);
  PERMUTATION_TK3(0x2, 0x3);
  PERMUTATION_TK3(0xa, 0x0);

#endif

}

#else /* ___SKINNY_LOOP */

void RunEncryptionKeyScheduleTK3(unsigned char *roundKeys, unsigned char *pRC)
{
  uint64_t *tk3;
  uint64_t dt0;         // used in MACRO
  uint64_t dt1;         // used in MACRO
  uint64_t dw;
  uint64_t c0;
  uint64_t c1;

  // odd
  
  // load master key
  dw = *(uint64_t*)&roundKeys[32];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = (uint64_t*)&roundKeys[384];
#else
  tk3 = (uint64_t*)&roundKeys[512];
#endif

  // 1st round
  *tk3++ = dw ^ 0x01;
  tk3 += 1;

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
    PERMUTATION_TK3(c0, c1);
  }

  // even

  // load master key
  dw = *(uint64_t*)&roundKeys[40];

#ifndef ___NUM_OF_ROUNDS_56
  pRC -= 78;
  tk3 = (uint64_t*)&roundKeys[392];
#else
  pRC -= 110;
  tk3 = (uint64_t*)&roundKeys[520];
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
    PERMUTATION_TK3(c0, c1);
  }

}

#endif /* ___SKINNY_LOOP */

#else /* ___ENABLE_DWORD_CAST */

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
    *tk3++ = w1 ^ ((uint32_t)c1Val << 8);                                         \
    tk3 += 2;

#ifndef ___SKINNY_LOOP

void RunEncryptionKeyScheduleTK3(unsigned char *roundKeys)
{
  uint32_t *tk3;
  uint32_t t0;         // used in MACRO
  uint32_t t1;         // used in MACRO
  uint32_t t2;         // used in MACRO
  uint32_t w0;
  uint32_t w1;

  // odd
  
  // load master key
  w0 = *(uint32_t*)&roundKeys[32];
  w1 = *(uint32_t*)&roundKeys[36];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = (uint32_t*)&roundKeys[384];
#else
  tk3 = (uint32_t*)&roundKeys[512];
#endif

  // 1st round
  *tk3++ = w0 ^ 0x01;
  *tk3++ = w1;
  tk3 += 2;

  // 3rd,5th, ... ,37th,39th round
  PERMUTATION_TK3(0x7, 0x0);
  PERMUTATION_TK3(0xf, 0x1);
  PERMUTATION_TK3(0xd, 0x3);
  PERMUTATION_TK3(0x7, 0x3);
  PERMUTATION_TK3(0xe, 0x1);
  PERMUTATION_TK3(0x9, 0x3);
  PERMUTATION_TK3(0x7, 0x2);
  PERMUTATION_TK3(0xd, 0x1);
  PERMUTATION_TK3(0x5, 0x3);

  PERMUTATION_TK3(0x6, 0x1);
  PERMUTATION_TK3(0x8, 0x1);
  PERMUTATION_TK3(0x1, 0x2);
  PERMUTATION_TK3(0x5, 0x0);
  PERMUTATION_TK3(0x7, 0x1);
  PERMUTATION_TK3(0xc, 0x1);
  PERMUTATION_TK3(0x1, 0x3);
  PERMUTATION_TK3(0x6, 0x0);
  PERMUTATION_TK3(0xb, 0x1);
  PERMUTATION_TK3(0xd, 0x2);

#ifdef ___NUM_OF_ROUNDS_56

  // 41td,43th, ... ,53th,55th round
  PERMUTATION_TK3(0x4, 0x3);
  PERMUTATION_TK3(0x2, 0x1);
  PERMUTATION_TK3(0x8, 0x0);
  PERMUTATION_TK3(0x2, 0x2);
  PERMUTATION_TK3(0x9, 0x0);
  PERMUTATION_TK3(0x6, 0x2);
  PERMUTATION_TK3(0x9, 0x1);
  PERMUTATION_TK3(0x5, 0x2);

#endif

  // even

  // load master key
  w0 = *(uint32_t*)&roundKeys[40];
  w1 = *(uint32_t*)&roundKeys[44];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = (uint32_t*)&roundKeys[392];
#else
  tk3 = (uint32_t*)&roundKeys[520];
#endif

  // 2nd,4th, ... ,38th,40th round
  PERMUTATION_TK3(0x3, 0x0);
  PERMUTATION_TK3(0xf, 0x0);
  PERMUTATION_TK3(0xe, 0x3);
  PERMUTATION_TK3(0xb, 0x3);
  PERMUTATION_TK3(0xf, 0x2);
  PERMUTATION_TK3(0xc, 0x3);
  PERMUTATION_TK3(0x3, 0x3);
  PERMUTATION_TK3(0xe, 0x0);
  PERMUTATION_TK3(0xa, 0x3);
  PERMUTATION_TK3(0xb, 0x2);

  PERMUTATION_TK3(0xc, 0x2);
  PERMUTATION_TK3(0x0, 0x3);
  PERMUTATION_TK3(0x2, 0x0);
  PERMUTATION_TK3(0xb, 0x0);
  PERMUTATION_TK3(0xe, 0x2);
  PERMUTATION_TK3(0x8, 0x3);
  PERMUTATION_TK3(0x3, 0x2);
  PERMUTATION_TK3(0xd, 0x0);
  PERMUTATION_TK3(0x6, 0x3);
  PERMUTATION_TK3(0xa, 0x1);

#ifdef ___NUM_OF_ROUNDS_56

  // 42nd,44th, ... ,54th,56th round
  PERMUTATION_TK3(0x9, 0x2);
  PERMUTATION_TK3(0x4, 0x2);
  PERMUTATION_TK3(0x1, 0x1);
  PERMUTATION_TK3(0x4, 0x0);
  PERMUTATION_TK3(0x3, 0x1);
  PERMUTATION_TK3(0xc, 0x0);
  PERMUTATION_TK3(0x2, 0x3);
  PERMUTATION_TK3(0xa, 0x0);

#endif

}

#else /* ___SKINNY_LOOP */

void RunEncryptionKeyScheduleTK3(unsigned char *roundKeys, unsigned char *pRC)
{
  uint32_t *tk3;
  uint32_t t0;         // used in MACRO
  uint32_t t1;         // used in MACRO
  uint32_t t2;         // used in MACRO
  uint32_t w0;
  uint32_t w1;
  uint32_t c0;
  uint32_t c1;

  // odd
  
  // load master key
  w0 = *(uint32_t*)&roundKeys[32];
  w1 = *(uint32_t*)&roundKeys[36];

#ifndef ___NUM_OF_ROUNDS_56
  tk3 = (uint32_t*)&roundKeys[384];
#else
  tk3 = (uint32_t*)&roundKeys[512];
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
    pRC += 2;
    PERMUTATION_TK3(c0, c1);
  }

  // even

  // load master key
  w0 = *(uint32_t*)&roundKeys[40];
  w1 = *(uint32_t*)&roundKeys[44];

#ifndef ___NUM_OF_ROUNDS_56
  pRC -= 78;
  tk3 = (uint32_t*)&roundKeys[392];
#else
  pRC -= 110;
  tk3 = (uint32_t*)&roundKeys[520];
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
    PERMUTATION_TK3(c0, c1);
  }

}

#endif /* ___SKINNY_LOOP */

#endif /* ___ENABLE_DWORD_CAST */

