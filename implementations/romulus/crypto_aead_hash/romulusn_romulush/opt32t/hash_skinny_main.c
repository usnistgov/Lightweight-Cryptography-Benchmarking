/******************************************************************************
 * Copyright (c) 2020, NEC Corporation.
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/

/*
 * SKINNY-128-384
 *
 * load TK2 ^ TK3 ^ AC(c0 c1)
 * load TK1
 * SC->SR->(AC->ART)->MC
 *
 * number of rounds : 40 or 56
 */

#include "hash_skinny.h"

extern unsigned char SBOX[];
extern unsigned char SBOX2[];

#ifdef ___SKINNY_LOOP
extern unsigned char RC[];
#endif

extern void hash_Encrypt(unsigned char *h, unsigned char *g, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2);
extern void hash_Encrypt_1StBlk(unsigned char *h, unsigned char *g, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2);
extern void hash_RunEncryptionKeyScheduleTK1(uint32_t *roundKeys);
#ifdef ___SKINNY_LOOP
extern void hash_RunEncryptionKeyScheduleTK23(uint32_t *roundKeys, unsigned char *pRC);
#else
extern void hash_RunEncryptionKeyScheduleTK23(uint32_t *roundKeys);
#endif

void hash_skinny_128_384_enc_321_main (unsigned char* h, unsigned char* g, hash_skinny_ctrl* pskinny_ctrl, unsigned char* key, unsigned char*m)
{

  uint32_t *pt = &pskinny_ctrl->roundKeys[0];

  pt[0] = *(uint32_t*)(&key[0]);
  pack_word(key[7],  key[4],  key[5],  key[6],  pt[1]);
  pt[2] = *(uint32_t*)(&key[8]);
  pack_word(key[15], key[12], key[13], key[14], pt[3]);

  pt[4] = *(uint32_t*)(&m[0]);
  pack_word(m[7],  m[4],  m[5],  m[6], pt[5]);
  pt[6] = *(uint32_t*)(&m[8]);
  pack_word(m[15], m[12], m[13], m[14], pt[7]);

  pt[8] = *(uint32_t*)(&m[16]);
  pack_word(m[23], m[20], m[21], m[22], pt[9]);
  pt[10] = *(uint32_t*)(&m[24]);
  pack_word(m[31], m[28], m[29], m[30], pt[11]);

#ifdef ___SKINNY_LOOP
  hash_RunEncryptionKeyScheduleTK23(pskinny_ctrl->roundKeys, RC);
#else
  hash_RunEncryptionKeyScheduleTK23(pskinny_ctrl->roundKeys);
#endif
  hash_RunEncryptionKeyScheduleTK1(pskinny_ctrl->roundKeys);

  hash_Encrypt(h, g, pskinny_ctrl->roundKeys, SBOX, SBOX2);

}

void hash_skinny_128_384_enc_32_main (unsigned char* h, unsigned char* g, hash_skinny_ctrl* pskinny_ctrl, unsigned char* key, unsigned char* m)
{

  (void)key;

  uint32_t *pt = &pskinny_ctrl->roundKeys[0];

  pt[4] = *(uint32_t*)(&m[0]);
  pack_word(m[7],  m[4],  m[5],  m[6], pt[5]);
  pt[6] = *(uint32_t*)(&m[8]);
  pack_word(m[15], m[12], m[13], m[14], pt[7]);

  pt[8] = *(uint32_t*)(&m[16]);
  pack_word(m[23], m[20], m[21], m[22], pt[9]);
  pt[10] = *(uint32_t*)(&m[24]);
  pack_word(m[31], m[28], m[29], m[30], pt[11]);

#ifdef ___SKINNY_LOOP
  hash_RunEncryptionKeyScheduleTK23(pskinny_ctrl->roundKeys, RC);
#else
  hash_RunEncryptionKeyScheduleTK23(pskinny_ctrl->roundKeys);
#endif

#if 0
  volatile uint32_t *DWT_CYCCNT = (uint32_t *)0xE0001004;
  volatile uint32_t tm1;
  volatile uint32_t tm2;

  tm1 = *DWT_CYCCNT;
#endif
  hash_Encrypt_1StBlk(h, g, pskinny_ctrl->roundKeys, SBOX, SBOX2);
#if 0
  tm2 = *DWT_CYCCNT;
  printf("ENC %d\n", (int)(tm2 - tm1));
#endif

  pskinny_ctrl->func_skinny_128_384_enc = hash_skinny_128_384_enc_321_main;
}

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
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    SBOX_0(w0);                                                                   \
    SBOX_8(w1);                                                                   \
    SBOX_16(w2);                                                                  \
    SBOX_24(w3);                                                                  \
                                                                                  \
  /* Load TK2 ^ TK3 ^ AC(c0 c1) */                                                \
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
    w3 = t0;

#define SKINNY_MAIN_1STBLK_1STROUND()                                             \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
  /* h0,h1,h2,h3 are already calculated. */                                       \
                                                                                  \
  /* Load TK2 ^ TK3 ^ AC(c0 c1) */                                                \
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


#define SKINNY_MAIN_1STBLK()                                                      \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    SBOX_0(w0);                                                                   \
    SBOX_8(w1);                                                                   \
    SBOX_16(w2);                                                                  \
    SBOX_24(w3);                                                                  \
                                                                                  \
  /* Load TK2 ^ TK3 ^ AC(c0 c1) */                                                \
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

void hash_Encrypt_1StBlk(unsigned char* h, unsigned char* g, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2)
{

  uint32_t *tk2;
  uint32_t t0;          // used in MACRO
  uint32_t t1;          // used in MACRO
  uint32_t t2;          // used in MACRO
  uint32_t t3;          // used in MACRO
  uint32_t w0;
  uint32_t w1;
  uint32_t w2;
  uint32_t w3;
  uint32_t t4;
  uint32_t t5;
  uint32_t t6;
  uint32_t t7;
  uint32_t t8;

// SB+AC+ShR+MC

  // load h
  // h[1] - h[15] are already zero.
  w0 = 0x65656500;
  w0 ^= sbox[h[0]];

  // w1,w2,w3 can be precalculated.
  w1 = 0x65656565;
  w2 = 0x65676565;
  w3 = 0x65656565;

  tk2 = &roundKeys[32];

  // g[0] = h[0] ^ 0x01;
  // g[1] - g[15] are equal h[1] - h[15]

  // 1st round

  t7 = sbox[h[0]] ^ sbox[h[0] ^ 0x01];          // A

  // 1 0 1 1   A - - -    A - - -    B - - -
  // 1 0 0 0 x - - - - -> A - - - -> C - - -
  // 0 1 1 0   - - - -    - - - -    - - - -
  // 1 0 1 0   - - - -    A - - -    D - - -

  SKINNY_MAIN_1STBLK_1STROUND();

  // 2nd round

  // A -> t7
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t7) & 0xff]; // B
  t5 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t7) & 0xff]; // C
  t6 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t7) & 0xff]; // D

  // 1 0 1 1   B - - -    B - - D    E - - F
  // 1 0 0 0 x - C - - -> B - - - -> G - - -
  // 0 1 1 0   - - - -    - C - -    - H - -
  // 1 0 1 0   - - - D    B - - -    I - - -

  SKINNY_MAIN_1STBLK();

  // 3rd round

  // B -> t4
  // C -> t5
  // D -> t6
  t6 = sbox[(w0 >> 24)& 0xff] ^ sbox[((w0 >> 24) ^ t6) & 0xff]; // F
  t5 = sbox[(w2 >> 8) & 0xff] ^ sbox[((w2 >> 8) ^ t5) & 0xff]; // H
  t7 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t4) & 0xff]; // G
  t8 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t4) & 0xff]; // I
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t4) & 0xff]; // E

  // 1 0 1 1   E - - F    E - - F+H+I
  // 1 0 0 0 x - G - - -> E - - F
  // 0 1 1 0   - - - H    - G - H
  // 1 0 1 0   - - - I    E - - F+H

  SKINNY_MAIN_1STBLK();

  // store g
  // precalculated after 3rd round

  // E -> t4
  // F -> t6
  // G -> t7
  // H -> t5
  // I -> t8

  *(uint32_t*)(&g[0])  = w0 ^ t4 ^ ((t6 ^ t5 ^ t8) << 24);
  *(uint32_t*)(&g[4])  = w1 ^ t4 ^ (t6 << 24);
  *(uint32_t*)(&g[8])  = w2 ^ (t7 << 8) ^ (t5 << 24);
  *(uint32_t*)(&g[12]) = w3 ^ t4 ^ ((t6 ^ t5) << 24);

  // 4th, ...,16th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

  // 17th, ...,32th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

  // 33th, ...,40th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

#ifdef ___NUM_OF_ROUNDS_56

  // 41th, ...,48th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

  // 49th, ... ,56th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

#endif

  // store h
  *(uint32_t*)(&h[0])  = w0;
  *(uint32_t*)(&h[4])  = w1;
  *(uint32_t*)(&h[8])  = w2;
  *(uint32_t*)(&h[12]) = w3;

  // load g
  // precalculated after 3rd round
  w0 = *(uint32_t*)(&g[0]);
  w1 = *(uint32_t*)(&g[4]);
  w2 = *(uint32_t*)(&g[8]);
  w3 = *(uint32_t*)(&g[12]);

  tk2 = &roundKeys[38];

  // 4th, ...,16th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

  // 17th, ...,32th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

  // 33th, ...,40th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

#ifdef ___NUM_OF_ROUNDS_56

  // 41th, ...,48th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

  // 49th, ... ,56th round
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();
  SKINNY_MAIN_1STBLK();

#endif

  // store g
  *(uint32_t*)(&g[0])  = w0;
  *(uint32_t*)(&g[4])  = w1;
  *(uint32_t*)(&g[8])  = w2;
  *(uint32_t*)(&g[12]) = w3;

}

void hash_Encrypt(unsigned char *h, unsigned char *g, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2)
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
  uint32_t t4;
  uint32_t t5;
  uint32_t t6;
  uint32_t t7;
  uint32_t t8;

// SB+AC+ShR+MC

  // load g
  w0 = *(uint32_t*)(&h[0]);
  w1 = *(uint32_t*)(&h[4]);
  w2 = *(uint32_t*)(&h[8]);
  w3 = *(uint32_t*)(&h[12]);

  tk2 = &roundKeys[32];

  tk1 = &roundKeys[0];

  // g[0] = h[0] ^ 0x01;
  // g[1] - g[15] are equal h[1] - h[15]

  // 1st round

  t7 = sbox[h[0]] ^ sbox[h[0] ^ 0x01];          // A

  // 1 0 1 1   A - - -    A - - -    B - - -
  // 1 0 0 0 x - - - - -> A - - - -> C - - -
  // 0 1 1 0   - - - -    - - - -    - - - -
  // 1 0 1 0   - - - -    A - - -    D - - -

  SKINNY_MAIN();

  // 2nd round

  // A -> t7
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t7) & 0xff]; // B
  t5 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t7) & 0xff]; // C
  t6 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t7) & 0xff]; // D

  // 1 0 1 1   B - - -    B - - D    E - - F
  // 1 0 0 0 x - C - - -> B - - - -> G - - -
  // 0 1 1 0   - - - -    - C - -    - H - -
  // 1 0 1 0   - - - D    B - - -    I - - -

  SKINNY_MAIN();

  // 3rd round

  // B -> t4
  // C -> t5
  // D -> t6
  t6 = sbox[(w0 >> 24)& 0xff] ^ sbox[((w0 >> 24) ^ t6) & 0xff]; // F
  t5 = sbox[(w2 >> 8) & 0xff] ^ sbox[((w2 >> 8) ^ t5) & 0xff]; // H
  t7 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t4) & 0xff]; // G
  t8 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t4) & 0xff]; // I
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t4) & 0xff]; // E

  // 1 0 1 1   E - - F    E - - F+H+I
  // 1 0 0 0 x - G - - -> E - - F
  // 0 1 1 0   - - - H    - G - H
  // 1 0 1 0   - - - I    E - - F+H

  SKINNY_MAIN();

  // store g
  // precalculated after 3rd round

  // E -> t4
  // F -> t6
  // G -> t7
  // H -> t5
  // I -> t8

  *(uint32_t*)(&g[0])  = w0 ^ t4 ^ ((t6 ^ t5 ^ t8) << 24);
  *(uint32_t*)(&g[4])  = w1 ^ t4 ^ (t6 << 24);
  *(uint32_t*)(&g[8])  = w2 ^ (t7 << 8) ^ (t5 << 24);
  *(uint32_t*)(&g[12]) = w3 ^ t4 ^ ((t6 ^ t5) << 24);

  // 4th, ...,16th round
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
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
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

#endif

  // store h
  *(uint32_t*)(&h[0])  = w0;
  *(uint32_t*)(&h[4])  = w1;
  *(uint32_t*)(&h[8])  = w2;
  *(uint32_t*)(&h[12]) = w3;

  // load g
  // precalculated after 3rd round
  w0 = *(uint32_t*)(&g[0]);
  w1 = *(uint32_t*)(&g[4]);
  w2 = *(uint32_t*)(&g[8]);
  w3 = *(uint32_t*)(&g[12]);

  // 4th , ... ,16th round

  tk2 = &roundKeys[38];

  tk1 = &roundKeys[6];

  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
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
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();
  SKINNY_MAIN();

#endif

  // store g
  *(uint32_t*)(&g[0])  = w0;
  *(uint32_t*)(&g[4])  = w1;
  *(uint32_t*)(&g[8])  = w2;
  *(uint32_t*)(&g[12]) = w3;

}

#else

void hash_Encrypt_1StBlk(unsigned char* h, unsigned char* g, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2)
{
  uint32_t *tk2;
  uint32_t t0;          // used in MACRO
  uint32_t t1;          // used in MACRO
  uint32_t t2;          // used in MACRO
  uint32_t t3;          // used in MACRO
  uint32_t w0;
  uint32_t w1;
  uint32_t w2;
  uint32_t w3;
  uint32_t t4;
  uint32_t t5;
  uint32_t t6;
  uint32_t t7;
  uint32_t t8;

// SB+AC+ShR+MC

  // load h
  // h[1] - h[15] are already zero.
  w0 = 0x65656500;
  w0 ^= sbox[h[0]];

  // w1,w2,w3 can be precalculated.
  w1 = 0x65656565;
  w2 = 0x65676565;
  w3 = 0x65656565;

  tk2 = &roundKeys[32];

  // g[0] = h[0] ^ 0x01;
  // g[1] - g[15] are equal h[1] - h[15]

  // 1st round

  t7 = sbox[h[0]] ^ sbox[h[0] ^ 0x01];          // A

  // 1 0 1 1   A - - -    A - - -    B - - -
  // 1 0 0 0 x - - - - -> A - - - -> C - - -
  // 0 1 1 0   - - - -    - - - -    - - - -
  // 1 0 1 0   - - - -    A - - -    D - - -

  SKINNY_MAIN_1STBLK_1STROUND();

  // 2nd round

  // A -> t7
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t7) & 0xff]; // B
  t5 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t7) & 0xff]; // C
  t6 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t7) & 0xff]; // D

  // 1 0 1 1   B - - -    B - - D    E - - F
  // 1 0 0 0 x - C - - -> B - - - -> G - - -
  // 0 1 1 0   - - - -    - C - -    - H - -
  // 1 0 1 0   - - - D    B - - -    I - - -

  SKINNY_MAIN_1STBLK();

  // 3rd round

  // B -> t4
  // C -> t5
  // D -> t6
  t6 = sbox[(w0 >> 24)& 0xff] ^ sbox[((w0 >> 24) ^ t6) & 0xff]; // F
  t5 = sbox[(w2 >> 8) & 0xff] ^ sbox[((w2 >> 8) ^ t5) & 0xff]; // H
  t7 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t4) & 0xff]; // G
  t8 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t4) & 0xff]; // I
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t4) & 0xff]; // E

  // 1 0 1 1   E - - F    E - - F+H+I
  // 1 0 0 0 x - G - - -> E - - F
  // 0 1 1 0   - - - H    - G - H
  // 1 0 1 0   - - - I    E - - F+H

  SKINNY_MAIN_1STBLK();

  // store g
  // precalculated after 3rd round

  // E -> t4
  // F -> t6
  // G -> t7
  // H -> t5
  // I -> t8

  *(uint32_t*)(&g[0])  = w0 ^ t4 ^ ((t6 ^ t5 ^ t8) << 24);
  *(uint32_t*)(&g[4])  = w1 ^ t4 ^ (t6 << 24);
  *(uint32_t*)(&g[8])  = w2 ^ (t7 << 8) ^ (t5 << 24);
  *(uint32_t*)(&g[12]) = w3 ^ t4 ^ ((t6 ^ t5) << 24);

  // 4th, ... ,40th, or 56th
#ifndef ___NUM_OF_ROUNDS_56
  for(int i=0;i<37;i++)
  {
    SKINNY_MAIN_1STBLK();
  }
#else
  for(int i=0;i<53;i++)
  {
    SKINNY_MAIN_1STBLK();
  }
#endif

  // store h
  *(uint32_t*)(&h[0])  = w0;
  *(uint32_t*)(&h[4])  = w1;
  *(uint32_t*)(&h[8])  = w2;
  *(uint32_t*)(&h[12]) = w3;

  // load g
  // precalculated after 3rd round
  w0 = *(uint32_t*)(&g[0]);
  w1 = *(uint32_t*)(&g[4]);
  w2 = *(uint32_t*)(&g[8]);
  w3 = *(uint32_t*)(&g[12]);

  tk2 = &roundKeys[38];

  // 4th, ... ,40th, or 56th
#ifndef ___NUM_OF_ROUNDS_56
  for(int i=0;i<37;i++)
  {
    SKINNY_MAIN_1STBLK();
  }
#else
  for(int i=0;i<53;i++)
  {
    SKINNY_MAIN_1STBLK();
  }
#endif

  // store g
  *(uint32_t*)(&g[0])  = w0;
  *(uint32_t*)(&g[4])  = w1;
  *(uint32_t*)(&g[8])  = w2;
  *(uint32_t*)(&g[12]) = w3;
}

void hash_Encrypt(unsigned char *h, unsigned char *g, uint32_t *roundKeys, unsigned char *sbox, unsigned char *sbox2)
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
  uint32_t t4;
  uint32_t t5;
  uint32_t t6;
  uint32_t t7;
  uint32_t t8;

// SB+AC+ShR+MC

  // load g
  w0 = *(uint32_t*)(&h[0]);
  w1 = *(uint32_t*)(&h[4]);
  w2 = *(uint32_t*)(&h[8]);
  w3 = *(uint32_t*)(&h[12]);

  tk2 = &roundKeys[32];

  tk1 = &roundKeys[0];

  // g[0] = h[0] ^ 0x01;
  // g[1] - g[15] are equal h[1] - h[15]

  // 1st round

  t7 = sbox[h[0]] ^ sbox[h[0] ^ 0x01];          // A

  // 1 0 1 1   A - - -    A - - -    B - - -
  // 1 0 0 0 x - - - - -> A - - - -> C - - -
  // 0 1 1 0   - - - -    - - - -    - - - -
  // 1 0 1 0   - - - -    A - - -    D - - -

  SKINNY_MAIN();

  // 2nd round

  // A -> t7
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t7) & 0xff]; // B
  t5 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t7) & 0xff]; // C
  t6 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t7) & 0xff]; // D

  // 1 0 1 1   B - - -    B - - D    E - - F
  // 1 0 0 0 x - C - - -> B - - - -> G - - -
  // 0 1 1 0   - - - -    - C - -    - H - -
  // 1 0 1 0   - - - D    B - - -    I - - -

  SKINNY_MAIN();

  // 3rd round

  // B -> t4
  // C -> t5
  // D -> t6
  t6 = sbox[(w0 >> 24)& 0xff] ^ sbox[((w0 >> 24) ^ t6) & 0xff]; // F
  t5 = sbox[(w2 >> 8) & 0xff] ^ sbox[((w2 >> 8) ^ t5) & 0xff]; // H
  t7 = sbox[w1 & 0xff] ^ sbox[(w1 ^ t4) & 0xff]; // G
  t8 = sbox[w3 & 0xff] ^ sbox[(w3 ^ t4) & 0xff]; // I
  t4 = sbox[w0 & 0xff] ^ sbox[(w0 ^ t4) & 0xff]; // E

  // 1 0 1 1   E - - F    E - - F+H+I
  // 1 0 0 0 x - G - - -> E - - F
  // 0 1 1 0   - - - H    - G - H
  // 1 0 1 0   - - - I    E - - F+H

  SKINNY_MAIN();

  // store g
  // precalculated after 3rd round

  // E -> t4
  // F -> t6
  // G -> t7
  // H -> t5
  // I -> t8

  *(uint32_t*)(&g[0])  = w0 ^ t4 ^ ((t6 ^ t5 ^ t8) << 24);
  *(uint32_t*)(&g[4])  = w1 ^ t4 ^ (t6 << 24);
  *(uint32_t*)(&g[8])  = w2 ^ (t7 << 8) ^ (t5 << 24);
  *(uint32_t*)(&g[12]) = w3 ^ t4 ^ ((t6 ^ t5) << 24);

  // 4th , ... ,16th round
  for(int i=0;i<13;i++)
  {
    SKINNY_MAIN();
  }

  // 17th , ... ,32th round
  tk1 = &roundKeys[0];
  for(int i=0;i<16;i++)
  {
    SKINNY_MAIN();
  }

#ifdef ___NUM_OF_ROUNDS_56
  // 33th , ... ,48th round
  tk1 = &roundKeys[0];
  for(int i=0;i<16;i++)
  {
    SKINNY_MAIN();
  }
#endif

  // 33th , ... ,40th or 49th, .... ,56th round
  {
    tk1 = &roundKeys[0];
    for(int i=0;i<8;i++)
    {
      SKINNY_MAIN();
    }
  }

  // store h
  *(uint32_t*)(&h[0])  = w0;
  *(uint32_t*)(&h[4])  = w1;
  *(uint32_t*)(&h[8])  = w2;
  *(uint32_t*)(&h[12]) = w3;

  // load g
  // precalculated after 3rd round
  w0 = *(uint32_t*)(&g[0]);
  w1 = *(uint32_t*)(&g[4]);
  w2 = *(uint32_t*)(&g[8]);
  w3 = *(uint32_t*)(&g[12]);

  // 4th , ... ,16th round

  tk2 = &roundKeys[38];

  tk1 = &roundKeys[6];
  for(int i=0;i<13;i++)
  {
    SKINNY_MAIN();
  }

  // 17th , ... ,32th round
  tk1 = &roundKeys[0];
  for(int i=0;i<16;i++)
  {
    SKINNY_MAIN();
  }

#ifdef ___NUM_OF_ROUNDS_56
  // 33th , ... ,48th round
  tk1 = &roundKeys[0];
  for(int i=0;i<16;i++)
  {
    SKINNY_MAIN();
  }
#endif

  // 33th , ... ,40th or 49th, .... ,56th round
  {
    tk1 = &roundKeys[0];
    for(int i=0;i<8;i++)
    {
      SKINNY_MAIN();
    }
  }

  // store g
  *(uint32_t*)(&g[0])  = w0;
  *(uint32_t*)(&g[4])  = w1;
  *(uint32_t*)(&g[8])  = w2;
  *(uint32_t*)(&g[12]) = w3;

}

#endif
