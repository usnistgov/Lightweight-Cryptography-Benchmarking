/*
 * Date: 29 November 2018
 * Contact: Thomas Peyrin - thomas.peyrin@gmail.com
 * Mustafa Khairallah - mustafam001@e.ntu.edu.sg
 */

#include "crypto_aead.h"
#include "api.h"
#include "skinny.h"
#include <stdio.h>
#include <stdlib.h>

void pad (const unsigned char* m, unsigned char* mp, int len8) {

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&mp[0]) = 0;
  *(uint32_t*)(&mp[4]) = 0;
  *(uint32_t*)(&mp[8]) = 0;
  *(uint32_t*)(&mp[12]) = 0;
  mp[15] = (len8 & 0x0f);
  for (int i = 0; i < len8; i++) {
    mp[i] = m[i];
  }

#else

  mp[0]  = 0;
  mp[1]  = 0;
  mp[2]  = 0;
  mp[3]  = 0;
  mp[4]  = 0;
  mp[5]  = 0;
  mp[6]  = 0;
  mp[7]  = 0;
  mp[8]  = 0;
  mp[9]  = 0;
  mp[10] = 0;
  mp[11] = 0;
  mp[12] = 0;
  mp[13] = 0;
  mp[14] = 0;
  mp[15] = (len8 & 0x0f);
  for (int i = 0; i < len8; i++) {
    mp[i] = m[i];
  }

#endif

}

void g8A (unsigned char* s, unsigned char* c) {

#ifdef ___ENABLE_WORD_CAST

  uint32_t s0 =  *(uint32_t*)(&s[0]);
  uint32_t s1 =  *(uint32_t*)(&s[4]);
  uint32_t s2 =  *(uint32_t*)(&s[8]);
  uint32_t s3 =  *(uint32_t*)(&s[12]);

  uint32_t c0, c1, c2, c3;

  c0 = ((s0 >> 1) & 0x7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x80808080);
  c1 = ((s1 >> 1) & 0x7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x80808080);
  c2 = ((s2 >> 1) & 0x7f7f7f7f) ^ ((s2 ^ (s2 << 7)) & 0x80808080);
  c3 = ((s3 >> 1) & 0x7f7f7f7f) ^ ((s3 ^ (s3 << 7)) & 0x80808080);

  *(uint32_t*)(&c[0])  = c0;
  *(uint32_t*)(&c[4])  = c1;
  *(uint32_t*)(&c[8])  = c2;
  *(uint32_t*)(&c[12]) = c3;

#else

  uint32_t s0, s1, s2, s3;
  uint32_t c0, c1, c2, c3;

  pack_word(s[0],  s[1],  s[2],  s[3],  s0);
  pack_word(s[4],  s[5],  s[6],  s[7],  s1);
  pack_word(s[8],  s[9],  s[10], s[11], s2);
  pack_word(s[12], s[13], s[14], s[15], s3);

  c0 = ((s0 >> 1) & 0x7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x80808080);
  c1 = ((s1 >> 1) & 0x7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x80808080);
  c2 = ((s2 >> 1) & 0x7f7f7f7f) ^ ((s2 ^ (s2 << 7)) & 0x80808080);
  c3 = ((s3 >> 1) & 0x7f7f7f7f) ^ ((s3 ^ (s3 << 7)) & 0x80808080);

  unpack_word(c[0],  c[1],  c[2],  c[3],  c0);
  unpack_word(c[4],  c[5],  c[6],  c[7],  c1);
  unpack_word(c[8],  c[9],  c[10], c[11], c2);
  unpack_word(c[12], c[13], c[14], c[15], c3);

#endif

}

#ifdef ___ENABLE_WORD_CAST

void g8A_for_Tag_Generation (unsigned char* s, unsigned char* c) {

  uint32_t s0 =  *(uint32_t*)(&s[0]);
  uint32_t s1 =  *(uint32_t*)(&s[4]);
  uint32_t s2 =  *(uint32_t*)(&s[8]);
  uint32_t s3 =  *(uint32_t*)(&s[12]);

  uint32_t c0, c1, c2, c3;

  c0 = ((s0 >> 1) & 0x7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x80808080);
  c1 = ((s1 >> 1) & 0x7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x80808080);
  c2 = ((s2 >> 1) & 0x7f7f7f7f) ^ ((s2 ^ (s2 << 7)) & 0x80808080);
  c3 = ((s3 >> 1) & 0x7f7f7f7f) ^ ((s3 ^ (s3 << 7)) & 0x80808080);

  // use byte access because of memory alignment.
  // c is not always in word(4 byte) alignment.
  c[0] =   c0     &0xFF;
  c[1] =  (c0>>8) &0xFF;
  c[2] =  (c0>>16)&0xFF;
  c[3] =   c0>>24;
  c[4] =   c1     &0xFF;
  c[5] =  (c1>>8) &0xFF;
  c[6] =  (c1>>16)&0xFF;
  c[7] =   c1>>24;
  c[8] =   c2     &0xFF;
  c[9] =  (c2>>8) &0xFF;
  c[10] = (c2>>16)&0xFF;
  c[11] =  c2>>24;
  c[12] =  c3     &0xFF;
  c[13] = (c3>>8) &0xFF;
  c[14] = (c3>>16)&0xFF;
  c[15] =  c3>>24;

}

#endif

#define rho_ad_eqov16_macro(i) \
  s[i] = s[i] ^ m[i];

void rho_ad_eqov16 (
    const unsigned char* m,
    unsigned char* s) {

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&s[0])  ^= *(uint32_t*)(&m[0]);
  *(uint32_t*)(&s[4])  ^= *(uint32_t*)(&m[4]);
  *(uint32_t*)(&s[8])  ^= *(uint32_t*)(&m[8]);
  *(uint32_t*)(&s[12]) ^= *(uint32_t*)(&m[12]);

#else

  rho_ad_eqov16_macro(0);
  rho_ad_eqov16_macro(1);
  rho_ad_eqov16_macro(2);
  rho_ad_eqov16_macro(3);
  rho_ad_eqov16_macro(4);
  rho_ad_eqov16_macro(5);
  rho_ad_eqov16_macro(6);
  rho_ad_eqov16_macro(7);
  rho_ad_eqov16_macro(8);
  rho_ad_eqov16_macro(9);
  rho_ad_eqov16_macro(10);
  rho_ad_eqov16_macro(11);
  rho_ad_eqov16_macro(12);
  rho_ad_eqov16_macro(13);
  rho_ad_eqov16_macro(14);
  rho_ad_eqov16_macro(15);

#endif

}

#define rho_ad_ud16_macro(i) \
  s[i] = s[i] ^ mp[i];

void rho_ad_ud16 (
    const unsigned char* m,
    unsigned char* s,
    int len8) {

  unsigned char mp [16];
  pad(m,mp,len8);

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&s[0])  ^= *(uint32_t*)(&mp[0]);
  *(uint32_t*)(&s[4])  ^= *(uint32_t*)(&mp[4]);
  *(uint32_t*)(&s[8])  ^= *(uint32_t*)(&mp[8]);
  *(uint32_t*)(&s[12]) ^= *(uint32_t*)(&mp[12]);

#else

  rho_ad_ud16_macro(0);
  rho_ad_ud16_macro(1);
  rho_ad_ud16_macro(2);
  rho_ad_ud16_macro(3);
  rho_ad_ud16_macro(4);
  rho_ad_ud16_macro(5);
  rho_ad_ud16_macro(6);
  rho_ad_ud16_macro(7);
  rho_ad_ud16_macro(8);
  rho_ad_ud16_macro(9);
  rho_ad_ud16_macro(10);
  rho_ad_ud16_macro(11);
  rho_ad_ud16_macro(12);
  rho_ad_ud16_macro(13);
  rho_ad_ud16_macro(14);
  rho_ad_ud16_macro(15);

#endif

}

void rho_eqov16 (
    const unsigned char* m,
    unsigned char* c,
    unsigned char* s) {

  g8A(s,c);

#ifdef ___ENABLE_WORD_CAST

  uint32_t c0 = *(uint32_t*)(&c[0]);
  uint32_t c1 = *(uint32_t*)(&c[4]);
  uint32_t c2 = *(uint32_t*)(&c[8]);
  uint32_t c3 = *(uint32_t*)(&c[12]);

  uint32_t s0 = *(uint32_t*)(&s[0]);
  uint32_t s1 = *(uint32_t*)(&s[4]);
  uint32_t s2 = *(uint32_t*)(&s[8]);
  uint32_t s3 = *(uint32_t*)(&s[12]);

  uint32_t m0 = *(uint32_t*)(&m[0]);
  uint32_t m1 = *(uint32_t*)(&m[4]);
  uint32_t m2 = *(uint32_t*)(&m[8]);
  uint32_t m3 = *(uint32_t*)(&m[12]);

  s0 ^= m0;
  s1 ^= m1;
  s2 ^= m2;
  s3 ^= m3;

  c0 ^= m0;
  c1 ^= m1;
  c2 ^= m2;
  c3 ^= m3;

  *(uint32_t*)(&s[0])  = s0;
  *(uint32_t*)(&s[4])  = s1;
  *(uint32_t*)(&s[8])  = s2;
  *(uint32_t*)(&s[12]) = s3;

  *(uint32_t*)(&c[0])  = c0;
  *(uint32_t*)(&c[4])  = c1;
  *(uint32_t*)(&c[8])  = c2;
  *(uint32_t*)(&c[12]) = c3;

#else

  uint32_t c0, c1, c2, c3;
  uint32_t s0, s1, s2, s3;
  uint32_t m0, m1, m2, m3;

  pack_word(m[0],  m[1],  m[2],  m[3],  m0);
  pack_word(m[4],  m[5],  m[6],  m[7],  m1);
  pack_word(m[8],  m[9],  m[10], m[11], m2);
  pack_word(m[12], m[13], m[14], m[15], m3);

  pack_word(s[0],  s[1],  s[2],  s[3],  s0);
  pack_word(s[4],  s[5],  s[6],  s[7],  s1);
  pack_word(s[8],  s[9],  s[10], s[11], s2);
  pack_word(s[12], s[13], s[14], s[15], s3);

  pack_word(c[0],  c[1],  c[2],  c[3],  c0);
  pack_word(c[4],  c[5],  c[6],  c[7],  c1);
  pack_word(c[8],  c[9],  c[10], c[11], c2);
  pack_word(c[12], c[13], c[14], c[15], c3);

  s0 ^= m0;
  s1 ^= m1;
  s2 ^= m2;
  s3 ^= m3;

  c0 ^= m0;
  c1 ^= m1;
  c2 ^= m2;
  c3 ^= m3;

  unpack_word(s[0],  s[1],  s[2],  s[3],  s0);
  unpack_word(s[4],  s[5],  s[6],  s[7],  s1);
  unpack_word(s[8],  s[9],  s[10], s[11], s2);
  unpack_word(s[12], s[13], s[14], s[15], s3);

  unpack_word(c[0],  c[1],  c[2],  c[3],  c0);
  unpack_word(c[4],  c[5],  c[6],  c[7],  c1);
  unpack_word(c[8],  c[9],  c[10], c[11], c2);
  unpack_word(c[12], c[13], c[14], c[15], c3);

#endif

}

#define rho_ud16_macro(i)   \
  s[i] = s[i] ^ mp[i];
  
void rho_ud16 (
    const unsigned char* m,
    unsigned char* c,
    unsigned char* s,
    int len8) {

  unsigned char mp [16];

  pad(m,mp,len8);

  g8A(s,c);
#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&s[0])  ^= *(uint32_t*)(&mp[0]);
  *(uint32_t*)(&s[4])  ^= *(uint32_t*)(&mp[4]);
  *(uint32_t*)(&s[8])  ^= *(uint32_t*)(&mp[8]);
  *(uint32_t*)(&s[12]) ^= *(uint32_t*)(&mp[12]);

  for (int i = 0; i < 16; i++) {
    if (i < len8) {
      c[i] = c[i] ^ mp[i];
    }
    else {
      c[i] = 0;
    }
  }

#else

  rho_ud16_macro(0);
  rho_ud16_macro(1);
  rho_ud16_macro(2);
  rho_ud16_macro(3);
  rho_ud16_macro(4);
  rho_ud16_macro(5);
  rho_ud16_macro(6);
  rho_ud16_macro(7);
  rho_ud16_macro(8);
  rho_ud16_macro(9);
  rho_ud16_macro(10);
  rho_ud16_macro(11);
  rho_ud16_macro(12);
  rho_ud16_macro(13);
  rho_ud16_macro(14);
  rho_ud16_macro(15);

  for (int i = 0; i < 16; i++) {
    if (i < len8) {
      c[i] = c[i] ^ mp[i];
    }
    else {
      c[i] = 0;
    }
  }

#endif

}

void irho_eqov16 (
    unsigned char* m,
    const unsigned char* c,
    unsigned char* s) {

  g8A(s,m);

#ifdef ___ENABLE_WORD_CAST

  uint32_t c0 = *(uint32_t*)(&c[0]);
  uint32_t c1 = *(uint32_t*)(&c[4]);
  uint32_t c2 = *(uint32_t*)(&c[8]);
  uint32_t c3 = *(uint32_t*)(&c[12]);

  uint32_t s0 = *(uint32_t*)(&s[0]);
  uint32_t s1 = *(uint32_t*)(&s[4]);
  uint32_t s2 = *(uint32_t*)(&s[8]);
  uint32_t s3 = *(uint32_t*)(&s[12]);

  uint32_t m0 = *(uint32_t*)(&m[0]);
  uint32_t m1 = *(uint32_t*)(&m[4]);
  uint32_t m2 = *(uint32_t*)(&m[8]);
  uint32_t m3 = *(uint32_t*)(&m[12]);

  s0 ^= c0 ^ m0;
  s1 ^= c1 ^ m1;
  s2 ^= c2 ^ m2;
  s3 ^= c3 ^ m3;

  m0 ^= c0;
  m1 ^= c1;
  m2 ^= c2;
  m3 ^= c3;

  *(uint32_t*)(&s[0])  = s0;
  *(uint32_t*)(&s[4])  = s1;
  *(uint32_t*)(&s[8])  = s2;
  *(uint32_t*)(&s[12]) = s3;

  *(uint32_t*)(&m[0])  = m0;
  *(uint32_t*)(&m[4])  = m1;
  *(uint32_t*)(&m[8])  = m2;
  *(uint32_t*)(&m[12]) = m3;

#else

  uint32_t c0, c1, c2, c3;
  uint32_t s0, s1, s2, s3;
  uint32_t m0, m1, m2, m3;

  pack_word(m[0],  m[1],  m[2],  m[3],  m0);
  pack_word(m[4],  m[5],  m[6],  m[7],  m1);
  pack_word(m[8],  m[9],  m[10], m[11], m2);
  pack_word(m[12], m[13], m[14], m[15], m3);

  pack_word(s[0],  s[1],  s[2],  s[3],  s0);
  pack_word(s[4],  s[5],  s[6],  s[7],  s1);
  pack_word(s[8],  s[9],  s[10], s[11], s2);
  pack_word(s[12], s[13], s[14], s[15], s3);

  pack_word(c[0],  c[1],  c[2],  c[3],  c0);
  pack_word(c[4],  c[5],  c[6],  c[7],  c1);
  pack_word(c[8],  c[9],  c[10], c[11], c2);
  pack_word(c[12], c[13], c[14], c[15], c3);

  s0 ^= c0 ^ m0;
  s1 ^= c1 ^ m1;
  s2 ^= c2 ^ m2;
  s3 ^= c3 ^ m3;

  m0 ^= c0;
  m1 ^= c1;
  m2 ^= c2;
  m3 ^= c3;

  unpack_word(s[0],  s[1],  s[2],  s[3],  s0);
  unpack_word(s[4],  s[5],  s[6],  s[7],  s1);
  unpack_word(s[8],  s[9],  s[10], s[11], s2);
  unpack_word(s[12], s[13], s[14], s[15], s3);

  unpack_word(m[0],  m[1],  m[2],  m[3],  m0);
  unpack_word(m[4],  m[5],  m[6],  m[7],  m1);
  unpack_word(m[8],  m[9],  m[10], m[11], m2);
  unpack_word(m[12], m[13], m[14], m[15], m3);

#endif

}

#define irho_ud16_macro(i)   \
  s[i] = s[i] ^ cp[i];

void irho_ud16 (
    unsigned char* m,
    const unsigned char* c,
    unsigned char* s,
    int len8) {

  unsigned char cp [16];

  pad(c,cp,len8);

  g8A(s,m);

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&s[0])  ^= *(uint32_t*)(&cp[0]);
  *(uint32_t*)(&s[4])  ^= *(uint32_t*)(&cp[4]);
  *(uint32_t*)(&s[8])  ^= *(uint32_t*)(&cp[8]);
  *(uint32_t*)(&s[12]) ^= *(uint32_t*)(&cp[12]);

  for (int i = 0; i < len8; i++) {
    s[i] ^= m[i];
  }

  for (int i = 0; i < 16; i++) {
    if (i < len8) {
      m[i] = m[i] ^ cp[i];
    }
    else {
      m[i] = 0;
    }
  }

#else

  irho_ud16_macro(0);
  irho_ud16_macro(1);
  irho_ud16_macro(2);
  irho_ud16_macro(3);
  irho_ud16_macro(4);
  irho_ud16_macro(5);
  irho_ud16_macro(6);
  irho_ud16_macro(7);
  irho_ud16_macro(8);
  irho_ud16_macro(9);
  irho_ud16_macro(10);
  irho_ud16_macro(11);
  irho_ud16_macro(12);
  irho_ud16_macro(13);
  irho_ud16_macro(14);
  irho_ud16_macro(15);

  for (int i = 0; i < len8; i++) {
    s[i] ^= m[i];
  }

  for (int i = 0; i < 16; i++) {
    if (i < len8) {
      m[i] = m[i] ^ cp[i];
    }
    else {
      m[i] = 0;
    }
  }

#endif

}

void reset_lfsr_gf56 (unsigned char* CNT) {

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&CNT[0]) = 0x00000001; // CNT3 CNT2 CNT1 CNT0
  *(uint32_t*)(&CNT[4]) = 0x00000000; // CNT7 CNT6 CNT5 CNT4

#else

  CNT[0] = 0x01;
  CNT[1] = 0x00;
  CNT[2] = 0x00;
  CNT[3] = 0x00;
  CNT[4] = 0x00;
  CNT[5] = 0x00;
  CNT[6] = 0x00;

#endif

}

void lfsr_gf56 (unsigned char* CNT) {

#ifdef ___ENABLE_WORD_CAST

  uint32_t C0;
  uint32_t C1;
  uint32_t fb0;

  C0 = *(uint32_t*)(&CNT[0]); // CNT3 CNT2 CNT1 CNT0
  C1 = *(uint32_t*)(&CNT[4]); // CNT7 CNT6 CNT5 CNT4

  fb0 = 0;
  if (CNT[6] & 0x80) {
    fb0 =  0x95;
  }

  C1 = C1 << 1 | C0 >> 31;
  C0 = C0 << 1 ^ fb0;

  *(uint32_t*)(&CNT[0]) = C0;
  *(uint32_t*)(&CNT[4]) = C1;

#else

  uint32_t fb0 = CNT[6] >> 7;

  CNT[6] = (CNT[6] << 1) | (CNT[5] >> 7);
  CNT[5] = (CNT[5] << 1) | (CNT[4] >> 7);
  CNT[4] = (CNT[4] << 1) | (CNT[3] >> 7);
  CNT[3] = (CNT[3] << 1) | (CNT[2] >> 7);
  CNT[2] = (CNT[2] << 1) | (CNT[1] >> 7);
  CNT[1] = (CNT[1] << 1) | (CNT[0] >> 7);
  if (fb0 == 1) {
    CNT[0] = (CNT[0] << 1) ^ 0x95;
  }
  else {
    CNT[0] = (CNT[0] << 1);
  }

#endif

}

void block_cipher(
    unsigned char* s,
    const unsigned char* k, unsigned char* T,
    unsigned char* CNT, unsigned char D,
    skinny_ctrl* p_skinny_ctrl) {

  CNT[7] = D;
  p_skinny_ctrl->func_skinny_128_384_enc(s, p_skinny_ctrl, CNT, T, k);

}

void nonce_encryption (
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    skinny_ctrl* p_skinny_ctrl) {

  block_cipher(s,k,(unsigned char*)N,CNT,D,p_skinny_ctrl);

}

void generate_tag (
    unsigned char** c, unsigned char* s,
    unsigned long long* clen) {

#ifdef ___ENABLE_WORD_CAST

  g8A_for_Tag_Generation(s, *c);

#else

  g8A(s, *c);

#endif
  *c = *c + 16;
  *c = *c - *clen;

}

unsigned long long msg_encryption_eqov16 (
    const unsigned char** M, unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long mlen,
    skinny_ctrl* p_skinny_ctrl) {

  rho_eqov16(*M, *c, s);
  *c = *c + 16;
  *M = *M + 16;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,p_skinny_ctrl);
  return mlen - 16;

}

unsigned long long msg_encryption_ud16 (
    const unsigned char** M, unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long mlen,
    skinny_ctrl* p_skinny_ctrl) {

  rho_ud16(*M, *c, s, mlen);
  *c = *c + mlen;
  *M = *M + mlen;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,p_skinny_ctrl);
  return 0;

}

unsigned long long msg_decryption_eqov16 (
    unsigned char** M, const unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long clen,
    skinny_ctrl* p_skinny_ctrl) {

  irho_eqov16(*M, *c, s);
  *c = *c + 16;
  *M = *M + 16;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,p_skinny_ctrl);
  return clen - 16;

}
unsigned long long msg_decryption_ud16 (
    unsigned char** M, const unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long clen,
    skinny_ctrl* p_skinny_ctrl) {

  irho_ud16(*M, *c, s, clen);
  *c = *c + clen;
  *M = *M + clen;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,p_skinny_ctrl);
  return 0;

}

unsigned long long ad_encryption_eqov32 (
    const unsigned char** A, unsigned char* s,
    const unsigned char* k, unsigned long long adlen,
    unsigned char* CNT,
    unsigned char D,
    skinny_ctrl* p_skinny_ctrl) {

  unsigned char T [16];

  rho_ad_eqov16(*A, s);
  *A = *A + 16;
  lfsr_gf56(CNT);

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&T[0])  = *(uint32_t*)(&(*A)[0]);
  *(uint32_t*)(&T[4])  = *(uint32_t*)(&(*A)[4]);
  *(uint32_t*)(&T[8])  = *(uint32_t*)(&(*A)[8]);
  *(uint32_t*)(&T[12]) = *(uint32_t*)(&(*A)[12]);

#else

  T[0] = (*A)[0];
  T[1] = (*A)[1];
  T[2] = (*A)[2];
  T[3] = (*A)[3];
  T[4] = (*A)[4];
  T[5] = (*A)[5];
  T[6] = (*A)[6];
  T[7] = (*A)[7];
  T[8] = (*A)[8];
  T[9] = (*A)[9];
  T[10] = (*A)[10];
  T[11] = (*A)[11];
  T[12] = (*A)[12];
  T[13] = (*A)[13];
  T[14] = (*A)[14];
  T[15] = (*A)[15];

#endif

  *A = *A + 16;
  block_cipher(s,k,T,CNT,D,p_skinny_ctrl);
  lfsr_gf56(CNT);

  return adlen - 32;

}

unsigned long long ad_encryption_ov16 (
    const unsigned char** A, unsigned char* s,
    const unsigned char* k, unsigned long long adlen,
    unsigned char* CNT,
    unsigned char D,
    skinny_ctrl* p_skinny_ctrl) {

  unsigned char T [16];

  adlen = adlen - 16;
  rho_ad_eqov16(*A, s);
  *A = *A + 16;
  lfsr_gf56(CNT);

  pad(*A, T, adlen);
  *A = *A + adlen;
  block_cipher(s,k,T,CNT,D,p_skinny_ctrl);
  lfsr_gf56(CNT);

  return 0;

}

unsigned long long ad_encryption_eq16 (
    const unsigned char** A, unsigned char* s,
    unsigned char* CNT) {

  rho_ad_eqov16(*A, s);
  *A = *A + 16;
  lfsr_gf56(CNT);

  return 0;

}

unsigned long long ad_encryption_ud16(
    const unsigned char** A, unsigned char* s,
    unsigned long long adlen,
    unsigned char* CNT) {

  rho_ad_ud16(*A, s, adlen);
  *A = *A + adlen;
  lfsr_gf56(CNT);

  return 0;

}

int crypto_aead_encrypt (
    unsigned char* c, unsigned long long* clen,
    const unsigned char* m, unsigned long long mlen,
    const unsigned char* ad, unsigned long long adlen,
    const unsigned char* nsec,
    const unsigned char* npub,
    const unsigned char* k) {

  unsigned char s[16];
  unsigned char CNT[8];
  const unsigned char* A;
  const unsigned char* M;
  const unsigned char* N;

  skinny_ctrl ctrl;
  ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

  (void) nsec;
  A = ad;
  M = m;
  N = npub;

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&s[0])  = 0;
  *(uint32_t*)(&s[4])  = 0;
  *(uint32_t*)(&s[8])  = 0;
  *(uint32_t*)(&s[12]) = 0;

#else

  s[0]  = 0;
  s[1]  = 0;
  s[2]  = 0;
  s[3]  = 0;
  s[4]  = 0;
  s[5]  = 0;
  s[6]  = 0;
  s[7]  = 0;
  s[8]  = 0;
  s[9]  = 0;
  s[10]  = 0;
  s[11]  = 0;
  s[12]  = 0;
  s[13]  = 0;
  s[14]  = 0;
  s[15]  = 0;

#endif

  reset_lfsr_gf56(CNT);

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x1a,&ctrl);
  }
  else while (adlen > 0) {
      if (adlen < 16) { // The last block of AD is odd and incomplete
        adlen = ad_encryption_ud16(&A,s,adlen,CNT);
        nonce_encryption(N,CNT,s,k,0x1a,&ctrl);
      }
      else if (adlen == 16) { // The last block of AD is odd and complete
        adlen = ad_encryption_eq16(&A,s,CNT);
        nonce_encryption(N,CNT,s,k,0x18,&ctrl);
      }
      else if (adlen < 32) { // The last block of AD is even and incomplete
        adlen = ad_encryption_ov16(&A,s,k,adlen,CNT,0x08,&ctrl);
        nonce_encryption(N,CNT,s,k,0x1a,&ctrl);
      }
      else if (adlen == 32) { // The last block of AD is even and complete
        adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&ctrl);
        nonce_encryption(N,CNT,s,k,0x18,&ctrl);
      }
      else { // A normal full pair of blocks of AD
        adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&ctrl);
      }
    }

  ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

  reset_lfsr_gf56(CNT);

  *clen = mlen + 16;

  if (mlen == 0) { // M is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x15,&ctrl);
  }
  else while (mlen > 0) {
    if (mlen < 16) { // The last block of M is incomplete
      mlen = msg_encryption_ud16(&M,&c,N,CNT,s,k,0x15,mlen,&ctrl);
    }
    else if (mlen == 16) { // The last block of M is complete
      mlen = msg_encryption_eqov16(&M,&c,N,CNT,s,k,0x14,mlen,&ctrl);
    }
    else { // A normal full message block
      mlen = msg_encryption_eqov16(&M,&c,N,CNT,s,k,0x04,mlen,&ctrl);
    }
  }

  // Tag generation
  generate_tag(&c,s,clen);

  return 0;

}

int crypto_aead_decrypt(
    unsigned char *m,unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c,unsigned long long clen,
    const unsigned char *ad,unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k) {

  unsigned char s[16];
  unsigned char T[16];
  unsigned char CNT[8];
  const unsigned char* A;
  unsigned char* M;
  const unsigned char* N;

  skinny_ctrl ctrl;
  ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

  (void) nsec;
  A = ad;
  M = m;
  N = npub;

#ifdef ___ENABLE_WORD_CAST

  *(uint32_t*)(&s[0])  = 0;
  *(uint32_t*)(&s[4])  = 0;
  *(uint32_t*)(&s[8])  = 0;
  *(uint32_t*)(&s[12]) = 0;

#else

  s[0]  = 0;
  s[1]  = 0;
  s[2]  = 0;
  s[3]  = 0;
  s[4]  = 0;
  s[5]  = 0;
  s[6]  = 0;
  s[7]  = 0;
  s[8]  = 0;
  s[9]  = 0;
  s[10]  = 0;
  s[11]  = 0;
  s[12]  = 0;
  s[13]  = 0;
  s[14]  = 0;
  s[15]  = 0;

#endif

  reset_lfsr_gf56(CNT);

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x1a,&ctrl);
  }
  else while (adlen > 0) {
      if (adlen < 16) { // The last block of AD is odd and incomplete
        adlen = ad_encryption_ud16(&A,s,adlen,CNT);
        nonce_encryption(N,CNT,s,k,0x1a,&ctrl);
      }
      else if (adlen == 16) { // The last block of AD is odd and complete
        adlen = ad_encryption_eq16(&A,s,CNT);
        nonce_encryption(N,CNT,s,k,0x18,&ctrl);
      }
      else if (adlen < 32) { // The last block of AD is even and incomplete
        adlen = ad_encryption_ov16(&A,s,k,adlen,CNT,0x08,&ctrl);
        nonce_encryption(N,CNT,s,k,0x1a,&ctrl);
      }
      else if (adlen == 32) { // The last block of AD is even and complete
        adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&ctrl);
        nonce_encryption(N,CNT,s,k,0x18,&ctrl);
      }
      else { // A normal full pair of blocks of AD
        adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&ctrl);
      }
    }

  ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

  reset_lfsr_gf56(CNT);

  clen = clen -16;
  *mlen = clen;

  if (clen == 0) { // C is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x15,&ctrl);
  }
  else while (clen > 0) {
    if (clen < 16) { // The last block of C is incomplete
      clen = msg_decryption_ud16(&M,&c,N,CNT,s,k,0x15,clen,&ctrl);
    }
    else if (clen == 16) { // The last block of C is complete
      clen = msg_decryption_eqov16(&M,&c,N,CNT,s,k,0x14,clen,&ctrl);
    }
    else { // A normal full message block
      clen = msg_decryption_eqov16(&M,&c,N,CNT,s,k,0x04,clen,&ctrl);
    }
  }

  // Tag generation
#ifdef ___ENABLE_WORD_CAST

  g8A_for_Tag_Generation(s, T);

#else

  g8A(s, T);

#endif
  for (int i = 0; i < 16; i++) {
    if (T[i] != (*(c+i))) {
      return -1;
    }
  }

  return 0;

}
