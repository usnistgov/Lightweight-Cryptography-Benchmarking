/*
 * Date: 29 November 2018
 * Contact: Thomas Peyrin - thomas.peyrin@gmail.com
 * Mustafa Khairallah - mustafam001@e.ntu.edu.sg
 */

#include "crypto_aead.h"
#include "api.h"
#include "skinny.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>

void irho_eqov16 (
    unsigned char* m,
    const unsigned char* c,
    unsigned char* s);
void irho_ud16 (
    unsigned char* m,
    const unsigned char* c,
    unsigned char* s,
    int len8);

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
