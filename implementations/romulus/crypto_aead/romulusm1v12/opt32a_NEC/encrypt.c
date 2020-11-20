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

#ifdef ___ENABLE_DWORD_CAST

  if (0 == len8) {
    *(uint64_t*)(&mp[0]) = 0;
    *(uint64_t*)(&mp[8]) = 0;
  } else if (8 >  len8) {
    *(uint64_t*)(&mp[0]) = *(uint64_t*)(&m[0]) & (0xffffffffffffffff >> (64 - len8*8));
    *(uint64_t*)(&mp[8]) = 0;
    mp[15] = len8;
  } else if (8 == len8) {
    *(uint64_t*)(&mp[0]) = *(uint64_t*)(&m[0]);
    *(uint64_t*)(&mp[8]) = 0;
    mp[15] = 8;
  } else if (16 > len8) {  
    *(uint64_t*)(&mp[0]) = *(uint64_t*)(&m[0]);
    *(uint64_t*)(&mp[8]) = *(uint64_t*)(&m[8]) & (0xffffffffffffffff >> (128 - len8*8));
    mp[15] = len8;
  } else {
    *(uint64_t*)(&mp[0]) = *(uint64_t*)(&m[0]);
    *(uint64_t*)(&mp[8]) = *(uint64_t*)(&m[8]);
  }

#else

  if (0 == len8) {
    *(uint32_t*)(&mp[0])  = 0;
    *(uint32_t*)(&mp[4])  = 0;
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
  } else if (4 >   len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]) & (0xffffffff >> (32 - len8*8));
    *(uint32_t*)(&mp[4])  = 0;
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    mp[15] = len8;
  } else if (4 ==  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = 0;
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    mp[15] = 4;
  } else if (8 >   len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]) & (0xffffffff >> (64 - len8*8));
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    mp[15] = len8;
  } else if (8 ==  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    mp[15] = 8;
  } else if (12 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]) & (0xffffffff >> (96 - len8*8));
    *(uint32_t*)(&mp[12]) = 0;
    mp[15] = len8;
  } else if (12 == len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = 0;
    mp[15] = 12;
  } else if (16 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]) & (0xffffffff >> (128 - len8*8));
    mp[15] = len8;
  } else {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
  }

#endif

}

void g8A (unsigned char* s, unsigned char* c) {

#ifdef ___ENABLE_DWORD_CAST

  uint64_t s0 =  *(uint64_t*)(&s[0]);
  uint64_t s1 =  *(uint64_t*)(&s[8]);

  uint64_t c0, c1;

  c0 = ((s0 >> 1) & 0x7f7f7f7f7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x8080808080808080);
  c1 = ((s1 >> 1) & 0x7f7f7f7f7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x8080808080808080);

  *(uint64_t*)(&c[0])  = c0;
  *(uint64_t*)(&c[8])  = c1;

#else

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

#endif

}

void g8A_for_Tag_Generation (unsigned char* s, unsigned char* c) {

#ifdef ___ENABLE_DWORD_CAST

  uint64_t s0 =  *(uint64_t*)(&s[0]);
  uint64_t s1 =  *(uint64_t*)(&s[8]);

  uint64_t c0, c1;

  c0 = ((s0 >> 1) & 0x7f7f7f7f7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x8080808080808080);
  c1 = ((s1 >> 1) & 0x7f7f7f7f7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x8080808080808080);

  // use byte access because of memory alignment.
  // c is not always in word(4 byte) alignment.
  c[0]  =  c0     &0xFF;
  c[1]  = (c0>>8) &0xFF;
  c[2]  = (c0>>16)&0xFF;
  c[3]  = (c0>>24)&0xFF;
  c[4]  = (c0>>32)&0xFF;
  c[5]  = (c0>>40)&0xFF;
  c[6]  = (c0>>48)&0xFF;
  c[7]  =  c0>>56;
  c[8]  =  c1     &0xFF;
  c[9]  = (c1>>8) &0xFF;
  c[10] = (c1>>16)&0xFF;
  c[11] = (c1>>24)&0xFF;
  c[12] = (c1>>32)&0xFF;
  c[13] = (c1>>40)&0xFF;
  c[14] = (c1>>48)&0xFF;
  c[15] =  c1>>56;

#else

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

#endif

}

void rho_ad_eqov16 (
    const unsigned char* m,
    unsigned char* s) {

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&s[0])  ^= *(uint64_t*)(&m[0]);
  *(uint64_t*)(&s[8])  ^= *(uint64_t*)(&m[8]);

#else

  *(uint32_t*)(&s[0])  ^= *(uint32_t*)(&m[0]);
  *(uint32_t*)(&s[4])  ^= *(uint32_t*)(&m[4]);
  *(uint32_t*)(&s[8])  ^= *(uint32_t*)(&m[8]);
  *(uint32_t*)(&s[12]) ^= *(uint32_t*)(&m[12]);

#endif

}

void rho_ad_ud16 (
    const unsigned char* m,
    unsigned char* s,
    int len8) {

  unsigned char mp [16];
  pad(m,mp,len8);

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&s[0])  ^= *(uint64_t*)(&mp[0]);
  *(uint64_t*)(&s[8])  ^= *(uint64_t*)(&mp[8]);

#else

  *(uint32_t*)(&s[0])  ^= *(uint32_t*)(&mp[0]);
  *(uint32_t*)(&s[4])  ^= *(uint32_t*)(&mp[4]);
  *(uint32_t*)(&s[8])  ^= *(uint32_t*)(&mp[8]);
  *(uint32_t*)(&s[12]) ^= *(uint32_t*)(&mp[12]);

#endif

}

void rho_eqov16 (
    const unsigned char* m,
    unsigned char* c,
    unsigned char* s) {

  g8A(s,c);

#ifdef ___ENABLE_DWORD_CAST

  uint64_t c0 = *(uint64_t*)(&c[0]);
  uint64_t c1 = *(uint64_t*)(&c[8]);

  uint64_t s0 = *(uint64_t*)(&s[0]);
  uint64_t s1 = *(uint64_t*)(&s[8]);

  uint64_t m0 = *(uint64_t*)(&m[0]);
  uint64_t m1 = *(uint64_t*)(&m[8]);

  s0 ^= m0;
  s1 ^= m1;

  c0 ^= m0;
  c1 ^= m1;

  *(uint64_t*)(&s[0])  = s0;
  *(uint64_t*)(&s[8])  = s1;

  *(uint64_t*)(&c[0])  = c0;
  *(uint64_t*)(&c[8])  = c1;

#else

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

#endif

}

void rho_ud16 (
    const unsigned char* m,
    unsigned char* c,
    unsigned char* s,
    int len8) {

  unsigned char mp [16];

  pad(m,mp,len8);

  g8A(s,c);

#ifdef ___ENABLE_DWORD_CAST

  uint64_t mp0 = *(uint64_t*)&mp[0];
  uint64_t mp1 = *(uint64_t*)&mp[8];
  uint64_t c0  = *(uint64_t*)&c[0];
  uint64_t c1  = *(uint64_t*)&c[8];
  
  *(uint64_t*)(&s[0])  ^= mp0;
  *(uint64_t*)(&s[8])  ^= mp1;

  if (0 == len8) {
    c0 = 0;
    c1 = 0;
  } else if (8 >  len8) {
    c0 = c0 ^ (mp0 & 0xffffffffffffffff >> (64 - (len8*8)));
    c0 = c0 ^ (c0  & 0xffffffffffffffff << (     (len8*8)));
    c1 = 0;
  } else if (8 == len8) {
    c0 = c0 ^ mp0;
    c1 = 0;
  } else if (16 > len8) {
    len8 -= 8;
    c0 = c0 ^  mp0;
    c1 = c1 ^ (mp1 & 0xffffffffffffffff >> (64 - (len8*8)));
    c1 = c1 ^ (c1  & 0xffffffffffffffff << (     (len8*8)));
  } else {
    c0 = c0 ^ mp0;
    c1 = c1 ^ mp1;
  }

  *(uint64_t*)&c[0] = c0;
  *(uint64_t*)&c[8] = c1;

#else

  uint32_t mp0 = *(uint32_t*)&mp[0];
  uint32_t mp1 = *(uint32_t*)&mp[4];
  uint32_t mp2 = *(uint32_t*)&mp[8];
  uint32_t mp3 = *(uint32_t*)&mp[12];
  uint32_t c0  = *(uint32_t*)&c[0];
  uint32_t c1  = *(uint32_t*)&c[4];
  uint32_t c2  = *(uint32_t*)&c[8];
  uint32_t c3  = *(uint32_t*)&c[12];
  
  *(uint32_t*)(&s[0])   ^= mp0;
  *(uint32_t*)(&s[4])   ^= mp1;
  *(uint32_t*)(&s[8])   ^= mp2;
  *(uint32_t*)(&s[12])  ^= mp3;

  if (0 == len8) {
    c0 = 0;
    c1 = 0;
    c2 = 0;
    c3 = 0;
  } else if (4 >  len8) {
    c0 = c0 ^ (mp0 & 0xffffffff >> (32 - (len8*8)));
    c0 = c0 ^ (c0  & 0xffffffff << (     (len8*8)));
    c1 = 0;
    c2 = 0;
    c3 = 0;
  } else if (4 == len8) {
    c0 = c0 ^  mp0;
    c1 = 0;
    c2 = 0;
    c3 = 0;
  } else if (8 >  len8) {
    len8 -= 4;
    c0 = c0 ^  mp0;
    c1 = c1 ^ (mp1 & 0xffffffff >> (32 - (len8*8)));
    c1 = c1 ^ (c1  & 0xffffffff << (     (len8*8)));
    c2 = 0;
    c3 = 0;
  } else if (8 == len8) {
    c0 = c0 ^  mp0;
    c1 = c1 ^  mp1;
    c2 = 0;
    c3 = 0;
  } else if (12 > len8) {
    len8 -= 8;
    c0 = c0 ^  mp0;
    c1 = c1 ^  mp1;
    c2 = c2 ^ (mp2 & 0xffffffff >> (32 - (len8*8)));
    c2 = c2 ^ (c2  & 0xffffffff << (     (len8*8)));
    c3 = 0;
  } else if (12 == len8) {
    c0 = c0 ^  mp0;
    c1 = c1 ^  mp1;
    c2 = c2 ^  mp2;
    c3 = 0;
  } else if (16 > len8) {
    len8 -= 12;
    c0 = c0 ^  mp0;
    c1 = c1 ^  mp1;
    c2 = c2 ^  mp2;
    c3 = c3 ^ (mp3 & 0xffffffff >> (32 - (len8*8)));
    c3 = c3 ^ (c3  & 0xffffffff << (     (len8*8)));
  } else {
    c0 = c0 ^  mp0;
    c1 = c1 ^  mp1;
    c2 = c2 ^  mp2;
    c3 = c3 ^  mp3;
  } 

  *(uint32_t*)&c[0]  = c0;
  *(uint32_t*)&c[4]  = c1;
  *(uint32_t*)&c[8]  = c2;
  *(uint32_t*)&c[12] = c3;

#endif

}

void irho_eqov16 (
    unsigned char* m,
    const unsigned char* c,
    unsigned char* s) {

  g8A(s,m);

#ifdef ___ENABLE_DWORD_CAST

  uint64_t c0 = *(uint64_t*)(&c[0]);
  uint64_t c1 = *(uint64_t*)(&c[8]);

  uint64_t s0 = *(uint64_t*)(&s[0]);
  uint64_t s1 = *(uint64_t*)(&s[8]);

  uint64_t m0 = *(uint64_t*)(&m[0]);
  uint64_t m1 = *(uint64_t*)(&m[8]);

  s0 ^= c0 ^ m0;
  s1 ^= c1 ^ m1;

  m0 ^= c0;
  m1 ^= c1;

  *(uint64_t*)(&s[0])  = s0;
  *(uint64_t*)(&s[8])  = s1;

  *(uint64_t*)(&m[0])  = m0;
  *(uint64_t*)(&m[8])  = m1;

#else

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

#endif

}

void irho_ud16 (
    unsigned char* m,
    const unsigned char* c,
    unsigned char* s,
    int len8) {

  unsigned char cp [16];

  pad(c,cp,len8);

  g8A(s,m);

#ifdef ___ENABLE_DWORD_CAST

  uint64_t cp0 = *(uint64_t*)&cp[0];
  uint64_t cp1 = *(uint64_t*)&cp[8];
  uint64_t m0  = *(uint64_t*)&m[0];
  uint64_t m1  = *(uint64_t*)&m[8];
  uint64_t s0  = *(uint64_t*)&s[0];
  uint64_t s1  = *(uint64_t*)&s[8];

  s0 ^= cp0;
  s1 ^= cp1;

  if (0 == len8) {
    m0 = 0;
    m1 = 0;
  } else if (8 >  len8) {
    s0 = s0 ^ (m0  & 0xffffffffffffffff >> (64 - (len8*8)));

    m0 = m0 ^ (cp0 & 0xffffffffffffffff >> (64 - (len8*8)));
    m0 = m0 ^ (m0  & 0xffffffffffffffff << (     (len8*8)));
    m1 = 0;
  } else if (8 == len8) {
    s0 = s0 ^  m0;

    m0 = m0 ^  cp0;
    m1 = 0;
  } else if (16 >  len8) {
    len8 -= 8;
    s0 = s0 ^  m0;
    s1 = s1 ^ (m1  & 0xffffffffffffffff >> (64 - (len8*8)));

    m0 = m0 ^  cp0;
    m1 = m1 ^ (cp1 & 0xffffffffffffffff >> (64 - (len8*8)));
    m1 = m1 ^ (m1  & 0xffffffffffffffff << (     (len8*8)));
  } else {
    s0 = s0 ^  m0;
    s1 = s1 ^  m1;

    m0 = m0 ^  cp0;
    m1 = m1 ^  cp1;
  }

  *(uint64_t*)&s[0] = s0;
  *(uint64_t*)&s[8] = s1;
  *(uint64_t*)&m[0] = m0;
  *(uint64_t*)&m[8] = m1;

#else

  uint32_t cp0 = *(uint32_t*)&cp[0];
  uint32_t cp1 = *(uint32_t*)&cp[4];
  uint32_t cp2 = *(uint32_t*)&cp[8];
  uint32_t cp3 = *(uint32_t*)&cp[12];
  uint32_t m0  = *(uint32_t*)&m[0];
  uint32_t m1  = *(uint32_t*)&m[4];
  uint32_t m2  = *(uint32_t*)&m[8];
  uint32_t m3  = *(uint32_t*)&m[12];
  uint32_t s0  = *(uint32_t*)&s[0];
  uint32_t s1  = *(uint32_t*)&s[4];
  uint32_t s2  = *(uint32_t*)&s[8];
  uint32_t s3  = *(uint32_t*)&s[12];

  s0 ^= cp0;
  s1 ^= cp1;
  s2 ^= cp2;
  s3 ^= cp3;

  if (0 == len8) {
    m0 = 0;
    m1 = 0;
    m2 = 0;
    m3 = 0;
  } else if (4 >  len8) {
    s0 = s0 ^ (m0  & 0xffffffff >> (32 - (len8*8)));

    m0 = m0 ^ (cp0 & 0xffffffff >> (32 - (len8*8)));
    m0 = m0 ^ (m0  & 0xffffffff << (     (len8*8)));
    m1 = 0;
    m2 = 0;
    m3 = 0;
  } else if (4 == len8) {
    s0 = s0 ^  m0;

    m0 = m0 ^  cp0;
    m1 = 0;
    m2 = 0;
    m3 = 0;
  } else if (8 >  len8) {
    len8 -= 4;
    s0 = s0 ^  m0;
    s1 = s1 ^ (m1  & 0xffffffff >> (32 - (len8*8)));

    m0 = m0 ^  cp0;
    m1 = m1 ^ (cp1 & 0xffffffff >> (32 - (len8*8)));
    m1 = m1 ^ (m1  & 0xffffffff << (     (len8*8)));
    m2 = 0;
    m3 = 0;
  } else if (8 == len8) {
    s0 = s0 ^  m0;
    s1 = s1 ^  m1;

    m0 = m0 ^  cp0;
    m1 = m1 ^  cp1;
    m2 = 0;
    m3 = 0;
  } else if (12 >  len8) {
    len8 -= 8;
    s0 = s0 ^  m0;
    s1 = s1 ^  m1;
    s2 = s2 ^ (m2  & 0xffffffff >> (32 - (len8*8)));

    m0 = m0 ^  cp0;
    m1 = m1 ^  cp1;
    m2 = m2 ^ (cp2 & 0xffffffff >> (32 - (len8*8)));
    m2 = m2 ^ (m2  & 0xffffffff << (     (len8*8)));
    m3 = 0;
  } else if (12 == len8) {
    s0 = s0 ^  m0;
    s1 = s1 ^  m1;
    s2 = s2 ^  m2;

    m0 = m0 ^  cp0;
    m1 = m1 ^  cp1;
    m2 = m2 ^  cp2;
    m3 = 0;
  } else if (16 >  len8) {
    len8 -= 12;
    s0 = s0 ^  m0;
    s1 = s1 ^  m1;
    s2 = s2 ^  m2;
    s3 = s3 ^ (m3  & 0xffffffff >> (32 - (len8*8)));

    m0 = m0 ^  cp0;
    m1 = m1 ^  cp1;
    m2 = m2 ^  cp2;
    m3 = m3 ^ (cp3 & 0xffffffff >> (32 - (len8*8)));
    m3 = m3 ^ (m3  & 0xffffffff << (     (len8*8)));
  } else {
    s0 = s0 ^  m0;
    s1 = s1 ^  m1;
    s2 = s2 ^  m2;
    s3 = s3 ^  m3;

    m0 = m0 ^  cp0;
    m1 = m1 ^  cp1;
    m2 = m2 ^  cp2;
    m3 = m3 ^  cp3;
  }

  *(uint32_t*)&s[0]  = s0;
  *(uint32_t*)&s[4]  = s1;
  *(uint32_t*)&s[8]  = s2;
  *(uint32_t*)&s[12] = s3;
  *(uint32_t*)&m[0]  = m0;
  *(uint32_t*)&m[4]  = m1;
  *(uint32_t*)&m[8]  = m2;
  *(uint32_t*)&m[12] = m3;

#endif

}

void reset_lfsr_gf56 (unsigned char* CNT) {

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&CNT[0]) = 0x0000000000000001; // CNT7 CNT6 CNT5 CNT4 CNT3 CNT2 CNT1 CNT0

#else

  *(uint32_t*)(&CNT[0]) = 0x00000001; // CNT3 CNT2 CNT1 CNT0
  *(uint32_t*)(&CNT[4]) = 0x00000000; // CNT7 CNT6 CNT5 CNT4

#endif

}

void lfsr_gf56 (unsigned char* CNT) {

#ifdef ___ENABLE_DWORD_CAST

  uint64_t C0;
  uint64_t fb0;

  C0 = *(uint64_t*)(&CNT[0]); // CNT7 CNT6 CNT5 CNT4 CNT3 CNT2 CNT1 CNT0

  fb0 = 0;
  if (CNT[6] & 0x80) {
    fb0 =  0x95;
  }

  C0 = C0 << 1 ^ fb0;

  *(uint64_t*)(&CNT[0]) = C0;

#else

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

  g8A_for_Tag_Generation(s, *c);

  *c = *c + 16;
  *c = *c - *clen;

}

unsigned long long msg_encryption (
    const unsigned char** M, unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long mlen,
    skinny_ctrl* l_skinny_ctrl) {

  int len8;

  if (mlen >= 16) {
    len8 = 16;
    mlen = mlen - 16;
    rho_eqov16(*M, *c, s);
  }
  else {
    len8 = mlen;
    mlen = 0;
    rho_ud16(*M, *c, s, len8);
  }
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf56(CNT);
  if (mlen != 0) {
    nonce_encryption(N,CNT,s,k,D,l_skinny_ctrl);
  }
  return mlen;

}

unsigned long long msg_decryption (
    unsigned char** M, const unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long clen,
    skinny_ctrl* l_skinny_ctrl) {

  int len8;

  if (clen >= 16) {
    len8 = 16;
    clen = clen - 16;
    irho_eqov16(*M, *c, s);
  }
  else {
    len8 = clen;
    clen = 0;
    irho_ud16(*M, *c, s, len8);
  }
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,l_skinny_ctrl);
  return clen;

}

unsigned long long ad2msg_encryption (
    const unsigned char** M,
    unsigned char* CNT,
    unsigned char*s, const unsigned char* k,
    unsigned char D,
    unsigned long long mlen,
    skinny_ctrl* l_skinny_ctrl) {

  unsigned char T [16];
  int len8;

  if (mlen <= 16) {
    len8 = mlen;
    mlen = 0;
  }
  else {
    len8 = 16;
    mlen = mlen - 16;
  }

  pad (*M,T,len8);
  block_cipher(s,k,T,CNT,D,l_skinny_ctrl);
  lfsr_gf56(CNT);
  *M = *M + len8;

  return mlen;

}

unsigned long long ad_encryption (
    const unsigned char** A, unsigned char* s,
    const unsigned char* k, unsigned long long adlen,
    unsigned char* CNT,
    unsigned char D,
    skinny_ctrl* l_skinny_ctrl) {

  unsigned char T [16];
  int len8;

  if (adlen >= 16) {
    len8 = 16;
    adlen = adlen - 16;

    rho_ad_eqov16(*A, s);
  }
  else {
    len8 = adlen;
    adlen = 0;
    rho_ad_ud16(*A, s, len8);
  }
  *A = *A + len8;
  lfsr_gf56(CNT);
  if (adlen != 0) {
    if (adlen >= 16) {
      len8 = 16;
      adlen = adlen - 16;
    }
    else {
      len8 = adlen;
      adlen = 0;
    }
    pad(*A, T, len8);
    *A = *A + len8;
    block_cipher(s,k,T,CNT,D,l_skinny_ctrl);
    lfsr_gf56(CNT);
  }

  return adlen;

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
  unsigned char T[16];
  const unsigned char* N;
  unsigned char w;
  unsigned long long xlen;

  skinny_ctrl l_skinny_ctrl;
  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

  (void)nsec;
  N = npub;

  xlen = mlen;

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&s[0])  = 0;
  *(uint64_t*)(&s[8])  = 0;

#else

  *(uint32_t*)(&s[0])  = 0;
  *(uint32_t*)(&s[4])  = 0;
  *(uint32_t*)(&s[8])  = 0;
  *(uint32_t*)(&s[12]) = 0;

#endif

  reset_lfsr_gf56(CNT);

  w = 48;

  if (adlen == 0) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(32) == 0) {
    w = w ^ 8;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(32) < 16) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(32) == 16) {
    w = w ^ 0;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else {
    w = w ^ 10;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
  }
  else while (adlen > 0) {
      adlen = ad_encryption(&ad,s,k,adlen,CNT,40,&l_skinny_ctrl);
    }

  if ((w & 8) == 0) {
    xlen = ad2msg_encryption (&m,CNT,s,k,44,xlen,&l_skinny_ctrl);
  }
  else if (mlen == 0) {
    lfsr_gf56(CNT);
  }
  while (xlen > 0) {
    xlen = ad_encryption(&m,s,k,xlen,CNT,44,&l_skinny_ctrl);
  }
  nonce_encryption(N,CNT,s,k,w,&l_skinny_ctrl);

  // Tag generation
  g8A(s, T);

  m = m - mlen;

  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

  reset_lfsr_gf56(CNT);

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&s[0])  = *(uint64_t*)(&T[0]);
  *(uint64_t*)(&s[8])  = *(uint64_t*)(&T[8]);

#else

  *(uint32_t*)(&s[0])  = *(uint32_t*)(&T[0]);
  *(uint32_t*)(&s[4])  = *(uint32_t*)(&T[4]);
  *(uint32_t*)(&s[8])  = *(uint32_t*)(&T[8]);
  *(uint32_t*)(&s[12]) = *(uint32_t*)(&T[12]);

#endif

  *clen = mlen + 16;

  if (mlen > 0) {
    nonce_encryption(N,CNT,s,k,36,&l_skinny_ctrl);
    while (mlen > 16) {
      mlen = msg_encryption(&m,&c,N,CNT,s,k,36,mlen,&l_skinny_ctrl);
    }
    rho_ud16(m, c, s, mlen);
    c = c + mlen;
    m = m + mlen;
  }

  // Tag Concatenation
  c[0]  = T[0];
  c[1]  = T[1];
  c[2]  = T[2];
  c[3]  = T[3];
  c[4]  = T[4];
  c[5]  = T[5];
  c[6]  = T[6];
  c[7]  = T[7];
  c[8]  = T[8];
  c[9]  = T[9];
  c[10] = T[10];
  c[11] = T[11];
  c[12] = T[12];
  c[13] = T[13];
  c[14] = T[14];
  c[15] = T[15];

  c = c - *clen;

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
  unsigned char CNT[8];
  unsigned char T[16];
  const unsigned char* N;
  unsigned char w;
  unsigned long long xlen;
  const unsigned char* mauth;
  unsigned char* p1;
  unsigned char* p2;

  skinny_ctrl l_skinny_ctrl;
  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

  (void)nsec;
  mauth = m;

  N = npub;

  xlen = clen-16;

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&s[0])  = 0;
  *(uint64_t*)(&s[8])  = 0;

#else

  *(uint32_t*)(&s[0])  = 0;
  *(uint32_t*)(&s[4])  = 0;
  *(uint32_t*)(&s[8])  = 0;
  *(uint32_t*)(&s[12]) = 0;

#endif

  reset_lfsr_gf56(CNT);

  w = 48;

  if (adlen == 0) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(32) == 0) {
    w = w ^ 8;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(32) < 16) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(32) == 16) {
    w = w ^ 0;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else {
    w = w ^ 10;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(32) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(32) < 16) {
      w = w ^ 1;
    }
    else if (xlen%(32) == 16) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
  }
  else while (adlen > 0) {
      adlen = ad_encryption(&ad,s,k,adlen,CNT,40,&l_skinny_ctrl);
    }

  if ((w & 8) == 0) {
    xlen = ad2msg_encryption (&mauth,CNT,s,k,44,xlen,&l_skinny_ctrl);
  }
  else if (clen == 0) {
    lfsr_gf56(CNT);
  }
  while (xlen > 0) {
    xlen = ad_encryption(&mauth,s,k,xlen,CNT,44,&l_skinny_ctrl);
  }
  nonce_encryption(N,CNT,s,k,w,&l_skinny_ctrl);

  // Tag generation
  g8A(s, T);

  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

  reset_lfsr_gf56(CNT);

  p1 = T;
  p2 = (unsigned char*)&c[clen - 16];

  p1[0]  = p2[0];
  p1[1]  = p2[1];
  p1[2]  = p2[2];
  p1[3]  = p2[3];
  p1[4]  = p2[4];
  p1[5]  = p2[5];
  p1[6]  = p2[6];
  p1[7]  = p2[7];
  p1[8]  = p2[8];
  p1[9]  = p2[9];
  p1[10] = p2[10];
  p1[11] = p2[11];
  p1[12] = p2[12];
  p1[13] = p2[13];
  p1[14] = p2[14];
  p1[15] = p2[15];

#ifdef ___ENABLE_DWORD_CAST

  *(uint64_t*)(&s[0])  = *(uint64_t*)(&T[0]);
  *(uint64_t*)(&s[8])  = *(uint64_t*)(&T[8]);

#else

  *(uint32_t*)(&s[0])  = *(uint32_t*)(&T[0]);
  *(uint32_t*)(&s[4])  = *(uint32_t*)(&T[4]);
  *(uint32_t*)(&s[8])  = *(uint32_t*)(&T[8]);
  *(uint32_t*)(&s[12]) = *(uint32_t*)(&T[12]);

#endif

  clen = clen - 16;
  *mlen = clen;

  if (clen > 0) {
    nonce_encryption(N,CNT,s,k,36,&l_skinny_ctrl);

    l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

    while (clen > 16) {
      clen = msg_decryption(&m,&c,N,CNT,s,k,36,clen,&l_skinny_ctrl);
    }
    irho_ud16(m, c, s, clen);
    c = c + clen;
    m = m + clen;
  }

  for (int i = 0; i < 16; i++) {
    if (T[i] != (*(c+i))) {
      return -1;
    }
  }

  return 0;

}
