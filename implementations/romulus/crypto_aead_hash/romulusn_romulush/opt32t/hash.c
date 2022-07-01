#include "hash_skinny.h"
#include <stdio.h>
#include <stdlib.h>

void hirose_128_128_256 (
  unsigned char* h,
  unsigned char* g,
  const unsigned char* m,
  hash_skinny_ctrl* pctrl) {

  unsigned char key [16];
  unsigned char hh  [16];

  // assign the key for the
  // hirose compresison function

  *(uint32_t*)(&key[0])  = *(uint32_t*)(&g[0]);
  *(uint32_t*)(&key[4])  = *(uint32_t*)(&g[4]);
  *(uint32_t*)(&key[8])  = *(uint32_t*)(&g[8]);
  *(uint32_t*)(&key[12]) = *(uint32_t*)(&g[12]);
//  *(uint32_t*)(&g[0])    = *(uint32_t*)(&h[0]);
//  *(uint32_t*)(&g[4])    = *(uint32_t*)(&h[4]);
//  *(uint32_t*)(&g[8])    = *(uint32_t*)(&h[8]);
//  *(uint32_t*)(&g[12])   = *(uint32_t*)(&h[12]);
  *(uint32_t*)(&hh[0])   = *(uint32_t*)(&h[0]);
  *(uint32_t*)(&hh[4])   = *(uint32_t*)(&h[4]);
  *(uint32_t*)(&hh[8])   = *(uint32_t*)(&h[8]);
  *(uint32_t*)(&hh[12])  = *(uint32_t*)(&h[12]);

//  g[0] ^= 0x01;

  pctrl->func_skinny_128_384_enc(h, g, pctrl, key, (unsigned char*)m);

  *(uint32_t*)(&h[0])  ^= *(uint32_t*)(&hh[0]);
  *(uint32_t*)(&h[4])  ^= *(uint32_t*)(&hh[4]);
  *(uint32_t*)(&h[8])  ^= *(uint32_t*)(&hh[8]);
  *(uint32_t*)(&h[12]) ^= *(uint32_t*)(&hh[12]);
  *(uint32_t*)(&g[0])  ^= *(uint32_t*)(&hh[0]);
  *(uint32_t*)(&g[4])  ^= *(uint32_t*)(&hh[4]);
  *(uint32_t*)(&g[8])  ^= *(uint32_t*)(&hh[8]);
  *(uint32_t*)(&g[12]) ^= *(uint32_t*)(&hh[12]);

  g[0] ^= 0x01;

}

void initialize (
  unsigned char* h,
  unsigned char* g) {

  *(uint32_t*)(&h[0])  = 0;
  *(uint32_t*)(&h[4])  = 0;
  *(uint32_t*)(&h[8])  = 0;
  *(uint32_t*)(&h[12]) = 0;
  *(uint32_t*)(&g[0])  = 0;
  *(uint32_t*)(&g[4])  = 0;
  *(uint32_t*)(&g[8])  = 0;
  *(uint32_t*)(&g[12]) = 0;

}

void hash_pad (
  const unsigned char* m,
  unsigned char* mp,
  int len8) {

  if (0 == len8) {
    *(uint32_t*)(&mp[0])  = 0;
    *(uint32_t*)(&mp[4])  = 0;
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
  } else if (4 >   len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]) & (0xffffffff >> (32 - len8*8));
    *(uint32_t*)(&mp[4])  = 0;
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (4 ==  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = 0;
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 4;
  } else if (8 >   len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]) & (0xffffffff >> (64 - len8*8));
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (8 ==  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = 0;
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 8;
  } else if (12 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]) & (0xffffffff >> (96 - len8*8));
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (12 == len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = 0;
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 12;
  } else if (16 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]) & (0xffffffff >> (128 - len8*8));
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (16 == len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = 0;
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 16;
  } else if (20 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]) & (0xffffffff >> (160 - len8*8));
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (20 == len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = 0;
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 20;
  } else if (24 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = *(uint32_t*)(&m[20]) & (0xffffffff >> (192 - len8*8));
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (24 == len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = *(uint32_t*)(&m[20]);
    *(uint32_t*)(&mp[24]) = 0;
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 24;
  } else if (28 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = *(uint32_t*)(&m[20]);
    *(uint32_t*)(&mp[24]) = *(uint32_t*)(&m[24]) & (0xffffffff >> (224 - len8*8));
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = len8;
  } else if (28 == len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = *(uint32_t*)(&m[20]);
    *(uint32_t*)(&mp[24]) = *(uint32_t*)(&m[24]);
    *(uint32_t*)(&mp[28]) = 0;
    mp[31] = 28;
  } else if (32 >  len8) {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = *(uint32_t*)(&m[20]);
    *(uint32_t*)(&mp[24]) = *(uint32_t*)(&m[24]);
    *(uint32_t*)(&mp[28]) = *(uint32_t*)(&m[28]) & (0xffffffff >> (256 - len8*8));
    mp[31] = len8;
  } else {
    *(uint32_t*)(&mp[0])  = *(uint32_t*)(&m[0]);
    *(uint32_t*)(&mp[4])  = *(uint32_t*)(&m[4]);
    *(uint32_t*)(&mp[8])  = *(uint32_t*)(&m[8]);
    *(uint32_t*)(&mp[12]) = *(uint32_t*)(&m[12]);
    *(uint32_t*)(&mp[16]) = *(uint32_t*)(&m[16]);
    *(uint32_t*)(&mp[20]) = *(uint32_t*)(&m[20]);
    *(uint32_t*)(&mp[24]) = *(uint32_t*)(&m[24]);
    *(uint32_t*)(&mp[28]) = *(uint32_t*)(&m[28]);
  }

}

int crypto_hash(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen) {

  unsigned char h[16];
  unsigned char g[16];
  unsigned long long mlen;
  unsigned char p[32];

  hash_skinny_ctrl ctrl;
  ctrl.func_skinny_128_384_enc = hash_skinny_128_384_enc_32_main;

  mlen = inlen;

  initialize(h,g);
  while (mlen >= 32) { // Normal loop
    hirose_128_128_256(h,g,in,&ctrl);
    in += 32;
    mlen -= 32;
  }
  hash_pad(in,p,mlen);
  h[0] ^= 2;
  hirose_128_128_256(h,g,p,&ctrl);

  *(uint32_t*)(&out[0])  = *(uint32_t*)(&h[0]);
  *(uint32_t*)(&out[4])  = *(uint32_t*)(&h[4]);
  *(uint32_t*)(&out[8])  = *(uint32_t*)(&h[8]);
  *(uint32_t*)(&out[12]) = *(uint32_t*)(&h[12]);
  *(uint32_t*)(&out[16]) = *(uint32_t*)(&g[0]);
  *(uint32_t*)(&out[20]) = *(uint32_t*)(&g[4]);
  *(uint32_t*)(&out[24]) = *(uint32_t*)(&g[8]);
  *(uint32_t*)(&out[28]) = *(uint32_t*)(&g[12]);

  return 0;
}
