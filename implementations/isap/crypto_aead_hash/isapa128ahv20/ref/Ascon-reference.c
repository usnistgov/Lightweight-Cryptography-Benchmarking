#include <stdio.h>
#include <assert.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;

/* ---------------------------------------------------------------- */

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

/* ---------------------------------------------------------------- */

void load64(u64* x, u8* S) {
  int i;
  *x = 0;
  for (i = 0; i < 8; ++i)
    *x |= ((u64) S[i]) << (56 - i * 8);
}

/* ---------------------------------------------------------------- */

void store64(u8* S, u64 x) {
  int i;
  for (i = 0; i < 8; ++i)
    S[i] = (u8) (x >> (56 - i * 8));
}

/* ---------------------------------------------------------------- */

void Ascon_Initialize(void *S){
  memset(S,0,40);
}

/* ---------------------------------------------------------------- */

void Ascon_AddBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length){
  unsigned int i;
  assert(offset < 40);
  assert(offset+length <= 40);
  for(i=0; i<length; i++){
    ((unsigned char *)state)[offset+i] ^= data[i];
  }
}

/* ---------------------------------------------------------------- */

void Ascon_OverwriteBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length){
  unsigned int i;
  assert(offset < 40);
  assert(offset+length <= 40);
  for(i=0; i<length; i++){
    ((unsigned char *)state)[offset+i] = data[i];
  }
}

/* ---------------------------------------------------------------- */

void Ascon_Permute_Nrounds(u8 *S, unsigned int rounds){
  assert(rounds <= 12);
  int start = 12 - rounds;
  unsigned int i;
  u64 x0, x1, x2, x3, x4;
  u64 t0, t1, t2, t3, t4;
  load64(&x0, S + 0);
  load64(&x1, S + 8);
  load64(&x2, S + 16);
  load64(&x3, S + 24);
  load64(&x4, S + 32);
  for (i = start; i < rounds + start; ++i) {
    // addition of round constant
    x2 ^= ((0xfull - i) << 4) | i;
    // substitution layer
    x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
    t0  = x0;    t1  = x1;    t2  = x2;    t3  = x3;    t4  = x4;
    t0 =~ t0;    t1 =~ t1;    t2 =~ t2;    t3 =~ t3;    t4 =~ t4;
    t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
    x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
    x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 =~ x2;
    // linear diffusion layer
    x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
    x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
    x2 ^= ROTR(x2,  1) ^ ROTR(x2,  6);
    x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
    x4 ^= ROTR(x4,  7) ^ ROTR(x4, 41);
  }
  store64(S + 0, x0);
  store64(S + 8, x1);
  store64(S + 16, x2);
  store64(S + 24, x3);
  store64(S + 32, x4);
}

/* ---------------------------------------------------------------- */

void Ascon_ExtractBytes(const void *state, unsigned char *data, unsigned int offset, unsigned int length){
  assert(offset < 40);
  assert(offset+length <= 40);
  memcpy(data, (unsigned char*)state+offset, length);
}
