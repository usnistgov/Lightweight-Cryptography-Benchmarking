/*
 * Date: 04 May 2021
 * Contact: Romulus Team (Mustafa Khairallah - mustafa.khairallah@ntu.edu.sg)
 * Romulus-T as compliant with the Romulus v1.3 specifications. 
 * This file icludes crypto_aead_encrypt()
  */

#include "crypto_aead.h"
#include "romulus_t_hash.h"
#include "api.h"
#include "variant.h"
#include "skinny.h"
#include "romulus_t.h"

// Resets the value of the counter.
void reset_lfsr_gf56 (unsigned char* CNT) {
  CNT[0] = 0x01;
  CNT[1] = 0x00;
  CNT[2] = 0x00;
  CNT[3] = 0x00;
  CNT[4] = 0x00;
  CNT[5] = 0x00;
  CNT[6] = 0x00;
}

// Applies CNT'=2 * CNT (mod GF(2^56)), where GF(2^56) is defined using the irreducible polynomial
// x^56 + x^7 + x^4 + x^2 + 1
void lfsr_gf56 (unsigned char* CNT) {
  unsigned char fb0;
  
  fb0 = CNT[6] >> 7;
  
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
}

// Combines the secret key, counter and domain bits to form the full 384-bit tweakey
void compose_tweakey (unsigned char* KT,
			      const unsigned char* K,
			      unsigned char* T,
			      unsigned char* CNT,
			      unsigned char D) {

  int i;

  for (i = 0; i < 7; i++) {
    KT[i] = CNT[i];
  }
  KT[i] = D;
  for (i = 8; i < 16; i++) {
    KT[i] = 0x00;
  }
  for (i = 0; i < 16; i++) {
    KT[i+16] = T[i];
  }
  for (i = 0; i < 16; i++) {
    KT[i+32] = K[i];
  }

}

// An interface between Romulus and the underlying TBC
void block_cipher(unsigned char* s,
		  const unsigned char* K,
		  unsigned char* T,
		  unsigned char* CNT, unsigned char D) {
  unsigned char KT [48];

  compose_tweakey(KT,K,T,CNT,D);
  skinny_128_384_plus_enc (s,KT);

}

// Initialization function: KDF
void kdf (const unsigned char* K, unsigned char* Z, const unsigned char* N, unsigned char* CNT) {  

  int i;
  unsigned char T[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  for (i = 0; i < 16; i++) {
    Z[i] = N[i];
  }

  block_cipher (Z,K,T,CNT,66); 
}

// Encrypts the message blocks.
unsigned long long msg_encryption (const unsigned char** M, unsigned char** C,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char* Z,				   
				   unsigned long long mlen) {

  unsigned char S[16];
  unsigned char T[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  int len8, i;
  
  if (mlen >= 16) {
    len8 = 16;
    mlen = mlen - 16;
  }
  else {
    len8 = mlen;
    mlen = 0;
  }

  for (i = 0; i < 16; i++) {
    S[i] = N[i];
  }

  block_cipher(S,Z,T,CNT,64);
  
  for (i = 0; i < len8; i++) {
    (*C)[i] = (*M)[i] ^ S[i];
  }
  *C = *C + len8;
  *M = *M + len8;

  for (i = 0; i < 16; i++) {
    S[i] = N[i];
  }

  if (mlen != 0) {
    block_cipher(S,Z,T,CNT,65);

    for (i = 0; i < 16; i++) {
      Z[i] = S[i];
    }
  }


  lfsr_gf56(CNT);

  return mlen;
  
}

// Decrypts the message blocks.
unsigned long long msg_decryption (unsigned char** M, const unsigned char** C,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char* Z,				   
				   unsigned long long clen) {

  unsigned char S[16];
  unsigned char T[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  int len8, i;
  
  if (clen >= 16) {
    len8 = 16;
    clen = clen - 16;
  }
  else {
    len8 = clen;
    clen = 0;
  }

  for (i = 0; i < 16; i++) {
    S[i] = N[i];
  }

  block_cipher(S,Z,T,CNT,64);
  
  for (i = 0; i < len8; i++) {
    (*M)[i] = (*C)[i] ^ S[i];
  }
  *C = *C + len8;
  *M = *M + len8;

  for (i = 0; i < 16; i++) {
    S[i] = N[i];
  }

  if (clen != 0) {
    block_cipher(S,Z,T,CNT,65);

    for (i = 0; i < 16; i++) {
      Z[i] = S[i];
    }
  }

  lfsr_gf56(CNT);

  

  return clen;
  
}

// Generates the tag T from the final state S by applying the Tag Generation Function (TGF).
void generate_tag (unsigned char* T, unsigned char* L,
		   unsigned char* CNT, const unsigned char* K) {

  int i;
  block_cipher(L,K,L+16,CNT,68);

  for (i = 0; i < 16; i++) {
    T[i] = L[i];
  }

}


// This function is required for Romulus-T. It assumes that the input comes in three parts that can
// be stored in different locations in the memory. It processes these inputs sequentially.
// The padding is ipad_256(ipad*_128(A)||ipad*_128(C)||N|| CNT )
// A and C are of variable length, while N is of 16 bytes and CNT is of 7 bytes

int crypto_hash_vector(
		       unsigned char *out,
		       const unsigned char *A,
		       unsigned long long adlen,
		       const unsigned char *C,
		       unsigned long long clen,
		       const unsigned char *N,
		       unsigned char *CNT
		       )
{
  unsigned char h[16];
  unsigned char g[16];
  unsigned char p[32];
  unsigned char i, n, adempty, cempty;

  n = 16;

  if (adlen == 0) {
    adempty = 1;
  }
  else {
    adempty = 0;
  }

  if (clen == 0) {
    cempty = 1;
  }
  else {
    cempty = 0;
  }
  
  reset_lfsr_gf56(CNT);

  initialize(h,g);
  while (adlen >= 32) { // AD Normal loop
    hirose_128_128_256(h,g,A);
    A += 32;
    adlen -= 32;
  }
  // Partial block (or in case there is no partial block we add a 0^2n block
  if (adlen >= 16) {
    ipad_128(A,p,32,adlen);
    hirose_128_128_256(h,g,p);
  }
  else if ((adlen >= 0) && (adempty == 0)) {
    ipad_128(A,p,16,adlen);
    adlen = 0;
    if (clen >= 16) {
      for (i = 0; i < 16; i++) {
	p[i+16] = C[i];	
      }
      hirose_128_128_256(h,g,p);
      lfsr_gf56(CNT);
      clen -= 16;
      C += 16;      
    }
    else if (clen > 0) {
      ipad_128(C,p+16,16,clen);
      hirose_128_128_256(h,g,p);
      clen = 0;
      cempty = 1;
      C += 16;
      lfsr_gf56(CNT);
    }
    else {
      for (i = 0; i < 16; i++) { // Pad the nonce
	p[i+16] = N[i];	
      }
      hirose_128_128_256(h,g,p);
      n = 0;
    }
  }
  
  while (clen >= 32) { // C Normal loop
    hirose_128_128_256(h,g,C);
    C += 32;
    clen -= 32;
    lfsr_gf56(CNT);
    lfsr_gf56(CNT);
  }
  if (clen > 16) {
    ipad_128(C,p,32,clen);
    hirose_128_128_256(h,g,p);
    lfsr_gf56(CNT);
    lfsr_gf56(CNT);
  }
  else if (clen == 16) {
    ipad_128(C,p,32,clen);
    hirose_128_128_256(h,g,p);
    lfsr_gf56(CNT);
  }
  else if ((clen >= 0) && (cempty == 0)) {
    ipad_128(C,p,16,clen);
    if (clen > 0) {
      lfsr_gf56(CNT);
    }
    for (i = 0; i < 16; i++) { // Pad the nonce
      p[i+16] = N[i];	
    }
    hirose_128_128_256(h,g,p);
    n = 0;
  }

  if (n == 16) {
    for (i = 0; i < 16; i++) { // Pad the nonce and counter
      p[i] = N[i];      
    }
    for (i = 16; i < 23; i++) {
      p[i] = CNT[i-16];      
    }
    ipad_256(p,p,32,23);
  }
  else {
    ipad_256(CNT,p,32,7);
  }
  h[0] ^= 2;
  hirose_128_128_256(h,g,p);
  
  for (i = 0; i < 16; i++) { // Assign the output tag
    out[i] = h[i];
    out[i+16] = g[i];
  }

  return 0;
  
}




int romulus_t_encrypt (
			 unsigned char* c, unsigned long long* clen,
			 const unsigned char* m, unsigned long long mlen,
			 const unsigned char* ad, unsigned long long adlen,
			 const unsigned char* nsec,
			 const unsigned char* npub,
			 const unsigned char* k
			 )
{
  unsigned char Z[16];
  unsigned char CNT[7];
  unsigned char CNT_Z[7] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  const unsigned char* A;
  const unsigned char* M;
  const unsigned char* N;
  unsigned long long mlen_int;
  unsigned char LR [32];
  unsigned int i;

  (void) nsec;
  A = ad;
  M = m;
  N = npub; 
     
  reset_lfsr_gf56(CNT);

  kdf(k,Z,N,CNT_Z);
  *clen = mlen+16;
  mlen_int = mlen;
  
  while (mlen != 0) {    
    mlen = msg_encryption(&M,&c,N,CNT,Z,mlen);    
  }

  // T = hash(A||N||M)
  // We need to first pad A, N and C
  c = c - mlen_int;
  i = crypto_hash_vector(LR,A,adlen,c,mlen_int,N,CNT);
  

  //reset_lfsr_gf56(CNT);
  c = c + mlen_int; 
  generate_tag(c,LR,CNT_Z,k);


  return 0;
}

int romulus_t_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
  unsigned char Z[16];
  unsigned char CNT[7];
  const unsigned char* A;
  const unsigned char* C;
  const unsigned char* N;
  unsigned char CNT_Z[7] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  unsigned long long mlen_int;
  unsigned char LR [32];
  unsigned char T[16];
  unsigned int i;

  (void) nsec;
  A = ad;

  C = c;
  N = npub;
  mlen_int = clen - 16;

  // T = hash(ipad*(A)||ipad*(C)||N||CNT)
  clen = clen - 16;
  i = crypto_hash_vector(LR,A,adlen,c,mlen_int,N,CNT);

  generate_tag(T,LR,CNT_Z,k);

  for (i = 0; i < 16; i++) {
    if (T[i] != (*(c+mlen_int+i))) {
      return -1;
    }    
  }
     
  reset_lfsr_gf56(CNT);

  kdf(k,Z,N,CNT_Z);

  *mlen = clen;
  while (clen != 0) {
    clen = msg_decryption(&m,&c,N,CNT,Z,clen);
  }  

  return 0;
}



