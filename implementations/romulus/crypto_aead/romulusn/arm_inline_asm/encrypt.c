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

void pad (const unsigned char* m, unsigned char* mp, int l, int len8) {
  int i;

  for (i = 0; i < l; i++) {
    if (i < len8) {      
      mp[i] = m[i];
    }
    else if (i == l - 1) {
      mp[i] = (len8 & 0x0f);
    }
    else {
      mp[i] = 0x00;
    }      
  }
  
}

void g8A (unsigned char* s, unsigned char* c) {
    unsigned int tmps[4];
    unsigned int tmpc[4];

    tmps[0] = *((unsigned int *)&s[0]);
    tmps[1] = *((unsigned int *)&s[4]);
    tmps[2] = *((unsigned int *)&s[8]);
    tmps[3] = *((unsigned int *)&s[12]);

    // c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
    //
    // (s[i] >> 1)          -> ((s[i]>>1)&0x7f)
    // (s[i] & 0x80)        ->  (s[i])&0x80)  not changed
    // ((s[i] & 0x01) << 7) -> ((s[i]<<7)&0x80)

    // use word access because of speeding up
    tmpc[0] = ((tmps[0]>>1) & 0x7f7f7f7f) ^ (tmps[0] & 0x80808080) ^ ((tmps[0]<<7) & 0x80808080);
    tmpc[1] = ((tmps[1]>>1) & 0x7f7f7f7f) ^ (tmps[1] & 0x80808080) ^ ((tmps[1]<<7) & 0x80808080);
    tmpc[2] = ((tmps[2]>>1) & 0x7f7f7f7f) ^ (tmps[2] & 0x80808080) ^ ((tmps[2]<<7) & 0x80808080);
    tmpc[3] = ((tmps[3]>>1) & 0x7f7f7f7f) ^ (tmps[3] & 0x80808080) ^ ((tmps[3]<<7) & 0x80808080);

    *((unsigned int *)&c[0]) = tmpc[0];
    *((unsigned int *)&c[4]) = tmpc[1];
    *((unsigned int *)&c[8]) = tmpc[2];
    *((unsigned int *)&c[12]) = tmpc[3];
}

void g8A_for_Tag_Generation (unsigned char* s, unsigned char* c) {
    unsigned int tmps[4];
    unsigned int tmpc[4];

    tmps[0] = *((unsigned int *)&s[0]);
    tmps[1] = *((unsigned int *)&s[4]);
    tmps[2] = *((unsigned int *)&s[8]);
    tmps[3] = *((unsigned int *)&s[12]);

    // c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
    //
    // (s[i] >> 1)          -> ((s[i]>>1)&0x7f)
    // (s[i] & 0x80)        ->  (s[i])&0x80)  not changed
    // ((s[i] & 0x01) << 7) -> ((s[i]<<7)&0x80)

    // use word access because of speeding up
    tmpc[0] = ((tmps[0]>>1) & 0x7f7f7f7f) ^ (tmps[0] & 0x80808080) ^ ((tmps[0]<<7) & 0x80808080);
    tmpc[1] = ((tmps[1]>>1) & 0x7f7f7f7f) ^ (tmps[1] & 0x80808080) ^ ((tmps[1]<<7) & 0x80808080);
    tmpc[2] = ((tmps[2]>>1) & 0x7f7f7f7f) ^ (tmps[2] & 0x80808080) ^ ((tmps[2]<<7) & 0x80808080);
    tmpc[3] = ((tmps[3]>>1) & 0x7f7f7f7f) ^ (tmps[3] & 0x80808080) ^ ((tmps[3]<<7) & 0x80808080);

    // use byte access because of memory alignment.
    // c is not always in word(4 byte) alignment.
    c[0] =   tmpc[0]     &0xFF;
    c[1] =  (tmpc[0]>>8) &0xFF;
    c[2] =  (tmpc[0]>>16)&0xFF;
    c[3] =  (tmpc[0]>>24)&0xFF;
    c[4] =   tmpc[1]     &0xFF;
    c[5] =  (tmpc[1]>>8) &0xFF;
    c[6] =  (tmpc[1]>>16)&0xFF;
    c[7] =  (tmpc[1]>>24)&0xFF;
    c[8] =   tmpc[2]     &0xFF;
    c[9] =  (tmpc[2]>>8) &0xFF;
    c[10] = (tmpc[2]>>16)&0xFF;
    c[11] = (tmpc[2]>>24)&0xFF;
    c[12] =  tmpc[3]     &0xFF;
    c[13] = (tmpc[3]>>8) &0xFF;
    c[14] = (tmpc[3]>>16)&0xFF;
    c[15] = (tmpc[3]>>24)&0xFF;
}

void rho_ad_eqov16 (const unsigned char* m,
	     unsigned char* s) {
  *((unsigned int *)&s[0])  ^= *((unsigned int *)&m[0]);
  *((unsigned int *)&s[4])  ^= *((unsigned int *)&m[4]);
  *((unsigned int *)&s[8])  ^= *((unsigned int *)&m[8]);
  *((unsigned int *)&s[12]) ^= *((unsigned int *)&m[12]);
}

void rho_ad_ud16 (const unsigned char* m,
	     unsigned char* s,
	     int len8) {
  unsigned char mp [16];

  pad(m,mp,16,len8);
  *((unsigned int *)&s[0])  ^= *((unsigned int *)&mp[0]);
  *((unsigned int *)&s[4])  ^= *((unsigned int *)&mp[4]);
  *((unsigned int *)&s[8])  ^= *((unsigned int *)&mp[8]);
  *((unsigned int *)&s[12]) ^= *((unsigned int *)&mp[12]);
}

void rho_eqov16 (const unsigned char* m,
	  unsigned char* c,
	  unsigned char* s) {
  g8A(s,c);

  *((unsigned int *)&s[0])  ^= *((unsigned int *)&m[0]);
  *((unsigned int *)&s[4])  ^= *((unsigned int *)&m[4]);
  *((unsigned int *)&s[8])  ^= *((unsigned int *)&m[8]);
  *((unsigned int *)&s[12]) ^= *((unsigned int *)&m[12]);

  *((unsigned int *)&c[0])  ^= *((unsigned int *)&m[0]);
  *((unsigned int *)&c[4])  ^= *((unsigned int *)&m[4]);
  *((unsigned int *)&c[8])  ^= *((unsigned int *)&m[8]);
  *((unsigned int *)&c[12]) ^= *((unsigned int *)&m[12]);
}

void rho_ud16 (const unsigned char* m,
	  unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char mp [16];

  pad(m,mp,ver,len8);

  g8A(s,c);
  *((unsigned int *)&s[0])  ^= *((unsigned int *)&mp[0]);
  *((unsigned int *)&s[4])  ^= *((unsigned int *)&mp[4]);
  *((unsigned int *)&s[8])  ^= *((unsigned int *)&mp[8]);
  *((unsigned int *)&s[12]) ^= *((unsigned int *)&mp[12]);
  for (i = 0; i < ver; i++) {
    if (i < len8) {
      c[i] = c[i] ^ mp[i];
    }
    else {
      c[i] = 0;
    }
  }
}

void irho (unsigned char* m,
	  const unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char cp [16];

  pad(c,cp,ver,len8);

  g8A(s,m);
  for (i = 0; i < ver; i++) {
    if (i < len8) {
      s[i] = s[i] ^ cp[i] ^ m[i];
    }
    else {
      s[i] = s[i] ^ cp[i];
    }
    if (i < len8) {
      m[i] = m[i] ^ cp[i];
    }
    else {
      m[i] = 0;
    }
  }
}

void reset_lfsr_gf56 (unsigned char* CNT) {
    *((unsigned int *)&CNT[0]) = 0x00000001;
    *((unsigned int *)&CNT[4]) = 0x00000000;
}

void lfsr_gf56 (unsigned char* CNT) {
    unsigned int tmpCNT[2];
    unsigned int fb0;

    tmpCNT[0] = *((unsigned int *)&CNT[0]);	// CNT3 CNT2 CNT1 CNT0
    tmpCNT[1] = *((unsigned int *)&CNT[4]);	// CNT7 CNT6 CNT5 CNT4

    fb0 = 0;
    if ((tmpCNT[1] >> 23)&0x01) {
        fb0 =  0x95;
    }

    tmpCNT[1] = tmpCNT[1] << 1 | tmpCNT[0] >> 31;
    tmpCNT[0] = tmpCNT[0] << 1 ^ fb0;

    *((unsigned int *)&CNT[0]) = tmpCNT[0];
    *((unsigned int *)&CNT[4]) = tmpCNT[1];
}

void block_cipher(unsigned char* s,
		  const unsigned char* k, unsigned char* T,
		  unsigned char* CNT,
		  skinny_ctrl* p_skinny_ctrl) {
  p_skinny_ctrl->func_skinny_128_384_enc (s,p_skinny_ctrl,CNT,T,k);
}

void nonce_encryption (const unsigned char* N,
		       unsigned char* CNT,
		       unsigned char*s, const unsigned char* k,
		       unsigned char D,
			   skinny_ctrl* p_skinny_ctrl) {
  unsigned char T [16];

  *((unsigned int *)&T[0])  = *((unsigned int *)&N[0]);
  *((unsigned int *)&T[4])  = *((unsigned int *)&N[4]);
  *((unsigned int *)&T[8])  = *((unsigned int *)&N[8]);
  *((unsigned int *)&T[12]) = *((unsigned int *)&N[12]);
  CNT[7] = D;
  block_cipher(s,k,T,CNT,p_skinny_ctrl);

}

void generate_tag (unsigned char** c, unsigned char* s,
		   int n, unsigned long long* clen) {
  g8A_for_Tag_Generation(s, *c);
  *c = *c + n;
  *c = *c - *clen;
}

unsigned long long msg_encryption_eqov16 (const unsigned char** M, unsigned char** c,
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

unsigned long long msg_encryption_ud16 (const unsigned char** M, unsigned char** c,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char*s, const unsigned char* k,
				   unsigned char D,
				   unsigned long long mlen,
				   skinny_ctrl* p_skinny_ctrl) {
  rho_ud16(*M, *c, s, mlen, 16);
  *c = *c + mlen;
  *M = *M + mlen;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,p_skinny_ctrl);
  return 0;
}

unsigned long long msg_decryption (unsigned char** M, const unsigned char** c,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char*s, const unsigned char* k,
				   unsigned char D,
				   unsigned long long clen,
				   skinny_ctrl* p_skinny_ctrl) {
  int len8;

  if (clen >= 16) {
    len8 = 16;
    clen = clen - 16;
  }
  else {
    len8 = clen;
    clen = 0;
  }
  irho(*M, *c, s, len8, 16);
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,D,p_skinny_ctrl);
  return clen;
}

unsigned long long ad_encryption_eqov32 (const unsigned char** A, unsigned char* s,
				  const unsigned char* k, unsigned long long adlen,
				  unsigned char* CNT,
				  unsigned char D,
				   skinny_ctrl* p_skinny_ctrl) {

  unsigned char T [16];

  rho_ad_eqov16(*A, s);
  *A = *A + 16;
  lfsr_gf56(CNT);

  //pad(*A, T, 16, 16);
  *((unsigned int *)&T[0])  = *((unsigned int *)&(*A)[0]);
  *((unsigned int *)&T[4])  = *((unsigned int *)&(*A)[4]);
  *((unsigned int *)&T[8])  = *((unsigned int *)&(*A)[8]);
  *((unsigned int *)&T[12]) = *((unsigned int *)&(*A)[12]);
  *A = *A + 16;
  CNT[7] = D;
  block_cipher(s,k,T,CNT,p_skinny_ctrl);
  lfsr_gf56(CNT);

  return adlen - 32;
}

unsigned long long ad_encryption_ov16 (const unsigned char** A, unsigned char* s,
				  const unsigned char* k, unsigned long long adlen,
				  unsigned char* CNT,
				  unsigned char D,
				   skinny_ctrl* p_skinny_ctrl) {

  unsigned char T [16];

  adlen = adlen - 16;
  rho_ad_eqov16(*A, s);
  *A = *A + 16;
  lfsr_gf56(CNT);

  pad(*A, T, 16, adlen);
  *A = *A + adlen;
  CNT[7] = D;
  block_cipher(s,k,T,CNT,p_skinny_ctrl);
  lfsr_gf56(CNT);

  return 0;
}

unsigned long long ad_encryption_eq16 (const unsigned char** A, unsigned char* s,
				  unsigned char* CNT) {

  rho_ad_eqov16(*A, s);
  *A = *A + 16;
  lfsr_gf56(CNT);

  return 0;
}

unsigned long long ad_encryption_ud16 (const unsigned char** A, unsigned char* s,
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
			 const unsigned char* k
			 )
{
  unsigned char s[16];
  // size 7 -> 8 for word access
  unsigned char CNT[8];
  const unsigned char* A;
  const unsigned char* M;
  const unsigned char* N;

  skinny_ctrl l_skinny_ctrl;

  (void) nsec;
  A = ad;
  M = m;
  N = npub;

  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

  *((unsigned int *)&s[0])  = 0x00000000;
  *((unsigned int *)&s[4])  = 0x00000000;
  *((unsigned int *)&s[8])  = 0x00000000;
  *((unsigned int *)&s[12]) = 0x00000000;
  reset_lfsr_gf56(CNT);

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x1a,&l_skinny_ctrl);
  }
  else while (adlen > 0) {
      if (adlen < 16) { // The last block of AD is odd and incomplete
         adlen = ad_encryption_ud16(&A,s,adlen,CNT);
         nonce_encryption(N,CNT,s,k,0x1a,&l_skinny_ctrl);
      }
      else if (adlen == 16) { // The last block of AD is odd and complete
         adlen = ad_encryption_eq16(&A,s,CNT);
         nonce_encryption(N,CNT,s,k,0x18,&l_skinny_ctrl);
      }
      else if (adlen < (32)) { // The last block of AD is even and incomplete
         adlen = ad_encryption_ov16(&A,s,k,adlen,CNT,0x08,&l_skinny_ctrl);
         nonce_encryption(N,CNT,s,k,0x1a,&l_skinny_ctrl);
      }
      else if (adlen == (32)) { // The last block of AD is even and complete
         adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&l_skinny_ctrl);
         nonce_encryption(N,CNT,s,k,0x18,&l_skinny_ctrl);
      }
      else { // A normal full pair of blocks of AD
         adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&l_skinny_ctrl);
      }
    }

  // because, nonce_encryption is called at the last block of AD encryption
  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

  reset_lfsr_gf56(CNT);

  *clen = mlen + 16;
  
  if (mlen == 0) { // M is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x15,&l_skinny_ctrl);
  }  
  else while (mlen > 0) {
    if (mlen < 16) { // The last block of M is incomplete
      mlen = msg_encryption_ud16(&M,&c,N,CNT,s,k,0x15,mlen,&l_skinny_ctrl);
      }
    else if (mlen == 16) { // The last block of M is complete
      mlen = msg_encryption_eqov16(&M,&c,N,CNT,s,k,0x14,mlen,&l_skinny_ctrl);
    }
    else { // A normal full message block
      mlen = msg_encryption_eqov16(&M,&c,N,CNT,s,k,0x04,mlen,&l_skinny_ctrl);
    }
  }

  // Tag generation 
  generate_tag(&c,s,16,clen);

  return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{

  unsigned char s[16];
  unsigned char T[16];
  // size 7 -> 8 for word access
  unsigned char CNT[8];
  const unsigned char* A;
  unsigned char* M;
  const unsigned char* N;
  unsigned int i;

  skinny_ctrl l_skinny_ctrl;

  (void) nsec;
  A = ad;
  M = m;
  N = npub;
  
  l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

  for (i = 0; i < 16; i++) {
    s[i] = 0;
  }
  reset_lfsr_gf56(CNT);

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x1a,&l_skinny_ctrl);
  }
  else while (adlen > 0) {
      if (adlen < 16) { // The last block of AD is odd and incomplete
        adlen = ad_encryption_ud16(&A,s,adlen,CNT);
        nonce_encryption(N,CNT,s,k,0x1a,&l_skinny_ctrl);
      }
      else if (adlen == 16) { // The last block of AD is odd and complete
        adlen = ad_encryption_eq16(&A,s,CNT);
        nonce_encryption(N,CNT,s,k,0x18,&l_skinny_ctrl);
      }
      else if (adlen < (32)) { // The last block of AD is even and incomplete
        adlen = ad_encryption_ov16(&A,s,k,adlen,CNT,0x08,&l_skinny_ctrl);
        nonce_encryption(N,CNT,s,k,0x1a,&l_skinny_ctrl);
      }
      else if (adlen == (32)) { // The last block of AD is even and complete
        adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&l_skinny_ctrl);
        nonce_encryption(N,CNT,s,k,0x18,&l_skinny_ctrl);
      }
      else { // A normal full pair of blocks of AD
        adlen = ad_encryption_eqov32(&A,s,k,adlen,CNT,0x08,&l_skinny_ctrl);
      }
    }

  reset_lfsr_gf56(CNT);
  
  clen = clen - 16;
  *mlen = clen;

  if (clen == 0) { // C is an empty string
    lfsr_gf56(CNT);
    nonce_encryption(N,CNT,s,k,0x15,&l_skinny_ctrl);
  }  
  else while (clen > 0) {
    if (clen < 16) { // The last block of C is incomplete
      clen = msg_decryption(&M,&c,N,CNT,s,k,0x15,clen,&l_skinny_ctrl);
    }
    else if (clen == 16) { // The last block of C is complete
      clen = msg_decryption(&M,&c,N,CNT,s,k,0x14,clen,&l_skinny_ctrl);
    }
    else { // A normal full message block
      clen = msg_decryption(&M,&c,N,CNT,s,k,0x04,clen,&l_skinny_ctrl);
    }
  }

  // Tag generation
  g8A_for_Tag_Generation(s, T);
  for (i = 0; i < 16; i++) {
    if (T[i] != (*(c+i))) {
      return -1;
    }    
  }
  
  return 0;
}


