/*
 * Date: 29 November 2018
 * Contact: Thomas Peyrin - thomas.peyrin@gmail.com
 * Mustafa Khairallah - mustafam001@e.ntu.edu.sg
 */

#include "crypto_aead.h"
#include "api.h"
#include "variant.h"
#include "skinny.h"
#include <stdio.h>
#include <stdlib.h>

/*void display_vector (const unsigned char* x, int lenx) {
  int i;

  for (i = 0; i < lenx; i++) {
    //printf("%02x",x[i]);
  }
  //printf("\n");
  }*/

void pad (const unsigned char* m, unsigned char* mp, int ver, int len8) {
  int i;

  for (i = 0; i < ver; i++) {
    if (i < len8) {      
      mp[i] = m[i];
    }
    else if (i == ver - 1) {
      mp[i] = (len8 & 0x0f);
    }
    else {
      mp[i] = 0x00;
    }      
  }
}

void g (unsigned char* s, unsigned char* c) {
  c[0] = s[4];
  c[1] = s[5];
  c[2] = s[6];
  c[3] = s[7];

  c[4] = s[8];
  c[5] = s[9];
  c[6] = s[10];
  c[7] = s[11];

  c[8] = s[12];
  c[9] = s[13];
  c[10] = s[14];
  c[11] = s[15];

  c[12] = s[0] ^ s[12];
  c[13] = s[1] ^ s[13];
  c[14] = s[2] ^ s[14];
  c[15] = s[3] ^ s[15];    
  
}

void g8A (unsigned char* s, unsigned char* c) {
  int i;

  for (i = 0; i < 16; i++) {
    c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
  }
}

void rho_ad (const unsigned char* m,
	     unsigned char* s,
	     int len8,
	     int ver) {
  int i;
  unsigned char mp [16];
  
  //mp = (unsigned char*) malloc(ver);

  //printf("rho in m  = ");display_vector(m,len8);
  pad(m,mp,ver,len8);
  //printf("rho in mp = ");display_vector(mp,16);
  //printf("rho in s  = ");display_vector(s,16);
  //g(s,c);
  //g8A(s,c);
  for (i = 0; i < ver; i++) {
    s[i] = s[i] ^ mp[i];
  }
  //printf("rho out s = ");display_vector(s,16);
  ////printf("rho out c = ");display_vector(c,16);

  //free(mp);
  
}

void rho (const unsigned char* m,
	  unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char mp [16];



  //printf("rho in m  = ");display_vector(m,len8);
  pad(m,mp,ver,len8);
  //printf("rho in mp = ");display_vector(mp,16);
  //printf("rho in s  = ");display_vector(s,16);
  //g(s,c);
  g8A(s,c);
  for (i = 0; i < ver; i++) {
    s[i] = s[i] ^ mp[i];
    if (i < len8) {
      c[i] = c[i] ^ mp[i];
    }
    else {
      c[i] = 0;
    }
  }
  //printf("rho out s = ");display_vector(s,16);
  //printf("rho out c = ");display_vector(c,16);

  
}

void reset_lfsr_gf24 (unsigned char* CNT) {
  CNT[0] = 0x01;
  CNT[1] = 0x00;
  CNT[2] = 0x00;
}

void lfsr_gf24 (unsigned char* CNT) {
  unsigned char fb0;
  
  fb0 = CNT[2] >> 7;
  
  CNT[2] = (CNT[2] << 1) | (CNT[1] >> 7);
  CNT[1] = (CNT[1] << 1) | (CNT[0] >> 7);
  if (fb0 == 1) {
    CNT[0] = (CNT[0] << 1) ^ 0x1b;
  }
  else {
    CNT[0] = (CNT[0] << 1);
  }
}

void compose_tweakey (unsigned char* KT,
		      const unsigned char* K,
		      unsigned char* T,
		      unsigned char* CNT,
		      unsigned char D,
		      int t) {

  int i;

  for (i = 0; i < 3; i++) {
    KT[i] = CNT[i];
  }
  KT[i] = D;
  for (i = 0; i < t; i++) {
    KT[i+4] = T[i];
  }
  for (i = 0; i < 16; i++) {
    KT[i+16] = K[i];
  }
  

}

void block_cipher(unsigned char* s,
		  const unsigned char* k, unsigned char* T,
		  unsigned char* CNT, unsigned char D, int t, int n) {
  unsigned char KT [32];

  (void)n;
  compose_tweakey(KT,k,T,CNT,D,t);
  //printf("BC in kt = ");display_vector(KT,2*n);
  //printf("BC in s  = ");display_vector(s,n);
  skinny_128_256_enc (s,KT);
  //printf("BC out s = ");display_vector(s,n);

}

void nonce_encryption (const unsigned char* N,
		       unsigned char* CNT,
		       unsigned char*s, const unsigned char* k,
		       unsigned int t, unsigned int n, unsigned char D) {
  unsigned char T [16];
  unsigned int i;

  for (i = 0; i < t; i++) {
    T[i] = N[i];
  }  
  //printf("nonce cnt = ");display_vector(CNT,3);
  block_cipher(s,k,T,CNT,D,t,n);

}

void generate_tag (unsigned char** c, unsigned char* s,
		   int n, unsigned long long* clen) {
  g8A(s, *c);
  *c = *c + n;
  *c = *c - *clen;

}

unsigned long long msg_encryption (const unsigned char** M, unsigned char** c,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char*s, const unsigned char* k,
				   unsigned int n, unsigned int t, unsigned char D,
				   unsigned long long mlen) {
  int len8;

  
  if (mlen >= n) {
    len8 = n;
    mlen = mlen - n;
  }
  else {
    len8 = mlen;
    mlen = 0;
  }
  rho(*M, *c, s, len8, n);
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf24(CNT);
  nonce_encryption(N,CNT,s,k,t,n,D);
  return mlen;
}

void irho (unsigned char* m,
	  const unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char cp [16];

  //printf("irho in c  = ");display_vector(c,len8);
  pad(c,cp,ver,len8);
  //printf("irho in cp = ");display_vector(cp,16);
  //printf("irho in s  = ");display_vector(s,16);

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
  //printf("irho out s = ");display_vector(s,16);
  //printf("irho out m = ");display_vector(c,16);
  
}

unsigned long long msg_decryption (unsigned char** M, const unsigned char** c,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char*s, const unsigned char* k,
				   unsigned int n, unsigned int t, unsigned char D,
				   unsigned long long clen) {
  int len8;

  
  if (clen >= n) {
    len8 = n;
    clen = clen - n;
  }
  else {
    len8 = clen;
    clen = 0;
  }
  irho(*M, *c, s, len8, n);
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf24(CNT);
  nonce_encryption(N,CNT,s,k,t,n,D);
  return clen;
}

unsigned long long ad_encryption (const unsigned char** A, unsigned char* s,
				  const unsigned char* k, unsigned long long adlen,
				  unsigned char* CNT,
				  unsigned char D,				  
				  unsigned int n, unsigned int t) {


  unsigned char T [16];

  int len8;
  
  
  if (adlen >= n) {
    len8 = n;
    adlen = adlen - n;
  }
  else {
    len8 = adlen;
    adlen = 0;
  }
  //printf("AD in = ");display_vector(*A,len8);
  rho_ad(*A, s, len8, n);
  *A = *A + len8;
  lfsr_gf24(CNT);
  //printf("AD cnt = ");display_vector(CNT,3);    
  if (adlen != 0) {
    if (adlen >= t) {
      len8 = t;
      adlen = adlen - t;
    }
    else {
      len8 = adlen;
      adlen = 0;    
    }
    pad(*A, T, t, len8);
    *A = *A + len8;
    block_cipher(s,k,T,CNT,D,t,n);
    lfsr_gf24(CNT);
  }
  
  return adlen;
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
  unsigned char CNT[3];
  const unsigned char* A;
  const unsigned char* M;
  const unsigned char* N;
  unsigned long long n, t, i;

  (void)nsec;
  A = ad;
  M = m;
  N = npub;
  
  n = AD_BLK_LEN_ODD;
  t = AD_BLK_LEN_EVN;

  for (i = 0; i < n; i++) {
    s[i] = 0;
  }      
  reset_lfsr_gf24(CNT);
  //printf("s = ");display_vector(s,16);
  //printf("cnt = ");display_vector(CNT,3);

  if (adlen == 0) { // AD is an empty string
    lfsr_gf24(CNT);
    nonce_encryption(N,CNT,s,k,t,n,0x9a);
  }
  else while (adlen > 0) {
      if (adlen < n) { // The last block of AD is odd and incomplete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x9a);
      }
      else if (adlen == n) { // The last block of AD is odd and complete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x98); 
      }    
      else if (adlen < (n+t)) { // The last block of AD is even and incomplete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x9a); 
      }
      else if (adlen == (n+t)) { // The last block of AD is even and complete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x98); 
      }
      else { // A normal full pair of blocks of AD
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
      }
    }

  reset_lfsr_gf24(CNT);
  
  n = MSG_BLK_LEN;
  *clen = mlen + n;

  if (mlen == 0) { // AD is an empty string
    lfsr_gf24(CNT);
    nonce_encryption(N,CNT,s,k,t,n,0x95);
  }  
  else while (mlen > 0) {
    if (mlen < n) { // The last block of M is incomplete
      mlen = msg_encryption(&M,&c,N,CNT,s,k,n,t,0x95,mlen);
    }
    else if (mlen == n) { // The last block of M is complete
      mlen = msg_encryption(&M,&c,N,CNT,s,k,n,t,0x94,mlen);
    }
    else { // A normal full message block
      mlen = msg_encryption(&M,&c,N,CNT,s,k,n,t,0x84,mlen);
    }
  }


  // Tag generation 
  generate_tag(&c,s,n,clen);
  //printf("T = ");display_vector(c+*clen-n,n);

  //free(s);
  //free(CNT);  
  
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
  unsigned char CNT[3];
  const unsigned char* A;
  unsigned char* M;
  const unsigned char* N;
  unsigned long long n, t, i;

  (void)nsec;
  A = ad;
  M = m;
  N = npub;
  
  n = AD_BLK_LEN_ODD;
  t = AD_BLK_LEN_EVN;

  for (i = 0; i < n; i++) {
    s[i] = 0;
  }      
  reset_lfsr_gf24(CNT);
  //printf("s = ");display_vector(s,16);
  //printf("cnt = ");display_vector(CNT,3);

  if (adlen == 0) { // AD is an empty string
    lfsr_gf24(CNT);
    nonce_encryption(N,CNT,s,k,t,n,0x9a);
  }
  else while (adlen > 0) {
      if (adlen < n) { // The last block of AD is odd and incomplete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x08,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x9a);
      }
      else if (adlen == n) { // The last block of AD is odd and complete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x98); 
      }    
      else if (adlen < (n+t)) { // The last block of AD is even and incomplete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x9a); 
      }
      else if (adlen == (n+t)) { // The last block of AD is even and complete
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
	nonce_encryption(N,CNT,s,k,t,n,0x98); 
      }
      else { // A normal full pair of blocks of AD
	adlen = ad_encryption(&A,s,k,adlen,CNT,0x88,n,t);
      }
    }

  reset_lfsr_gf24(CNT);
  
  n = MSG_BLK_LEN;

  clen = clen - n;

  *mlen = clen;

  if (clen == 0) { // C is an empty string
    lfsr_gf24(CNT);
    nonce_encryption(N,CNT,s,k,t,n,0x95);
  }  
  else while (clen > 0) {
    if (clen < n) { // The last block of C is incomplete
      clen = msg_decryption(&M,&c,N,CNT,s,k,n,t,0x95,clen);
    }
    else if (clen == n) { // The last block of C is complete
      clen = msg_decryption(&M,&c,N,CNT,s,k,n,t,0x94,clen);
    }
    else { // A normal full message block
      clen = msg_decryption(&M,&c,N,CNT,s,k,n,t,0x84,clen);
    }
  }


  // Tag generation 
  g8A(s, T);
  //printf("T = ");display_vector(T,n);
  for (i = 0; i < 16; i++) {
    if (T[i] != (*(c+i))) {
      return -1;
    }    
  }

  return 0;
  
}
