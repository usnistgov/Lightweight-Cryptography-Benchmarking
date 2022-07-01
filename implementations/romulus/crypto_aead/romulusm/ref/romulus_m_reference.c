/*
 * Date: 05 May 2021
 * Contact: Romulus Team (Mustafa Khairallah - mustafa.khairallah@ntu.edu.sg)
 * Romulus-M as compliant with the Romulus v1.3 specifications. 
 * This file icludes the functions of Romulus-N
 * It superseeds earlier versions developed by Mustafa Khairallah and maintained
 * by Mustafa Khairallah, Thomas Peyrin and Kazuhiko Minematsu
 */

#include "api.h"
#include "variant.h"
#include "skinny.h"
#include "romulus_m.h"


// Padding function: pads the byte length of the message mod 16 to the last incomplete block.
// For complete blocks it returns the same block.
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

// G(S): generates the key stream from the internal state by multiplying the state S by the constant matrix G
void g8A (unsigned char* s, unsigned char* c) {
  int i;

  for (i = 0; i < 16; i++) {
    c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
  }
  
}

// Rho(S,A) pads an A block and XORs it to the internal state.
void rho_ad (const unsigned char* m,
	     unsigned char* s,
	     int len8,
	     int ver) {
  int i;
  unsigned char mp [16];  


  pad(m,mp,ver,len8);
  for (i = 0; i < ver; i++) {
    s[i] = s[i] ^ mp[i];
  }
  
}

// Rho(S,M): pads an M block and outputs S'= M xor S and C = M xor G(S) 
void rho (const unsigned char* m,
	  unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char mp [16];

  pad(m,mp,ver,len8);

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
  
}

// Inverse-Rho(S,M): pads a C block and outputs S'= C xor G(S) xor S and M = C xor G(S) 
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

// Combines the secret key, nonce (or A block), counter and domain bits to form the full 384-bit tweakey
void compose_tweakey (unsigned char* KT,
		      const unsigned char* K,
		      unsigned char* T,
		      unsigned char* CNT,
		      unsigned char D,
		      int t) {

  int i;

  for (i = 0; i < 7; i++) {
    KT[i] = CNT[i];
  }
  KT[i] = D;
  for (i = 8; i < 16; i++) {
    KT[i] = 0x00;
  }
  for (i = 0; i < t; i++) {
    KT[i+16] = T[i];
  }
  for (i = 0; i < 16; i++) {
    KT[i+16+t] = K[i];
  }

}

// An interface between Romulus and the underlying TBC
void block_cipher(unsigned char* s,
		  const unsigned char* k, unsigned char* T,
		  unsigned char* CNT, unsigned char D, int t) {
  unsigned char KT [48];

  compose_tweakey(KT,k,T,CNT,D,t);
  skinny_128_384_plus_enc (s,KT);

}

// Calls the TBC using the nonce as part of the tweakey
void nonce_encryption (const unsigned char* N,
		       unsigned char* CNT,
		       unsigned char*s, const unsigned char* k,
		       int t, unsigned char D) {
  unsigned char T [16];
  int i;  
  for (i = 0; i < t; i++) {
    T[i] = N[i];
  }  
  block_cipher(s,k,T,CNT,D,t);

}

// Generates the tag T from the final state S by applying T=G(S).
void generate_tag (unsigned char** c, unsigned char* s,
		   int n, unsigned long long* clen) {
  
  g8A(s, *c);
  *c = *c + n;
  *c = *c - *clen;

}

// Absorbs and encrypts the message blocks.
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
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,t,D);
  return mlen;
}

// Absorbs and decrypts the ciphertext blocks.
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
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,t,D);
  return clen;
}

// Handles the special case when the number of blocks of A is odd
unsigned long long ad2msg_encryption (const unsigned char** M,
				      unsigned char* CNT,
				      unsigned char*s, const unsigned char* k,
				      unsigned int t, unsigned char D,
				      unsigned long long mlen) {
  unsigned char T [16];
  int len8;

  if (mlen <= t) {
    len8 = mlen;
    mlen = 0;
  }
  else {
    len8 = t;
    mlen = mlen - t;
  }

  pad (*M,T,t,len8);

  block_cipher(s,k,T,CNT,D,t);
  lfsr_gf56(CNT);
  *M = *M + len8;
  
  return mlen;

}

// Absorbs the AD blocks.
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
  rho_ad(*A, s, len8, n);
  *A = *A + len8;
  lfsr_gf56(CNT);
  
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
    block_cipher(s,k,T,CNT,D,t);
    lfsr_gf56(CNT);
  }

  return adlen;
}

int romulus_m_encrypt (
			 unsigned char* c, unsigned long long* clen,
			 const unsigned char* m, unsigned long long mlen,
			 const unsigned char* ad, unsigned long long adlen,
			 const unsigned char* nsec,
			 const unsigned char* npub,
			 const unsigned char* k
			 )
{
  unsigned char s[16];
  unsigned char CNT[7];
  unsigned char T[16];
  const unsigned char* N;
  unsigned int n, t, i;
  unsigned char w;
  unsigned long long xlen;

  (void)nsec;
  N = npub;
  
  n = AD_BLK_LEN_ODD;
  t = AD_BLK_LEN_EVN;

  xlen = mlen;

  for (i = 0; i < n; i++) {
    s[i] = 0;
  }      
  reset_lfsr_gf56(CNT);

  // Calculating the domain separation bits for the last block MAC TBC call depending on the length of M and AD
  w = 48;

  if (adlen == 0) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }   
  }
  else if (adlen%(n+t) == 0) {
    w = w ^ 8;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }       
  }
  else if (adlen%(n+t) < n) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }       
  }
  else if (adlen%(n+t) == n) {
    w = w ^ 0;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
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
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
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
      adlen = ad_encryption(&ad,s,k,adlen,CNT,40,n,t);
    }

  if ((w & 8) == 0) {
    xlen = ad2msg_encryption (&m,CNT,s,k,t,44,xlen);      
  }
  else if (mlen == 0) {
    lfsr_gf56(CNT);    
  }
  while (xlen > 0) {
    xlen = ad_encryption(&m,s,k,xlen,CNT,44,n,t);
  }
  nonce_encryption(N,CNT,s,k,t,w);
  
  
  // Tag generation 
  g8A(s, T);

  m = m - mlen;
  
  reset_lfsr_gf56(CNT);

  for (i = 0; i < n; i = i + 1) {
    s[i] = T[i];
  }

  n = MSG_BLK_LEN;
  *clen = mlen + n;



  if (mlen > 0) {
    nonce_encryption(N,CNT,s,k,t,36);  
    while (mlen > n) {
      mlen = msg_encryption(&m,&c,N,CNT,s,k,n,t,36,mlen);
    }
    rho(m, c, s, mlen, 16);
    c = c + mlen;
    m = m + mlen;    
  }

  // Tag Concatenation
  for (i = 0; i < 16; i = i + 1) {
    *(c + i) = T[i];
  }

  c = c - *clen;

  
  
  return 0;
}

int romulus_m_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
  unsigned char s[16];
  unsigned char CNT[7];
  unsigned char T[16];
  const unsigned char* N;
  unsigned int n, t, i;
  unsigned char w;
  unsigned long long xlen;
  const unsigned char* mauth;

  (void)nsec;
  mauth = m;

  N = npub;
  
  n = AD_BLK_LEN_ODD;
  t = AD_BLK_LEN_EVN;

  xlen = clen-16;

  reset_lfsr_gf56(CNT);

  for (i = 0; i < 16; i++) {
    T[i] = *(c + clen - 16 + i);
  }

  for (i = 0; i < n; i = i + 1) {
    s[i] = T[i];
  }

  n = MSG_BLK_LEN;
  clen = clen - 16;
  *mlen = clen;


  if (clen > 0) {    
    nonce_encryption(N,CNT,s,k,t,36);
    while (clen > n) {
      clen = msg_decryption(&m,&c,N,CNT,s,k,n,t,36,clen);
    }
    irho(m, c, s, clen, 16);
    c = c + clen;
    m = m + clen;
  }
  

  for (i = 0; i < n; i++) {
    s[i] = 0;
  }      
  reset_lfsr_gf56(CNT);
  
  // Calculating the domain separation bits for the last block MAC TBC call depending on the length of M and AD
  w = 48;
  
  if (adlen == 0) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }   
  }
  else if (adlen%(n+t) == 0) {
    w = w ^ 8;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }       
  }
  else if (adlen%(n+t) < n) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }       
  }
  else if (adlen%(n+t) == n) {
    w = w ^ 0;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
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
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
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
      adlen = ad_encryption(&ad,s,k,adlen,CNT,40,n,t);
    }


  if ((w & 8) == 0) {
    xlen = ad2msg_encryption (&mauth,CNT,s,k,t,44,xlen);      
  }
  else if (clen == 0) {
    lfsr_gf56(CNT);    
  }  
  while (xlen > 0) {
    xlen = ad_encryption(&mauth,s,k,xlen,CNT,44,n,t);
  }
  nonce_encryption(N,CNT,s,k,t,w);

  // Tag generation 
  g8A(s, T);

  // Tag verification
  for (i = 0; i < 16; i++) {
    if (T[i] != (*(c+i))) {
      return -1;
    }    
  }
  
  return 0;
}
