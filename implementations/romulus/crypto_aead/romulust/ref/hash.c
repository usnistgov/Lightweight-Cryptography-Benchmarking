/*
 * Date: 21 April 2021
 * Contact: Romulus Team (Mustafa Khairallah - mustafa.khairallah@ntu.edu.sg)
 * Romulus-H as compliant with the Romulus v1.3 specifications. 
 * This file icludes crypto_aead_decrypt()
 * It superseeds earlier versions developed by Mustafa Khairallah and maintained
 * by Mustafa Khairallah, Thomas Peyrin and Kazuhiko Minematsu
 */

#include "skinny.h"
#include "api.h"
#include "crypto_hash.h"


// The hirose double-block length (DBL) compression function.
void hirose_128_128_256 (unsigned char* h,
			 unsigned char* g,
			 const unsigned char* m) {
  unsigned char key [48];
  unsigned char hh  [16];
  int i;

  for (i = 0; i < 16; i++) { // assign the key for the
                             // hirose compresison function
    key[i] = g[i];
    g[i]   = h[i];
    hh[i]  = h[i];
  }
  g[0] ^= 0x01;
  for (i = 0; i < 32; i++) {
    key[i+16] = m[i];
  }
  
  skinny_128_384_plus_enc(h,key);
  skinny_128_384_plus_enc(g,key);

  for (i = 0; i < 16; i++) {
    h[i] ^= hh[i];
    g[i] ^= hh[i];
  }
  g[0] ^= 0x01;
  
}

// Sets the initial value to 0^2n
void initialize (unsigned char* h,
		 unsigned char* g) {
  unsigned char i;

  for (i = 0; i < 16; i++) {
    h[i] = 0;
    g[i] = 0;
  }
}

// Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N 
void ipad_256 (const unsigned char* m, unsigned char* mp, int l, int len8) {
  int i;

  for (i = 0; i < l; i++) {
    if (i < len8) {      
      mp[i] = m[i];
    }
    else if (i == l - 1) {
      mp[i] = (len8 & 0x1f);
    }
    else {
      mp[i] = 0x00;
    }      
  }
  
}

// Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N 
void ipad_128 (const unsigned char* m, unsigned char* mp, int l, int len8) {
  int i;

  for (i = 0; i < l; i++) {
    if (i < len8) {      
      mp[i] = m[i];
    }
    else if (i == l - 1) {
      mp[i] = (len8 & 0xf);
    }
    else {
      mp[i] = 0x00;
    }      
  }
  
}


int crypto_hash(
		unsigned char *out,
		const unsigned char *in,
		unsigned long long inlen
		)
{
  unsigned char h[16];
  unsigned char g[16];
  unsigned long long mlen;
  unsigned char p[32];
  unsigned char i;

  mlen = inlen;

  initialize(h,g);
  while (mlen >= 32) { // Normal loop
    hirose_128_128_256(h,g,in);
    in += 32;
    mlen -= 32;
  }
  // Partial block (or in case there is no partial block we add a 0^2n block
  ipad_256(in,p,32,mlen);
  h[0] ^= 2;
  hirose_128_128_256(h,g,p);
  
  for (i = 0; i < 16; i++) { // Assign the output tag
    out[i] = h[i];
    out[i+16] = g[i];
  }

  return 0;
}


