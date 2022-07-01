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

