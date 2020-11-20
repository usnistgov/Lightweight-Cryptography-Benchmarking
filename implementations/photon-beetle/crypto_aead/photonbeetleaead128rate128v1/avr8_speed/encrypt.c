#include <avr/io.h>
#include <avr/sfr_defs.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

extern void crypto_aead_encrypt_asm(
      unsigned char *c,         
      const unsigned char *m,   
      unsigned char mlen,  
      const unsigned char *ad,  
      unsigned char adlen, 
      const unsigned char *npub,
      const unsigned char *k    
      );

extern char crypto_aead_decrypt_asm(
     unsigned char *m,          
     const unsigned char *c,    
     unsigned char clen,   
     const unsigned char *ad,   
     unsigned char adlen,  
     const unsigned char *npub, 
     const unsigned char *k     
     );

int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
    )
{
    /*
    ... 
    ... the code for the cipher implementation goes here,
    ... generating a ciphertext c[0],c[1],...,c[*clen-1]
    ... from a plaintext m[0],m[1],...,m[mlen-1]
    ... and associated data ad[0],ad[1],...,ad[adlen-1]
    ... and nonce npub[0],npub[1],..
    ... and secret key k[0],k[1],...
    ... the implementation shall not use nsec
    ...
    ... return 0;
    */

    (void)nsec;

    crypto_aead_encrypt_asm(c, m, mlen, ad, adlen, npub, k);

    *clen = mlen + CRYPTO_ABYTES;
    return 0;
}



int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
    )
{
    /*
    ...
    ... the code for the AEAD implementation goes here,
    ... generating a plaintext m[0],m[1],...,m[*mlen-1]
    ... and secret message number nsec[0],nsec[1],...
    ... from a ciphertext c[0],c[1],...,c[clen-1]
    ... and associated data ad[0],ad[1],...,ad[adlen-1]
    ... and nonce number npub[0],npub[1],...
    ... and secret key k[0],k[1],...
    ...
    ... return 0;
    */
    unsigned long long    mlen_;
    char tag_is_match;

    (void)nsec;
    if (clen < CRYPTO_ABYTES) {
        return -1;
    }
    mlen_ = clen - CRYPTO_ABYTES;

    tag_is_match = crypto_aead_decrypt_asm(m, c, mlen_, ad, adlen, npub, k);

    if (tag_is_match != 0)
    {
        memset(m, 0, (size_t)mlen_);
        return -1;
    }
    *mlen = mlen_;
    return 0;
}