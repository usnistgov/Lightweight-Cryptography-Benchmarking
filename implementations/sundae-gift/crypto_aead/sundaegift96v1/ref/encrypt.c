/*
SUNDAE-GIFT
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 09 Feb 2019
*/

#include <stdlib.h>
#include "api.h"
#include "sundae.h"
#include "gift128.h"
#include "crypto_aead.h"


/*
 the code for the cipher implementation goes here,
 generating a ciphertext c[0],c[1],...,c[*clen-1]
 from a plaintext m[0],m[1],...,m[mlen-1]
 and associated data ad[0],ad[1],...,ad[adlen-1]
 and secret message number nsec[0],nsec[1],...
 and public message number npub[0],npub[1],...
 and secret key k[0],k[1],...
 */

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    sundae_enc(npub,CRYPTO_NPUBBYTES,ad,adlen,m,mlen,k,c,0);
    *clen = mlen+16;
    (void)nsec;
    return 0;
}

/*
 the code for the cipher implementation goes here,
 generating a plaintext m[0],m[1],...,m[*mlen-1]
 and secret message number nsec[0],nsec[1],...
 from a ciphertext c[0],c[1],...,c[clen-1]
 and associated data ad[0],ad[1],...,ad[adlen-1]
 and public message number npub[0],npub[1],...
 and secret key k[0],k[1],...
 */
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    int result = sundae_dec(npub,CRYPTO_NPUBBYTES,ad,adlen,m,k,c,clen);
    *mlen = clen-16;
    (void)nsec;
    return result;
}
