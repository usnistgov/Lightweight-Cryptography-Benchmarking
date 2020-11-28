#include "crypto_aead.h"
#include "api.h"
#include "drysponge.h"

/**
generating a ciphertext c[0],c[1],...,c[*clen-1]
from a plaintext m[0],m[1],...,m[mlen-1]
and associated data ad[0],ad[1],...,ad[adlen-1]
and nonce npub[0],npub[1],...
and secret key k[0],k[1],...
the implementation shall not use nsec
*/
int crypto_aead_encrypt(
    unsigned char *c,unsigned long long *clen,
    const unsigned char *m,unsigned long long mlen,
    const unsigned char *ad,unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
){
    (void) nsec; //avoid warning
    (void) DRYSPONGE_hash; //avoid warning
    size_t impl_clen;
    DRYSPONGE_enc(k,CRYPTO_KEYBYTES,npub,m,mlen,ad,adlen,c,&impl_clen);
    *clen = impl_clen;
    return 0;
}

/**
the code for the AEAD implementation goes here,
generating a plaintext m[0],m[1],...,m[*mlen-1]
and secret message number nsec[0],nsec[1],...
from a ciphertext c[0],c[1],...,c[clen-1]
and associated data ad[0],ad[1],...,ad[adlen-1]
and nonce number npub[0],npub[1],...
and secret key k[0],k[1],...
*/
int crypto_aead_decrypt(
    unsigned char *m,unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c,unsigned long long clen,
    const unsigned char *ad,unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
){
    (void) nsec; //avoid warning
    if(DRYSPONGE_PASS!=DRYSPONGE_dec(k,CRYPTO_KEYBYTES,npub,c,clen,ad,adlen,m))
        return -1;
    *mlen = clen - DRYSPONGE_TAGSIZE;
    return 0;
}
