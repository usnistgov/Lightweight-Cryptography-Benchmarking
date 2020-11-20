/*
 *  Copyright 2019 Mitsubishi Electric Corporation. All Rights Reserved.
 *
 *  SAEAES
 *
 *  version 1.0.0
 *  February 2019
 */

#include "crypto_aead.h"
#include "saeaes.h"

/*
 *  Hash
 */
static void hash (
          unsigned char      *s,
    const unsigned char      *ad,
          unsigned long long adlen,
    const unsigned char      *npub,
    const unsigned long      *ekey
)
{
    unsigned long long i;

    for( i=0; i<AES_BLOCK; i++ ) s[i] = 0;

    while( adlen > SAEAES_R1 ) {
        for( i=0; i<SAEAES_R1; i++ ) s[i] ^= ad[i];

        AesEnc( s, ekey );

        ad    += SAEAES_R1;
        adlen -= SAEAES_R1;
    }

    for( i=0; i<adlen; i++ ) s[i] ^= ad[i];

    if( adlen==SAEAES_R1 ) {
        s[AES_BLOCK-1] ^= 1;
    }
    else {
        s[adlen] ^= 0x80;
        s[AES_BLOCK-1] ^= 2;
    }

    AesEnc( s, ekey );

    for( i=0; i<CRYPTO_NPUBBYTES; i++ ) s[i] ^= npub[i];
    s[AES_BLOCK-1] ^= 3;
}


/*
 *  Encryption
 */
int crypto_aead_encrypt (
          unsigned char      *c,
          unsigned long long *clen,
    const unsigned char      *m,
          unsigned long long mlen,
    const unsigned char      *ad,
          unsigned long long adlen,
    const unsigned char      *nsec,
    const unsigned char      *npub,
    const unsigned char      *k
)
{
    unsigned long ekey[AES_EKEY];
    unsigned char s[AES_BLOCK];
    unsigned long long i;

    *clen = mlen + CRYPTO_ABYTES;

    AesKey( k, ekey );
    hash  ( s, ad, adlen, npub, ekey );
    AesEnc( s, ekey );

    while( mlen > SAEAES_R ) {
        for( i=0; i<SAEAES_R; i++ ) {
            s[i] ^= m[i];
            c[i]  = s[i];
        }

        AesEnc( s, ekey );

        m    += SAEAES_R;
        c    += SAEAES_R;
        mlen -= SAEAES_R;
    }

    for( i=0; i<mlen; i++ ) {
        s[i] ^= m[i];
        c[i]  = s[i];
    }
    c += mlen;

    if( mlen==SAEAES_R ) {
        s[AES_BLOCK-1] ^= 1;
    }
    else {
        s[mlen] ^= 0x80;
        s[AES_BLOCK-1] ^= 2;
    }

    AesEnc( s, ekey );

    for( i=0; i<CRYPTO_ABYTES; i++ ) c[i] = s[i];

    return 0;
}


/*
 *  Decryption
 */
int crypto_aead_decrypt (
          unsigned char      *m,
          unsigned long long *mlen,
          unsigned char      *nsec,
    const unsigned char      *c,
          unsigned long long clen,
    const unsigned char      *ad,
          unsigned long long adlen,
    const unsigned char      *npub,
    const unsigned char      *k
)
{
    unsigned long ekey[AES_EKEY];
    unsigned char s[AES_BLOCK];
    unsigned long long i;

    if( clen < CRYPTO_ABYTES ) return -2;

    clen -= CRYPTO_ABYTES;
    *mlen = clen;

    AesKey( k, ekey );
    hash  ( s, ad, adlen, npub, ekey );
    AesEnc( s, ekey );

    while( clen > SAEAES_R ) {
        for( i=0; i<SAEAES_R; i++ ) {
            m[i]  = s[i] ^ c[i];
            s[i] ^= m[i];
        }

        AesEnc( s, ekey );

        m    += SAEAES_R;
        c    += SAEAES_R;
        clen -= SAEAES_R;
    }

    for( i=0; i<clen; i++ ) {
        m[i]  = s[i] ^ c[i];
        s[i] ^= m[i];
    }
    m += clen;
    c += clen;

    if( clen==SAEAES_R ) {
        s[AES_BLOCK-1] ^= 1;
    }
    else {
        s[clen] ^= 0x80;
        s[AES_BLOCK-1] ^= 2;
    }

    AesEnc( s, ekey );

    for( i=0; i<CRYPTO_ABYTES; i++ ) {
        if( c[i] != s[i] ) {
            m -= *mlen;
            for( i=0; i<*mlen; i++ ) m[i] = 0;
            return -1;
        }
    }

    return 0;
}

