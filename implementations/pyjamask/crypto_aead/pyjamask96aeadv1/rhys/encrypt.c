
#include "pyjamask.h"

int crypto_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    return pyjamask_96_aead_encrypt
        (c, clen, m, mlen, ad, adlen, nsec, npub, k);
}

int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    return pyjamask_96_aead_decrypt
        (m, mlen, nsec, c, clen, ad, adlen, npub, k);
}
