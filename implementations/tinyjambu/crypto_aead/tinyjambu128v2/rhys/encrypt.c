
#include "tinyjambu-aead.h"

int crypto_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    size_t len = 0;
    int result = tiny_jambu_128_aead_encrypt
        (c, &len, m, mlen, ad, adlen, npub, k);
    (void)nsec;
    *clen = len;
    return result;
}

int crypto_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    size_t len = 0;
    int result = tiny_jambu_128_aead_decrypt
        (m, &len, c, clen, ad, adlen, npub, k);
    (void)nsec;
    *mlen = len;
    return result;
}
