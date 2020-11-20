#include <stdio.h>
#include <stdlib.h>
#include "subterranean_ref.h"
#include "api.h"

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k){
    /* Call AEAD function */
    subterranean_SAE_direct_encrypt(c, &c[mlen], k, 8*CRYPTO_KEYBYTES, npub, 8*CRYPTO_NPUBBYTES, 8*CRYPTO_ABYTES, ad, 8*adlen, m, 8*mlen);
    /* Compact output */
    *clen = mlen+CRYPTO_ABYTES;
    return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k){
    unsigned char t[CRYPTO_ABYTES];
    int tags_match;
    /* Call AEAD function */
    tags_match = subterranean_SAE_direct_decrypt(m, t, k, 8*CRYPTO_KEYBYTES, npub, 8*CRYPTO_NPUBBYTES, &c[clen-CRYPTO_ABYTES], 8*CRYPTO_ABYTES, ad, 8*adlen, c, 8*(clen-CRYPTO_ABYTES));
    /* Compact output */
    *mlen = clen-CRYPTO_ABYTES;
    return tags_match;
}