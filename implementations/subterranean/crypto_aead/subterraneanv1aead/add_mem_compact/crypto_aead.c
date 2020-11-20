#include <stdio.h>
#include <stdlib.h>
#include "subterranean_mem_compact.h"
#include "api.h"

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k){
    /* Call AEAD function */
    subterranean_SAE_direct_encrypt(c, &c[mlen], k, CRYPTO_KEYBYTES, npub, CRYPTO_NPUBBYTES, CRYPTO_ABYTES, ad, adlen, m, mlen);
    /* Compact output */
    *clen = mlen+CRYPTO_ABYTES;
    /* Release memory */
    return 0;
}

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k){
    unsigned char t_prime[CRYPTO_ABYTES];
    int tags_match;
    /* Call AEAD function */
    tags_match = subterranean_SAE_direct_decrypt(m, t_prime, k, CRYPTO_KEYBYTES, npub, CRYPTO_NPUBBYTES, &c[clen-CRYPTO_ABYTES], CRYPTO_ABYTES, ad, adlen, c, (clen-CRYPTO_ABYTES));
    /* Compact output */
    *mlen = clen-CRYPTO_ABYTES;
    /* Release memory */
    return tags_match;
}