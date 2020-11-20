
#include "api.h"

int crypto_aead_encrypt(unsigned char *c,unsigned long long *clen,
						const unsigned char *m,unsigned long long mlen,
						const unsigned char *ad,unsigned long long adlen,
						const unsigned char *nsec,
						const unsigned char *npub,
						const unsigned char *k)
{
    *clen = mlen + CRYPTO_ABYTES;
    return 0;
}

int crypto_aead_decrypt(unsigned char *m,unsigned long long *mlen,
						unsigned char *nsec,
						const unsigned char *c,unsigned long long clen,
						const unsigned char *ad,unsigned long long adlen,
						const unsigned char *npub,
						const unsigned char *k)
{
	*mlen = clen - CRYPTO_ABYTES;
	return 0;
}
