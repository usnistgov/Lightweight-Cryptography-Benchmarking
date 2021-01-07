#include "api.h"
#include "isap.h"

int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
){
    (void)nsec;  
    
	// Ciphertext length is mlen + tag length
	*clen = mlen+ISAP_TAG_SZ;

	// Encrypt plaintext
	if (mlen > 0) {
		isap_enc(k,npub,m,mlen,c);
	}

	// Generate tag
	unsigned char *tag = c+mlen;
	isap_mac(k,npub,ad,adlen,c,mlen,tag);
	return 0;
}

