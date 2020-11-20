#include "lwc_crypto_aead.h"
#include "api.h"
#include "AES.h"
#include "GCM.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k)
{
	GCM<AES128> aesgcm;
	aesgcm.setKey(k, CRYPTO_KEYBYTES);
	aesgcm.setIV(npub, CRYPTO_NPUBBYTES);
	aesgcm.addAuthData(ad, adlen);
	aesgcm.encrypt(c, m, mlen);
	aesgcm.computeTag(c + mlen, CRYPTO_ABYTES);
	*clen = mlen + CRYPTO_ABYTES;
	return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
	unsigned char* nsec,
	const unsigned char* c, unsigned long long clen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* npub,
	const unsigned char* k)
{
	GCM<AES128> aesgcm;
	aesgcm.setKey(k, CRYPTO_KEYBYTES);
	aesgcm.setIV(npub, CRYPTO_NPUBBYTES);
	aesgcm.addAuthData(ad, adlen);
	aesgcm.decrypt(m, c, clen - CRYPTO_ABYTES);
	*mlen = clen - CRYPTO_ABYTES;
	return !aesgcm.checkTag(c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
}

aead_ctx lwc_aead_cipher = {
	"aes-gcm",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_encrypt,
	crypto_aead_decrypt
};

