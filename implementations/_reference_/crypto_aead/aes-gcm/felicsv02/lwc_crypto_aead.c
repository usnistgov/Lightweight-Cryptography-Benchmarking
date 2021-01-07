#include "lwc_crypto_aead.h"
#include "api.h"
#include "cipher.h"
#include "constants.h"
#include <string.h>

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k)
{
    RAM_DATA_BYTE state[STATE_SIZE] = { 0 };

	// copy message to ciphertext buffer for inplace encryption
	memcpy(c, m, mlen);

    Initialize(state, k, npub);
    ProcessAssociatedData(state, ad, adlen);
    ProcessPlaintext(state, c, mlen);
    Finalize(state, k);
    TagGeneration(state, c + mlen);

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
    RAM_DATA_BYTE state[STATE_SIZE] = { 0 };
    RAM_DATA_BYTE tag[TAG_SIZE] = { 0 };

	// copy ciphertext to message buffer for inplace decryption
	memcpy(m, c, clen - CRYPTO_ABYTES);

    Initialize(state, k, npub);
    ProcessAssociatedData(state, ad, adlen);
    ProcessCiphertext(state, m, clen - CRYPTO_ABYTES);
    Finalize(state, k);
    TagGeneration(state, tag);

	*mlen = clen - CRYPTO_ABYTES;

	// tag comparison
	unsigned int diff = 0;
	for(int i = 0; i < CRYPTO_ABYTES; i++)
		diff |= tag[i] ^ c[clen - CRYPTO_ABYTES + i];

	return ((diff - 1) & 1) - 1;
}

aead_ctx lwc_aead_cipher = {
	"aes-gcm",
	"felicsv02",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_encrypt,
	crypto_aead_decrypt
};

