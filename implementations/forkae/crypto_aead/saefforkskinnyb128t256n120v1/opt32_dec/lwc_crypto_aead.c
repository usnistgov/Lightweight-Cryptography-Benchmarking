#include "lwc_crypto_aead.h"
#include "api.h"
#include "forkae.h"


aead_ctx lwc_aead_cipher = {
	"saefforkskinnyb128t256n120v1",
	"opt32_dec",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	forkae_saef_128_256_aead_encrypt,
	forkae_saef_128_256_aead_decrypt
};

