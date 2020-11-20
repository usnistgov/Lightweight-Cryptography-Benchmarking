#include "lwc_crypto_aead.h"
#include "api.h"
#include "forkae.h"


aead_ctx lwc_aead_cipher = {
	"paefforkskinnyb128t256n112v1",
	"opt32_table",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	forkae_paef_128_256_aead_encrypt,
	forkae_paef_128_256_aead_decrypt
};

