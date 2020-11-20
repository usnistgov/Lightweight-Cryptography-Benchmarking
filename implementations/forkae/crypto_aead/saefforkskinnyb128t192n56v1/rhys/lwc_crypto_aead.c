#include "lwc_crypto_aead.h"
#include "api.h"
#include "forkae.h"


aead_ctx lwc_aead_cipher = {
	"saefforkskinnyb128t192n56v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	forkae_saef_128_192_aead_encrypt,
	forkae_saef_128_192_aead_decrypt
};

