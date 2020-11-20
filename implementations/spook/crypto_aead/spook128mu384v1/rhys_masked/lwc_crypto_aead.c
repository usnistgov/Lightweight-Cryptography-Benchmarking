#include "lwc_crypto_aead.h"
#include "api.h"
#include "spook-masked.h"


aead_ctx lwc_aead_cipher = {
	"spook128mu384v1",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	spook_128_384_mu_masked_aead_encrypt,
	spook_128_384_mu_masked_aead_decrypt
};

