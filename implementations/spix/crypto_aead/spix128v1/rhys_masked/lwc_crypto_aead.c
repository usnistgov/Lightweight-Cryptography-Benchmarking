#include "lwc_crypto_aead.h"
#include "api.h"
#include "spix-masked.h"


aead_ctx lwc_aead_cipher = {
	"spix128v1",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	spix_masked_aead_encrypt,
	spix_masked_aead_decrypt
};

