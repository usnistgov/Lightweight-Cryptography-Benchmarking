#include "lwc_crypto_aead.h"
#include "api.h"
#include "spix.h"


aead_ctx lwc_aead_cipher = {
	"spix128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	spix_aead_encrypt,
	spix_aead_decrypt
};

