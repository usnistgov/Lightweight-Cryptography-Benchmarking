#include "lwc_crypto_aead.h"
#include "api.h"
#include "gimli24-masked.h"


aead_ctx lwc_aead_cipher = {
	"gimli24v1aead",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	gimli24_masked_aead_encrypt,
	gimli24_masked_aead_decrypt
};

