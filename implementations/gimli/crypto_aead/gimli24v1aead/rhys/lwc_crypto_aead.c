#include "lwc_crypto_aead.h"
#include "api.h"
#include "gimli24.h"


aead_ctx lwc_aead_cipher = {
	"gimli24v1aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	gimli24_aead_encrypt,
	gimli24_aead_decrypt
};

