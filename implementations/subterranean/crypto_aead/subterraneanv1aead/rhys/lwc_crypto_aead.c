#include "lwc_crypto_aead.h"
#include "api.h"
#include "subterranean.h"


aead_ctx lwc_aead_cipher = {
	"subterraneanv1aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	subterranean_aead_encrypt,
	subterranean_aead_decrypt
};

