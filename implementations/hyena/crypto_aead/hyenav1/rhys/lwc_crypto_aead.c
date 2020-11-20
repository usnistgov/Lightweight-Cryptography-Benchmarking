#include "lwc_crypto_aead.h"
#include "api.h"
#include "hyena.h"


aead_ctx lwc_aead_cipher = {
	"hyenav1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	hyena_v1_aead_encrypt,
	hyena_v1_aead_decrypt
};

