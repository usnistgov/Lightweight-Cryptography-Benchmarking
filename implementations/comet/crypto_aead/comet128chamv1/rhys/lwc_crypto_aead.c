#include "lwc_crypto_aead.h"
#include "api.h"
#include "comet.h"


aead_ctx lwc_aead_cipher = {
	"comet128chamv1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	comet_128_cham_aead_encrypt,
	comet_128_cham_aead_decrypt
};

