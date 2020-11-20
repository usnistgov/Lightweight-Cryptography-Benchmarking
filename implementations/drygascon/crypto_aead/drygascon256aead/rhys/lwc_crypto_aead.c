#include "lwc_crypto_aead.h"
#include "api.h"
#include "drygascon.h"


aead_ctx lwc_aead_cipher = {
	"drygascon256aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	drygascon256_aead_encrypt,
	drygascon256_aead_decrypt
};

