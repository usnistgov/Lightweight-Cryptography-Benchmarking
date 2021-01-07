#include "lwc_crypto_aead.h"
#include "api.h"
#include "drygascon.h"


aead_ctx lwc_aead_cipher = {
	"drygascon128aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	drygascon128k16_aead_encrypt,
	drygascon128k16_aead_decrypt
};

