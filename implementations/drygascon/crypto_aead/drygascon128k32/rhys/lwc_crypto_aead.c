#include "lwc_crypto_aead.h"
#include "api.h"
#include "drygascon.h"


aead_ctx lwc_aead_cipher = {
	"drygascon128k32",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	drygascon128k32_aead_encrypt,
	drygascon128k32_aead_decrypt
};

