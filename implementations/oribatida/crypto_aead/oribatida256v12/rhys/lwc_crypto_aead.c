#include "lwc_crypto_aead.h"
#include "api.h"
#include "oribatida.h"


aead_ctx lwc_aead_cipher = {
	"oribatida256v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	oribatida_256_aead_encrypt,
	oribatida_256_aead_decrypt
};

