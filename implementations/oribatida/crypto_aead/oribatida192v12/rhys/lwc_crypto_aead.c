#include "lwc_crypto_aead.h"
#include "api.h"
#include "oribatida.h"


aead_ctx lwc_aead_cipher = {
	"oribatida192v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	oribatida_192_aead_encrypt,
	oribatida_192_aead_decrypt
};

