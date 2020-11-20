#include "lwc_crypto_aead.h"
#include "api.h"
#include "romulus.h"


aead_ctx lwc_aead_cipher = {
	"romulusn3v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	romulus_n3_aead_encrypt,
	romulus_n3_aead_decrypt
};

