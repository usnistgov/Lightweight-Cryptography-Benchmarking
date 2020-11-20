#include "lwc_crypto_aead.h"
#include "api.h"
#include "romulus.h"


aead_ctx lwc_aead_cipher = {
	"romulusm3v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	romulus_m3_aead_encrypt,
	romulus_m3_aead_decrypt
};

