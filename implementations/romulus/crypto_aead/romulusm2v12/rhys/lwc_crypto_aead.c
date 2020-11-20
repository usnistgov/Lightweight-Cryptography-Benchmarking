#include "lwc_crypto_aead.h"
#include "api.h"
#include "romulus.h"


aead_ctx lwc_aead_cipher = {
	"romulusm2v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	romulus_m2_aead_encrypt,
	romulus_m2_aead_decrypt
};

