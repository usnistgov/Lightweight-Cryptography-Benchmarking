#include "lwc_crypto_aead.h"
#include "api.h"
#include "romulus.h"


aead_ctx lwc_aead_cipher = {
	"romulusm1v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	romulus_m1_aead_encrypt,
	romulus_m1_aead_decrypt
};

