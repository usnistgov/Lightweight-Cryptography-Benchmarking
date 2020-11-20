#include "lwc_crypto_aead.h"
#include "api.h"
#include "romulus.h"


aead_ctx lwc_aead_cipher = {
	"romulusn2v12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	romulus_n2_aead_encrypt,
	romulus_n2_aead_decrypt
};

