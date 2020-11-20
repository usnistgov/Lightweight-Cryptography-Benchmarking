#include "lwc_crypto_aead.h"
#include "api.h"
#include "sparkle.h"


aead_ctx lwc_aead_cipher = {
	"schwaemm128128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	schwaemm_128_128_aead_encrypt,
	schwaemm_128_128_aead_decrypt
};

