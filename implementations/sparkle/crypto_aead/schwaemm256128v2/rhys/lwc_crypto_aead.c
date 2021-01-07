#include "lwc_crypto_aead.h"
#include "api.h"
#include "sparkle.h"


aead_ctx lwc_aead_cipher = {
	"schwaemm256128v2",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	schwaemm_256_128_aead_encrypt,
	schwaemm_256_128_aead_decrypt
};

