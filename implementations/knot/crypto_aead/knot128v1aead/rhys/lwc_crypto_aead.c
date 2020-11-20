#include "lwc_crypto_aead.h"
#include "api.h"
#include "knot.h"


aead_ctx lwc_aead_cipher = {
	"knot128v1aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	knot_aead_128_256_encrypt,
	knot_aead_128_256_decrypt
};

