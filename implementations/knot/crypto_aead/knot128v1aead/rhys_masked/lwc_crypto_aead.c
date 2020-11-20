#include "lwc_crypto_aead.h"
#include "api.h"
#include "knot-masked.h"


aead_ctx lwc_aead_cipher = {
	"knot128v1aead",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	knot_masked_128_256_aead_encrypt,
	knot_masked_128_256_aead_decrypt
};

