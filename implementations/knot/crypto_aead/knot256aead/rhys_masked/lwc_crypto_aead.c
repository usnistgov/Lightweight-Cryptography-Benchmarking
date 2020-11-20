#include "lwc_crypto_aead.h"
#include "api.h"
#include "knot-masked.h"


aead_ctx lwc_aead_cipher = {
	"knot256aead",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	knot_masked_256_512_aead_encrypt,
	knot_masked_256_512_aead_decrypt
};

