#include "lwc_crypto_aead.h"
#include "api.h"
#include "knot-masked.h"


aead_ctx lwc_aead_cipher = {
	"knot192aead",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	knot_masked_192_384_aead_encrypt,
	knot_masked_192_384_aead_decrypt
};

