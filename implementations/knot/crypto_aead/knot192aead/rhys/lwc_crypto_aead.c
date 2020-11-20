#include "lwc_crypto_aead.h"
#include "api.h"
#include "knot.h"


aead_ctx lwc_aead_cipher = {
	"knot192aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	knot_aead_192_384_encrypt,
	knot_aead_192_384_decrypt
};

