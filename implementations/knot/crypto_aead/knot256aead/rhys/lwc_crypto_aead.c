#include "lwc_crypto_aead.h"
#include "api.h"
#include "knot.h"


aead_ctx lwc_aead_cipher = {
	"knot256aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	knot_aead_256_512_encrypt,
	knot_aead_256_512_decrypt
};

