#include "lwc_crypto_aead.h"
#include "api.h"
#include "sparkle.h"


aead_ctx lwc_aead_cipher = {
	"schwaemm192192v2",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	schwaemm_192_192_aead_encrypt,
	schwaemm_192_192_aead_decrypt
};

