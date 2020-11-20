#include "lwc_crypto_aead.h"
#include "api.h"
#include "spoc.h"


aead_ctx lwc_aead_cipher = {
	"spoc64sliscplight192v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	spoc_64_aead_encrypt,
	spoc_64_aead_decrypt
};

