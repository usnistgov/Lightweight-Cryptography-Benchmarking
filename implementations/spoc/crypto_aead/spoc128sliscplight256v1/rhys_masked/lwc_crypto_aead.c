#include "lwc_crypto_aead.h"
#include "api.h"
#include "spoc-masked.h"


aead_ctx lwc_aead_cipher = {
	"spoc128sliscplight256v1",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	spoc_128_masked_aead_encrypt,
	spoc_128_masked_aead_decrypt
};

