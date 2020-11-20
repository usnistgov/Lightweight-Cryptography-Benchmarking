#include "lwc_crypto_aead.h"
#include "api.h"
#include "spoc-masked.h"


aead_ctx lwc_aead_cipher = {
	"spoc64sliscplight192v1",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	spoc_64_masked_aead_encrypt,
	spoc_64_masked_aead_decrypt
};

