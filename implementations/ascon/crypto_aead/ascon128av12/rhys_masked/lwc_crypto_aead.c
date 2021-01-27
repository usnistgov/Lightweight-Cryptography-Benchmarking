#include "lwc_crypto_aead.h"
#include "api.h"
#include "ascon128-masked.h"


aead_ctx lwc_aead_cipher = {
	"ascon128av12",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	ascon128a_masked_aead_encrypt,
	ascon128a_masked_aead_decrypt
};

