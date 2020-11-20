#include "lwc_crypto_aead.h"
#include "api.h"
#include "wage.h"


aead_ctx lwc_aead_cipher = {
	"wageae128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	wage_aead_encrypt,
	wage_aead_decrypt
};

