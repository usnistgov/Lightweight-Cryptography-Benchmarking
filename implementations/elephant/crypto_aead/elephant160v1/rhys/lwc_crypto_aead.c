#include "lwc_crypto_aead.h"
#include "api.h"
#include "elephant.h"


aead_ctx lwc_aead_cipher = {
	"elephant160v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	dumbo_aead_encrypt,
	dumbo_aead_decrypt
};

