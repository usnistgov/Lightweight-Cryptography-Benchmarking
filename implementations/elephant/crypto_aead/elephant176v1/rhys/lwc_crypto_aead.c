#include "lwc_crypto_aead.h"
#include "api.h"
#include "elephant.h"


aead_ctx lwc_aead_cipher = {
	"elephant176v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	jumbo_aead_encrypt,
	jumbo_aead_decrypt
};

