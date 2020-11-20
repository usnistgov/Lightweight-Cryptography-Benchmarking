#include "lwc_crypto_aead.h"
#include "api.h"
#include "elephant.h"


aead_ctx lwc_aead_cipher = {
	"elephant200v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	delirium_aead_encrypt,
	delirium_aead_decrypt
};

