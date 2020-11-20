#include "lwc_crypto_aead.h"
#include "api.h"
#include "grain128.h"


aead_ctx lwc_aead_cipher = {
	"grain128aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	grain128_aead_encrypt,
	grain128_aead_decrypt
};

