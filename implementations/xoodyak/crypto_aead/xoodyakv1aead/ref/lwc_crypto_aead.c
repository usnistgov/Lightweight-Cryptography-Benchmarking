#include "lwc_crypto_aead.h"
#include "api.h"
#include "xoodyak.h"


aead_ctx lwc_aead_cipher = {
	"xoodyakv1aead",
	"ref",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_encrypt,
	crypto_aead_decrypt
};

