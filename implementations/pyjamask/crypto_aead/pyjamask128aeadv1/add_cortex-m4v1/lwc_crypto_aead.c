#include "lwc_crypto_aead.h"
#include "lwc_api.h"


aead_ctx lwc_aead_cipher = {
	"pyjamask128aeadv1",
	"add_cortex-m4v1",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_encrypt,
	crypto_aead_decrypt
};

