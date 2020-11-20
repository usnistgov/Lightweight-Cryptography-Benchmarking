#include "lwc_crypto_aead.h"
#include "api.h"
#include "pyjamask.h"


aead_ctx lwc_aead_cipher = {
	"pyjamask128aeadv1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	pyjamask_128_aead_encrypt,
	pyjamask_128_aead_decrypt
};

