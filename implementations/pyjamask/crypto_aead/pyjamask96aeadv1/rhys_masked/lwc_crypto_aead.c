#include "lwc_crypto_aead.h"
#include "api.h"
#include "pyjamask-masked.h"


aead_ctx lwc_aead_cipher = {
	"pyjamask96aeadv1",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	pyjamask_masked_96_aead_encrypt,
	pyjamask_masked_96_aead_decrypt
};

