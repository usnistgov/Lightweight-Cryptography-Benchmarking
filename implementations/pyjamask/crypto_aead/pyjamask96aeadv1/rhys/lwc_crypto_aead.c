#include "lwc_crypto_aead.h"
#include "api.h"
#include "pyjamask.h"


aead_ctx lwc_aead_cipher = {
	"pyjamask96aeadv1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	pyjamask_96_aead_encrypt,
	pyjamask_96_aead_decrypt
};

