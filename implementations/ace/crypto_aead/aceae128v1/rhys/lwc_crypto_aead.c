#include "lwc_crypto_aead.h"
#include "api.h"
#include "ace.h"


aead_ctx lwc_aead_cipher = {
	"aceae128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	ace_aead_encrypt,
	ace_aead_decrypt
};

