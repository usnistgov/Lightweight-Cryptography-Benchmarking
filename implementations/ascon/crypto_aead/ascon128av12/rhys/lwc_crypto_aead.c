#include "lwc_crypto_aead.h"
#include "api.h"
#include "ascon128.h"


aead_ctx lwc_aead_cipher = {
	"ascon128av12",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	ascon128a_aead_encrypt,
	ascon128a_aead_decrypt
};

