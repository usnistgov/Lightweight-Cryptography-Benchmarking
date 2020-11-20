#include "lwc_crypto_aead.h"
#include "api.h"
#include "isap.h"


aead_ctx lwc_aead_cipher = {
	"isapa128av20",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	isap_ascon_128a_aead_encrypt,
	isap_ascon_128a_aead_decrypt
};

