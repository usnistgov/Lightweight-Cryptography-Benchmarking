#include "lwc_crypto_aead.h"
#include "api.h"
#include "isap.h"


aead_ctx lwc_aead_cipher = {
	"isapk128av20",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	isap_keccak_128a_aead_encrypt,
	isap_keccak_128a_aead_decrypt
};

