#include "lwc_crypto_aead.h"
#include "api.h"
#include "tinyjambu.h"


aead_ctx lwc_aead_cipher = {
	"tinyjambu128",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	tiny_jambu_128_aead_encrypt,
	tiny_jambu_128_aead_decrypt
};

