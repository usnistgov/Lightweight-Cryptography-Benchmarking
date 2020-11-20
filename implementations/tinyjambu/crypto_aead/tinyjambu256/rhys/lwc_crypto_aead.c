#include "lwc_crypto_aead.h"
#include "api.h"
#include "tinyjambu.h"


aead_ctx lwc_aead_cipher = {
	"tinyjambu256",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	tiny_jambu_256_aead_encrypt,
	tiny_jambu_256_aead_decrypt
};

