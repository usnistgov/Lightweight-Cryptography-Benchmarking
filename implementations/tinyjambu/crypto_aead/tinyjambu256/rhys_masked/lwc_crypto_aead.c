#include "lwc_crypto_aead.h"
#include "api.h"
#include "tinyjambu-masked.h"


aead_ctx lwc_aead_cipher = {
	"tinyjambu256",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	tiny_jambu_256_masked_aead_encrypt,
	tiny_jambu_256_masked_aead_decrypt
};

