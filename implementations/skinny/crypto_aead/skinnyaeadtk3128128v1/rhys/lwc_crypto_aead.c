#include "lwc_crypto_aead.h"
#include "api.h"
#include "skinny-aead.h"


aead_ctx lwc_aead_cipher = {
	"skinnyaeadtk3128128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	skinny_aead_m1_encrypt,
	skinny_aead_m1_decrypt
};

