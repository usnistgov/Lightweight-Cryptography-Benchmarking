#include "lwc_crypto_aead.h"
#include "api.h"
#include "skinny-aead.h"


aead_ctx lwc_aead_cipher = {
	"skinnyaeadtk296128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	skinny_aead_m5_encrypt,
	skinny_aead_m5_decrypt
};

