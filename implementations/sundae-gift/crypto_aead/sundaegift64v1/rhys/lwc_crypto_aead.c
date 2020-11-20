#include "lwc_crypto_aead.h"
#include "api.h"
#include "sundae-gift.h"


aead_ctx lwc_aead_cipher = {
	"sundaegift64v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	sundae_gift_64_aead_encrypt,
	sundae_gift_64_aead_decrypt
};

