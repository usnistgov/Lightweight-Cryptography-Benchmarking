#include "lwc_crypto_aead.h"
#include "api.h"
#include "sundae-gift.h"


aead_ctx lwc_aead_cipher = {
	"sundaegift0v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	sundae_gift_0_aead_encrypt,
	sundae_gift_0_aead_decrypt
};

