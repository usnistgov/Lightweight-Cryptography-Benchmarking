#include "lwc_crypto_aead.h"
#include "api.h"
#include "gift-cofb.h"


aead_ctx lwc_aead_cipher = {
	"giftcofb128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	gift_cofb_aead_encrypt,
	gift_cofb_aead_decrypt
};

