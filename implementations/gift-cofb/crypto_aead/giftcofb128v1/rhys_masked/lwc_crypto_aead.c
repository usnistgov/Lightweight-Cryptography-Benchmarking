#include "lwc_crypto_aead.h"
#include "api.h"
#include "gift-cofb-masked.h"


aead_ctx lwc_aead_cipher = {
	"giftcofb128v1",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	gift_cofb_masked_aead_encrypt,
	gift_cofb_masked_aead_decrypt
};

