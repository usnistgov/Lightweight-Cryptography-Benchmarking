#include "lwc_crypto_aead.h"
#include "api.h"
#include "xoodyak-masked.h"


aead_ctx lwc_aead_cipher = {
	"xoodyakv1aead",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	xoodyak_masked_aead_encrypt,
	xoodyak_masked_aead_decrypt
};

