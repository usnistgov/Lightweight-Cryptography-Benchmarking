#include "lwc_crypto_aead.h"
#include "api.h"
#include "xoodyak.h"


aead_ctx lwc_aead_cipher = {
	"xoodyakv1aead",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	xoodyak_aead_encrypt,
	xoodyak_aead_decrypt
};

