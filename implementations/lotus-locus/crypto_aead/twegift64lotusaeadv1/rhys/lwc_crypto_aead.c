#include "lwc_crypto_aead.h"
#include "api.h"
#include "lotus-locus.h"


aead_ctx lwc_aead_cipher = {
	"twegift64lotusaeadv1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	lotus_aead_encrypt,
	lotus_aead_decrypt
};

