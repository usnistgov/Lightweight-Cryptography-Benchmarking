#include "lwc_crypto_aead.h"
#include "api.h"
#include "lotus-locus.h"


aead_ctx lwc_aead_cipher = {
	"twegift64locusaeadv1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	locus_aead_encrypt,
	locus_aead_decrypt
};

