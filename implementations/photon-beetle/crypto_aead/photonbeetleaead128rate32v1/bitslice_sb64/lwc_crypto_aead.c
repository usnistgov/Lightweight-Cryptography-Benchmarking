#include "lwc_crypto_aead.h"
#include "api.h"


aead_ctx lwc_aead_cipher = {
	"photonbeetleaead128rate32v1",
	"bitslice_sb64",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_encrypt,
	crypto_aead_decrypt
};

