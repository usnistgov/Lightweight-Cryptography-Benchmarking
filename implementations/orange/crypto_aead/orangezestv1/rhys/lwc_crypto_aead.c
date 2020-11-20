#include "lwc_crypto_aead.h"
#include "api.h"
#include "orange.h"


aead_ctx lwc_aead_cipher = {
	"orangezestv1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	orange_zest_aead_encrypt,
	orange_zest_aead_decrypt
};

