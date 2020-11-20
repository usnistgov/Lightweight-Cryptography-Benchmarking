#include "lwc_crypto_aead.h"
#include "api.h"
#include "crypto_aead_gimli24v1.h"


aead_ctx lwc_aead_cipher = {
	"gimli24v1aead",
	"littleendian",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	crypto_aead_gimli24v1_littleendian_encrypt,
	crypto_aead_gimli24v1_littleendian_decrypt
};

