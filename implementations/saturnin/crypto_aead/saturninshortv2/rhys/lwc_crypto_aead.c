#include "lwc_crypto_aead.h"
#include "api.h"
#include "saturnin.h"


aead_ctx lwc_aead_cipher = {
	"saturninshortv2",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	saturnin_short_aead_encrypt,
	saturnin_short_aead_decrypt
};

