#include "lwc_crypto_aead.h"
#include "api.h"
#include "forkae.h"


aead_ctx lwc_aead_cipher = {
	"paefforkskinnyb128t288n104v1",
	"opt32_table",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	forkae_paef_128_288_aead_encrypt,
	forkae_paef_128_288_aead_decrypt
};

