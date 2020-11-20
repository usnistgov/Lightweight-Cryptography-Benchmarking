#include "lwc_crypto_aead.h"
#include "api.h"
#include "photon-beetle.h"


aead_ctx lwc_aead_cipher = {
	"photonbeetleaead128rate128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	photon_beetle_128_aead_encrypt,
	photon_beetle_128_aead_decrypt
};

