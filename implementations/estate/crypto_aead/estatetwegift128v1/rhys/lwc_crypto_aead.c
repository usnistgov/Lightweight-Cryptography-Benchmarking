#include "lwc_crypto_aead.h"
#include "api.h"
#include "estate.h"


aead_ctx lwc_aead_cipher = {
	"estatetwegift128v1",
	"rhys",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	estate_twegift_aead_encrypt,
	estate_twegift_aead_decrypt
};

