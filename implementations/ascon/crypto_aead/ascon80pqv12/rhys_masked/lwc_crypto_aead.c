#include "lwc_crypto_aead.h"
#include "api.h"
#include "ascon128-masked.h"


aead_ctx lwc_aead_cipher = {
	"ascon80pqv12",
	"rhys_masked",
	CRYPTO_KEYBYTES,
	CRYPTO_NPUBBYTES,
	CRYPTO_ABYTES,
	ascon80pq_masked_aead_encrypt,
	ascon80pq_masked_aead_decrypt
};

