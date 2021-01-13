#include "lwc_crypto_hash.h"
#include "api.h"

hash_ctx lwc_hash_ctx = {
	"esch256v2",
	"add_avr",
	CRYPTO_BYTES,
	crypto_hash,
};

