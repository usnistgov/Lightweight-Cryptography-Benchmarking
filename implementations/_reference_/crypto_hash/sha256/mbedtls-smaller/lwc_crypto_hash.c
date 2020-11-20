#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"sha256",
	"mbedtls-smaller",
	CRYPTO_BYTES,
	crypto_hash,
};

