#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"drygascon256hash",
	"ref",
	CRYPTO_BYTES,
	crypto_hash,
};

