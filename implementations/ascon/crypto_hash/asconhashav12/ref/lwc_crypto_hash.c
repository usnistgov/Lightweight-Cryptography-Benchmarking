#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"asconhashav12",
	"ref",
	CRYPTO_BYTES,
	crypto_hash,
};

