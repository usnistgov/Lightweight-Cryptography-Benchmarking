#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"knot256v2hash",
	"armcortexm_5",
	CRYPTO_BYTES,
	crypto_hash,
};

