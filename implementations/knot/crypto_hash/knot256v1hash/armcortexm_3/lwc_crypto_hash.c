#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"knot256v1hash",
	"armcortexm_3",
	CRYPTO_BYTES,
	crypto_hash,
};

