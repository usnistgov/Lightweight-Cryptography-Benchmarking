#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"knot512hash",
	"armcortexm_2",
	CRYPTO_BYTES,
	crypto_hash,
};

