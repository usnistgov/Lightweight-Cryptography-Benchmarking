#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"knot384hash",
	"opt",
	CRYPTO_BYTES,
	crypto_hash,
};

