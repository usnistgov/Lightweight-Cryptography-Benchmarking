#include "lwc_crypto_hash.h"
#include "api.h"
#include "knot.h"

hash_ctx lwc_hash_ctx = {
	"knot384hash",
	"rhys",
	CRYPTO_BYTES,
	knot_hash_384_384,
};

