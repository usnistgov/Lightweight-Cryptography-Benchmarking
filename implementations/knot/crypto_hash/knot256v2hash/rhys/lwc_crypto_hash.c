#include "lwc_crypto_hash.h"
#include "api.h"
#include "knot.h"

hash_ctx lwc_hash_ctx = {
	"knot256v2hash",
	"ryhs",
	CRYPTO_BYTES,
	knot_hash_256_384,
};

