#include "lwc_crypto_hash.h"
#include "api.h"
#include "knot.h"

hash_ctx lwc_hash_ctx = {
	"knot512hash",
	"ryhs",
	CRYPTO_BYTES,
	knot_hash_512_512,
};

