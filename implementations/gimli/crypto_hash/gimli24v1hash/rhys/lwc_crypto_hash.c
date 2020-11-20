#include "lwc_crypto_hash.h"
#include "api.h"
#include "gimli24.h"

hash_ctx lwc_hash_ctx = {
	"gimli24v1hash",
	"ryhs",
	CRYPTO_BYTES,
	gimli24_hash,
};

