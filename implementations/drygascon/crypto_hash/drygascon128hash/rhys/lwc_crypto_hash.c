#include "lwc_crypto_hash.h"
#include "api.h"
#include "drygascon.h"

hash_ctx lwc_hash_ctx = {
	"drygascon128hash",
	"ryhs",
	CRYPTO_BYTES,
	drygascon128_hash,
};

