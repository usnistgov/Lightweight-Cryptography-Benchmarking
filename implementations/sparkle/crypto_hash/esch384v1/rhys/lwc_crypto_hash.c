#include "lwc_crypto_hash.h"
#include "api.h"
#include "sparkle.h"

hash_ctx lwc_hash_ctx = {
	"esch384v1",
	"ryhs",
	CRYPTO_BYTES,
	esch_384_hash,
};

