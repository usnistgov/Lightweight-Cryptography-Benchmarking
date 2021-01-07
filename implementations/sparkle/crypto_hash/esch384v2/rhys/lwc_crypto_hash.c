#include "lwc_crypto_hash.h"
#include "api.h"
#include "sparkle.h"

hash_ctx lwc_hash_ctx = {
	"esch384v2",
	"rhys",
	CRYPTO_BYTES,
	esch_384_hash,
};

