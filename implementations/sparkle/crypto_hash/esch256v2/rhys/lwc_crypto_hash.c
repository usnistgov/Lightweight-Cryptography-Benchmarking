#include "lwc_crypto_hash.h"
#include "api.h"
#include "sparkle.h"

hash_ctx lwc_hash_ctx = {
	"esch256v2",
	"rhys",
	CRYPTO_BYTES,
	esch_256_hash,
};

