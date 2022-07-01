#include "lwc_crypto_hash.h"
#include "api.h"


hash_ctx lwc_hash_ctx = {
	"photonbeetlehash256rate32v1",
	"table3",
	CRYPTO_BYTES,
	crypto_hash,
};

