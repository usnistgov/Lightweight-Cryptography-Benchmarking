#include "lwc_crypto_hash.h"
#include "api.h"
#include "sparkle_ref.h"

hash_ctx lwc_hash_ctx = {
	"esch384v2",
	"ref",
	CRYPTO_BYTES,
	crypto_hash,
};

