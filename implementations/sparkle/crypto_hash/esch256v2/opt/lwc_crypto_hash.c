#include "lwc_crypto_hash.h"
#include "api.h"
#include "sparkle_opt.h"

hash_ctx lwc_hash_ctx = {
	"esch256v2",
	"opt",
	CRYPTO_BYTES,
	crypto_hash,
};

